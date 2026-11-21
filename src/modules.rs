//! Cross-referenced module map.
//!
//! Builds a comprehensive view of which Nim modules are compiled into a
//! binary by cross-referencing four independent data sources:
//!
//! 1. **Demangled symbols**: module names from mangled symbol names in
//!    every layout that carries one (see [`crate::demangle::symbol`]).
//! 2. **Emitting C files**: for Nim 1.0 - 1.4 names, which carry no module,
//!    the source file each function was compiled from
//!    ([`Container::symbol_source_file`]). That is the module that emitted
//!    the code, which for inline procs and generic instances is the one that
//!    uses them, so such entries are flagged
//!    ([`ModuleSymbol::from_source_file`]).
//! 3. **Init functions**: module paths decoded from `*Init000` symbol names.
//! 4. **Stack-trace file paths**: `.nim` file paths embedded in rodata.
//!
//! All sources are reconciled into a single map. The key is the
//! compiler's unique module name taken from the symbols (`system`,
//! `pureZstrutils`, `stdZprivateZdigitsutils`: the module path with `/` as
//! `Z`, `.` as `O`, other characters as decimal codes). Init-function paths,
//! stack-trace paths and Itanium owners are encoded the same way and
//! attached to the one unique name they match; without a match (stripped
//! binaries, Nim 1.0 - 1.4) the key falls back to the init-path stem, the
//! emitting file's module (Nim 1.x's own naming: `stdlib_io`, as in
//! `stdlib_ioInit000`) or the `.nim` file stem.

use std::collections::BTreeMap;

use crate::{
    container::{Container, Symbol},
    demangle::{
        modpath::PathPrefix,
        symbol::{Demangled, MangleScheme},
    },
    inits, stacktrace,
    util::encode_unique_name,
};

/// A reconstructed map of Nim modules present in the binary.
#[derive(Debug, Clone)]
pub struct ModuleMap {
    /// Modules keyed by canonical name (see the module docs): the compiler's
    /// unique module name when symbols provide one (`system`,
    /// `pureZstrutils`), otherwise an init-path or file stem.
    pub modules: BTreeMap<String, ModuleInfo>,
}

/// Information about a single Nim module.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Decoded filesystem path from init functions (e.g. `system/exceptions.nim`).
    pub init_path: Option<String>,
    /// Module path prefix (`@m`, `@p`, `@d`, etc.).
    pub prefix: Option<PathPrefix>,
    /// Virtual address of the `Init000` function, if found.
    pub init_addr: Option<u64>,
    /// Virtual address of the `DatInit000` function, if found.
    pub dat_init_addr: Option<u64>,
    /// Function symbols attributed to this module (demangled name + VA).
    pub symbols: Vec<ModuleSymbol>,
    /// Stack-trace file paths matching this module, if any.
    pub file_paths: Vec<String>,
}

/// A function symbol within a module.
///
/// `address` is a virtual address (image load space). Convert to an RVA
/// via [`crate::container::Container::va_to_rva`] /
/// [`crate::NimBinary::image_base`].
#[derive(Debug, Clone)]
pub struct ModuleSymbol {
    /// Demangled Nim identifier, followed by the compiler clone suffix when
    /// the symbol is a clone or split part (e.g. `eval.cold`, `foo.part.0`).
    pub name: String,
    /// Virtual address (image load space, not file offset).
    pub address: u64,
    /// Size in bytes (from ELF `st_size`; zero if unavailable).
    pub size: u64,
    /// The numeric disambiguator from the mangled name, when the layout has
    /// one: `itemId.item` for Nim 1.6 - 2.3, the per-(module, name) `disamb`
    /// from 2.4 (see [`crate::demangle::symbol::Demangled::disambiguator`]).
    pub disambiguator: Option<u64>,
    /// `true` when the module is the one whose C file emitted the function
    /// (Nim 1.0 - 1.4 names carry no module), not the one its name declares.
    /// For inline procs and generic instances that is the using module, not
    /// the owner. Covers every function on PE (COFF `.file` records); on ELF,
    /// local functions (`STT_FILE` grouping) and, in builds with DWARF, all
    /// others (compile-unit address ranges).
    pub from_source_file: bool,
}

impl ModuleInfo {
    /// Number of function symbols in this module.
    ///
    /// `usize` is always representable in `u64` on every target nimrod
    /// supports (32- and 64-bit), so callers persisting this count to a
    /// 64-bit column may cast `as u64` without overflow.
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }
}

/// Builds a cross-referenced module map from the container.
pub fn build(container: &Container<'_>) -> ModuleMap {
    let mut modules: BTreeMap<String, ModuleInfo> = BTreeMap::new();

    // Source 1: demangled symbols. Their module part is the compiler's
    // unique module name (`stdZprivateZdigitsutils`, `stdlib95mix`), which
    // becomes the canonical key; the other sources are matched against it.
    // Signature-hash names (Nim 1.0 - 1.4) carry no module. Itanium names
    // carry the plain module name and are matched like the other sources.
    let mut itanium = Vec::new();
    for sym in container.symbols() {
        let Some(d) = container.demangle(sym.name.as_ref()) else {
            continue;
        };
        let Some(module) = d.module.filter(|_| d.is_scheme_name()) else {
            continue;
        };
        if d.scheme == Some(MangleScheme::Itanium) {
            itanium.push((module, module_symbol(&d, sym)));
        } else {
            modules
                .entry(module.to_owned())
                .or_insert_with(default_info)
                .symbols
                .push(module_symbol(&d, sym));
        }
    }
    let unique: Vec<String> = modules.keys().cloned().collect();

    for (owner, msym) in itanium {
        let key =
            resolve_unique_key(&unique, owner).unwrap_or_else(|| encode_unique_name(owner, true));
        modules
            .entry(key)
            .or_insert_with(default_info)
            .symbols
            .push(msym);
    }

    // Source 2: init functions → decoded module paths.
    for f in inits::scan(container) {
        let stem = module_key_from_path(&f.module_path.path);
        let key = resolve_unique_key(&unique, &stem).unwrap_or(stem);
        let entry = modules.entry(key).or_insert_with(default_info);
        if entry.init_path.is_none() {
            entry.init_path = Some(f.module_path.path.clone());
        }
        if entry.prefix.is_none() {
            entry.prefix = f.module_path.prefix;
        }
        match f.kind {
            inits::InitKind::Init => entry.init_addr = Some(f.address),
            inits::InitKind::DatInit => entry.dat_init_addr = Some(f.address),
            inits::InitKind::HcrInit => {}
        }
    }

    // Signature-hash names (Nim 1.0 - 1.4) carry no module: group their
    // functions by the C file that emitted them. The file `stdlib_io.nim.c`
    // and the init function `stdlib_ioInit000` name the module alike, but
    // `stdlib_system.nim.c` initializes as `systemInit000`: an existing key
    // without the prefix is preferred over a new one with it.
    for (i, path) in functions_by_source_file(container) {
        let Some(sym) = container.symbols().get(i) else {
            continue;
        };
        let Some(d) = container.demangle(sym.name.as_ref()) else {
            continue;
        };
        if d.scheme != Some(MangleScheme::SigHash) {
            continue;
        }
        let key = match path.strip_prefix("stdlib_") {
            Some(bare) if !modules.contains_key(&path) && modules.contains_key(bare) => {
                bare.to_owned()
            }
            _ => path,
        };
        let mut msym = module_symbol(&d, sym);
        msym.from_source_file = true;
        modules
            .entry(key)
            .or_insert_with(default_info)
            .symbols
            .push(msym);
    }

    // Source 3: stack-trace file paths → merge into existing modules.
    let harvest = stacktrace::harvest(container);
    for fp in &harvest.file_paths {
        let without_ext = fp.path.strip_suffix(".nim").unwrap_or(&fp.path);
        let basename = fp.path.rsplit(['/', '\\']).next().unwrap_or(&fp.path);
        let stem = basename.strip_suffix(".nim").unwrap_or(basename);

        // Match, in order: a unique module name, an existing key equal to
        // the stem or (Nim 1.x library modules) to `stdlib_<stem>`, an init
        // path naming the same file.
        let stdlib_stem = format!("stdlib_{stem}");
        let matched_key = resolve_unique_key(&unique, without_ext)
            .or_else(|| modules.contains_key(stem).then(|| stem.to_owned()))
            .or_else(|| modules.contains_key(&stdlib_stem).then_some(stdlib_stem))
            .or_else(|| {
                modules
                    .iter()
                    .find(|(_, info)| {
                        info.init_path
                            .as_ref()
                            .is_some_and(|p| same_file_tail(p, &fp.path))
                    })
                    .map(|(k, _)| k.clone())
            });

        let entry = modules
            .entry(matched_key.unwrap_or_else(|| stem.to_owned()))
            .or_insert_with(default_info);
        if !entry.file_paths.contains(&fp.path) {
            entry.file_paths.push(fp.path.clone());
        }
    }

    ModuleMap { modules }
}

/// A module entry with nothing known yet.
fn default_info() -> ModuleInfo {
    ModuleInfo {
        init_path: None,
        prefix: None,
        init_addr: None,
        dat_init_addr: None,
        symbols: Vec::new(),
        file_paths: Vec::new(),
    }
}

/// The module whose C file emitted each function, by symbol index, from
/// [`Container::symbol_source_file`] (symbol-table grouping by object file,
/// or DWARF compile units). This is exact about where the code was emitted,
/// which is not always the declaring module: inline procs and generic
/// instances are emitted in the module that uses them. On Nim 1.6+ builds,
/// whose names carry the owner, the two differ for 15% of mingw functions
/// and 28% of ELF local functions (inline copies dominate those).
fn functions_by_source_file(container: &Container<'_>) -> BTreeMap<usize, String> {
    container
        .symbols()
        .iter()
        .enumerate()
        .filter(|(_, s)| s.is_defined_function())
        .filter_map(|(i, _)| {
            let path = container
                .symbol_source_file(i)
                .and_then(source_file_module_path)?;
            Some((i, path))
        })
        .collect()
}

/// The module path of a Nim-generated C file: `@mmain.nim.c` -> `main`,
/// `@pstd@sprivate@sdigitsutils.nim.c` -> `std/private/digitsutils`,
/// `stdlib_io.nim.c` (Nim 1.x library modules) -> `stdlib_io`. mingw's
/// COFF `.file` records keep only 14 bytes of short names that do not fit
/// (`@palgorithm.ni`, seen for 15 - 17 byte names);
/// those still name their module, since a module path holds no `.`, but a
/// name cut inside the module path does not and yields `None`.
fn source_file_module_path(file: &str) -> Option<String> {
    const SUFFIXES: [&str; 3] = [".nim.c", ".nim.cpp", ".nim.m"];
    const COFF_TRUNCATED_LEN: usize = 14;
    let complete = SUFFIXES.iter().find_map(|s| file.strip_suffix(s));
    let stem = complete.or_else(|| {
        // A cut name: the text after the first `.` is a cut suffix.
        let (stem, ext) = file.split_once('.')?;
        (file.len() == COFF_TRUNCATED_LEN
            && SUFFIXES.iter().any(|s| s.starts_with(&format!(".{ext}"))))
        .then_some(stem)
    })?;
    let path = if let Some(rest) = stem.strip_prefix('@') {
        // @m (project), @p (library), @h ... : drop the marker, `@s` is `/`.
        rest.get(1..)?.replace("@s", "/")
    } else {
        stem.to_owned()
    };
    (!path.is_empty()).then_some(path)
}

/// The module-map entry of a demangled symbol: its identifier with any clone
/// suffix kept (`eval.cold`), address, size and disambiguator.
fn module_symbol(d: &Demangled<'_>, sym: &Symbol<'_>) -> ModuleSymbol {
    let mut name = d.identifier.clone().into_owned();
    if let Some(clone) = d.clone_suffix {
        name.push_str(clone);
    }
    ModuleSymbol {
        name,
        address: sym.vm_addr,
        size: sym.size,
        disambiguator: d.disambiguator,
        from_source_file: false,
    }
}

/// Finds the one unique module name that a path-like name refers to.
///
/// `path` is a module path without `.nim` (`std/private/digitsutils`,
/// `/opt/nim/lib/pure/strutils`) or a plain module name (`digitsutils`).
/// Its path tails, longest first, are encoded like `uniqueModuleName` and
/// compared with `unique`; a key matches when it equals the encoding or
/// ends in `Z<encoding>` (a whole path component). The first tail that
/// matches exactly one key wins; a tail matching several keys is ambiguous
/// and ends the search.
fn resolve_unique_key(unique: &[String], path: &str) -> Option<String> {
    let comps: Vec<&str> = path.split(['/', '\\']).filter(|c| !c.is_empty()).collect();
    for start in 0..comps.len() {
        let tail = comps.get(start..)?.join("/");
        let encodings = [
            encode_unique_name(&tail, true),
            encode_unique_name(&tail, false),
        ];
        let mut hits = unique.iter().filter(|k| {
            encodings.iter().any(|e| {
                k.as_str() == e
                    || k.strip_suffix(e.as_str())
                        .is_some_and(|head| head.ends_with('Z'))
            })
        });
        match (hits.next(), hits.next()) {
            (Some(only), None) => return Some(only.clone()),
            (Some(_), Some(_)) => return None,
            _ => {}
        }
    }
    None
}

/// Whether the decoded init path `init` (e.g. `std/exitprocs.nim`) names
/// the same file as the stack-trace path `trace`, comparing whole path
/// components from the end (`nif.nim` must not match `ast2nif.nim`).
fn same_file_tail(init: &str, trace: &str) -> bool {
    let mut a = init.rsplit(['/', '\\']);
    let mut b = trace.rsplit(['/', '\\']);
    let mut compared = false;
    loop {
        match (a.next(), b.next()) {
            (Some(x), Some(y)) if x == y => compared = true,
            (None, _) => return compared,
            _ => return false,
        }
    }
}

/// Derives a canonical module key from a decoded init-function path.
///
/// `"system.nim"` → `"system"`, `"system/exceptions.nim"` → `"system/exceptions"`,
/// `"dist/nimony/src/lib/nifstreams.nim"` → `"dist/nimony/src/lib/nifstreams"`.
fn module_key_from_path(path: &str) -> String {
    path.strip_suffix(".nim").unwrap_or(path).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_like_names_resolve_to_unique_keys() {
        let unique: Vec<String> = [
            "stdZprivateZdigitsutils",
            "stdlib95mix",
            "system",
            "aZhashes",
            "bZhashes",
            "OOZdistZnimonyZsrcZlibZnifpools",
            "pureZstrutils",
            "xsystem",
            "ospaths50",
        ]
        .map(String::from)
        .to_vec();
        let r = |p| resolve_unique_key(&unique, p);
        // Itanium owners (plain names).
        assert_eq!(r("digitsutils").as_deref(), Some("stdZprivateZdigitsutils"));
        assert_eq!(r("stdlib_mix").as_deref(), Some("stdlib95mix"));
        assert_eq!(r("system").as_deref(), Some("system"));
        // Init paths and stack-trace paths.
        assert_eq!(
            r("dist/nimony/src/lib/nifpools").as_deref(),
            Some("OOZdistZnimonyZsrcZlibZnifpools")
        );
        assert_eq!(
            r("../../opt/nim-1.6.20/lib/system").as_deref(),
            Some("system")
        );
        assert_eq!(
            r("/opt/nim/lib/pure/strutils").as_deref(),
            Some("pureZstrutils")
        );
        assert_eq!(
            r("C:\\nim\\lib\\pure\\strutils").as_deref(),
            Some("pureZstrutils")
        );
        // 1.6 encodes digits.
        assert_eq!(r("std/ospaths2").as_deref(), Some("ospaths50"));
        // Ambiguous across packages, unknown, partial component.
        assert_eq!(r("hashes"), None);
        assert_eq!(r("/src/a/hashes").as_deref(), Some("aZhashes"));
        assert_eq!(r("my_mod"), None);
        assert_eq!(r("ystem"), None);
    }

    #[test]
    fn file_tail_matches_whole_components() {
        assert!(same_file_tail("system.nim", "/opt/nim/lib/system.nim"));
        assert!(same_file_tail(
            "std/exitprocs.nim",
            "/opt/nim/lib/std/exitprocs.nim"
        ));
        assert!(same_file_tail(
            "std/exitprocs.nim",
            "C:\\nim\\lib\\std\\exitprocs.nim"
        ));
        assert!(!same_file_tail("ast2nif.nim", "/x/nif.nim"));
        assert!(!same_file_tail(
            "std/exitprocs.nim",
            "/x/pure/exitprocs.nim"
        ));
        assert!(!same_file_tail("", "/x/a.nim"));
    }

    #[test]
    fn source_file_module_paths() {
        assert_eq!(
            source_file_module_path("@mstdlib_mix.nim.c").as_deref(),
            Some("stdlib_mix")
        );
        assert_eq!(
            source_file_module_path("stdlib_system.nim.c").as_deref(),
            Some("stdlib_system")
        );
        assert_eq!(
            source_file_module_path("@pstd@sprivate@sdigitsutils.nim.c").as_deref(),
            Some("std/private/digitsutils")
        );
        assert_eq!(source_file_module_path("crtstuff.c"), None);
        // mingw keeps 14 bytes of short `.file` names that do not fit.
        assert_eq!(
            source_file_module_path("@palgorithm.ni").as_deref(),
            Some("algorithm")
        );
        assert_eq!(
            source_file_module_path("@pstrutils.nim").as_deref(),
            Some("strutils")
        );
        assert_eq!(source_file_module_path("@pveryverylong"), None);
        assert_eq!(source_file_module_path("@palgorithm.ni.x"), None);
        // Paths outside the project keep their dots.
        assert_eq!(
            source_file_module_path("@m..@sshared@sutil.nim.c").as_deref(),
            Some("../shared/util")
        );
    }
}
