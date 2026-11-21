//! Nim proc inventory.
//!
//! [`build`] lists every function the crate can identify as Nim code, one
//! [`NimProc`] per virtual address, sorted by address. Each entry carries the
//! demangled name, the owning module and a [`ProcRole`]: what the function is
//! for Nim. A call-graph tool uses the role to explain functions that no
//! direct call reaches: entry shims and module inits run at startup, and hooks
//! (`=destroy`, `=trace`, GC markers, finalizers) are called by the runtime
//! through the type's RTTI ([`crate::relations`] gives those type-to-hook
//! edges).
//!
//! Sources, in the order they decide an address's role:
//!
//! 1. entry shims ([`crate::shims`]);
//! 2. module init functions ([`crate::inits`]);
//! 3. Nim symbol names: a hook identifier (`=destroy`, `=copy`, ...; see
//!    [`HookKind::from_identifier`]), a refc GC marker (`Marker_*`), a lambda
//!    (`:anonymous`), a part of an async proc ([`AsyncPart`]), otherwise a
//!    user proc;
//! 4. functions enclosing a raise site ([`crate::sites`]);
//! 5. the RTTI hook slots ([`NimType::hooks`]), which name the role of a
//!    function the earlier sources call a user proc (a finalizer is an
//!    ordinary proc by name) and add hook targets that have no symbol.
//!
//! Only addresses are listed, so the inventory is as complete as the symbol
//! table and RTTI: a stripped binary has none. Stack-trace proc names carry
//! no address and are not included ([`crate::NimBinary::stack_trace`]).

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    container::{Container, SymbolKind},
    demangle::symbol::MangleScheme,
    inits::{InitFunction, InitKind},
    modules::ModuleMap,
    shims::{EntryShim, ShimKind},
    sites::RaiseSite,
    types::{HookKind, NimType},
};

/// What a [`NimProc`] is for Nim.
///
/// # Stability
///
/// The string returned by [`as_str`](ProcRole::as_str) /
/// [`Display`](core::fmt::Display) is part of nimrod's stable API. Changes are
/// SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcRole {
    /// An ordinary proc, as far as Nim metadata tells.
    User,
    /// A proc the runtime calls on behalf of a type (hook, GC marker, trace
    /// proc or finalizer).
    Hook(HookKind),
    /// An anonymous proc (`proc () = ...`, `:anonymous`).
    Lambda,
    /// A proc the `{.async.}` macro generates for an async proc.
    Async(AsyncPart),
    /// A module init function (`*Init000`, `*DatInit000`, `*HcrInit000`).
    Init(InitKind),
    /// A Nim entry shim (`NimMain`, `PreMain`, ...).
    EntryShim(ShimKind),
}

impl ProcRole {
    /// Returns the stable string identifier of the role's category,
    /// without its detail (`"Hook"` for every [`ProcRole::Hook`]).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Hook(_) => "Hook",
            Self::Lambda => "Lambda",
            Self::Async(_) => "Async",
            Self::Init(_) => "Init",
            Self::EntryShim(_) => "EntryShim",
        }
    }
}

/// Writes the category and, where there is one, its detail: `Hook(Destroy)`,
/// `Init(DatInit)`, `EntryShim(NimMain)`, `User`.
impl core::fmt::Display for ProcRole {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())?;
        match self {
            Self::Hook(kind) => write!(f, "({kind})"),
            Self::Async(part) => write!(f, "({part})"),
            Self::Init(kind) => write!(f, "({kind})"),
            Self::EntryShim(kind) => write!(f, "({kind})"),
            Self::User | Self::Lambda => Ok(()),
        }
    }
}

/// Which generated proc of an async proc `foo` a [`ProcRole::Async`] is
/// (`lib/pure/asyncmacro.nim`). [`crate::relations`] links both to `foo`.
///
/// # Stability
///
/// The string returned by [`as_str`](AsyncPart::as_str) /
/// [`Display`](core::fmt::Display) is part of nimrod's stable API. Changes are
/// SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AsyncPart {
    /// The closure iterator holding `foo`'s body: `foo (Async)` (Nim 2.0+)
    /// or `fooIter` (before 2.0).
    Iterator,
    /// `fooNimAsyncContinue`, the callback that resumes the iterator each
    /// time an awaited future completes.
    Continuation,
}

impl AsyncPart {
    /// Returns the stable string identifier for this part.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Iterator => "Iterator",
            Self::Continuation => "Continuation",
        }
    }
}

impl core::fmt::Display for AsyncPart {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `asyncmacro.nim`'s iterator name suffix from Nim 2.0 on.
const ITERATOR_SUFFIX: &str = " (Async)";
/// The iterator name suffix before Nim 2.0.
const LEGACY_ITERATOR_SUFFIX: &str = "Iter";
/// `asyncfutures.nim NimAsyncContinueSuffix`, the same in every release.
const CONTINUATION_SUFFIX: &str = "NimAsyncContinue";

/// A Nim function and what it is.
///
/// `va` is a **virtual address** in the image's load space. Convert to an RVA
/// with [`crate::NimBinary::proc_rva`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NimProc {
    /// Virtual address of the function's first instruction.
    pub va: u64,
    /// Size in bytes, when the symbol table gives one.
    pub size: Option<u64>,
    /// The raw symbol name. `None` for an RTTI hook target no symbol covers.
    pub symbol_name: Option<String>,
    /// Best human-readable name: the demangled identifier (with any compiler
    /// clone suffix, such as `.cold`), the module path for an init function,
    /// the symbol name for a shim. Empty when nothing names the address.
    pub name: String,
    /// The owning module, keyed as in [`ModuleMap::modules`].
    pub module: Option<String>,
    /// What the function is.
    pub role: ProcRole,
    /// For a hook named in the Itanium layout (debug-info builds), the type
    /// it serves, from its first parameter (`exceptions.IndexDefect` for
    /// `=destroy(var[exceptions.IndexDefect])`).
    pub hook_type: Option<String>,
}

impl NimProc {
    /// For a [`ProcRole::Async`] proc, the name of the async proc it was
    /// generated for (`fetch` for `fetch (Async)`, `fetchIter` and
    /// `fetchNimAsyncContinue`).
    pub fn async_base(&self) -> Option<&str> {
        let base = match self.role {
            ProcRole::Async(AsyncPart::Iterator) => self
                .name
                .strip_suffix(ITERATOR_SUFFIX)
                .or_else(|| self.name.strip_suffix(LEGACY_ITERATOR_SUFFIX)),
            ProcRole::Async(AsyncPart::Continuation) => self.name.strip_suffix(CONTINUATION_SUFFIX),
            _ => None,
        }?;
        (!base.is_empty()).then_some(base)
    }
}

/// The async part a generated proc's identifier names: `fetch (Async)` and
/// `fetchNimAsyncContinue`. The pre-2.0 iterator name `fetchIter` is no
/// generated name by itself and is recognised in [`build`].
fn async_part(identifier: &str) -> Option<AsyncPart> {
    let (base, part) = match identifier.strip_suffix(ITERATOR_SUFFIX) {
        Some(base) => (base, AsyncPart::Iterator),
        None => (
            identifier.strip_suffix(CONTINUATION_SUFFIX)?,
            AsyncPart::Continuation,
        ),
    };
    (!base.is_empty()).then_some(part)
}

/// Builds the VA-sorted proc inventory from the per-binary scans.
pub fn build(
    container: &Container<'_>,
    shims: &[EntryShim],
    inits: &[InitFunction],
    sites: &[RaiseSite],
    types: &[NimType],
    modules: &ModuleMap,
) -> Vec<NimProc> {
    let mut module_of: BTreeMap<u64, &str> = BTreeMap::new();
    for (key, info) in &modules.modules {
        let addrs = info.symbols.iter().map(|s| s.address);
        for va in addrs.chain(info.init_addr).chain(info.dat_init_addr) {
            module_of.entry(va).or_insert(key);
        }
    }
    let mut inv = Inventory {
        container,
        module_of,
        procs: BTreeMap::new(),
    };

    for s in shims {
        let name = s.symbol_name.clone();
        inv.add(
            s.address,
            ProcRole::EntryShim(s.kind),
            name.clone(),
            Some(name),
        );
    }
    for f in inits {
        let name = if f.module_path.path.is_empty() {
            f.symbol_name.clone()
        } else {
            f.module_path.path.clone()
        };
        let symbol = Some(f.symbol_name.clone());
        inv.add(f.address, ProcRole::Init(f.kind), name, symbol);
    }
    for sym in container.symbols() {
        if sym.kind != SymbolKind::Function || sym.vm_addr == 0 {
            continue;
        }
        let raw = sym.name.as_ref();
        let Some((role, name, hook_type)) = classify(container, raw) else {
            continue;
        };
        let p = inv.add(sym.vm_addr, role, name, Some(raw.to_owned()));
        if p.hook_type.is_none() {
            p.hook_type = hook_type;
        }
    }
    // Before 2.0 the iterator is `fooIter`, a name a user proc may have: it
    // is the iterator only next to the `fooNimAsyncContinue` of its scope.
    let continuations: BTreeSet<(&str, Option<&str>)> = inv
        .procs
        .values()
        .filter(|p| p.role == ProcRole::Async(AsyncPart::Continuation))
        .filter_map(|p| Some((p.async_base()?, p.module.as_deref())))
        .collect();
    let legacy: Vec<u64> = inv
        .procs
        .values()
        .filter(|p| p.role == ProcRole::User)
        .filter(|p| {
            p.name
                .strip_suffix(LEGACY_ITERATOR_SUFFIX)
                .is_some_and(|base| continuations.contains(&(base, p.module.as_deref())))
        })
        .map(|p| p.va)
        .collect();
    for va in legacy {
        if let Some(p) = inv.procs.get_mut(&va) {
            p.role = ProcRole::Async(AsyncPart::Iterator);
        }
    }

    for site in sites {
        if let (Some(va), Some(func)) = (site.enclosing_va, &site.enclosing_function) {
            inv.add(va, ProcRole::User, func.clone(), Some(func.clone()));
        }
    }
    for t in types {
        for (kind, r) in t.hooks() {
            let name = r
                .function
                .clone()
                .or_else(|| r.symbol_name.clone())
                .unwrap_or_default();
            let p = inv.add(r.address, ProcRole::Hook(kind), name, r.symbol_name.clone());
            if p.role == ProcRole::User {
                p.role = ProcRole::Hook(kind);
            }
        }
    }

    inv.procs.into_values().collect()
}

/// The inventory being built: the first source to name an address decides
/// its entry.
struct Inventory<'c, 'a, 'm> {
    /// The binary, for symbol sizes.
    container: &'c Container<'a>,
    /// The owning module of each address, from the module map.
    module_of: BTreeMap<u64, &'m str>,
    /// The entries so far, by address.
    procs: BTreeMap<u64, NimProc>,
}

impl Inventory<'_, '_, '_> {
    /// The entry at `va`, created from the arguments if there is none yet.
    fn add(
        &mut self,
        va: u64,
        role: ProcRole,
        name: String,
        symbol_name: Option<String>,
    ) -> &mut NimProc {
        self.procs.entry(va).or_insert_with(|| NimProc {
            va,
            size: size_at(self.container, va),
            symbol_name,
            name,
            module: self.module_of.get(&va).map(|m| (*m).to_owned()),
            role,
            hook_type: None,
        })
    }
}

/// The role, display name and Itanium hook type of a Nim function symbol, or
/// `None` for a name that is not Nim's.
fn classify(container: &Container<'_>, raw: &str) -> Option<(ProcRole, String, Option<String>)> {
    // `Marker_<type>__<hash>` (`ccgtypes.nim genTraverseProc`) is no
    // routine name: it has no mangling layout of its own.
    if raw.starts_with("Marker_") {
        return Some((ProcRole::Hook(HookKind::Marker), raw.to_owned(), None));
    }
    let d = container.demangle(raw)?;
    if !d.is_scheme_name() {
        return None;
    }
    let hook = HookKind::from_identifier(&d.identifier);
    let role = match hook {
        Some(kind) => ProcRole::Hook(kind),
        None if d.identifier == ":anonymous" => ProcRole::Lambda,
        // A clone fragment (`foo.cold`) is part of a proc, not the proc.
        None if d.clone_suffix.is_some() => ProcRole::User,
        None => async_part(&d.identifier).map_or(ProcRole::User, ProcRole::Async),
    };
    let hook_type = hook
        .filter(|_| d.scheme == Some(MangleScheme::Itanium))
        .and_then(|_| {
            d.params
                .as_ref()?
                .first()
                .map(|p| hook_target(p).to_owned())
        });
    let mut name = d.identifier.into_owned();
    if let Some(clone) = d.clone_suffix {
        name.push_str(clone);
    }
    Some((role, name, hook_type))
}

/// The type a hook's first parameter names: `var[T]` (every hook but
/// `=destroy` on some releases takes its object by `var`) is `T`.
fn hook_target(param: &str) -> &str {
    param
        .strip_prefix("var[")
        .and_then(|p| p.strip_suffix(']'))
        .unwrap_or(param)
}

/// Size of the function symbol that starts exactly at `va`, if it has one.
fn size_at(container: &Container<'_>, va: u64) -> Option<u64> {
    container
        .function_at_va(va)
        .filter(|s| s.vm_addr == va && s.size > 0)
        .map(|s| s.size)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::{
        container::{Arch, Format, Symbol},
        types::CodeRef,
    };

    fn function(name: &'static str, vm_addr: u64, size: u64) -> Symbol<'static> {
        Symbol {
            name: Cow::Borrowed(name),
            vm_addr,
            size,
            kind: SymbolKind::Function,
        }
    }

    fn container(symbols: Vec<Symbol<'static>>) -> Container<'static> {
        static BYTES: [u8; 16] = [0; 16];
        Container::from_parts(&BYTES, Format::Elf, Arch::Amd64, 0, vec![], symbols)
    }

    #[test]
    fn role_as_str_and_display_are_stable() {
        assert_eq!(ProcRole::User.as_str(), "User");
        assert_eq!(ProcRole::Hook(HookKind::Destroy).as_str(), "Hook");
        assert_eq!(
            ProcRole::Hook(HookKind::Destroy).to_string(),
            "Hook(Destroy)"
        );
        assert_eq!(
            ProcRole::Init(InitKind::DatInit).to_string(),
            "Init(DatInit)"
        );
        assert_eq!(
            ProcRole::EntryShim(ShimKind::NimMain).to_string(),
            "EntryShim(NimMain)"
        );
        assert_eq!(ProcRole::Lambda.to_string(), "Lambda");
    }

    /// Names taken from the fixtures, one or more per mangling layout.
    #[test]
    fn classify_names_in_every_layout() {
        let c = container(vec![]);
        let role = |raw: &str| classify(&c, raw).map(|(r, _, _)| r);
        let hook = |k| Some(ProcRole::Hook(k));
        // SigHash (1.0 - 1.4).
        assert_eq!(
            role("eqdestroy___dS1BF3Vxjg9aJMmmhVJKSpQ"),
            hook(HookKind::Destroy)
        );
        assert_eq!(
            role("eqcopy___rR9boD7urcxl7uyUtE46AOA"),
            hook(HookKind::Copy)
        );
        assert_eq!(
            role("eqdispose___4fQQqvAqifkWGVa4g39cI5A_2"),
            hook(HookKind::Dispose)
        );
        assert_eq!(
            role("colonanonymous___cIbw1JY0P6qg1HQxZCe5Fw"),
            Some(ProcRole::Lambda)
        );
        assert_eq!(
            role("Marker_tyRef__C0A9bPZSVeyr2BWpBf4Jxqw"),
            hook(HookKind::Marker)
        );
        // Nim16 (1.6 - 2.3).
        assert_eq!(
            role("eqdestroy___stdlib95mix_u1393"),
            hook(HookKind::Destroy)
        );
        assert_eq!(role("eqsink___stdZassertions_u36"), hook(HookKind::Sink));
        assert_eq!(role("eqdup___stdlib95mix_u101"), hook(HookKind::Dup));
        assert_eq!(
            role("colonanonymous___stdlib95mix_u657"),
            Some(ProcRole::Lambda)
        );
        // Nim24 (2.4+).
        assert_eq!(role("eqcopy__u0__stdlib95mix"), hook(HookKind::Copy));
        assert_eq!(role("eqdestroy__u104__system"), hook(HookKind::Destroy));
        assert_eq!(
            role("colonanonymous__u0__stdlib95mix"),
            Some(ProcRole::Lambda)
        );
        // Itanium (debug info), with the hooked type.
        let (r, name, ty) = classify(
            &c,
            "_ZN10exceptions10eqdestroy_E3varIN10exceptions11IndexDefectEE",
        )
        .unwrap();
        assert_eq!(
            (r, name.as_str(), ty.as_deref()),
            (
                ProcRole::Hook(HookKind::Destroy),
                "=destroy",
                Some("exceptions.IndexDefect")
            )
        );
        let (r, _, ty) = classify(
            &c,
            "_ZN10exceptions8eqtrace_E3varIN10exceptions11IndexDefectEE7pointer",
        )
        .unwrap();
        assert_eq!(
            (r, ty.as_deref()),
            (
                ProcRole::Hook(HookKind::Trace),
                Some("exceptions.IndexDefect")
            )
        );
        // Not hooks: the `==` operator and a routine merely starting `eq`.
        assert_eq!(role("parseInt__strutils_u42"), Some(ProcRole::User));
        assert_eq!(role("eqeq___system_u12"), Some(ProcRole::User));
        assert_eq!(role("equalMem__system_u5"), Some(ProcRole::User));
        // Not Nim.
        assert_eq!(role("memcpy"), None);
    }

    #[test]
    fn async_parts_by_name() {
        let c = container(vec![
            function("fetchIter__m_u1", 0x1000, 8),
            function("fetchNimAsyncContinue__m_u2", 0x2000, 8),
            function("fetchNimAsyncContinue__m_u2.cold", 0x2800, 8),
            function("lonelyIter__m_u3", 0x3000, 8),
            function("loadX20X28AsyncX29__u0__m", 0x4000, 8),
            // `fooIter` next to a callback of another module is a user proc.
            function("storeIter__a_u4", 0x5000, 8),
            function("storeNimAsyncContinue__b_u5", 0x6000, 8),
        ]);
        let modules = crate::modules::build(&c);
        let procs = build(&c, &[], &[], &[], &[], &modules);
        let role = |va| procs.iter().find(|p| p.va == va).unwrap().role;
        let (it, cont) = (
            ProcRole::Async(AsyncPart::Iterator),
            ProcRole::Async(AsyncPart::Continuation),
        );
        assert_eq!(role(0x1000), it, "pre-2.0 iterator beside its callback");
        assert_eq!(role(0x2000), cont);
        assert_eq!(role(0x2800), ProcRole::User, "a clone fragment");
        assert_eq!(role(0x3000), ProcRole::User, "no callback");
        assert_eq!(role(0x4000), it, "`load (Async)`");
        assert_eq!(role(0x5000), ProcRole::User, "callback in another module");
        let p = procs.iter().find(|p| p.va == 0x4000).unwrap();
        assert_eq!(p.async_base(), Some("load"));
        assert_eq!(
            procs.iter().find(|p| p.va == 0x3000).unwrap().async_base(),
            None
        );
    }

    #[test]
    fn hook_type_only_for_itanium_hooks() {
        let c = container(vec![]);
        let ty = |raw: &str| classify(&c, raw).and_then(|(_, _, t)| t);
        assert_eq!(ty("eqdestroy__u104__system"), None);
        // An Itanium routine that is no hook keeps no type.
        assert_eq!(ty("_ZN10assertions11raiseAssertE6string"), None);
        assert_eq!(hook_target("var[seq[int]]"), "seq[int]");
        assert_eq!(hook_target("Foo"), "Foo");
    }

    #[test]
    fn build_orders_sources_and_skips_non_nim() {
        let c = container(vec![
            function("NimMain", 0x1000, 0),
            function("parseInt__strutils_u42", 0x2000, 16),
            function("memcpy", 0x3000, 0),
            function("eqdestroy__u3__m", 0x4000, 8),
            function("release__m_u7", 0x5000, 8),
        ]);
        let shims = crate::shims::scan(&c);
        let code_ref = |address| CodeRef {
            address,
            function: None,
            module: None,
            symbol_name: None,
            emulated: false,
        };
        // Its finalizer is a user proc by name, its trace proc has no
        // symbol, and its destructor is a hook by name.
        let mut t = NimType::synthetic(0x9000);
        t.finalizer = Some(code_ref(0x5000));
        t.trace_impl = Some(code_ref(0x6000));
        t.destructor = Some(code_ref(0x4000));
        let modules = ModuleMap {
            modules: BTreeMap::new(),
        };
        let procs = build(&c, &shims, &[], &[], &[t], &modules);

        let at = |va| procs.iter().find(|p| p.va == va);
        assert_eq!(
            at(0x1000).unwrap().role,
            ProcRole::EntryShim(ShimKind::NimMain)
        );
        let p = at(0x2000).unwrap();
        assert_eq!(
            (p.role, p.name.as_str(), p.size),
            (ProcRole::User, "parseInt", Some(16))
        );
        assert!(at(0x3000).is_none(), "non-Nim symbol excluded");
        assert_eq!(at(0x4000).unwrap().role, ProcRole::Hook(HookKind::Destroy));
        assert_eq!(
            at(0x5000).unwrap().role,
            ProcRole::Hook(HookKind::Finalizer)
        );
        let p = at(0x6000).unwrap();
        assert_eq!(
            (p.role, p.symbol_name.as_deref()),
            (ProcRole::Hook(HookKind::Trace), None)
        );
        assert!(procs.windows(2).all(|w| w[0].va < w[1].va));
    }
}
