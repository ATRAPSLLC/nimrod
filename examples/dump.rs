//! Dump all recoverable Nim artifacts from a single binary.
//!
//! Prints the container summary, the detection verdict and compiler hints,
//! then every scan: entry shims, init functions, RTTI symbols and the type
//! graph, code entrypoints, string literals, stack-trace data, nimble paths,
//! exception types, raise sites and the module map, as plain text meant for
//! reading and diffing.
//!
//! Usage:
//!
//! ```text
//! cargo run --example dump -- <path-to-binary>
//! ```

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs, process,
};

use nimrod::{NimBinary, ProcRole, RelationKind, metadata::GcMode, rtti::symbols::RttiVersion};

/// Parses the binary named on the command line and prints its artifacts.
fn main() {
    let args: Vec<String> = env::args().collect();
    let Some(path) = args.get(1) else {
        eprintln!("usage: dump <path-to-binary>");
        process::exit(2);
    };

    let data = fs::read(path).unwrap_or_else(|e| {
        eprintln!("error reading {path}: {e}");
        process::exit(1);
    });

    let bin = match nimrod::NimBinary::from_bytes(&data) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error parsing {path}: {e}");
            process::exit(1);
        }
    };

    println!("file      : {path}");
    println!("size      : {} bytes", data.len());
    println!("format    : {:?}", bin.format());
    println!("arch      : {:?}", bin.arch());

    let container = bin.container();
    println!("sections  : {}", container.sections().len());
    println!(
        "  rodata  : {} ({} bytes)",
        container.rodata_sections().count(),
        container
            .rodata_sections()
            .map(|s| s.data.len())
            .sum::<usize>()
    );
    println!("symbols   : {}", container.symbols().len());

    let detection = bin.detection();
    println!();
    println!("is_nim    : {}", detection.is_nim);
    println!("matches   : {} flag(s)", detection.matches.count());
    for (name, _) in detection.matches.iter() {
        println!("  - {name}");
    }

    if !detection.is_nim {
        return;
    }

    println!();
    let gc = bin.gc_mode();
    println!(
        "gc_mode   : {}",
        match gc {
            GcMode::Refc => "refc",
            GcMode::ArcOrc => "arc/orc",
            GcMode::Unknown => "unknown",
        }
    );
    println!("nim_ver   : {}", bin.nim_version());
    match bin.mangle_scheme() {
        Some(scheme) => println!("mangling  : {scheme} (Nim {})", scheme.compiler_range()),
        None => println!("mangling  : (undetermined)"),
    }
    let profile = bin.build_profile();
    println!(
        "build     : exceptions={} stack_traces={} runtime_checks={} library={}",
        profile.exceptions,
        profile
            .stack_traces
            .map_or("unknown", |on| if on { "on" } else { "off" }),
        profile
            .runtime_checks
            .map_or("unknown", |on| if on { "on" } else { "off" }),
        profile.library,
    );
    println!("imports   : {}", bin.container().imports().len());
    if let Some(bits) = bin.bitness() {
        println!("bitness   : {bits}-bit");
    }
    if let Some(prefix) = bin.nim_main_prefix() {
        if prefix.is_empty() {
            println!("nim_prefix: (default)");
        } else {
            println!("nim_prefix: {prefix}");
        }
    }

    let shims = bin.entry_shims();
    println!();
    println!("entry_shims: {} found", shims.len());
    for s in shims {
        println!("  {:?} at {:#x}  ({})", s.kind, s.address, s.symbol_name);
    }

    let inits = bin.init_functions();
    println!();
    println!("init_functions: {} found", inits.len());
    for f in inits {
        println!(
            "  {:?} at {:#x}  {} => {}",
            f.kind, f.address, f.symbol_name, f.module_path.path
        );
    }

    let rtti = bin.rtti_symbols();
    let v2_count = rtti.iter().filter(|r| r.version == RttiVersion::V2).count();
    let v1_count = rtti.iter().filter(|r| r.version == RttiVersion::V1).count();
    println!();
    println!("rtti_symbols: {} V2, {} V1", v2_count, v1_count);

    // Full cross-linked type graph: members, offsets, layout, inheritance,
    // enum values, and resolved destructor / finalizer functions.
    let types = bin.types();
    let unreadable = types.iter().filter(|t| !t.is_readable()).count();
    println!();
    println!(
        "types: {} total ({} unreadable / name-only)",
        types.len(),
        unreadable
    );
    for t in types {
        let name = t.name.as_deref().unwrap_or(t.symbol_name.as_str());
        let mut line = format!(
            "  [{}] {} @{:#x}  shape={} size={} align={}",
            t.version, name, t.address, t.shape, t.size, t.align
        );
        if let Some(depth) = t.depth {
            line.push_str(&format!(" depth={depth}"));
        }
        let mut fl = Vec::new();
        if t.flags.acyclic {
            fl.push("acyclic");
        }
        if t.flags.no_refs {
            fl.push("norefs");
        }
        if t.flags.enum_hole {
            fl.push("enumhole");
        }
        if !fl.is_empty() {
            line.push_str(&format!(" flags={}", fl.join("|")));
        }
        if let Some(expr) = &t.type_expr {
            line.push_str(&format!("  type={expr}"));
        }
        if !t.is_readable() {
            line.push_str("  (name-only)");
        }
        println!("{line}");

        if let Some(p) = &t.parent {
            let pname = p
                .name
                .clone()
                .unwrap_or_else(|| format!("{:#x}", p.address));
            println!("      parent: {pname}");
        }
        if let Some(d) = &t.destructor {
            println!(
                "      destructor: {} @{:#x}",
                d.function.as_deref().unwrap_or("?"),
                d.address
            );
        }
        if let Some(f) = &t.finalizer {
            println!(
                "      finalizer: {} @{:#x}",
                f.function.as_deref().unwrap_or("?"),
                f.address
            );
        }
        if !t.display_tokens.is_empty() {
            println!("      display: {:?}", t.display_tokens);
        }
        for f in &t.fields {
            match f.type_ref.as_ref().and_then(|r| r.name.as_deref()) {
                Some(fty) => println!("      +{:<4} {}: {}", f.offset, f.name, fty),
                None => println!("      +{:<4} {}", f.offset, f.name),
            }
        }
        for e in &t.enum_values {
            println!("      = {} ({})", e.name, e.ordinal);
        }
    }

    let procs = bin.procs();
    if !procs.is_empty() {
        println!();
        println!("procs: {} total", procs.len());
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for p in procs {
            let c = counts.entry(p.role.to_string()).or_default();
            *c = c.saturating_add(1);
        }
        for (role, n) in &counts {
            println!("  {role}: {n}");
        }
    }

    let relations = bin.relations();
    if !relations.is_empty() {
        println!();
        println!("relations: {} total", relations.len());
        let mut counts: BTreeMap<(String, &str), usize> = BTreeMap::new();
        for r in relations {
            let c = counts
                .entry((r.kind.to_string(), r.source.as_str()))
                .or_default();
            *c = c.saturating_add(1);
        }
        for ((kind, source), n) in &counts {
            println!("  {kind} [{source}]: {n}");
        }
        print_startup(&bin);
    }

    let harvest = bin.stack_trace();
    let abs_paths: Vec<_> = harvest
        .file_paths
        .iter()
        .filter(|f| f.is_absolute)
        .collect();
    let rel_paths: Vec<_> = harvest
        .file_paths
        .iter()
        .filter(|f| !f.is_absolute)
        .collect();
    println!();
    println!(
        "stack_trace_files: {} total ({} absolute, {} relative)",
        harvest.file_paths.len(),
        abs_paths.len(),
        rel_paths.len()
    );
    for f in &abs_paths {
        println!("  [abs] {}", f.path);
    }
    for f in &rel_paths {
        println!("  [rel] {}", f.path);
    }

    if !harvest.proc_names.is_empty() {
        println!();
        println!("stack_trace_procs: {} found", harvest.proc_names.len());
        for name in &harvest.proc_names {
            println!("  {name}");
        }
    }

    let nimble = bin.nimble_paths();
    if !nimble.is_empty() {
        println!();
        println!("nimble_paths: {} found", nimble.len());
        for p in nimble {
            println!("  {:?} os={:?}", p.raw, p.os_hint);
            if let Some(ref user) = p.user_hint {
                println!("    user: {user}");
            }
            if let Some(ref pkg) = p.pkg_name {
                print!("    pkg: {pkg}");
                if let Some(ref ver) = p.pkg_version {
                    print!("@{ver}");
                }
                if let Some(ref hash) = p.pkg_hash {
                    print!(" ({hash})");
                }
                println!();
            }
        }
    }

    let exceptions = bin.exception_types();
    if !exceptions.is_empty() {
        println!();
        println!("exception_types: {} found", exceptions.len());
        for e in exceptions {
            println!("  {}", e.type_name);
        }
    }

    let raise_sites = bin.raise_sites();
    if !raise_sites.is_empty() {
        println!();
        println!("raise_sites: {} found", raise_sites.len());
        for rs in raise_sites {
            let etype = rs.exception_type.as_deref().unwrap_or("?");
            let proc_n = rs.proc_name.as_deref().unwrap_or("?");
            let file = rs.file.as_deref().unwrap_or("?");
            let line = rs
                .line
                .map(|l| l.to_string())
                .unwrap_or_else(|| "?".to_string());
            let enclosing = rs.enclosing_function.as_deref().unwrap_or("?");
            println!(
                "  {:#x}  {etype} in {proc_n} at {file}:{line}  [fn: {enclosing}]",
                rs.call_addr
            );
        }
    }

    let mmap = bin.module_map();
    if !mmap.modules.is_empty() {
        println!();
        println!("module_map: {} modules", mmap.modules.len());
        for (key, info) in &mmap.modules {
            let path = info.init_path.as_deref().unwrap_or(key.as_str());
            let mut flags = Vec::new();
            if info.init_addr.is_some() {
                flags.push("+init");
            }
            if info.dat_init_addr.is_some() {
                flags.push("+datinit");
            }
            if !info.file_paths.is_empty() {
                flags.push("+stacktrace");
            }
            let flags_str = if flags.is_empty() {
                String::new()
            } else {
                format!("  {}", flags.join(" "))
            };

            if info.symbol_count() > 0 {
                println!("  {path}  ({} symbols){flags_str}", info.symbol_count());
            } else {
                println!("  {path}{flags_str}");
            }

            for fp in &info.file_paths {
                println!("    path: {fp}");
            }
            for sym in &info.symbols {
                if sym.size > 0 {
                    println!("    {:#x}  {} ({} bytes)", sym.address, sym.name, sym.size);
                } else {
                    println!("    {:#x}  {}", sym.address, sym.name);
                }
            }
        }
    }

    let v2_literals = bin.string_literals_v2();
    println!();
    println!("string_literals_v2: {} found", v2_literals.len());
    for lit in v2_literals {
        let display = if lit.value.len() > 80 {
            format!("{:?}...", &lit.value[..77])
        } else {
            format!("{:?}", lit.value)
        };
        println!("  {:#x}  {display}", lit.payload_addr);
    }

    let v3_literals = bin.string_literals_v3();
    if !v3_literals.is_empty() {
        println!();
        println!("string_literals_v3 (sso): {} found", v3_literals.len());
        for lit in v3_literals {
            let shown: String = lit.value.chars().take(77).collect();
            let more = if shown.len() < lit.value.len() {
                "..."
            } else {
                ""
            };
            println!("  {:#x}  {:<6} {shown:?}{more}", lit.addr, lit.kind);
        }
    }

    let v1_literals = bin.string_literals_v1();
    if !v1_literals.is_empty() {
        println!();
        println!("string_literals_v1: {} found", v1_literals.len());
        for lit in v1_literals {
            let display = if lit.value.len() > 80 {
                format!("{:?}...", &lit.value[..77])
            } else {
                format!("{:?}", lit.value)
            };
            println!("  {:#x}  {display}", lit.header_addr);
        }
    }
}

/// Prints the startup call structure from `NimMain` down, callees sorted by
/// name (the binary does not record their order).
fn print_startup(bin: &NimBinary<'_>) {
    let mut callees: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut called = BTreeSet::new();
    for r in bin.relations() {
        if r.kind == RelationKind::StartupCall {
            callees.entry(r.from).or_default().push(r.to);
            called.insert(r.to);
        }
    }
    let roots: Vec<u64> = callees
        .keys()
        .copied()
        .filter(|va| !called.contains(va))
        .collect();
    if roots.is_empty() {
        return;
    }
    println!("  startup (callee order not recorded):");
    let mut seen = BTreeSet::new();
    for root in roots {
        print_startup_node(bin, root, 0, &callees, &mut seen);
    }
}

/// Prints one startup node and, the first time it is seen, its callees.
fn print_startup_node(
    bin: &NimBinary<'_>,
    va: u64,
    depth: usize,
    callees: &BTreeMap<u64, Vec<u64>>,
    seen: &mut BTreeSet<u64>,
) {
    println!(
        "    {:indent$}{}",
        "",
        proc_name(bin, va),
        indent = depth.saturating_mul(2)
    );
    if !seen.insert(va) {
        return;
    }
    let mut next: Vec<(String, u64)> = callees
        .get(&va)
        .into_iter()
        .flatten()
        .map(|&to| (proc_name(bin, to), to))
        .collect();
    next.sort();
    for (_, to) in next {
        print_startup_node(bin, to, depth.saturating_add(1), callees, seen);
    }
}

/// The inventory name of the proc at `va` (with the kind of an init
/// function, whose DatInit and Init share the module's name), or the
/// address.
fn proc_name(bin: &NimBinary<'_>, va: u64) -> String {
    let procs = bin.procs();
    let Some(p) = procs
        .binary_search_by_key(&va, |p| p.va)
        .ok()
        .and_then(|i| procs.get(i))
    else {
        return format!("{va:#x}");
    };
    match p.role {
        ProcRole::Init(kind) => format!("{} ({kind})", p.name),
        _ => p.name.clone(),
    }
}
