//! Cross-version fixture tests.
//!
//! Fixtures live under
//! `tests/fixtures/nim-<version>/{linux_x64,mingw,mingw_i686,linux_arm64,linux_ppc64,linux_mips}/`
//! and are built in Docker by `tests/build_fixtures/build_versions.sh` (one
//! image per Nim release, see `tests/build_fixtures/docker/`). File names
//! carry the build flags (`<source>_<mm>_<mode>`), and the expectations below
//! are derived from them. A version whose directory is missing is skipped,
//! so a fresh checkout without fixtures passes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

mod common;

use nimrod::{
    AsyncLink, AsyncPart, ExceptionModel, HookKind, InitKind, MangleScheme, NimBinary, NimKind,
    NimVersionHint, ProcRole, Provenance, RelationKind, RttiVersion, ShimKind,
};

/// Every release in `tests/build_fixtures/docker/nim-sha256.txt` and the
/// symbol layout its compiler emits.
const VERSIONS: &[(&str, MangleScheme)] = &[
    ("1.0.10", MangleScheme::SigHash),
    ("1.2.18", MangleScheme::SigHash),
    ("1.4.8", MangleScheme::SigHash),
    ("1.6.20", MangleScheme::Nim16),
    ("2.0.0", MangleScheme::Nim16),
    ("2.0.16", MangleScheme::Nim16),
    ("2.2.0", MangleScheme::Nim16),
    ("2.2.14", MangleScheme::Nim16),
    ("2.4.0", MangleScheme::Nim24),
    ("2.4.2", MangleScheme::Nim24),
];

/// The fixtures of one version, or `None` when its directory is absent.
fn fixtures(version: &str) -> Option<Vec<PathBuf>> {
    let root = common::fixture_path(&format!("nim-{version}"));
    if !root.is_dir() {
        eprintln!("skip: {} not present", root.display());
        return None;
    }
    let mut out = Vec::new();
    for platform in [
        "linux_x64",
        "mingw",
        "mingw_i686",
        "linux_arm64",
        "linux_ppc64",
        "linux_mips",
    ] {
        let Ok(entries) = std::fs::read_dir(root.join(platform)) else {
            continue;
        };
        out.extend(entries.filter_map(|e| e.ok().map(|e| e.path())));
    }
    out.sort();
    Some(out)
}

/// The fixture's file name, which carries its build flags.
fn name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

/// Runs `check` on every fixture of every present version.
fn for_each_fixture(mut check: impl FnMut(&str, MangleScheme, &str, &NimBinary<'_>)) {
    let mut seen = 0usize;
    for &(version, scheme) in VERSIONS {
        let Some(paths) = fixtures(version) else {
            continue;
        };
        for path in paths {
            let data = std::fs::read(&path).unwrap();
            let bin =
                NimBinary::from_bytes(&data).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            check(version, scheme, &name(&path), &bin);
            seen = seen.saturating_add(1);
        }
    }
    eprintln!("checked {seen} fixtures");
}

/// Whether nimrod decodes this binary's machine code: raise sites and the
/// startup-code evaluation behind refc type recovery cover x86-64 and
/// AArch64 only.
fn decodes_code(bin: &NimBinary<'_>) -> bool {
    matches!(bin.arch(), nimrod::Arch::Amd64 | nimrod::Arch::Aarch64)
}

/// `(major, minor)` of a version string, for range checks.
fn minor(version: &str) -> (u32, u32) {
    let mut parts = version.split('.').map(|p| p.parse::<u32>().unwrap());
    (parts.next().unwrap(), parts.next().unwrap())
}

/// Every fixture detects as Nim, votes the symbol layout of its compiler, and
/// yields named procs.
#[test]
fn every_fixture_is_nim_with_its_symbol_layout_and_procs() {
    for_each_fixture(|version, scheme, name, bin| {
        assert!(bin.is_nim(), "nim-{version}/{name}: not detected");
        assert_eq!(
            bin.mangle_scheme(),
            Some(scheme),
            "nim-{version}/{name}: symbol layout"
        );
        let procs = bin
            .procs()
            .iter()
            .filter(|p| p.role == ProcRole::User)
            .count();
        assert!(procs > 0, "nim-{version}/{name}: no procs recovered");
    });
}

/// The version hint names the build's memory manager (atomicArc only on
/// x86-64, where it is detectable).
#[test]
fn version_hint_matches_memory_manager() {
    for_each_fixture(|version, _, name, bin| {
        let expected = if name.contains("yrc") {
            NimVersionHint::Nim24Yrc
        } else if name.contains("orc") {
            NimVersionHint::Nim2xOrc
        } else if name.contains("atomicarc") && bin.container().arch() == nimrod::Arch::Amd64 {
            NimVersionHint::Nim2xAtomicArc
        } else if name.contains("arc") {
            NimVersionHint::Nim2xArc
        } else {
            NimVersionHint::Nim1xRefc
        };
        assert_eq!(bin.nim_version(), expected, "nim-{version}/{name}");
    });
}

/// Stack traces, runtime checks, exception model and library flag match the
/// flags in the file name.
#[test]
fn build_profile_matches_build_flags() {
    for_each_fixture(|version, _, name, bin| {
        let p = bin.build_profile();
        let debug = name.ends_with("_debug") || name.ends_with("_debug.exe");
        assert_eq!(
            p.stack_traces,
            Some(debug),
            "nim-{version}/{name}: stack traces"
        );
        assert_eq!(
            p.runtime_checks,
            Some(!name.contains("danger")),
            "nim-{version}/{name}: runtime checks"
        );
        // 1.4 ignores `--exceptions:setjmp` under ORC.
        let setjmp = name.contains("refc") || (name.contains("setjmp") && minor(version) >= (1, 6));
        let expected = if setjmp {
            ExceptionModel::Setjmp
        } else {
            ExceptionModel::Goto
        };
        assert_eq!(p.exceptions, expected, "nim-{version}/{name}: exceptions");
        let library = name.starts_with("lib") || name.ends_with(".dll");
        assert_eq!(p.library, library, "nim-{version}/{name}: library");
    });
}

/// SSO literals appear exactly in `--strings:sso` builds, which have no V2
/// literals, and include the source words wherever they were stored.
#[test]
fn sso_literals_only_in_sso_builds() {
    for_each_fixture(|version, _, name, bin| {
        let v3 = bin.string_literals_v3();
        if !name.contains("sso") {
            assert!(
                v3.is_empty(),
                "nim-{version}/{name}: SSO literals in a non-SSO build"
            );
            return;
        }
        assert!(
            bin.string_literals_v2().is_empty(),
            "nim-{version}/{name}: V2 literals in an SSO build"
        );
        if name.starts_with("strings_and_seqs") {
            // The source literals, kept as data or folded into instruction
            // immediates (x86-64 `movabs`, AArch64 `movz`/`movk`).
            for word in ["alpha", "beta", "gamma", "delta"] {
                assert!(
                    v3.iter().any(|l| l.value == word),
                    "nim-{version}/{name}: {word:?} not recovered"
                );
            }
        }
        assert!(!v3.is_empty(), "nim-{version}/{name}: no SSO literals");
    });
}

/// refc type names from Nim 1.6 on decode to Nim type expressions.
#[test]
fn refc_type_names_decode_to_nim_expressions() {
    for_each_fixture(|version, _, name, bin| {
        // Nim 1.0 - 1.4 name V1 RTTI `NTI__<hash>_`: no type part to decode.
        if !name.starts_with("strings_and_seqs")
            || !name.contains("refc")
            || minor(version) < (1, 6)
        {
            return;
        }
        let exprs: Vec<&str> = bin
            .types()
            .iter()
            .filter_map(|t| t.type_expr.as_deref())
            .collect();
        for want in ["seq[string]", "seq[int]"] {
            assert!(
                exprs.contains(&want),
                "nim-{version}/{name}: {want} not among {exprs:?}"
            );
        }
    });
}

/// The user's exception types and a source line are recovered at raise sites
/// on the architectures whose code is decoded.
#[test]
fn user_exception_types_recovered_at_raise_sites() {
    for_each_fixture(|version, _, name, bin| {
        if !name.starts_with("exceptions_") || !decodes_code(bin) {
            return;
        }
        let sites = bin.raise_sites();
        // Both `raise` statements of `inner` can merge into one tail jump
        // (refc release), so at least one of the two types is required.
        assert!(
            sites
                .iter()
                .any(|s| matches!(s.exception_type.as_deref(), Some("MyError" | "OtherError"))),
            "nim-{version}/{name}: no user exception type among {:?}",
            sites.iter().map(|s| &s.exception_type).collect::<Vec<_>>()
        );
        assert!(
            sites.iter().any(|s| s.line.is_some()),
            "nim-{version}/{name}: no raise-site line"
        );
    });
}

/// Type recovery from the startup code (`DatInit000`), checked against the
/// fixtures' known types. The values themselves were verified byte for byte
/// against runtime memory dumps of the Linux x64 fixtures (gdb oracle,
/// `tests/build_fixtures/oracle/`).
#[test]
fn types_recovered_from_startup_code() {
    for_each_fixture(|version, _, name, bin| {
        let types = bin.types();
        // Never an impossible kind.
        for t in types.iter().filter(|t| t.is_readable()) {
            if let Some(NimKind::Other(k)) = t.kind {
                assert!(
                    k <= 64,
                    "nim-{version}/{name}: {} has kind {k}",
                    t.symbol_name
                );
            }
        }
        if !decodes_code(bin) {
            // The startup code is not evaluated (big_endian_fixtures_read_in_
            // their_byte_order covers what these builds do yield).
            return;
        }
        let v1: Vec<_> = types
            .iter()
            .filter(|t| t.version == RttiVersion::V1)
            .collect();
        let v2: Vec<_> = types
            .iter()
            .filter(|t| t.version == RttiVersion::V2)
            .collect();
        let readable = |ts: &[&nimrod::NimType]| ts.iter().filter(|t| t.is_readable()).count();
        // refc: V1 objects live in .bss (a shared library reaches them
        // through GOT slots the loader fills).
        if name.contains("refc") {
            // At most one or 5% unreadable: a few `NTI` objects are not valid
            // `TNimType` even at run time and are rejected on purpose.
            let unreadable = v1.len() - readable(&v1);
            assert!(
                unreadable <= 1.max(v1.len() / 20),
                "nim-{version}/{name}: {} of {} V1 types readable",
                readable(&v1),
                v1.len()
            );
        }
        // ARC/ORC before 2.0: V2 objects are filled at startup too.
        if !name.contains("refc") && minor(version) >= (1, 4) && minor(version) < (2, 0) {
            assert_eq!(readable(&v2), v2.len(), "nim-{version}/{name}: V2 types");
        }
        let by_expr = |e: &str| types.iter().find(|t| t.type_expr.as_deref() == Some(e));
        if name.starts_with("sumtypes") && name.contains("refc") {
            let variant = by_expr("variant:objecttype").expect("Variant:ObjectType");
            let fields: Vec<_> = variant
                .fields
                .iter()
                .map(|f| (f.name.as_str(), f.offset))
                .collect();
            assert_eq!(
                fields,
                [("kind", 0), ("i", 8), ("s", 8)],
                "nim-{version}/{name}"
            );
            let kind = by_expr("kind").expect("Kind");
            let values: Vec<_> = kind
                .enum_values
                .iter()
                .map(|e| (e.name.as_str(), e.ordinal))
                .collect();
            assert_eq!(values, [("kInt", 0), ("kStr", 1)], "nim-{version}/{name}");
        }
        if name.starts_with("exceptions") && name.contains("refc") && minor(version) >= (1, 6) {
            let my = by_expr("myerror").expect("MyError");
            assert_eq!(my.kind, Some(NimKind::Object), "nim-{version}/{name}");
            let parent = my
                .parent
                .as_ref()
                .and_then(|p| p.index)
                .and_then(|i| types.get(i));
            assert_eq!(
                parent.and_then(|p| p.type_expr.as_deref()),
                Some("catchableerror"),
                "nim-{version}/{name}"
            );
        }
    });
}

/// Nim 1.0 - 1.4 names carry no module. Every function is grouped under
/// the C file that emitted it: on mingw by COFF `.file` records, on ELF
/// debug-info builds by DWARF compile units. That module merges with the
/// init-function and stack-trace sources.
#[test]
fn signature_hash_functions_grouped_by_source_file() {
    for_each_fixture(|version, scheme, name, bin| {
        if scheme != MangleScheme::SigHash
            || !(name.ends_with(".exe") || name.ends_with("_debuginfo"))
            || !name.starts_with("stdlib_mix_")
        {
            return;
        }
        let modules = &bin.module_map().modules;
        let with_symbols: Vec<&str> = modules
            .iter()
            .filter(|(_, m)| !m.symbols.is_empty())
            .map(|(k, _)| k.as_str())
            .collect();
        for key in ["system", "stdlib_mix", "stdlib_tables", "stdlib_algorithm"] {
            assert!(
                with_symbols.contains(&key),
                "nim-{version}/{name}: no functions under {key:?}: {with_symbols:?}"
            );
        }
        assert!(
            modules
                .values()
                .flat_map(|m| &m.symbols)
                .all(|s| s.from_source_file),
            "nim-{version}/{name}: a 1.x function attributed by name"
        );
        // The io module survives on mingw (inlined away on ELF): its
        // functions, init and stack-trace path share one key.
        if name.ends_with(".exe") {
            let io = modules.get("stdlib_io");
            assert!(
                io.is_some_and(|m| m.init_addr.is_some() && !m.symbols.is_empty()),
                "nim-{version}/{name}: stdlib_io not merged"
            );
        }
        assert!(
            !modules.contains_key("io"),
            "nim-{version}/{name}: io split from stdlib_io"
        );
    });
}

/// The PPC64 and MIPS fixtures are big-endian: data words read in that
/// order, pointer width from the ELF class. Little-endian reads find none of
/// the source literals there and misread every V2 type.
#[test]
fn big_endian_fixtures_read_in_their_byte_order() {
    let mut seen = 0usize;
    for_each_fixture(|version, _, name, bin| {
        if bin.container().is_little_endian() {
            return;
        }
        seen += 1;
        let bits = match bin.arch() {
            nimrod::Arch::PowerPc64 => 64,
            nimrod::Arch::Mips => 32,
            other => panic!("nim-{version}/{name}: unexpected big-endian arch {other}"),
        };
        assert_eq!(bin.bitness(), Some(bits), "nim-{version}/{name}");
        if name.starts_with("strings_and_seqs") {
            let words: Vec<&str> = bin
                .string_literals_v1()
                .iter()
                .map(|l| l.value.as_str())
                .chain(bin.string_literals_v2().iter().map(|l| l.value.as_str()))
                .collect();
            for word in ["alpha", "beta", "gamma", "delta"] {
                assert!(
                    words.contains(&word),
                    "nim-{version}/{name}: {word:?} not recovered"
                );
            }
        }
        // ARC/ORC 2.x type info is static data: every object reads, with a
        // sane size and alignment.
        if !name.contains("refc") && minor(version) >= (2, 0) {
            let v2: Vec<_> = bin
                .types()
                .iter()
                .filter(|t| t.version == RttiVersion::V2)
                .collect();
            assert!(!v2.is_empty(), "nim-{version}/{name}: no V2 types");
            for t in v2 {
                assert!(
                    t.is_readable()
                        && t.size > 0
                        && t.size < 1 << 20
                        && t.align.is_power_of_two()
                        && t.align <= 16,
                    "nim-{version}/{name}: V2 {} size {} align {}",
                    t.symbol_name,
                    t.size,
                    t.align
                );
            }
        }
    });
    eprintln!("big-endian fixtures: {seen}");
}

/// 32-bit Windows decorates C-level names (`_NimMain`, fastcall
/// `@name@N`). With the decoration removed by the container, an i686 build
/// reads like the x86-64 build of the same program: the same version hint,
/// entry shims, init functions, RTTI symbols (from 1.4, see below) and
/// modules.
#[test]
fn i686_builds_read_like_their_x86_64_counterparts() {
    let mut pairs = 0usize;
    for &(version, _) in VERSIONS {
        let dir = common::fixture_path(&format!("nim-{version}/mingw_i686"));
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let file = name(&entry.path());
            let Some(x64) = common::fixture(&format!("nim-{version}/mingw/{file}")) else {
                continue;
            };
            let i686 = std::fs::read(entry.path()).unwrap();
            let (a, b) = (
                NimBinary::from_bytes(&i686).unwrap(),
                NimBinary::from_bytes(&x64).unwrap(),
            );
            assert_eq!(a.arch(), nimrod::Arch::I386);
            let label = format!("nim-{version}/{file}");
            assert_eq!(a.nim_version(), b.nim_version(), "{label}: version");
            let shims = |bin: &NimBinary<'_>| {
                let mut k: Vec<_> = bin
                    .entry_shims()
                    .iter()
                    .map(|s| s.symbol_name.clone())
                    .collect();
                k.sort();
                k
            };
            assert_eq!(shims(&a), shims(&b), "{label}: entry shims");
            let inits = |bin: &NimBinary<'_>| {
                let mut k: Vec<_> = bin
                    .init_functions()
                    .iter()
                    .map(|f| (f.module_path.path.clone(), f.kind))
                    .collect();
                k.sort_by(|x, y| x.0.cmp(&y.0));
                k
            };
            assert_eq!(inits(&a), inits(&b), "{label}: init functions");
            let rtti = |bin: &NimBinary<'_>| {
                let mut k: Vec<_> = bin
                    .rtti_symbols()
                    .iter()
                    .map(|r| r.symbol_name.clone())
                    .collect();
                k.sort();
                k
            };
            // Before 1.4 the allocator's `SmallChunk` has a field only on
            // 32-bit targets (`lib/system/alloc.nim`, `when defined(cpu32)`),
            // which changes the signature hash in the RTTI name of every type
            // that contains it.
            if minor(version) >= (1, 4) {
                assert_eq!(rtti(&a), rtti(&b), "{label}: RTTI symbols");
            }
            let modules = |bin: &NimBinary<'_>| -> Vec<String> {
                bin.module_map().modules.keys().cloned().collect()
            };
            assert_eq!(modules(&a), modules(&b), "{label}: modules");
            pairs += 1;
        }
    }
    eprintln!("i686 / x86-64 pairs: {pairs}");
}

/// Every relation's endpoints are in the inventory: procs, and for a hook
/// edge an RTTI global.
#[test]
fn relation_endpoints_resolve() {
    for_each_fixture(|version, _, name, bin| {
        let procs: BTreeSet<u64> = bin.procs().iter().map(|p| p.va).collect();
        let types: BTreeSet<u64> = bin.rtti_symbols().iter().map(|s| s.address).collect();
        for r in bin.relations() {
            let from = match r.kind {
                RelationKind::Hook(_) => types.contains(&r.from),
                RelationKind::StartupCall | RelationKind::Async(_) => procs.contains(&r.from),
            };
            assert!(from && procs.contains(&r.to), "nim-{version}/{name}: {r:?}");
        }
    });
}

/// Every RTTI hook slot has its edge, with the provenance the layout implies:
/// Nim 2.x ARC/ORC/YRC type info is in the file, refc and pre-2.0 ARC/ORC
/// type info is written by the `DatInit000` functions. A marker linked by
/// name never contradicts the RTTI, and on builds whose startup code is
/// evaluated it only adds markers of types the evaluation left unreadable.
#[test]
fn hook_edges_follow_the_rtti() {
    for_each_fixture(|version, _, name, bin| {
        let edges: BTreeMap<(RelationKind, u64, u64), Provenance> = bin
            .relations()
            .iter()
            .map(|r| ((r.kind, r.from, r.to), r.source))
            .collect();
        let static_rtti = minor(version) >= (2, 0) && !name.contains("refc");
        let mut rtti_marker = BTreeMap::new();
        for t in bin.types() {
            for (kind, r) in t.hooks() {
                let source = edges.get(&(RelationKind::Hook(kind), t.address, r.address));
                let expected = if static_rtti {
                    Provenance::Rtti
                } else {
                    Provenance::Emulated
                };
                assert_eq!(
                    source,
                    Some(&expected),
                    "nim-{version}/{name}: {kind} of {}",
                    t.symbol_name
                );
                if kind == HookKind::Marker {
                    rtti_marker.insert(t.address, r.address);
                }
            }
        }
        let readable: BTreeSet<u64> = bin
            .types()
            .iter()
            .filter(|t| t.is_readable())
            .map(|t| t.address)
            .collect();
        for r in bin.relations() {
            if r.kind != RelationKind::Hook(HookKind::Marker) || r.source != Provenance::SymbolName
            {
                continue;
            }
            assert!(
                !rtti_marker.contains_key(&r.from),
                "nim-{version}/{name}: marker {:#x} by name contradicts the RTTI",
                r.to
            );
            if decodes_code(bin) && bin.container().is_little_endian() {
                assert!(
                    !readable.contains(&r.from),
                    "nim-{version}/{name}: evaluated type {:#x} lacks the marker its name gives",
                    r.from
                );
            }
        }
    });
}

/// The startup edges follow the code generator: `PreMain` calls every
/// `DatInit000` and the system `Init000`, `PreMainInner` every other
/// `Init000`, and `NimMain` both inner shims.
#[test]
fn startup_edges_follow_codegen() {
    for_each_fixture(|version, _, name, bin| {
        let shim = |kind| {
            bin.entry_shims()
                .iter()
                .find(|s| s.kind == kind)
                .map(|s| s.address)
        };
        let calls: BTreeSet<(u64, u64)> = bin
            .relations()
            .iter()
            .filter(|r| r.kind == RelationKind::StartupCall)
            .map(|r| (r.from, r.to))
            .collect();
        let callers = |to: u64| calls.iter().filter(|c| c.1 == to).count();
        let (Some(pre_main), Some(nim_main)) = (shim(ShimKind::PreMain), shim(ShimKind::NimMain))
        else {
            return;
        };
        assert!(
            calls.contains(&(nim_main, pre_main)),
            "nim-{version}/{name}"
        );
        let mut system_init = 0usize;
        for f in bin.init_functions() {
            match f.kind {
                InitKind::DatInit => {
                    assert!(
                        calls.contains(&(pre_main, f.address)),
                        "nim-{version}/{name}: {}",
                        f.symbol_name
                    );
                }
                InitKind::Init if calls.contains(&(pre_main, f.address)) => {
                    system_init = system_init.saturating_add(1);
                }
                InitKind::Init => {
                    let inner = shim(ShimKind::PreMainInner).unwrap();
                    assert!(
                        calls.contains(&(inner, f.address)),
                        "nim-{version}/{name}: {}",
                        f.symbol_name
                    );
                }
                InitKind::HcrInit => continue,
            }
            assert_eq!(
                callers(f.address),
                1,
                "nim-{version}/{name}: {}",
                f.symbol_name
            );
        }
        assert!(
            system_init <= 1,
            "nim-{version}/{name}: {system_init} system inits"
        );
    });
}

/// An async proc's generated procs link to it by name in every release:
/// the iterator (`fetchIter` before 2.0, `fetch (Async)` from 2.0) to the
/// proc and to its `NimAsyncContinue` callback. The fixture has two async
/// procs, `fetch` and `pipeline`.
#[test]
fn async_procs_link_by_name() {
    for_each_fixture(|version, _, name, bin| {
        if !name.starts_with("dispatch") {
            return;
        }
        let name_of = |va: u64| {
            let p = bin.procs().iter().find(|p| p.va == va).unwrap();
            (p.name.as_str(), p.role)
        };
        let mut links: Vec<(AsyncLink, &str, &str)> = bin
            .relations()
            .iter()
            .filter_map(|r| match r.kind {
                RelationKind::Async(link) => Some((link, name_of(r.from).0, name_of(r.to).0)),
                _ => None,
            })
            .collect();
        links.sort();
        let it = |base: &str| {
            if minor(version) >= (2, 0) {
                format!("{base} (Async)")
            } else {
                format!("{base}Iter")
            }
        };
        let (fetch, pipeline) = (it("fetch"), it("pipeline"));
        assert_eq!(
            links,
            [
                (AsyncLink::Body, "fetch", fetch.as_str()),
                (AsyncLink::Body, "pipeline", pipeline.as_str()),
                (AsyncLink::Resume, "fetchNimAsyncContinue", fetch.as_str()),
                (
                    AsyncLink::Resume,
                    "pipelineNimAsyncContinue",
                    pipeline.as_str()
                ),
            ],
            "nim-{version}/{name}"
        );
        for r in bin
            .relations()
            .iter()
            .filter(|r| matches!(r.kind, RelationKind::Async(_)))
        {
            assert_eq!(name_of(r.to).1, ProcRole::Async(AsyncPart::Iterator));
        }
    });
}

/// `new(r, release)` makes `release` the type's finalizer, which the refc
/// RTTI records once the startup code is evaluated.
#[test]
fn finalizer_recovered_from_refc_rtti() {
    for_each_fixture(|version, _, name, bin| {
        if !name.starts_with("dispatch_refc") || !decodes_code(bin) {
            return;
        }
        assert!(
            bin.procs()
                .iter()
                .any(|p| p.name == "release" && p.role == ProcRole::Hook(HookKind::Finalizer)),
            "nim-{version}/{name}"
        );
    });
}

/// A function or object is listed once, though ELF repeats exported symbols
/// in `.dynsym` and PE lists exports beside the COFF table. (COFF section
/// symbols, one per object file, may share an address.)
#[test]
fn functions_and_objects_listed_once() {
    for_each_fixture(|version, _, name, bin| {
        let mut seen = BTreeSet::new();
        for s in bin.container().symbols() {
            if matches!(
                s.kind,
                nimrod::SymbolKind::Function | nimrod::SymbolKind::Object
            ) {
                assert!(
                    seen.insert((s.name.as_ref(), s.vm_addr)),
                    "nim-{version}/{name}: {} at {:#x} listed twice",
                    s.name,
                    s.vm_addr
                );
            }
        }
    });
}
