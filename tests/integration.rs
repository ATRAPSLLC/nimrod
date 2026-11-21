//! Integration tests over the native, mingw and nightly fixtures:
//! detection (and its absence on other binaries), demangling, entry shims,
//! init functions, GC mode, RTTI symbols, string literals, stack-trace and
//! nimble path leaks, exception types, raise sites, the module map, address
//! conversion, caching, and fat Mach-O files.
//!
//! Fixtures are described in `tests/common/mod.rs`; every test skips when
//! its fixture is absent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

mod common;

use common::fixture;
use nimrod::{
    Arch, DetectionMatches, Format, NimBinary, metadata::GcMode, rtti::symbols::RttiVersion,
    shims::ShimKind,
};

/// Asserts that fixture `rel` detects as Nim with the given format and
/// architecture (skipping when it is absent).
fn assert_is_nim(rel: &str, expected_format: Format, expected_arch: Arch) {
    let Some(data) = fixture(rel) else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap_or_else(|e| panic!("failed to parse {rel}: {e}"));
    assert!(
        bin.is_nim(),
        "{rel}: expected is_nim==true, got matches={:?}",
        bin.detection_matches()
    );
    assert_eq!(bin.format(), expected_format, "{rel}: format mismatch");
    assert_eq!(bin.arch(), expected_arch, "{rel}: arch mismatch");
}

/// The nightly compiler for Linux x86-64 detects.
#[test]
fn nightly_elf_linux_x64_detects() {
    assert_is_nim(
        "nightly/linux_x64/nim-2.3.1/bin/nim",
        Format::Elf,
        Arch::Amd64,
    );
}

/// The nightly compiler for macOS arm64 detects.
#[test]
fn nightly_macho_arm64_detects() {
    assert_is_nim(
        "nightly/macosx_arm64/nim-2.3.1/bin/nim",
        Format::MachO,
        Arch::Aarch64,
    );
}

/// The nightly compiler for Windows x86-64 detects.
#[test]
fn nightly_pe_windows_x64_detects() {
    assert_is_nim(
        "nightly/windows_x64/nim-2.3.1/bin/nim.exe",
        Format::Pe,
        Arch::Amd64,
    );
}

/// Every detection probe that can fire on an ELF ARC/ORC build fires on the
/// nightly compiler.
#[test]
fn nightly_elf_has_all_applicable_flags() {
    let Some(data) = fixture("nightly/linux_x64/nim-2.3.1/bin/nim") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let m = bin.detection_matches();

    // Every flag that can possibly set on an ELF ARC/ORC build must set.
    // NTI_LEGACY is expected to be absent on Nim 2.x ARC/ORC builds.
    let expected = DetectionMatches::NIMMAIN_SYMBOL
        | DetectionMatches::NIMMAIN_STRING
        | DetectionMatches::FATAL_NIM
        | DetectionMatches::SYS_FATAL
        | DetectionMatches::NIM_ERROR_STRINGS
        | DetectionMatches::INIT000_SYMBOL
        | DetectionMatches::NTIV2_SYMBOL
        | DetectionMatches::STT_FILE_DOT_NIM
        | DetectionMatches::NIMBLE_PATH_LEAK;
    assert!(m.contains(expected), "ELF nightly missing flags: got {m:?}");
}

/// Every detection probe that can fire on a PE ARC/ORC build fires.
#[test]
fn nightly_pe_has_all_applicable_flags() {
    let Some(data) = fixture("nightly/windows_x64/nim-2.3.1/bin/nim.exe") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let m = bin.detection_matches();
    let expected = DetectionMatches::NIMMAIN_SYMBOL
        | DetectionMatches::FATAL_NIM
        | DetectionMatches::SYS_FATAL
        | DetectionMatches::NIM_ERROR_STRINGS
        | DetectionMatches::INIT000_SYMBOL
        | DetectionMatches::NTIV2_SYMBOL
        | DetectionMatches::STT_FILE_DOT_NIM
        | DetectionMatches::NIMBLE_PATH_LEAK;
    assert!(m.contains(expected), "PE nightly missing flags: got {m:?}");
}

/// Every detection probe that can fire on a Mach-O ARC/ORC build fires.
#[test]
fn nightly_macho_has_all_applicable_flags() {
    let Some(data) = fixture("nightly/macosx_arm64/nim-2.3.1/bin/nim") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let m = bin.detection_matches();
    // Mach-O has no STT_FILE equivalent in the main symbol table, so we
    // don't expect STT_FILE_DOT_NIM.
    let expected = DetectionMatches::NIMMAIN_SYMBOL
        | DetectionMatches::FATAL_NIM
        | DetectionMatches::SYS_FATAL
        | DetectionMatches::NIM_ERROR_STRINGS
        | DetectionMatches::INIT000_SYMBOL
        | DetectionMatches::NTIV2_SYMBOL;
    assert!(
        m.contains(expected),
        "Mach-O nightly missing flags: got {m:?}"
    );
}

/// The native set: every source in every memory manager and build mode.
const NATIVE_FIXTURES: &[&str] = &[
    "native/hello_basic_refc_debug",
    "native/hello_basic_refc_release",
    "native/hello_basic_orc_debug",
    "native/hello_basic_orc_release",
    "native/hello_basic_orc_danger_size",
    "native/hello_basic_arc_release",
    "native/strings_and_seqs_refc_debug",
    "native/strings_and_seqs_refc_release",
    "native/strings_and_seqs_orc_debug",
    "native/strings_and_seqs_orc_release",
    "native/strings_and_seqs_orc_danger_size",
    "native/strings_and_seqs_arc_release",
    "native/exceptions_refc_debug",
    "native/exceptions_refc_release",
    "native/exceptions_orc_debug",
    "native/exceptions_orc_release",
    "native/exceptions_orc_danger_size",
    "native/exceptions_arc_release",
    "native/stdlib_mix_refc_debug",
    "native/stdlib_mix_refc_release",
    "native/stdlib_mix_orc_debug",
    "native/stdlib_mix_orc_release",
    "native/stdlib_mix_orc_danger_size",
    "native/stdlib_mix_arc_release",
    "native/fileio_json_refc_debug",
    "native/fileio_json_refc_release",
    "native/fileio_json_orc_debug",
    "native/fileio_json_orc_release",
    "native/fileio_json_orc_danger_size",
    "native/fileio_json_arc_release",
];

/// Every native fixture detects.
#[test]
fn all_native_fixtures_detect() {
    for rel in NATIVE_FIXTURES {
        let Some(data) = fixture(rel) else {
            continue;
        };
        let bin =
            NimBinary::from_bytes(&data).unwrap_or_else(|e| panic!("failed to parse {rel}: {e}"));
        assert!(
            bin.is_nim(),
            "{rel}: is_nim==false, matches={:?}",
            bin.detection_matches()
        );
    }
}

/// A refc build has legacy `NTI` RTTI symbols and no `NTIv2` ones.
#[test]
fn refc_fixture_has_nti_legacy_symbols() {
    let label = "native/hello_basic_refc_debug";
    let Some(data) = fixture(label) else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let m = bin.detection_matches();
    assert!(
        m.contains(DetectionMatches::NTI_LEGACY_SYMBOL),
        "{label}: expected NTI_LEGACY_SYMBOL, got {m:?}"
    );
    // refc builds never produce NTIv2 symbols.
    assert!(
        !m.contains(DetectionMatches::NTIV2_SYMBOL),
        "{label}: unexpected NTIV2_SYMBOL in refc build"
    );
}

/// An ORC build has `NTIv2` RTTI symbols and no legacy ones.
#[test]
fn orc_release_fixture_has_ntiv2_symbols() {
    let label = "native/hello_basic_orc_release";
    let Some(data) = fixture(label) else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let m = bin.detection_matches();
    assert!(
        m.contains(DetectionMatches::NTIV2_SYMBOL),
        "{label}: expected NTIV2_SYMBOL, got {m:?}"
    );
    assert!(
        !m.contains(DetectionMatches::NTI_LEGACY_SYMBOL),
        "{label}: unexpected NTI_LEGACY_SYMBOL in orc build"
    );
}

/// The mingw (Windows x86-64 PE) set.
const MINGW_FIXTURES: &[&str] = &[
    "mingw/hello_basic_orc_release.exe",
    "mingw/hello_basic_orc_danger_size.exe",
    "mingw/strings_and_seqs_orc_release.exe",
    "mingw/strings_and_seqs_orc_danger_size.exe",
    "mingw/exceptions_orc_release.exe",
    "mingw/exceptions_orc_danger_size.exe",
    "mingw/stdlib_mix_orc_release.exe",
    "mingw/stdlib_mix_orc_danger_size.exe",
    "mingw/fileio_json_orc_release.exe",
    "mingw/fileio_json_orc_danger_size.exe",
];

/// Every mingw fixture detects as a PE x86-64 Nim binary.
#[test]
fn all_mingw_fixtures_detect() {
    for rel in MINGW_FIXTURES {
        let Some(data) = fixture(rel) else {
            continue;
        };
        let bin =
            NimBinary::from_bytes(&data).unwrap_or_else(|e| panic!("failed to parse {rel}: {e}"));
        assert!(
            bin.is_nim(),
            "{rel}: is_nim==false, matches={:?}",
            bin.detection_matches()
        );
        assert_eq!(bin.format(), Format::Pe, "{rel}: expected PE");
        assert_eq!(bin.arch(), Arch::Amd64, "{rel}: expected Amd64");
    }
}

/// A stripped `-d:danger --opt:size` build still detects from the runtime's
/// own strings.
#[test]
fn danger_fixture_still_detects_without_rtti_string_leak() {
    // -d:danger --opt:size --passL:-s strips diagnostic tables and symbol
    // tables aggressively, but Nim signal-handler strings ("Attempt to read
    // from nil?") and exception formatting ("@[[reraised from:") still
    // survive. See RESEARCH.md §11.3.
    let label = "mingw/hello_basic_orc_danger_size.exe";
    let Some(data) = fixture(label) else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    assert!(
        bin.is_nim(),
        "{label}: danger-size build should still detect"
    );
}

/// Asserts that the binary at `path` (outside the fixtures; skipped when
/// absent or unparseable) does not detect as Nim.
fn assert_not_nim(path: &str) {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!("skip: negative fixture {path} not present");
            return;
        }
    };
    // A binary nimrod cannot parse is fine: only parseable ones must not
    // detect as Nim.
    let Ok(bin) = NimBinary::from_bytes(&data) else {
        return;
    };
    assert!(
        !bin.is_nim(),
        "{path}: expected is_nim==false on non-Nim binary, got matches={:?}",
        bin.detection_matches()
    );
}

/// macOS system binaries must not detect as Nim.
#[test]
fn system_macho_binaries_do_not_detect() {
    // Universal binaries always present on macOS.
    for path in &["/usr/bin/true", "/usr/bin/false", "/usr/bin/env", "/bin/ls"] {
        assert_not_nim(path);
    }
}

/// Common system utilities (shell, `sed`, `grep`, `awk`) do not detect as
/// Nim.
#[test]
fn other_system_binaries_do_not_detect() {
    for path in &["/bin/sh", "/usr/bin/sed", "/usr/bin/grep", "/usr/bin/awk"] {
        assert_not_nim(path);
    }
}

/// Pure garbage bytes must not parse at all, or if they do, must not detect.
#[test]
fn garbage_bytes_do_not_detect() {
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
    // Parse failure is also acceptable.
    if let Ok(bin) = NimBinary::from_bytes(&garbage) {
        assert!(!bin.is_nim(), "garbage bytes should not detect");
    }
}

/// The nightly `nimble` and `nimsuggest` are Nim programs too and detect on
/// all three platforms.
#[test]
fn nightly_secondary_tools_also_detect() {
    let tools = &[
        "nightly/linux_x64/nim-2.3.1/bin/nimble",
        "nightly/linux_x64/nim-2.3.1/bin/nimsuggest",
        "nightly/macosx_arm64/nim-2.3.1/bin/nimble",
        "nightly/macosx_arm64/nim-2.3.1/bin/nimsuggest",
        "nightly/windows_x64/nim-2.3.1/bin/nimble.exe",
        "nightly/windows_x64/nim-2.3.1/bin/nimsuggest.exe",
    ];
    for rel in tools {
        let Some(data) = fixture(rel) else {
            continue;
        };
        let bin =
            NimBinary::from_bytes(&data).unwrap_or_else(|e| panic!("failed to parse {rel}: {e}"));
        assert!(
            bin.is_nim(),
            "{rel}: expected is_nim==true for nightly Nim tool",
        );
    }
}

/// Names from the nightly compiler demangle to identifier, module and id.
#[test]
fn demangle_real_world_symbols() {
    use nimrod::demangle::symbol;

    let cases = &[
        (
            "genNimMainInner__cgen_u41496",
            "genNimMainInner",
            "cgen",
            Some(41496),
        ),
        ("amp___docgen_u11299", "&", "docgen", Some(11299)),
        ("ampeq___sighashes_u12", "&=", "sighashes", Some(12)),
        (
            "GC_getStatistics__system_u7819",
            "GC_getStatistics",
            "system",
            Some(7819),
        ),
        (
            "FF__OOZdistZchecksumsZsrcZchecksumsZmd5_u42",
            "FF",
            "OOZdistZchecksumsZsrcZchecksumsZmd5",
            Some(42),
        ),
        (
            "colonanonymous___cgen_u4206",
            ":anonymous",
            "cgen",
            Some(4206),
        ),
    ];

    for &(sym, expected_ident, expected_module, expected_id) in cases {
        let d = symbol::parse(sym, None).unwrap_or_else(|| panic!("failed to parse {sym}"));
        assert_eq!(&*d.identifier, expected_ident, "ident mismatch for {sym}");
        assert_eq!(d.module, Some(expected_module), "module mismatch for {sym}");
        assert_eq!(d.disambiguator, expected_id, "id mismatch for {sym}");
    }
}

/// The nightly compiler has all five entry shims.
#[test]
fn nightly_elf_has_all_five_entry_shims() {
    let Some(data) = fixture("nightly/linux_x64/nim-2.3.1/bin/nim") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let shims = bin.entry_shims();

    let kinds: Vec<ShimKind> = shims.iter().map(|s| s.kind).collect();
    for expected in &[
        ShimKind::NimMain,
        ShimKind::NimMainInner,
        ShimKind::NimMainModule,
        ShimKind::PreMain,
        ShimKind::PreMainInner,
    ] {
        assert!(
            kinds.contains(expected),
            "missing entry shim {:?}",
            expected
        );
    }
}

/// Init function names decode to module paths, `system.nim` among them.
#[test]
fn nightly_elf_init_functions_decode_paths() {
    let Some(data) = fixture("nightly/linux_x64/nim-2.3.1/bin/nim") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let inits = bin.init_functions();

    assert!(
        !inits.is_empty(),
        "expected at least one init function in nightly ELF"
    );

    // The nightly binary should have system.nim as an init function.
    let system_init = inits.iter().find(|f| f.module_path.path == "system.nim");
    assert!(
        system_init.is_some(),
        "expected system.nim init function, found: {:?}",
        inits
            .iter()
            .map(|f| &f.module_path.path)
            .collect::<Vec<_>>()
    );
}

/// An ORC build reads as ARC/ORC.
#[test]
fn native_orc_release_gc_mode() {
    let Some(data) = fixture("native/hello_basic_orc_release") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    assert_eq!(bin.gc_mode(), GcMode::ArcOrc);
}

/// A refc build reads as refc.
#[test]
fn native_refc_debug_gc_mode() {
    let Some(data) = fixture("native/hello_basic_refc_debug") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    assert_eq!(bin.gc_mode(), GcMode::Refc);
}

/// Without `--nimMainPrefix` the entry-shim prefix is empty.
#[test]
fn native_orc_release_has_default_prefix() {
    let Some(data) = fixture("native/hello_basic_orc_release") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    assert_eq!(bin.nim_main_prefix(), Some(""));
}

/// A refc build has `DatInit000` functions (they fill its RTTI).
#[test]
fn refc_debug_has_datinit_functions() {
    let Some(data) = fixture("native/hello_basic_refc_debug") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let inits = bin.init_functions();

    let has_datinit = inits.iter().any(|f| f.kind == nimrod::InitKind::DatInit);
    assert!(
        has_datinit,
        "refc debug fixture should have DatInit000 functions"
    );
}

/// The nightly compiler has exactly 86 `NTIv2` symbols.
#[test]
fn nightly_elf_has_86_ntiv2_symbols() {
    let Some(data) = fixture("nightly/linux_x64/nim-2.3.1/bin/nim") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let rtti = bin.rtti_symbols();
    let v2_count = rtti.iter().filter(|r| r.version == RttiVersion::V2).count();
    assert_eq!(v2_count, 86, "expected 86 NTIv2_ symbols in nightly ELF");
}

/// A refc debug build has legacy RTTI symbols carrying type fragments.
#[test]
fn refc_debug_has_nti_v1_symbols() {
    let Some(data) = fixture("native/hello_basic_refc_debug") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let rtti = bin.rtti_symbols();
    let v1_count = rtti.iter().filter(|r| r.version == RttiVersion::V1).count();
    assert!(v1_count > 0, "expected V1 NTI_ symbols in refc debug build");

    // At least some V1 symbols should have a type name fragment.
    let with_type = rtti
        .iter()
        .filter(|r| r.version == RttiVersion::V1 && r.type_fragment.is_some())
        .count();
    assert!(
        with_type > 0,
        "expected V1 symbols with type fragments, got none"
    );
}

/// The source's string literals are found by the V2 scan.
#[test]
fn strings_and_seqs_orc_release_recovers_source_literals() {
    let Some(data) = fixture("native/strings_and_seqs_orc_release") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let literals = bin.string_literals_v2();

    let values: Vec<&str> = literals.iter().map(|l| l.value.as_str()).collect();

    for expected in &["alpha", "beta", "gamma", "delta"] {
        assert!(
            values.contains(expected),
            "missing string literal {expected:?} in V2 scan; found: {values:?}"
        );
    }
}

/// `strings_and_seqs` (ORC release) has exactly 4 `NTIv2` symbols.
#[test]
fn orc_release_has_ntiv2_symbols() {
    let Some(data) = fixture("native/strings_and_seqs_orc_release") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let rtti = bin.rtti_symbols();
    let v2_count = rtti.iter().filter(|r| r.version == RttiVersion::V2).count();
    assert_eq!(v2_count, 4, "expected 4 NTIv2_ symbols in strings_and_seqs");
}

/// A debug build leaks absolute `.nim` paths, the stdlib's and the source's.
#[test]
fn refc_debug_has_absolute_nim_paths() {
    let Some(data) = fixture("native/hello_basic_refc_debug") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let harvest = bin.stack_trace();

    let abs_count = harvest.file_paths.iter().filter(|f| f.is_absolute).count();
    assert!(
        abs_count > 0,
        "refc debug should have absolute .nim paths (build-host leak)"
    );

    // Should include the homebrew cellar system.nim path.
    let has_system = harvest
        .file_paths
        .iter()
        .any(|f| f.path.contains("system.nim") && f.is_absolute);
    assert!(
        has_system,
        "expected absolute system.nim path in refc debug"
    );

    // Should include the build fixture source path.
    let has_fixture = harvest
        .file_paths
        .iter()
        .any(|f| f.path.contains("hello_basic.nim"));
    assert!(
        has_fixture,
        "expected hello_basic.nim source path in refc debug"
    );
}

/// A danger build leaks no `.nim` paths.
#[test]
fn orc_danger_size_has_zero_nim_paths() {
    let Some(data) = fixture("native/hello_basic_orc_danger_size") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let harvest = bin.stack_trace();
    assert_eq!(
        harvest.file_paths.len(),
        0,
        "danger-size build should have zero .nim paths"
    );
}

/// The nightly compiler leaks nimble package paths.
#[test]
fn nightly_elf_has_nimble_path_leak() {
    let Some(data) = fixture("nightly/linux_x64/nim-2.3.1/bin/nim") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let nimble = bin.nimble_paths();
    assert!(
        !nimble.is_empty(),
        "nightly ELF should have .nimble/pkgs path leak"
    );
}

/// The user's exception types are found among the rodata strings.
#[test]
fn exceptions_fixture_has_user_defined_types() {
    let Some(data) = fixture("native/exceptions_orc_release") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let exceptions = bin.exception_types();

    let names: Vec<&str> = exceptions.iter().map(|e| e.type_name.as_str()).collect();
    assert!(
        names.contains(&"MyError"),
        "expected MyError in exceptions fixture; found: {names:?}"
    );
    assert!(
        names.contains(&"OtherError"),
        "expected OtherError in exceptions fixture; found: {names:?}"
    );
}

/// The nightly compiler's raise sites carry full `(type, proc, file, line)`
/// tuples, `ValueError` among them.
#[test]
fn nightly_elf_raise_sites_have_full_tuples() {
    let Some(data) = fixture("nightly/linux_x64/nim-2.3.1/bin/nim") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let sites = bin.raise_sites();

    assert!(!sites.is_empty(), "expected raise sites in nightly ELF");

    // At least some sites should have full tuples.
    let full = sites
        .iter()
        .filter(|s| {
            s.exception_type.is_some()
                && s.proc_name.is_some()
                && s.file.is_some()
                && s.line.is_some()
        })
        .count();
    assert!(
        full >= 5,
        "expected at least 5 fully-recovered raise sites, got {full}"
    );

    // Should include ValueError raises from strutils.
    let has_value_error = sites
        .iter()
        .any(|s| s.exception_type.as_deref() == Some("ValueError"));
    assert!(has_value_error, "expected ValueError raise site");
}

/// The arm64 macOS build's raise sites include the user's `MyError`.
#[test]
fn exceptions_aarch64_raise_sites() {
    let Some(data) = fixture("native/exceptions_orc_release") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let sites = bin.raise_sites();

    // Should find MyError from the test fixture source.
    let has_my_error = sites
        .iter()
        .any(|s| s.exception_type.as_deref() == Some("MyError"));
    assert!(
        has_my_error,
        "expected MyError raise site in exceptions fixture; got: {:?}",
        sites.iter().map(|s| &s.exception_type).collect::<Vec<_>>()
    );
}

/// The nightly compiler's module map holds `system` and `ast`, with
/// `system`'s functions.
#[test]
fn nightly_elf_module_map_has_known_modules() {
    let Some(data) = fixture("nightly/linux_x64/nim-2.3.1/bin/nim") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let mmap = bin.module_map();

    // The nightly nim compiler should have well-known modules.
    assert!(
        mmap.modules.contains_key("system"),
        "expected 'system' module in module map"
    );
    assert!(
        mmap.modules.contains_key("ast"),
        "expected 'ast' module in module map"
    );

    // The 'system' module should have many symbols.
    let system = &mmap.modules["system"];
    assert!(
        system.symbol_count() > 10,
        "expected 'system' to have >10 symbols, got {}",
        system.symbol_count()
    );
}

// ----- §11.2 RVA accessors --------------------------------------------------

/// PE: image_base is non-zero and shim VAs convert to a sane RVA.
#[test]
fn nightly_pe_image_base_and_shim_rva() {
    let label = "nightly/windows_x64/nim-2.3.1/bin/nim.exe";
    let Some(data) = fixture(label) else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap_or_else(|e| panic!("parse {label}: {e}"));

    let base = bin.image_base();
    assert!(base > 0, "PE image_base should be non-zero, got {base:#x}");

    let shims = bin.entry_shims();
    assert!(
        !shims.is_empty(),
        "expected at least one shim on nightly PE"
    );
    for s in shims {
        let rva = bin.shim_rva(s).unwrap_or_else(|| {
            panic!(
                "shim {} VA {:#x} below image_base {:#x}",
                s.symbol_name, s.address, base
            )
        });
        assert!(rva < 0x1_0000_0000, "RVA suspiciously large: {rva:#x}");
        assert_eq!(rva.checked_add(base), Some(s.address));
    }
}

/// §11.5: scans are cached; repeat calls return the same slice
/// (identical pointer + length).
#[test]
fn scan_accessors_are_cached() {
    let label = "nightly/linux_x64/nim-2.3.1/bin/nim";
    let Some(data) = fixture(label) else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap_or_else(|e| panic!("parse {label}: {e}"));

    let a = bin.entry_shims();
    let b = bin.entry_shims();
    assert_eq!(a.as_ptr(), b.as_ptr(), "entry_shims not cached");

    let a = bin.init_functions();
    let b = bin.init_functions();
    assert_eq!(a.as_ptr(), b.as_ptr(), "init_functions not cached");

    let a = bin.rtti_symbols();
    let b = bin.rtti_symbols();
    assert_eq!(a.as_ptr(), b.as_ptr(), "rtti_symbols not cached");

    let a = bin.raise_sites();
    let b = bin.raise_sites();
    assert_eq!(a.as_ptr(), b.as_ptr(), "raise_sites not cached");

    let a = bin.string_literals_v2();
    let b = bin.string_literals_v2();
    assert_eq!(a.as_ptr(), b.as_ptr(), "string_literals_v2 not cached");

    let a = bin.module_map() as *const _;
    let b = bin.module_map() as *const _;
    assert_eq!(a, b, "module_map not cached");
}

/// ELF: image_base is the lowest PT_LOAD vaddr and RVAs are computed from it.
#[test]
fn nightly_elf_image_base_and_init_rva() {
    let label = "nightly/linux_x64/nim-2.3.1/bin/nim";
    let Some(data) = fixture(label) else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap_or_else(|e| panic!("parse {label}: {e}"));

    let base = bin.image_base();
    let inits = bin.init_functions();
    assert!(!inits.is_empty(), "expected init functions on nightly ELF");
    for i in inits {
        if let Some(rva) = bin.init_rva(i) {
            assert_eq!(rva.checked_add(base), Some(i.address));
        }
    }
}

/// A universal (fat) file holding `thin`, an arm64 Mach-O, as its only
/// slice.
fn fat_wrap(thin: &[u8]) -> Vec<u8> {
    /// Where `lipo` puts the first slice: page-aligned (16 KiB on arm64).
    const OFFSET: usize = 0x4000;
    let mut fat = Vec::with_capacity(OFFSET + thin.len());
    fat.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
    fat.extend_from_slice(&1u32.to_be_bytes()); // nfat_arch
    fat.extend_from_slice(&0x0100_000c_u32.to_be_bytes()); // CPU_TYPE_ARM64
    fat.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
    fat.extend_from_slice(&(OFFSET as u32).to_be_bytes());
    fat.extend_from_slice(&(thin.len() as u32).to_be_bytes());
    fat.extend_from_slice(&14u32.to_be_bytes()); // align 2^14
    fat.resize(OFFSET, 0);
    fat.extend_from_slice(thin);
    fat
}

#[test]
fn fat_macho_reads_like_its_slice() {
    // Offsets inside a fat slice count from the slice: reading them from
    // the start of the file put every section's data in the wrong place.
    let Some(thin) = fixture("native/exceptions_refc_debug") else {
        return;
    };
    let fat = fat_wrap(&thin);
    let a = NimBinary::from_bytes(&thin).unwrap();
    let b = NimBinary::from_bytes(&fat).unwrap();
    let data = |bin: &NimBinary<'_>| -> Vec<(String, Vec<u8>)> {
        bin.container()
            .sections()
            .iter()
            .map(|s| (s.name.clone(), s.data.to_vec()))
            .collect()
    };
    assert_eq!(data(&a), data(&b));
    let strings = |bin: &NimBinary<'_>| -> Vec<String> {
        bin.string_literals_v1()
            .iter()
            .map(|l| l.value.clone())
            .collect()
    };
    assert!(!strings(&a).is_empty());
    assert_eq!(strings(&a), strings(&b));
    let types = |bin: &NimBinary<'_>| -> Vec<(String, bool, u64)> {
        bin.types()
            .iter()
            .map(|t| (t.symbol_name.clone(), t.is_readable(), t.size))
            .collect()
    };
    assert_eq!(types(&a), types(&b));
}

/// A COFF symbol whose string-table offset points inside the table's
/// 4-byte length prefix is skipped, not an arithmetic overflow (found by
/// the fuzzer: goblin's `Symbol::name_offset` subtracts the prefix
/// unchecked).
#[test]
fn coff_name_offset_inside_length_prefix_does_not_panic() {
    let Some(mut data) = fixture("mingw/hello_basic_orc_release.exe") else {
        return;
    };
    let u32_at = |d: &[u8], at: usize| u32::from_le_bytes(d[at..at + 4].try_into().unwrap());
    let pe = u32_at(&data, 0x3c) as usize;
    let symtab = u32_at(&data, pe + 12) as usize;
    let count = u32_at(&data, pe + 16) as usize;
    // The first symbol named through the string table (aux records are
    // stepped over).
    let mut i = 0;
    let record = loop {
        assert!(i < count, "no string-table symbol name in the fixture");
        let at = symtab + i * 18;
        if data[at..at + 4] == [0; 4] {
            break at;
        }
        i += 1 + usize::from(data[at + 17]);
    };
    data[record + 4..record + 8].copy_from_slice(&2u32.to_le_bytes());
    let bin = NimBinary::from_bytes(&data).unwrap();
    assert!(bin.is_nim());
    let _ = bin.module_map();
    let _ = bin.types();
}
