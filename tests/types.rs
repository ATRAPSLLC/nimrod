//! Integration tests for the type graph, code entrypoints and compiler
//! version.
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
use nimrod::{NimBinary, NimVersionHint, ProcRole, TypeShape, rtti::symbols::RttiVersion};

/// The nightly compiler binary (ORC, Nim 2.3.1, x86-64 Linux).
const NIGHTLY_ELF: &str = "nightly/linux_x64/nim-2.3.1/bin/nim";

/// Every V2 type of the nightly compiler reads (size, alignment, depth), one
/// per RTTI symbol, with display tokens and destructors resolved.
#[test]
fn elf_v2_type_graph_is_fully_readable() {
    let Some(data) = fixture(NIGHTLY_ELF) else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();

    let types = bin.types();
    assert!(
        types.len() >= 80,
        "expected many V2 types, got {}",
        types.len()
    );

    // One NimType per RTTI symbol (1:1 with the symbol scan).
    assert_eq!(types.len(), bin.rtti_symbols().len());

    // Every type is a readable V2 record with a parsed size/align.
    for t in types {
        assert_eq!(t.version, RttiVersion::V2);
        assert!(
            t.is_readable(),
            "V2 type {} should be file-backed",
            t.symbol_name
        );
        assert!(
            t.align > 0,
            "align should be populated for {}",
            t.symbol_name
        );
        assert!(t.depth.is_some(), "V2 depth should be populated");
    }

    // At least one object type has resolved members or an inheritance chain.
    assert!(
        types.iter().any(|t| !t.display_tokens.is_empty()),
        "expected V2 inheritance display tokens"
    );
    // Destructors resolve to functions for the bulk of types.
    let with_dtor = types.iter().filter(|t| t.destructor.is_some()).count();
    assert!(with_dtor > 0, "expected resolved destructors");
}

/// A V2 display array holds `depth + 1` class tokens, one per inheritance
/// level including the type itself.
#[test]
fn elf_v2_display_tokens_track_depth() {
    let Some(data) = fixture(NIGHTLY_ELF) else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    // The display array holds depth+1 class tokens (RESEARCH.md §3.2). Verify
    // for every type that produced one.
    let mut checked = 0;
    for t in bin.types() {
        if t.display_tokens.is_empty() {
            continue;
        }
        let depth = t.depth.expect("V2 type has depth");
        let expected = usize::try_from(depth).unwrap() + 1;
        assert_eq!(
            t.display_tokens.len(),
            expected,
            "{}: display token count should be depth+1",
            t.symbol_name
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "expected at least one type with display tokens"
    );
}

#[test]
fn macho_v1_types_recovered_from_startup_code() {
    // V1 globals land in Mach-O __DATA,__common (no file backing, §3.6) and
    // are filled by the `DatInit000` functions, which nimrod evaluates: every
    // type reads, and the user exception keeps its place in the hierarchy.
    let Some(data) = fixture("native/exceptions_refc_debug") else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let types = bin.types();
    assert!(!types.is_empty(), "expected V1 RTTI symbols");
    for t in types {
        assert_eq!(t.version, RttiVersion::V1);
        assert!(t.is_readable(), "{} not recovered", t.symbol_name);
        // The embedded type fragment survives either way.
        assert!(t.type_fragment.is_some());
    }
    let by_fragment = |f: &str| {
        types
            .iter()
            .position(|t| t.type_fragment.as_deref() == Some(f))
            .unwrap_or_else(|| panic!("no {f} type"))
    };
    let my = &types[by_fragment("myerror")];
    assert_eq!(my.shape, TypeShape::Object);
    // refc `Exception`: m_type, parent, name, msg, trace, up.
    assert_eq!((my.size, my.align), (48, 8));
    let parent = my.parent.as_ref().and_then(|p| p.index).map(|i| &types[i]);
    assert_eq!(
        parent.and_then(|p| p.type_fragment.as_deref()),
        Some("catchableerror")
    );
    let r = &types[by_fragment("refmyerror")];
    assert_eq!(r.shape, TypeShape::Ref);
    assert_eq!(
        r.parent.as_ref().and_then(|p| p.index),
        Some(by_fragment("myerror"))
    );
}

/// The version hint tells refc, ARC and ORC apart on the native fixtures.
#[test]
fn compiler_version_distinguishes_modes() {
    let cases = [
        ("native/exceptions_arc_release", NimVersionHint::Nim2xArc),
        ("native/exceptions_orc_release", NimVersionHint::Nim2xOrc),
        ("native/exceptions_refc_debug", NimVersionHint::Nim1xRefc),
    ];
    for (rel, expected) in cases {
        let Some(data) = fixture(rel) else {
            continue;
        };
        let bin = NimBinary::from_bytes(&data).unwrap();
        assert_eq!(bin.nim_version(), expected, "{rel}: version mismatch");
    }
}

/// The proc inventory combines shims, init functions and procs, sorted and
/// deduplicated by address.
#[test]
fn procs_aggregate_sources() {
    let Some(data) = fixture(NIGHTLY_ELF) else {
        return;
    };
    let bin = NimBinary::from_bytes(&data).unwrap();
    let procs = bin.procs();
    assert!(!procs.is_empty());
    assert!(
        procs.windows(2).all(|w| w[0].va < w[1].va),
        "must be VA-sorted & deduped"
    );
    let has = |f: fn(&ProcRole) -> bool| procs.iter().any(|p| f(&p.role));
    assert!(
        has(|r| matches!(r, ProcRole::EntryShim(_))),
        "expected entry shims"
    );
    assert!(
        has(|r| matches!(r, ProcRole::Init(_))),
        "expected module inits"
    );
    assert!(has(|r| *r == ProcRole::User), "expected user procs");
}

/// Format, bitness and 64-bit predicates of the nightly ELF.
#[test]
fn format_and_bitness_predicates() {
    if let Some(data) = fixture(NIGHTLY_ELF) {
        let bin = NimBinary::from_bytes(&data).unwrap();
        assert!(bin.format().is_elf());
        assert!(!bin.format().is_pe());
        assert!(bin.is_64bit());
        assert_eq!(bin.bitness(), Some(64));
    }
}
