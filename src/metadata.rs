//! Nim binary metadata detection.
//!
//! Infers high-level properties from the container's symbol table:
//!
//! - **GC mode**: `refc` (legacy) vs `arc`/`orc` (modern), based on
//!   which RTTI global naming convention is present.
//! - **Compiler and memory manager** ([`NimVersionHint`]): refc, ARC,
//!   atomicArc (from `lock`-prefixed reference-count updates, x86-64 only),
//!   ORC (the cycle collector's symbols) and YRC (its runtime routines).
//! - **`--nimMainPrefix`**: the user-configurable prefix on entry shims.
//!
//! See RESEARCH.md §3.5 (RTTI counts by mode) and §6 (entry shims).

use crate::{container::Container, detect::DetectionMatches};
use core::fmt;

/// Nim garbage-collector / memory-management mode.
///
/// # Stability
///
/// The string returned by [`Display`](fmt::Display) is part of nimrod's
/// stable API. Changes are SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GcMode {
    /// `--mm:refc`: traditional reference-counting GC (Nim 1.x default).
    /// Indicated by the presence of legacy `NTI_` RTTI globals.
    Refc,
    /// `--mm:arc` or `--mm:orc`: deterministic ARC with optional cycle
    /// collector (Nim 2.x default). Indicated by `NTIv2_` globals.
    ArcOrc,
    /// Could not determine the GC mode (no RTTI symbols found, e.g.
    /// in a fully name binary).
    Unknown,
}

impl GcMode {
    /// Returns the stable string identifier for this mode.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Refc => "Refc",
            Self::ArcOrc => "ArcOrc",
            Self::Unknown => "Unknown",
        }
    }
}

impl fmt::Display for GcMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Best-effort Nim compiler-family hint.
///
/// Derived from RTTI generation plus the cycle-collector signal - there is no
/// deterministic version stamp in a Nim binary (`RESEARCH.md` §12), so this is
/// a heuristic, not a precise point-release.
///
/// # Stability
///
/// The string returned by [`Display`](fmt::Display) is part of nimrod's stable
/// API. Changes are SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NimVersionHint {
    /// Legacy `--mm:refc` build (Nim 1.x default, still available in 2.x).
    /// Signalled by V1 `NTI_` RTTI globals with no V2 globals.
    Nim1xRefc,
    /// Modern `--mm:arc` build (Nim 2.x). V2 RTTI present, no cycle collector.
    Nim2xArc,
    /// `--mm:atomicArc` build: ARC with atomic reference counts. Told apart
    /// from ARC by `lock`-prefixed reference-count updates in the code
    /// (x86-64 only; elsewhere such builds read as [`NimVersionHint::Nim2xArc`]).
    Nim2xAtomicArc,
    /// Modern `--mm:orc` build (Nim 2.x default). V2 RTTI present *and*
    /// cycle-collector symbols (`collectCycles`) present.
    Nim2xOrc,
    /// `--mm:yrc` build (Nim 2.4+, thread-safe ORC with a concurrent cycle
    /// collector). V2 RTTI plus the YRC runtime (`nimAsgnYrc`, `nimSinkYrc`,
    /// `yrcGcFenceEnter`, from `lib/system/yrc.nim`).
    Nim24Yrc,
    /// Could not determine (no RTTI globals - e.g. a fully name binary).
    Unknown,
}

impl NimVersionHint {
    /// Returns the stable string identifier for this hint.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Nim1xRefc => "Nim1xRefc",
            Self::Nim2xArc => "Nim2xArc",
            Self::Nim2xAtomicArc => "Nim2xAtomicArc",
            Self::Nim2xOrc => "Nim2xOrc",
            Self::Nim24Yrc => "Nim24Yrc",
            Self::Unknown => "Unknown",
        }
    }
}

impl fmt::Display for NimVersionHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Infers a best-effort Nim compiler-family hint.
///
/// - V2 RTTI + a YRC runtime symbol → [`NimVersionHint::Nim24Yrc`]
/// - V2 RTTI + a cycle-collector symbol (`collectCycles…`) → [`NimVersionHint::Nim2xOrc`]
/// - V2 RTTI without one → [`NimVersionHint::Nim2xArc`]
/// - V1 RTTI only → [`NimVersionHint::Nim1xRefc`]
/// - neither → [`NimVersionHint::Unknown`]
///
/// The ARC vs ORC split keys off the ORC cycle collector
/// (`collectCyclesBacon`, `registerCycle`, `unregisterCycle`, from
/// `lib/system/orc.nim`), and YRC off its own runtime. Without RTTI globals
/// (small `-d:danger` programs) those runtimes alone decide. Symbol
/// stripping (`--passL:-s`) removes them, so a name ORC build may be
/// reported as [`NimVersionHint::Nim2xArc`]. Nim 1.2 ARC builds still used
/// V1 RTTI and are reported as [`NimVersionHint::Nim1xRefc`]. The refc-vs-modern split is
/// robust regardless of stripping (it keys off the RTTI naming convention,
/// `RESEARCH.md` §3.4).
pub fn detect_compiler_version(
    container: &Container<'_>,
    matches: DetectionMatches,
) -> NimVersionHint {
    // The ARC-family runtime decides when present: Nim 1.2 ARC builds still
    // emit V1 RTTI, and small `-d:danger` programs keep no RTTI globals.
    let arc_family = gc_mode(matches) == GcMode::ArcOrc || has_arc_runtime(container);
    if arc_family || has_yrc_runtime(container) || has_cycle_collector(container) {
        // YRC also defines `collectCycles`; test for it first.
        if has_yrc_runtime(container) {
            NimVersionHint::Nim24Yrc
        } else if has_cycle_collector(container) {
            NimVersionHint::Nim2xOrc
        } else if has_atomic_refcounts(container) {
            NimVersionHint::Nim2xAtomicArc
        } else {
            NimVersionHint::Nim2xArc
        }
    } else if gc_mode(matches) == GcMode::Refc {
        NimVersionHint::Nim1xRefc
    } else {
        NimVersionHint::Unknown
    }
}

/// ARC/ORC/YRC object and string runtime (`lib/system/arc.nim`,
/// `strs_v2.nim`, `seqs_v2.nim`). Fixtures: in every ARC/ORC/YRC build of
/// Nim 1.2 - 2.4 and in no refc build.
const ARC_RUNTIME: &[&str] = &[
    "nimNewObj",
    "nimRawDispose",
    "nimDestroyAndDispose",
    "nimAsgnStrV2",
    "setLengthStrV2",
    "newSeqPayload",
];

/// Whether the code updates reference counts atomically (`--mm:atomicArc`):
/// x86-64 `lock add`/`lock sub` of the RC increment (8) on the header just
/// before the object, `f0 48|49 83 /0|/5 f8 08` (`-0x8(%reg)`). The
/// fixtures: 1 - 91 such instructions in every atomicArc build, none in any
/// ARC build.
fn has_atomic_refcounts(container: &Container<'_>) -> bool {
    if container.arch() != crate::container::Arch::Amd64 {
        return false;
    }
    container
        .sections()
        .iter()
        .filter(|s| s.kind == crate::container::SectionKind::Text)
        .any(|s| {
            s.data.windows(6).any(|w| {
                matches!(w, [0xf0, 0x48 | 0x49, 0x83, modrm, 0xf8, 0x08]
                    if modrm & 0xc0 == 0x40 && matches!((modrm >> 3) & 7, 0 | 5) && modrm & 7 != 4)
            })
        })
}

/// Returns `true` if the symbol table contains the ARC-family runtime.
fn has_arc_runtime(container: &Container<'_>) -> bool {
    container.symbols().iter().any(|s| {
        let name = s.name.as_ref();
        ARC_RUNTIME.contains(&name)
            || container
                .demangle(name)
                .is_some_and(|d| d.is_scheme_name() && ARC_RUNTIME.contains(&d.identifier.as_ref()))
    })
}

/// YRC runtime compilerprocs (`lib/system/yrc.nim`), exported unmangled.
const YRC_COMPILERPROCS: &[&str] = &["nimAsgnYrc", "nimSinkYrc"];
/// YRC runtime routines recognised by their demangled identifier.
const YRC_ROUTINES: &[&str] = &["yrcGcFenceEnter", "yrcGcFenceExit"];

/// Returns `true` if the symbol table contains a YRC runtime routine.
fn has_yrc_runtime(container: &Container<'_>) -> bool {
    container.symbols().iter().any(|s| {
        let name = s.name.as_ref();
        YRC_COMPILERPROCS.contains(&name)
            || container
                .demangle(name)
                .is_some_and(|d| YRC_ROUTINES.contains(&d.identifier.as_ref()))
    })
}

/// ORC cycle-collector routines (`lib/system/orc.nim`). Exact names: refc's
/// `gc.nim` defines a `collectCycles` of its own, so the bare name is not
/// evidence of ORC (fixtures: these three are in every ORC build and in no
/// refc or ARC build).
const ORC_ROUTINES: &[&str] = &["collectCyclesBacon", "registerCycle", "unregisterCycle"];

/// Returns `true` if the symbol table contains an ORC cycle-collector routine.
fn has_cycle_collector(container: &Container<'_>) -> bool {
    container.symbols().iter().any(|s| {
        let name = s.name.as_ref();
        ORC_ROUTINES.contains(&name)
            || container.demangle(name).is_some_and(|d| {
                d.is_scheme_name() && ORC_ROUTINES.contains(&d.identifier.as_ref())
            })
    })
}

/// Infers the GC mode from the detection report's RTTI flags.
///
/// - `NTIv2_` symbols → [`GcMode::ArcOrc`]
/// - `NTI_` symbols (without `NTIv2_`) → [`GcMode::Refc`]
/// - Neither → [`GcMode::Unknown`]
pub fn gc_mode(matches: DetectionMatches) -> GcMode {
    let has_v2 = matches.contains(DetectionMatches::NTIV2_SYMBOL);
    let has_legacy = matches.contains(DetectionMatches::NTI_LEGACY_SYMBOL);

    match (has_v2, has_legacy) {
        (true, _) => GcMode::ArcOrc,
        (false, true) => GcMode::Refc,
        _ => GcMode::Unknown,
    }
}

/// Attempts to detect the `--nimMainPrefix` from the symbol table.
///
/// Scans for a symbol matching `<prefix>NimMain` (exact name, no module
/// suffix). Returns the prefix (empty string for the default, non-empty
/// for custom prefixes), or `None` if `NimMain` was not found.
pub fn nim_main_prefix<'a>(container: &'a Container<'a>) -> Option<&'a str> {
    for sym in container.symbols() {
        let name = sym.name.as_ref();
        if name == "NimMain" {
            return Some("");
        }
        // Custom prefix `<prefix>NimMain`, which must not contain `__`
        // (which would indicate a normal mangled symbol).
        if let Some(prefix) = name.strip_suffix("NimMain")
            && !prefix.is_empty()
            && !name.contains("__")
        {
            // The prefix should be a valid identifier fragment.
            if prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Some(prefix);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiler_version_splits_arc_orc_via_cycle_collector() {
        use crate::container::{Arch, Container, Format, Symbol, SymbolKind};
        use std::borrow::Cow;

        let bytes = [0u8; 4];
        let orc_syms = vec![Symbol {
            name: Cow::Borrowed("collectCyclesBacon__system_u3313"),
            vm_addr: 0x1000,
            size: 0,
            kind: SymbolKind::Function,
        }];
        let orc = Container::from_parts(&bytes, Format::Elf, Arch::Amd64, 0, vec![], orc_syms);
        assert_eq!(
            detect_compiler_version(&orc, DetectionMatches::NTIV2_SYMBOL),
            NimVersionHint::Nim2xOrc
        );

        // Same V2 flags but no cycle collector → ARC.
        let arc = Container::from_parts(&bytes, Format::Elf, Arch::Amd64, 0, vec![], vec![]);
        assert_eq!(
            detect_compiler_version(&arc, DetectionMatches::NTIV2_SYMBOL),
            NimVersionHint::Nim2xArc
        );
        // V1 only → refc; nothing → unknown.
        assert_eq!(
            detect_compiler_version(&arc, DetectionMatches::NTI_LEGACY_SYMBOL),
            NimVersionHint::Nim1xRefc
        );
        assert_eq!(
            detect_compiler_version(&arc, DetectionMatches::EMPTY),
            NimVersionHint::Unknown
        );
    }

    #[test]
    fn compiler_version_detects_yrc_before_orc() {
        use crate::container::{Arch, Container, Format, Symbol, SymbolKind};
        use std::borrow::Cow;

        let func = |name: &'static str| Symbol {
            name: Cow::Borrowed(name),
            vm_addr: 0x1000,
            size: 0,
            kind: SymbolKind::Function,
        };
        let bytes = [0u8; 4];
        // YRC defines `collectCycles` too; its own runtime decides.
        for marker in ["nimAsgnYrc", "nimSinkYrc", "yrcGcFenceEnter_u0__system"] {
            let syms = vec![func("registerCycle_u0__system"), func(marker)];
            let c = Container::from_parts(&bytes, Format::Elf, Arch::Amd64, 0, vec![], syms);
            assert_eq!(
                detect_compiler_version(&c, DetectionMatches::NTIV2_SYMBOL),
                NimVersionHint::Nim24Yrc,
                "{marker}"
            );
        }
        // A user proc merely named like the runtime does not count.
        let syms = vec![
            func("registerCycle_u0__system"),
            func("nimAsgnYrcHelper_u0__app"),
        ];
        let c = Container::from_parts(&bytes, Format::Elf, Arch::Amd64, 0, vec![], syms);
        assert_eq!(
            detect_compiler_version(&c, DetectionMatches::NTIV2_SYMBOL),
            NimVersionHint::Nim2xOrc
        );
    }

    #[test]
    fn collector_runtime_decides_without_rtti() {
        use crate::container::{Arch, Container, Format, Symbol, SymbolKind};
        use std::borrow::Cow;

        let func = |name: &'static str| Symbol {
            name: Cow::Borrowed(name),
            vm_addr: 0x1000,
            size: 0,
            kind: SymbolKind::Function,
        };
        let bytes = [0u8; 4];
        let hint = |syms| {
            let c = Container::from_parts(&bytes, Format::Elf, Arch::Amd64, 0, vec![], syms);
            detect_compiler_version(&c, DetectionMatches::EMPTY)
        };
        assert_eq!(
            hint(vec![func("registerCycle_u0__system")]),
            NimVersionHint::Nim2xOrc
        );
        assert_eq!(hint(vec![func("nimAsgnYrc")]), NimVersionHint::Nim24Yrc);
        // refc's own `collectCycles` is not ORC evidence.
        assert_eq!(
            hint(vec![func("collectCycles__XHio9cMpnLoH7GyCj1Z9besg_3")]),
            NimVersionHint::Unknown
        );
    }

    #[test]
    fn arc_runtime_overrides_v1_rtti() {
        use crate::container::{Arch, Container, Format, Symbol, SymbolKind};
        use std::borrow::Cow;

        let func = |name: &'static str| Symbol {
            name: Cow::Borrowed(name),
            vm_addr: 0x1000,
            size: 0,
            kind: SymbolKind::Function,
        };
        let bytes = [0u8; 4];
        let hint = |syms, matches| {
            let c = Container::from_parts(&bytes, Format::Elf, Arch::Amd64, 0, vec![], syms);
            detect_compiler_version(&c, matches)
        };
        // Nim 1.2 ARC: V1 RTTI plus the ARC runtime (signature-hash names).
        let arc12 = vec![func("nimNewObj"), func("setLengthStrV2__abc")];
        assert_eq!(
            hint(arc12, DetectionMatches::NTI_LEGACY_SYMBOL),
            NimVersionHint::Nim2xArc
        );
        // refc: V1 RTTI and its own collector only.
        let refc = vec![func("collectZCT__XHio9cMpnLoH7GyCj1Z9besg"), func("addZCT")];
        assert_eq!(
            hint(refc, DetectionMatches::NTI_LEGACY_SYMBOL),
            NimVersionHint::Nim1xRefc
        );
        // No RTTI at all: the ARC runtime alone.
        assert_eq!(
            hint(vec![func("nimRawDispose")], DetectionMatches::EMPTY),
            NimVersionHint::Nim2xArc
        );
    }

    #[test]
    fn atomic_refcounts_mark_atomic_arc() {
        use crate::container::{Arch, Container, Format, Section, SectionKind, Symbol, SymbolKind};
        use std::borrow::Cow;

        let hint = |text: &'static [u8]| {
            let sections = vec![Section {
                name: ".text".into(),
                kind: SectionKind::Text,
                vm_addr: 0x1000,
                vm_size: text.len() as u64,
                data: text,
            }];
            let syms = vec![Symbol {
                name: Cow::Borrowed("nimRawDispose"),
                vm_addr: 0x1000,
                size: 0,
                kind: SymbolKind::Function,
            }];
            let c = Container::from_parts(text, Format::Elf, Arch::Amd64, 0, sections, syms);
            detect_compiler_version(&c, DetectionMatches::NTIV2_SYMBOL)
        };
        // lock addq $0x8,-0x8(%rax)
        assert_eq!(
            hint(&[0x90, 0xf0, 0x48, 0x83, 0x40, 0xf8, 0x08, 0xc3]),
            NimVersionHint::Nim2xAtomicArc
        );
        // addq $0x8,-0x8(%rax) without lock: plain ARC
        assert_eq!(
            hint(&[0x90, 0x48, 0x83, 0x40, 0xf8, 0x08, 0xc3]),
            NimVersionHint::Nim2xArc
        );
    }

    #[test]
    fn gc_mode_from_flags() {
        assert_eq!(gc_mode(DetectionMatches::NTIV2_SYMBOL), GcMode::ArcOrc);
        assert_eq!(gc_mode(DetectionMatches::NTI_LEGACY_SYMBOL), GcMode::Refc);
        assert_eq!(gc_mode(DetectionMatches::EMPTY), GcMode::Unknown);
        // Both set: V2 wins (ARC/ORC is the authoritative modern mode).
        assert_eq!(
            gc_mode(DetectionMatches::NTIV2_SYMBOL | DetectionMatches::NTI_LEGACY_SYMBOL),
            GcMode::ArcOrc
        );
    }
}
