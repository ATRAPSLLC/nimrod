//! Parse and inspect Nim-compiled native binaries.
//!
//! This crate provides a pure-Rust parser and forensic-artifact extractor for
//! binaries produced by the Nim compiler via its C, C++, or Objective-C
//! backends. A Nim-compiled program is a normal ELF, PE, or Mach-O executable:
//! there is no Nim-specific container. The crate recovers Nim **runtime
//! artifacts** left inside an otherwise-ordinary native binary.
//!
//! # What it extracts
//!
//! | Artifact | Method | Notes |
//! |----------|--------|-------|
//! | Detection verdict | [`NimBinary::is_nim`] | 11 independent probes, on stripped binaries too |
//! | Format / arch / width | [`NimBinary::format`], [`NimBinary::arch`], [`NimBinary::bitness`] | ELF, PE, Mach-O (fat: first slice); byte order and width from the header |
//! | Compiler and memory manager | [`NimBinary::nim_version`], [`NimBinary::gc_mode`], [`NimBinary::mangle_scheme`] | refc, ARC, atomicArc (x86-64), ORC, YRC; symbol layout dates the compiler (1.0 - 1.4, 1.6 - 2.3, 2.4+) |
//! | Build profile | [`NimBinary::build_profile`] | Exception model, stack traces, runtime checks, library |
//! | Entry shims | [`NimBinary::entry_shims`] | `NimMain`, `PreMain`, etc.; `--nimMainPrefix` via [`NimBinary::nim_main_prefix`] |
//! | Init functions | [`NimBinary::init_functions`] | With decoded module paths |
//! | Module map | [`NimBinary::module_map`] | Per module: functions, sizes, init VAs, leaked paths; Nim 1.x functions grouped by emitting C file |
//! | RTTI globals | [`NimBinary::rtti_symbols`] | V1 (`TNimType`) and V2 (`TNimTypeV2`) |
//! | Type graph | [`NimBinary::types`] | Members, offsets, sizes, inheritance, enum values, hooks; startup-filled RTTI recovered by evaluating `DatInit000` (x86-64, AArch64) |
//! | Procs | [`NimBinary::procs`] | Every Nim function by VA: name, module, role (user proc, hook, GC marker, finalizer, lambda, async iterator / callback, init, shim) |
//! | Relations | [`NimBinary::relations`] | Type-to-hook edges the runtime calls through RTTI, the startup call structure (`NimMain` to the module inits), async callback to iterator, each with its provenance |
//! | String literals | [`NimBinary::string_literals_v1`], [`NimBinary::string_literals_v2`], [`NimBinary::string_literals_v3`] | refc `NimStringDesc`, ARC/ORC `NIM_STRLIT_FLAG` payloads, Nim 2.4 `--strings:sso` (also folded into immediates) |
//! | Stack-trace metadata | [`NimBinary::stack_trace`] | Proc names + `.nim` file paths (build-host leaks) |
//! | Nimble path leaks | [`NimBinary::nimble_paths`] | Package name, version, hash, username, OS |
//! | Exception types | [`NimBinary::exception_types`] | `*Error`, `*Defect` cstrings in rodata |
//! | Raise sites | [`NimBinary::raise_sites`] | (type, proc, file, line) per raise via instruction analysis; x86-64 (System V and Microsoft ABI) and AArch64 |
//! | Imports | [`Container::imports`] | Imported symbols with their library (PE, Mach-O) |
//! | Demangled symbols | [`demangle::symbol::parse`] | Identifier, module, disambiguator, layout |
//!
//! # Quick start
//!
//! ```no_run
//! use nimrod::NimBinary;
//!
//! let data = std::fs::read("sample").unwrap();
//! let bin = NimBinary::from_bytes(&data).unwrap();
//!
//! if !bin.is_nim() {
//!     eprintln!("not a Nim binary");
//!     return;
//! }
//!
//! // Detection and classification
//! println!("format: {:?}, gc: {:?}", bin.format(), bin.gc_mode());
//!
//! // Module map: which Nim modules are compiled in, with every function
//! let mmap = bin.module_map();
//! for (name, info) in &mmap.modules {
//!     println!("{name}: {} functions", info.symbol_count());
//!     for sym in &info.symbols {
//!         // sym.name    = demangled Nim identifier
//!         // sym.address = VA (start disassembling here)
//!         // sym.size    = byte count (ELF; 0 on Mach-O/PE)
//!         let _ = (sym.name.as_str(), sym.address, sym.size);
//!     }
//! }
//!
//! // Raise sites: exception type + enclosing function + source location
//! for rs in bin.raise_sites() {
//!     let _ = (
//!         rs.exception_type.as_deref(),   // "ValueError"
//!         rs.enclosing_function.as_deref(), // "parseHexInt__strutils_u1234"
//!         rs.file.as_deref(),              // "strutils.nim"
//!         rs.line,                         // Some(1242)
//!     );
//! }
//! ```
//!
//! # Design
//!
//! - **Pure Rust**, `#![deny(unsafe_code)]`.
//! - **Cross-format**: ELF, PE, Mach-O via [`goblin`](https://docs.rs/goblin).
//! - **Zero-copy** where possible: borrows from the input byte slice.
//! - **Forensic-oriented**: prioritises attribution-grade artifacts (build-host
//!   paths, package refs, exception locations) over pretty-printing.
//!
//! The format-level research backing every probe and struct layout is
//! documented in `RESEARCH.md` at the crate root.
//!
//! # Robustness contract
//!
//! nimrod parses adversarial input, so every public artifact iterator obeys a
//! uniform contract:
//!
//! - **Never panics** on malformed input. The crate denies `unwrap`, `expect`,
//!   `panic`, unchecked indexing, and unchecked arithmetic in library code
//!   (see the `[lints]` table in `Cargo.toml`).
//! - **Returns empty on missing data.** A walker whose artifact is absent (no
//!   V2 strings in a refc build, no raise sites in a binary that never raises)
//!   returns an empty slice, not an error.
//! - **Skips malformed records individually.** A single undecodable record
//!   (e.g. an RTTI global left zero in the file on an architecture whose
//!   startup code is not evaluated) is dropped or degraded to a name-only
//!   entry; the rest of the scan still completes. Name-only RTTI entries are
//!   flagged by [`NimType::is_readable`].
//! - **Bounded work.** Loops over input-controlled counts (startup-code
//!   instructions, RTTI node trees, DWARF units) run under fixed budgets.
//!
//! # Address space
//!
//! Every address-bearing field returned by this crate is a **virtual address**
//! in the input image's load space, never a file offset. Convert to a
//! disassembler-relative RVA with the `*_rva` helpers on [`NimBinary`], with
//! [`Container::va_to_rva`], or with [`va_to_i64`] for signed-integer storage.
//!
//! # Thread safety
//!
//! [`NimBinary`] is `Send + Sync` (enforced by a compile-time assertion), so it
//! can be shared across threads or held across `.await` points. Its scan caches
//! use [`std::sync::OnceLock`].

// `missing_docs`, `unsafe_code`, the clippy panic-prevention set
// (`unwrap_used`, `expect_used`, `panic`, `arithmetic_side_effects`,
// `indexing_slicing`) and `missing_docs_in_private_items` are declared in
// `Cargo.toml` under `[lints]` so they enforce on every build regardless of
// the consuming workspace.
// nimrod is used in malware-analysis pipelines where every input byte
// is adversarial and the parser must not panic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )
)]

pub mod addr;
pub mod container;
pub mod demangle;
pub mod detect;
pub mod error;
pub mod inits;
pub mod metadata;
pub mod modules;
pub mod paths;
pub mod procs;
pub mod profile;
pub mod raises;
pub mod relations;
pub mod rtti;
pub mod shims;
pub mod sites;
pub mod stacktrace;
pub mod strings;
pub mod types;

mod binary;
mod emu;
mod isa;
mod util;

pub use addr::va_to_i64;
pub use binary::NimBinary;
pub use container::{Arch, Container, Format, Import, Section, SectionKind, Symbol, SymbolKind};
pub use demangle::symbol::{Demangled, MangleScheme};
pub use detect::{DetectionMatches, DetectionReport};
pub use error::{Error, Result};
pub use inits::{InitFunction, InitKind};
pub use metadata::{GcMode, NimVersionHint};
pub use modules::{ModuleInfo, ModuleMap, ModuleSymbol};
pub use paths::{NimblePath, PathOs};
pub use procs::{AsyncPart, NimProc, ProcRole};
pub use profile::{BuildProfile, ExceptionModel};
pub use raises::ExceptionRef;
pub use relations::{AsyncLink, Provenance, Relation, RelationKind};
pub use rtti::symbols::{RttiSymbol, RttiVersion};
pub use rtti::v1::{NimKind, NimTypeFlag};
pub use shims::{EntryShim, ShimKind};
pub use sites::RaiseSite;
pub use stacktrace::{FilePath, StackTraceHarvest};
pub use strings::v1::StringLiteralV1;
pub use strings::v2::StringLiteral;
pub use strings::v3::{SsoLiteralKind, StringLiteralV3};
pub use types::{CodeRef, EnumValue, HookKind, NimType, TypeField, TypeFlags, TypeRef, TypeShape};
