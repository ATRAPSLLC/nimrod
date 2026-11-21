# Changelog

All notable changes to `nimrod` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-11-20

Reads every Nim release from 1.0 to 2.4 (all four symbol layouts, SSO
strings, YRC and atomicArc), recovers refc and pre-2.0 type information by
evaluating the startup code, serves a Nim proc inventory with the type-hook,
startup and async relations for call-graph tools, and reads big-endian and
32-bit images. Checked against a committed fixture matrix of 1155 binaries
built by ten Nim releases. Breaking changes are marked **Breaking**.

### Added

- **Proc inventory: `NimBinary::procs()`.** Every function nimrod identifies as
  Nim code, one `NimProc` per address: name, module (the `ModuleMap` key),
  size, and a `ProcRole` saying what it is for Nim: a user proc, a hook the
  runtime calls for a type (`HookKind`: `=destroy`, `=copy`, `=sink`, `=trace`,
  `=wasMoved`, `=dup`, `=dispose`, `=deepCopy`, GC marker, finalizer), a lambda,
  a part of an async proc (`AsyncPart`: the closure iterator, the
  `NimAsyncContinue` callback), a module init or an entry shim. Roles come from
  the symbol names in all four layouts and from the RTTI hook slots, which also
  add hook targets without a symbol and name finalizers. Itanium-named hooks
  carry the type they serve (`NimProc::hook_type`). `NimBinary::proc_rva`
  converts an address. Replaces `code_entrypoints()` (see Removed).
- **Nim relations: `NimBinary::relations()`.** Edges Nim metadata records and
  machine code does not show as direct calls, each with its `Provenance`
  (`Rtti`, `Emulated`, `SymbolName`, `Codegen`):
  - type to hook (`RelationKind::Hook`), from the RTTI slots and, for refc GC
    markers, from the name (`Marker_<type>__<hash>` shares the hash of the
    type's `NTI` symbol), which also covers builds whose RTTI is not read
    (big-endian, i686). On the fixtures the 4039 markers both sources give
    agree, with no contradiction;
  - the startup call structure (`RelationKind::StartupCall`): `NimMain` to
    `PreMain` and `NimMainInner`, `PreMain` to every `DatInit000`, the system
    `Init000` and `PreMainInner`, `PreMainInner` to the other `Init000`s,
    `NimMainInner` to `NimMainModule`, the same in every release from 1.0 to
    2.4 (`cgen.nim`). The order of a caller's callees is recorded only in
    code and not given. Against `objdump` on the 771 linux x86-64 fixtures,
    every init function the startup code references has an edge; 248 edges
    name a function whose call the C compiler inlined while keeping it;
  - async procs (`RelationKind::Async`): the proc to its closure iterator
    (`AsyncLink::Body`) and the `NimAsyncContinue` callback to the iterator it
    resumes through the closure (`AsyncLink::Resume`), by name, in every
    release (`fooIter` before 2.0, `foo (Async)` after). Method dispatch is not
    covered: dispatcher and methods share a name and the RTTI has no method
    table.
- **Type recovery from the startup code.** refc builds of every Nim version, and
  ARC/ORC builds of Nim 1.4 - 1.6, leave their RTTI objects (`TNimType` /
  `TNimNode`, pre-2.0 `TNimTypeV2`) zero in the file: each module's
  `DatInit000` fills them at startup. A small emulator for those functions
  (x86-64 and AArch64; straight-line stores, SSE/q-register moves, loops,
  `rep movs`/`memcpy`, with per-function and per-binary step budgets, a
  write-size cap and writes limited to the image) recovers them, and the type
  graph reads the result. V1 types went from 0% to 100% readable on the
  fixtures (Linux, mingw and macOS refc; 1.4/1.6 ARC/ORC V2 likewise), with
  members and enum values. Checked against runtime memory dumps of every Linux
  x64 fixture (gdb, `tests/build_fixtures/oracle/`): 9741 types identical, none
  different; arm64 and macOS agree with the x64 runtime types of the same
  programs. Shared libraries reach their type objects through GOT slots the
  file leaves 0; `Container::pointer_fixups()` (ELF `RELATIVE`, `GLOB_DAT` and
  absolute relocations, x86-64 and AArch64) gives the emulator the loader's
  values. `CodeRef::emulated` marks a hook pointer written by this code rather
  than stored in the file, and `NimType::hooks()` lists a type's hook slots
  with their `HookKind`.
- **Every Nim symbol layout.** `demangle::symbol` parses all four layouts the C
  backend has used, reported as `MangleScheme`:
  - `SigHash` (Nim 1.0 - 1.4): `<ident>__<sighash>[_<n>][<module>]`, a
    22-symbol base64 signature hash and no module. Previously dropped, so 1.x
    binaries had no proc recovery (`stdlib_mix` on 1.0.10 / 1.2.18 / 1.4.8:
    0 procs, now 126 / 130 / 131). The literal temporaries `TM__<hash>_<n>` are
    excluded.
  - `Nim16` (1.6 - 2.3): `<ident>__<module>_u<itemId>`, as before.
  - `Nim24` (2.4+): `<ident>_u<disamb>__<module>` (`_c<n>` for
    incremental-compilation symbols). Previously the disambiguator stayed on
    the identifier (`abs_u0`) and every 2.4 proc was dropped (official nim 2.4.2
    compiler binary: 210 procs and 117 modules, now 9577 and 262).
  - `Itanium` (1.6+ debug-info builds, `--debugger:native` / `-g`):
    `_ZN<owner><name>E<params>`, with parameter types decoded into
    `Demangled::params` (`["var[string]", "int64"]`). Previously not parsed
    (1.6.20 `stdlib_mix` debug-info build: 0 procs, now 136).

  New API: `MangleScheme` (with `compiler_range()`), `dominant_scheme`
  (per-binary vote), `Demangled::is_scheme_name()`, `Container::mangle_scheme()`
  / `Container::demangle()`, and `NimBinary::mangle_scheme()`, which also dates
  a binary to a compiler range. Compiler clone suffixes (`.cold`, `.part.N`,
  `.constprop.N`, `.isra.N`, `.lto_priv.N`) are split off before parsing and
  kept in `Demangled::clone_suffix`.
- **`--strings:sso` string literals (Nim 2.4).** `strings::v3` and
  `NimBinary::string_literals_v3()` recover literals from the 2.4 small-string
  layout, which has no `NIM_STRLIT_FLAG` payloads: inline `SmallString`
  constants (up to 14 bytes on 64-bit, e.g. `cmd.exe`, `powershell.exe`),
  static long blocks, and constants GCC folds into instruction immediates
  (x86-64 `movabs`, AArch64 `movz`/`movk`, `SsoLiteralKind::Immediate`), the
  only copy release builds keep. Reports nothing unless the binary shows SSO
  structure; no hits on any non-SSO fixture. Inline literals are decoded on
  little-endian 64-bit targets only.
- **Build profile.** `NimBinary::build_profile()` (`BuildProfile`,
  `ExceptionModel`) infers the exception model (goto / setjmp / C++), whether
  stack traces and runtime checks were compiled in, and whether the image is a
  library. Each field reports unknown rather than guessing: right on every
  fixture, and on stripped copies no field is wrong.
- **Memory managers.** `NimVersionHint::Nim2xAtomicArc` (`--mm:atomicArc`, by
  its `lock`-prefixed inlined reference counting on x86-64; other
  architectures read as ARC) and `NimVersionHint::Nim24Yrc` (`--mm:yrc`, by its
  runtime: `nimAsgnYrc`, `nimSinkYrc`, `yrcGcFenceEnter`). **Breaking** for
  exhaustive matches on `NimVersionHint`.
- **Big-endian and 32-bit images.** `Container::is_little_endian()` and
  `Container::pointer_bits()` (from the ELF header, PE32 / PE32+, the Mach-O
  magic) drive every data reader: string literals, RTTI and type display
  tokens read words in the image's byte order and width. Previously all read
  little-endian with the width guessed from `Arch`. PPC64 and MIPS builds now
  recover their literals and ORC types. Still little-endian only: the SSO
  scanner and the startup-code evaluation. `Arch::Mips` and `Arch::Mips64` are
  new; 32-bit RISC-V maps to `Arch::Riscv32`.
- **Type expressions.** `NimType::type_expr` and
  `rtti::symbols::decode_type_fragment` decode V1 type fragments back into Nim
  type expressions (`seqLintT` -> `seq[int]`, `arrayL48OO51_stringT` ->
  `array[0..3, string]`); `TypeRef::name` falls back to them. Letter case and
  spaces are not recoverable; Nim 1.0 - 1.4 V1 RTTI names have no fragment.
- **Source files of symbols.** `Container::symbol_source_file(i)` (ELF: the
  `STT_FILE` a local symbol is grouped under, else the DWARF compile unit whose
  `.debug_aranges` cover the function, read by a small bounds-checked reader;
  PE: the COFF `.file` record) and `ModuleSymbol::from_source_file`: Nim 1.0 -
  1.4 names carry no module, so the module map groups their functions by the C
  file that emitted them (the emitting module, which for inline procs and
  generic instances is the one that uses them). On 1.0 - 1.4 `stdlib_mix`:
  126 - 134 functions in 8 - 9 modules, against none before.
- `Container::imports()` (`Import`: PE import table, Mach-O binds, ELF
  undefined dynamic symbols) and `Container::is_library()`.
- `Container::from_parts(...)` builds a container from already-parsed sections
  and symbols (another loader, a memory dump, synthetic test data), with
  `with_little_endian`, `with_imports` and `with_library` builders.
- `RaiseSite::enclosing_va`: the enclosing function's address, its key in
  `procs()`.
- **Fixture matrix and cross-version tests.** `tests/build_fixtures/` builds
  seven fixture programs with ten Nim releases (1.0.10 - 2.4.2) in Docker, one
  image per release with the official tarball checked against a pinned
  checksum, for Linux x86-64, AArch64, PPC64 and MIPS and mingw x86-64 and
  i686, across refc / ARC / ORC / YRC / atomicArc, debug / release / danger,
  `--strings:sso`, debug info, setjmp exceptions and `--app:lib`: 1155
  binaries, committed under `tests/fixtures/nim-<version>/` (excluded from the
  crate package). `ONLY_SOURCES` builds one program without rebuilding the
  others. `tests/versions.rs` checks every binary for detection, symbol layout,
  procs, version hint, build profile, literals, types, relations and
  cross-platform agreement. A gdb runtime oracle (`oracle/`) dumps the real
  type objects for comparison.

### Changed

- **Breaking:** `demangle::symbol::parse(symbol, prefer)` takes the layout to
  prefer for names that fit several (`None` without binary context breaks ties
  toward `Nim16`), and `rtti::v1::read(container, va, layout)` takes the
  `TNimType` layout from `detect_layout`.
- **Breaking:** `Demangled::item_id` is now `Demangled::disambiguator`;
  `Demangled::module` is `Option<&str>` (signature-hash names carry no module);
  `ModuleSymbol::item_id` is now `ModuleSymbol::disambiguator: Option<u64>`.
  `Demangled` gained `scheme`, `signature_hash`, `params`, `backend_minted` and
  `clone_suffix`.
- **Breaking:** public structs are exhaustive and gained fields (`CodeRef`,
  `NimType`, `RaiseSite`, `ModuleSymbol`, `Demangled`), so struct literals need
  updating. `Error` is no longer `#[non_exhaustive]`: matches need no wildcard
  arm, and a new variant or field is a breaking change.
- `NimBinary::bitness()` and `is_64bit()` come from the container header, so
  they are known for `Arch::Other` too; `bitness()` is always `Some`.
- Module map keys are unified: init-function paths, stack-trace paths and
  Itanium owners are matched against the compiler's unique module names from
  the symbol table, so one module no longer appears under several keys
  (`strutils` and `pureZstrutils`; on the nim 2.4.2 compiler binary 256 entries
  become 232, with the same symbols and paths attributed). Nim 1.x keys follow
  its own naming (`stdlib_io`).
- Every item, private ones included, is documented, and the
  `missing_docs_in_private_items` lint keeps it so. Module headers describe the
  current behaviour, limits and evidence.
- Internals consolidated without output changes: one AArch64 decoder and one
  x86-64 calling-convention table shared by the raise-site scanner, the SSO
  immediate scanner and the emulator; one `Container::section_at` for the rule
  that address lookups skip non-program sections; the endian-aware
  `DataLayout` reader; one string scanner per layout and one cstring walker.
  New helpers `Section::contains`, `SectionKind::is_data`,
  `Symbol::is_defined_function`.
- The binary fuzz target also runs `types` (with the startup-code
  evaluation), `string_literals_v3`, `procs`, `relations`, `build_profile`,
  `nim_version` and `mangle_scheme`.
- Bumped `memchr` to 2.8.3, the `proptest` dev-dependency to 1.12.0 and the
  fuzz crate's `libfuzzer-sys` to 0.4.13; transitive dependencies refreshed.
  `goblin` 0.10.7 is the latest release. MSRV is unchanged at 1.88.

### Removed

- **Breaking:** `NimBinary::code_entrypoints()`, `CodeEntrypoint` and
  `EntrypointKind`, replaced by `NimBinary::procs()`, `NimProc` and `ProcRole`:
  `EntryShim`, `ModuleInit` and `ModuleDatInit` are `ProcRole::EntryShim` and
  `ProcRole::Init`, `ProcSymbol` and `EnclosingFunction` are `ProcRole::User`
  (or the role the name gives), `RttiDestructor` and `RttiTraceImpl` are
  `ProcRole::Hook`. A proc no longer loses its hook role to its symbol.

### Fixed

- **32-bit Windows (i686) builds were barely read.** Their C-level names carry
  the Microsoft decoration (`_NimMain`, fastcall `@name@N` for every Nim proc),
  so init functions, RTTI symbols and the version hint were not found. The PE
  backend undecorates i386 names at the source, as the Mach-O backend strips
  its `_`, and the consumer-side stripping is gone. i686 builds now read like
  their x86-64 builds (same version hint, shims, init functions, RTTI symbols
  from 1.4 on, and modules).
- **A symbol in two symbol tables was listed twice.** ELF repeats exported
  `.symtab` symbols in `.dynsym`, and PE lists exports beside the COFF table,
  so unstripped executables listed `NimMain` twice in `entry_shims()` and a
  shared library with exported RTTI had each type twice. Each backend lists a
  symbol once, keeping the entry that knows its source file.
- **Fat (universal) Mach-O files read every section from the wrong place**: the
  first slice is now parsed on its own bytes, and a fat file reads exactly like
  its slice.
- **Raise sites, rewritten for x86-64 and extended on AArch64.** PE uses the
  Microsoft x64 convention (`rdx, r8, r9`, line at `[rsp + 0x20]`; with System
  V registers 0 of 524 mingw sites had a type, now 513 do, each with its line);
  tail calls to `raiseExceptionEx` are scanned (1764 more sites); argument
  registers are tracked over a 256-byte window, with calls clobbering the
  caller-saved set; a recovered exception type must be a Nim identifier.
  Across the fixtures: 2308 types, 1613 files, 910 lines and 571 proc names
  gained, 291 wrong values corrected. Both `raise` statements of a proc can
  merge into one tail jump, leaving only one type recoverable statically.
- **Legacy RTTI layouts.** Nim 1.0 and 1.2 have no `align` field in
  `TNimType`, so every later field was read 8 bytes off; the layout is now
  detected per binary (`rtti::v1::V1Layout`, `detect_layout`), including Nim
  1.2 ARC's own type-info struct under the same `NTI` names
  (`V1Layout::Nim12Arc`), and objects that fit no layout are rejected.
- `TNimNode` walking: enum value lists were skipped, so no enum had values; a
  variant's discriminator field was dropped and branches shared by several
  discriminant values were listed repeatedly. A 2.4 sum type's hidden
  discriminator appears as `` `kind ``. Anonymous V1 types (`NTI__<hash>_`)
  no longer report the hash as their `type_fragment`.
- Memory-manager detection: Nim 1.2 ARC builds (V1 RTTI) read as ARC, not
  refc, and `gc_mode()` agrees with `nim_version()`; ORC is detected by
  ORC-only routines (`collectCyclesBacon`, `registerCycle`) instead of any
  `collectCycles`, which refc also defines, and without RTTI globals (small
  `-d:danger` ORC programs were `Unknown`). The hint is now right for every
  fixture. The per-binary layout vote ignores refc's `Marker_` procs, which
  every version names in the signature-hash style.
- **String literals.** A refc V1 literal also matched the V2 payload shape, so
  `string_literals_v2()` repeated every V1 literal in refc builds, and zero
  padding before an empty V2 payload read as an empty V1 literal. The `double`
  `2.0` (`0x4000_0000_0000_0000`, an empty 64-bit payload's `cap` word) read as
  an empty V2 literal; a payload's zero tail padding is now required (75 float
  constants on the fixtures, no real literal lost).
- **Sections.** Sections that are not loaded are no longer scanned or used for
  address lookups: ELF sections without `SHF_ALLOC` (`.debug_*`, `.comment`),
  PE `DISCARDABLE` sections, and ELF thread-local templates (`.tdata`/`.tbss`,
  which overlap `.data`/`.bss`). Debug-info builds had fed their DWARF strings
  to every data scan, and `.debug_*` sections at address 0 shadowed every low
  address. ELF `.data.rel.ro` is classified as read-only data (RELRO), where
  constant pointer data such as SSO literal arrays lives. Address-to-offset
  mapping requires a section's data to lie inside the container's bytes.
- **Stack-trace paths.** A `.nim`-terminated cstring is accepted only when its
  basename is a Nim identifier, dropping literals that merely end in `.nim`;
  basenames glued onto preceding unterminated data are recovered when the
  symbol table proves the module is present; non-ASCII directories, UNC and
  `C:/` paths are handled. Module map: a bare `.nim` no longer attaches to an
  arbitrary module, and paths match init paths on whole components.
- 1.6 - 2.3 names whose `_u<digits>` is followed by anything other than an HCR
  `_<signature>` are no longer accepted as an id (`foo__bar_u12x` is the bare
  module `bar_u12x`).
- A PE COFF symbol naming a string-table offset below 4 panicked with an
  arithmetic overflow (goblin's `Symbol::name_offset`); the backend reads such
  references itself. Found by the fuzzer.
- The startup-code evaluator follows the image's calling convention for
  `memcpy` / `memset` (`rcx`, `rdx`, `r8` on PE).
- Fixture builds: the cross compilers are named explicitly (Nim 1.x and 2.2.14
  had silently built the AArch64 fixtures as x86-64), the nimcache is per
  platform and binary (a shared cache linked one target's objects into
  another's), and `nim -v | head -1` no longer aborts the build under
  `pipefail`.

## [0.3.1] - 2026-08-09

### Changed

- Added the missing `LICENSE` file. `Cargo.toml` has declared `license = "Apache-2.0"`
  since the first release, but no license text was ever shipped with the crate.
- Recorded ATRAPS LLC as copyright holder and added a `NOTICE` file. No functional change.
- Dropped the deprecated `authors` field and repointed `repository` at the organisation.
- Refreshed transitive dependencies (`cargo update`); no direct dependency changed version.
- Publishing now uses crates.io trusted publishing instead of a stored registry token.

## [0.3.0] - 2026-06-17

Type intelligence and API maturity. The headline is a cross-linked **type
graph** that surfaces RTTI data (members, offsets, sizes, layout,
inheritance, enum values, destructors) which 0.2.0 parsed internally but
never exposed on the facade.

### Added

- **`types` module + `NimBinary::types()`** — the full Nim type graph
  recovered from V1 (`TNimType`) and V2 (`TNimTypeV2`) RTTI. Each
  `NimType` merges the RTTI symbol with parsed struct fields and resolves
  raw pointers into cross-references: member field types and parent
  (inheritance) types as `TypeRef`, and destructor / trace / finalizer /
  marker / deepcopy procs as `CodeRef` (demangled function + module). New
  public types: `NimType`, `TypeField`, `EnumValue`, `TypeRef`, `CodeRef`,
  `TypeFlags`, `TypeShape`. Accessors `type_at(va)`, `object_types()`,
  `enum_types()`, and `type_rva()`.
  - V2 **inheritance chain** decoded from the `display` class-token array
    (`depth + 1` tokens, RESEARCH.md §3.2), with V2 parents linked through it.
  - V1 **enum values** (`name`, `ordinal`) recovered from the `TNimNode`
    slots, distinct from struct fields.
  - V2 → V1 **field bridge**: a non-nil `typeInfoV1` backpointer is followed
    to import member names for ARC/ORC objects lacking `nimTypeNames`.
  - Non-file-backed RTTI globals (Mach-O `__DATA,__common`, §3.6) degrade to
    name-only entries (`is_readable() == false`) instead of being dropped.
- **`entrypoints` module + `NimBinary::code_entrypoints()`** — one
  deduplicated, VA-sorted stream of every labelled code address (entry shims,
  module inits, demangled procs, raise-enclosing functions, RTTI destructor /
  trace procs), tagged by `EntrypointKind`.
- **`NimBinary::nim_version()`** → `NimVersionHint` (`Nim1xRefc` / `Nim2xArc`
  / `Nim2xOrc` / `Unknown`), splitting ARC vs ORC by the presence of the ORC
  cycle collector (`collectCycles`). Heuristic; see rustdoc for limits
  (stripped ORC builds report as ARC).
- **Ergonomics**: `Format::is_elf()/is_pe()/is_macho()`; `Arch::bits()` and
  `Arch::is_64bit()`; `NimBinary::bitness()/is_64bit()`;
  `DetectionMatches::bits()/from_bits()/from_bits_truncate()`; `as_str()` on
  every public discriminator enum (`Format`, `Arch`, `GcMode`, `ShimKind`,
  `PathOs`, `NimKind`, `RttiVersion`, plus the new `TypeShape`,
  `EntrypointKind`, `NimVersionHint`).
- Compile-time `Send + Sync` guarantee on `NimBinary`, plus a documented
  **robustness contract** (never panics, empty on missing, skip-per-record)
  and address-space contract in the crate docs.

### Changed

- `examples/dump.rs` now prints the full type graph (members, offsets, enum
  values, inheritance, resolved destructors), the code-entrypoint kind
  histogram, and the Nim version hint.

## [0.2.0] - 2026-05-04

Public-API hardening, RVA helpers, and scan caching. **Breaking
release** under [Cargo SemVer for 0.x][cargo-0x] — every breaking
change in a `0.x.y` crate is a `0.x` minor bump, so the scan-accessor
return-type change and the dropped lifetime parameters on three
structs make this `0.2.0`.

[cargo-0x]: https://doc.rust-lang.org/cargo/reference/semver.html

### Added

- `addr` module with `nimrod::va_to_i64(u64) -> Option<i64>` for
  consumers persisting VAs into a signed 64-bit column. Returns `None`
  when the VA exceeds `i64::MAX` (TODO §11.6).
- `Display` impls on every public discriminator enum — `Format`, `Arch`,
  `GcMode`, `ShimKind`, `InitKind`, `RttiVersion`, `PathOs`. Strings
  match the existing `Debug` output exactly so consumers persisting
  `format!("{:?}", …)` don't need a schema migration. The `Display`
  output is now part of the crate's stable API; future changes are
  breaking (TODO §11.1).
- `Container::image_base()` and `Container::va_to_rva(va)` —
  per-format image-base recovery (PE `image_base`, ELF lowest `PT_LOAD`
  `p_vaddr`, Mach-O lowest segment `vmaddr`) plus checked VA→RVA
  translation (TODO §11.2).
- `NimBinary::image_base`, `shim_rva`, `init_rva`, `raise_rva`,
  `rtti_rva` — first-class RVA accessors so consumers stop paying the
  `va.saturating_sub(image_base)` tax (TODO §11.2).
- "Address space" rustdoc section on `NimBinary`, `Container`,
  `EntryShim`, `InitFunction`, `RaiseSite`, `RttiSymbol`,
  `ModuleSymbol`, `StringLiteral`, `StringLiteralV1` documenting that
  every address field is a VA, not a file offset (TODO §11.3).
- Rustdoc on `ModuleInfo::symbol_count` confirming `usize` is always
  representable in `u64` on every supported target (TODO §11.4).
- `tests/display_stability.rs` — snapshot test asserting Display output
  matches Debug for every variant of every public enum.

### Changed

- **All scan accessors on `NimBinary` are now lazily cached.** Each of
  `entry_shims`, `init_functions`, `rtti_symbols`, `string_literals_v2`,
  `string_literals_v1`, `stack_trace`, `nimble_paths`,
  `exception_types`, `raise_sites`, `module_map` runs at most once per
  `NimBinary` instance and returns a borrowed slice (`&[T]`) or
  reference (`&T`) on subsequent calls in O(1). Caching uses
  `std::sync::OnceLock` and is thread-safe (TODO §11.5).
- **Breaking.** Scan accessors that previously returned `Vec<T>` now
  return `&[T]`; `module_map` and `stack_trace` return `&T` instead
  of an owned value. Callers that bound by value should clone
  (`.to_vec()`) or take by reference.
- **Breaking.** `EntryShim<'a>`, `InitFunction<'a>`, and
  `RttiSymbol<'a>` lost their lifetime parameter. `symbol_name` and
  `RttiSymbol::type_fragment` are now `String` / `Option<String>`
  instead of `&'a str` / `Option<&'a str>`. This was required to
  make caching tractable inside `NimBinary` (otherwise the cached
  values would be self-referential through the embedded
  `Container`). Cost is a handful of short-string allocations per
  binary; the caching gain dominates.
- `shims::detect_prefix` signature loosened from
  `<'a>(&'a [EntryShim<'a>]) -> Option<&'a str>` to
  `(&[EntryShim]) -> Option<&str>` to match the new owned types.

### Fixed

- **Lint policy uniformity (TODO §11.0).** Cleared 232 `cargo clippy`
  violations introduced when the panic-prevention lint set
  (`unwrap_used`, `expect_used`, `panic`, `arithmetic_side_effects`,
  `indexing_slicing`) was added to `Cargo.toml`. Every site is now
  bounds-checked or uses `wrapping_*` / `checked_*` / `saturating_*`
  arithmetic, with the choice driven by whether overflow is genuinely
  impossible at the call site or could be triggered by adversarial
  input. No behavioral changes — the parser was already correct, just
  not provably panic-free under the new lints.

## [0.1.0] - initial release

- ELF, PE, Mach-O container abstraction.
- Detection probes covering entry shims, fatal strings, NTIv2 symbols,
  STT_FILE `.nim` suffix, danger-mode signal/exception strings.
- Demangler for Nim identifiers, mangled symbols, and `@m`/`@s`/`@h`
  module-path tokens.
- Entry shims, init functions, GC mode, `--nimMainPrefix` detection.
- V1 + V2 string literal scanners.
- V1 + V2 RTTI recovery.
- Stack-trace harvesting; `.nimble/pkgs` attribution.
- Phase 1 + phase 2 raise-site recovery (cstring exception types and
  full `(type, proc, file, line)` tuples on x86_64 / AArch64).
- Cross-referenced module map.
