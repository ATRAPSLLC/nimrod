# nimrod

A pure-Rust parser and forensic-artifact extractor for
[Nim](https://nim-lang.org/)-compiled native binaries. Built for **malware
analysis** and **reverse engineering**.

Nim compiles to C/C++/ObjC and then to a standard **ELF, PE, or Mach-O**
binary — there is no Nim-specific container. This crate recovers the runtime
artifacts that the Nim compiler leaves behind: entry shims, module init
functions, RTTI tables, string literals, stack-trace metadata, build-host
attribution paths, and exception raise sites.

## What it extracts

| Artifact | Description |
|----------|-------------|
| **Detection** | 11 independent fingerprint probes — reliable even on stripped `-d:danger` builds |
| **GC mode / version** | refc, ARC, atomicArc, ORC, YRC (`NimVersionHint`); the symbol layout (`mangle_scheme`) dates the compiler to 1.0 - 1.4, 1.6 - 2.3 or 2.4+ |
| **Build profile** | Exception model (goto / setjmp / C++), stack traces, runtime checks, library build (`build_profile`), each unknown rather than guessed |
| **Entry shims** | `NimMain`, `PreMain`, `NimMainModule`, etc. with addresses |
| **Init functions** | `*Init000` / `*DatInit000` with decoded build-host module paths |
| **Type graph** | Cross-linked types: members, offsets, sizes, alignment, inheritance, enum values, hooks; refc and pre-2.0 type info, which the file leaves zero, recovered by evaluating the startup code (x86-64, AArch64) |
| **Procs** | Every Nim function by address with its name, module and role: user proc, hook (`=destroy`, `=trace`, GC marker, finalizer, ...), lambda, async iterator / callback, module init, entry shim |
| **Relations** | Edges the machine code does not show as direct calls: type to hook (called by the runtime through RTTI), the startup call structure, async callback to iterator, each with its provenance |
| **Module map** | Every Nim module compiled into the binary, with per-function name, address, and size (ELF); Nim 1.x functions grouped by the C file that emitted them |
| **Symbol demangling** | All four Nim name layouts (1.0-1.4 signature hash, 1.6-2.3, 2.4+, Itanium debug builds) back to identifier, module and parameter types |
| **RTTI** | `TNimTypeV2` fields (size, align, depth, destructor) and `TNimType` with field-name recovery |
| **String literals** | V1 (`NimStringDesc`), V2 (`NIM_STRLIT_FLAG`) and Nim 2.4 `--strings:sso` literals, including those folded into instruction immediates |
| **Stack traces** | Proc names and `.nim` file paths — absolute paths leak the build host |
| **Nimble paths** | `.nimble/pkgs` leaks parsed into package name, version, hash, and username |
| **Exception types** | `*Error` / `*Defect` cstrings found in rodata |
| **Raise sites** | Full (type, proc, file, line) tuples recovered via x86-64 (System V and Microsoft ABI) and AArch64 instruction analysis |
| **Imports** | Imported symbols with their library (`Container::imports`) |

## Quick start

```rust
use nimrod::NimBinary;

let data = std::fs::read("sample.exe")?;
let bin = NimBinary::from_bytes(&data)?;

if !bin.is_nim() {
    println!("Not a Nim binary");
    return Ok(());
}

println!("Format: {:?}, GC: {:?}", bin.format(), bin.gc_mode());
```

## Type graph

`bin.types()` recovers every Nim type from RTTI (V1 `TNimType` and V2
`TNimTypeV2`) into one cross-linked graph: size, alignment, inheritance
depth, member fields with offsets and resolved field types, enum values, and
destructor procs resolved to function symbols.

```rust
for t in bin.types() {
    let name = t.name.as_deref().or(t.type_fragment.as_deref()).unwrap_or("?");
    println!("{} {} (size={}, align={})", t.version, name, t.size, t.align);

    if let Some(parent) = &t.parent {
        println!("  inherits: {}", parent.name.as_deref().unwrap_or("?"));
    }
    for f in &t.fields {
        let fty = f.type_ref.as_ref().and_then(|r| r.name.as_deref()).unwrap_or("?");
        println!("  +{:<4} {}: {}", f.offset, f.name, fty);
    }
    for e in &t.enum_values {
        println!("  = {} ({})", e.name, e.ordinal);
    }
    if let Some(d) = &t.destructor {
        println!("  =destroy: {}", d.function.as_deref().unwrap_or("?"));
    }
}
```

V2 (ARC/ORC) object layouts also expose the inheritance chain via the
`display` class-token array. On Mach-O, legacy V1 globals are stored in
`__DATA,__common` with no file backing, so they degrade gracefully to
name-only entries (`t.is_readable() == false`) carrying the type-name
fragment — never a panic, never a dropped type.

## Procs and relations

`bin.procs()` lists every function nimrod identifies as Nim code, one entry
per address, so a disassembler front-end can label a whole binary from a
single call. Each entry's `ProcRole` says what it is for Nim, including the
functions no direct call reaches (hooks the runtime calls for a type, async
iterators, module inits):

```rust
for p in bin.procs() {
    println!("{:#x}  {}  {}", p.va, p.role, p.name);
}
```

`bin.relations()` gives the edges Nim metadata records for a call-graph
builder to add to the calls it decodes: each type's hooks (from the RTTI, or
for refc markers from the name), the startup structure from `NimMain` down to
the module inits (callee order is recorded only in code), and the async
callback resuming its closure iterator. Every edge says where it came from:

```rust
use nimrod::RelationKind;

for r in bin.relations() {
    if let RelationKind::Hook(kind) = r.kind {
        println!("type {:#x} -> {kind} {:#x} [{}]", r.from, r.to, r.source);
    }
}
```

## Module map

The module map cross-references init functions, demangled symbols, and
stack-trace file paths into a per-module view. Each module lists every
function with its demangled name, virtual address, and size (ELF):

```rust
let mmap = bin.module_map();
for (name, info) in &mmap.modules {
    println!("{name}: {} functions", info.symbol_count());
    if let Some(ref path) = info.init_path {
        println!("  source: {path}");
    }
    for sym in &info.symbols {
        println!("  {:#x} {} ({} bytes)", sym.address, sym.name, sym.size);
    }
}
```

```text
cgen: 650 functions
  source: cgen.nim
  0x7b6100 cProcParams (439 bytes)
  0x7b62c0 genProcPrototype (312 bytes)
  ...
system: 224 functions
  source: system.nim
  0x405e70 rawAlloc (1284 bytes)
  0x406360 collectCyclesBacon (820 bytes)
  ...
```

This gives downstream tools (Binary Ninja, Ghidra, IDA) the function
boundaries they need for disassembly and analysis.

## Raise-site recovery

Phase 2 raise-site recovery analyses x86_64 and AArch64 instructions around
calls to `raiseExceptionEx` to extract the full exception tuple:

```rust
for rs in &bin.raise_sites() {
    println!(
        "{} in {} at {}:{} [fn: {}]",
        rs.exception_type.as_deref().unwrap_or("?"),
        rs.proc_name.as_deref().unwrap_or("?"),
        rs.file.as_deref().unwrap_or("?"),
        rs.line.map(|l| l.to_string()).unwrap_or("?".into()),
        rs.enclosing_function.as_deref().unwrap_or("?"),
    );
}
```

```text
ValueError in parseHexInt at strutils.nim:1242  [fn: nsuParseHexInt]
IndexDefect in delete at system.nim:2196        [fn: delete__closureiters_u3150]
MyError in inner at exceptions.nim:7            [fn: outer__exceptions_u129]
```

## Build-host attribution

Debug and standard-release Nim builds leak build-host paths via stack-trace
metadata and nimble package paths:

```rust
// Absolute .nim file paths (build-host leak)
let harvest = bin.stack_trace();
for f in &harvest.file_paths {
    if f.is_absolute {
        println!("leaked: {}", f.path);
    }
}

// Nimble package paths (username + package intel)
for p in &bin.nimble_paths() {
    println!("pkg: {}@{}", 
        p.pkg_name.as_deref().unwrap_or("?"),
        p.pkg_version.as_deref().unwrap_or("?"));
    if let Some(ref user) = p.user_hint {
        println!("  user: {user}");
    }
}
```

```text
leaked: /opt/homebrew/Cellar/nim/2.2.8/nim/lib/system.nim
pkg: nimSHA2@0.1.1
  user: alex
```

## Dump example

The included `dump` example prints every recoverable artifact:

```sh
cargo run --example dump -- sample.exe
```

## Supported formats

- **ELF** (Linux, BSD): full support, including function sizes from
  `st_size`, source files from `STT_FILE` and DWARF, and loader fixups
- **PE** (Windows): COFF symbol table and exports, MinGW and MSVC linked,
  64- and 32-bit (i386 name decoration removed)
- **Mach-O** (macOS): single-arch and universal (fat) binaries

Words are read in the image's byte order and pointer width, so big-endian
(PPC64, MIPS) and 32-bit images read like their x86-64 counterparts. Code
analysis (raise sites, startup-code evaluation) covers x86-64 and AArch64.

Tested against binaries built by ten Nim releases, 1.0.10 to 2.4.2, across
memory managers, build modes and platforms (`tests/build_fixtures/`,
`tests/versions.rs`).

## Dependencies

Deliberately minimal:

- [`goblin`](https://docs.rs/goblin) — ELF/PE/Mach-O parsing
- [`memchr`](https://docs.rs/memchr) — fast byte-level rodata scanning

## License

Copyright 2026 ATRAPS LLC. Licensed under the Apache License,
Version 2.0. See `LICENSE` and `NOTICE`.
