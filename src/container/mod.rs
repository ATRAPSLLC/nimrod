//! Container-format abstraction over ELF, PE, and Mach-O.
//!
//! The rest of the crate reads host-binary structure (sections, symbols,
//! imports, byte order, pointer width) through this layer, so the
//! Nim-specific scans never care which native format they run against.
//!
//! [`Container::parse`] dispatches on the magic bytes to a per-format
//! backend, which collects sections and symbols eagerly into vectors that
//! borrow from the input slice. The backends (`elf`, `pe`, `macho`, and the
//! `dwarf` compile-unit reader the ELF one uses) are private: only the
//! unified types below are API. [`Container::from_parts`] builds a container
//! from parts another loader produced, with the `with_*` setters for what
//! the header would otherwise supply.
//!
//! What each backend records:
//!
//! | | ELF | PE | Mach-O |
//! |---|---|---|---|
//! | symbols (each once) | `.symtab`, then the `.dynsym` entries it lacks | exports the COFF table lacks, then COFF symbols | nlist table |
//! | [`Container::symbol_source_file`] | `STT_FILE` grouping (locals), DWARF compile units (others) | COFF `.file` records | none |
//! | [`Container::pointer_fixups`] | `RELATIVE`, `GLOB_DAT`, `ABS64` (x86-64, AArch64) | none | none |
//! | byte order, pointer width | `EI_DATA`, `EI_CLASS` | little-endian, PE32 / PE32+ | magic |

mod dwarf;
mod elf;
mod macho;
mod pe;

use std::sync::OnceLock;

use crate::{
    demangle::symbol::{self, Demangled, MangleScheme},
    error::{Error, Result},
};
use core::fmt;

/// Native container format of the underlying binary.
///
/// # Stability
///
/// The string returned by [`Display`](fmt::Display) is part of nimrod's
/// stable API: downstream consumers persist it as a schema
/// discriminator. Changes to these strings are SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// Executable and Linkable Format: Linux, BSD, and other Unix hosts.
    Elf,
    /// Portable Executable: Windows.
    Pe,
    /// Mach object format: macOS, iOS, and other Apple platforms.
    MachO,
}

impl Format {
    /// Returns the stable string identifier for this format.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Elf => "Elf",
            Self::Pe => "Pe",
            Self::MachO => "MachO",
        }
    }

    /// Returns `true` for [`Format::Elf`].
    pub fn is_elf(&self) -> bool {
        matches!(self, Self::Elf)
    }

    /// Returns `true` for [`Format::Pe`].
    pub fn is_pe(&self) -> bool {
        matches!(self, Self::Pe)
    }

    /// Returns `true` for [`Format::MachO`].
    pub fn is_macho(&self) -> bool {
        matches!(self, Self::MachO)
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CPU architecture reported by the container header.
///
/// # Stability
///
/// The string returned by [`Display`](fmt::Display) is part of nimrod's
/// stable API. Changes are SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    /// 32-bit x86.
    I386,
    /// 64-bit x86.
    Amd64,
    /// 32-bit ARM.
    Arm,
    /// 64-bit ARM (AArch64 / ARM64).
    Aarch64,
    /// 32-bit RISC-V.
    Riscv32,
    /// 64-bit RISC-V.
    Riscv64,
    /// 32-bit PowerPC.
    PowerPc,
    /// 64-bit PowerPC.
    PowerPc64,
    /// 32-bit MIPS.
    Mips,
    /// 64-bit MIPS.
    Mips64,
    /// Any architecture we did not map explicitly.
    Other,
}

impl Arch {
    /// Returns the stable string identifier for this architecture.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::I386 => "I386",
            Self::Amd64 => "Amd64",
            Self::Arm => "Arm",
            Self::Aarch64 => "Aarch64",
            Self::Riscv32 => "Riscv32",
            Self::Riscv64 => "Riscv64",
            Self::PowerPc => "PowerPc",
            Self::PowerPc64 => "PowerPc64",
            Self::Mips => "Mips",
            Self::Mips64 => "Mips64",
            Self::Other => "Other",
        }
    }

    /// Returns the pointer width in bits, or `None` for [`Arch::Other`]
    /// (an architecture nimrod does not map explicitly).
    pub fn bits(&self) -> Option<u8> {
        match self {
            Self::Amd64 | Self::Aarch64 | Self::Riscv64 | Self::PowerPc64 | Self::Mips64 => {
                Some(64)
            }
            Self::I386 | Self::Arm | Self::Riscv32 | Self::PowerPc | Self::Mips => Some(32),
            Self::Other => None,
        }
    }

    /// Returns `true` for a known 64-bit architecture.
    pub fn is_64bit(&self) -> bool {
        self.bits() == Some(64)
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Coarse classification of a section's role.
///
/// The Nim probes only need to distinguish "code" from "read-only data"
/// from "everything else": we deliberately do not expose every
/// format-specific section type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionKind {
    /// Machine code (ELF `.text`, PE `.text`, Mach-O `__TEXT,__text`).
    Text,
    /// Read-only data (ELF `.rodata`, PE `.rdata`, Mach-O `__TEXT,__cstring`,
    /// `__TEXT,__const`, `__DATA_CONST,__const`).
    RoData,
    /// Initialised mutable data.
    Data,
    /// Uninitialised / BSS-like (no file bytes).
    Bss,
    /// Anything else: debug info, relocations, unwind tables, etc.
    Other,
}

impl SectionKind {
    /// Whether the section holds program data: read-only, writable or
    /// zero-fill. These are where RTTI, string literals and the startup
    /// code's writes live.
    pub fn is_data(self) -> bool {
        matches!(self, Self::RoData | Self::Data | Self::Bss)
    }
}

/// One section/segment of the parsed binary.
///
/// The `data` slice borrows from the input bytes; for BSS-like sections
/// with no file backing, the slice is empty and `SectionKind::Bss` is set.
#[derive(Debug, Clone)]
pub struct Section<'a> {
    /// Section name as it appears in the container (without normalisation).
    ///
    /// ELF/PE names are a single token (`.text`, `.rdata`). Mach-O section
    /// names are qualified with their segment as `__SEGMENT,__sect`.
    pub name: String,
    /// Virtual address this section is mapped at. Zero for sections with no
    /// VA (e.g. ELF `.shstrtab`).
    pub vm_addr: u64,
    /// Section size in bytes as declared by the container header.
    pub vm_size: u64,
    /// File bytes backing this section. Empty for BSS-like sections.
    pub data: &'a [u8],
    /// Coarse classification used by higher-level scans.
    pub kind: SectionKind,
}

impl Section<'_> {
    /// Whether `va` lies inside the section's address range
    /// `[vm_addr, vm_addr + vm_size)`.
    pub fn contains(&self, va: u64) -> bool {
        va.checked_sub(self.vm_addr)
            .is_some_and(|off| off < self.vm_size)
    }
}

/// Coarse classification of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// Executable code.
    Function,
    /// Data / global variable.
    Object,
    /// Source file marker (ELF `STT_FILE`). Used for Nim `.nim` file
    /// suffix detection.
    File,
    /// Section-level symbol.
    Section,
    /// Unclassified / unknown.
    Other,
}

/// Normalised symbol extracted from the container.
///
/// Names are normalised at the container level only to remove the C-level
/// decoration a format adds: Mach-O's leading `_`, and on 32-bit PE the
/// Microsoft decoration (`_name`, `_name@N`, fastcall `@name@N`). Every scan
/// then compares names as the source declared them (`NimMain`) on all
/// formats.
#[derive(Debug, Clone)]
pub struct Symbol<'a> {
    /// Normalised symbol name. Borrows from the input bytes where possible
    /// (decoration removal takes a substring), owns the string when
    /// normalisation required allocation (short COFF names stored inline in
    /// the symbol record, a 32-bit PE name with an `__imp_` prefix or clone
    /// suffix around its decoration).
    pub name: std::borrow::Cow<'a, str>,
    /// Virtual address of the symbol, when known. Zero for undefined
    /// symbols.
    pub vm_addr: u64,
    /// Size in bytes of the symbol (from ELF `st_size`). Zero when the
    /// format doesn't provide size information (Mach-O, stripped PE).
    pub size: u64,
    /// Classification of the symbol.
    pub kind: SymbolKind,
}

impl Symbol<'_> {
    /// Whether the symbol is a function defined in this image (it has an
    /// address; imported functions have none).
    pub fn is_defined_function(&self) -> bool {
        self.kind == SymbolKind::Function && self.vm_addr != 0
    }
}

/// A symbol the binary imports from another image.
///
/// ELF: undefined dynamic symbols (the providing library is not recorded
/// per symbol). PE: the import table. Mach-O: bind opcodes, with the
/// leading underscore stripped as for [`Symbol`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import<'a> {
    /// Imported symbol name. Ordinal-only PE imports are named
    /// `ORDINAL <n>` (goblin's convention).
    pub name: std::borrow::Cow<'a, str>,
    /// Library the symbol is imported from, when the format records it
    /// (PE DLL name, Mach-O dylib path).
    pub library: Option<std::borrow::Cow<'a, str>>,
}

/// Parsed container-format view of a native binary.
///
/// # Address space
///
/// All address fields exposed by `Container` and the higher-level scans
/// (`Section::vm_addr`, `Symbol::vm_addr`, `EntryShim::address`,
/// `RaiseSite::call_addr`, …) are **virtual addresses** in the input
/// image's load space, not file offsets. To translate a VA into a
/// disassembler-style RVA, subtract [`Container::image_base`] (or use
/// the `*_rva` helpers on [`crate::NimBinary`]).
pub struct Container<'a> {
    /// The whole input file; section data borrows from it.
    bytes: &'a [u8],
    /// [`Container::format`].
    format: Format,
    /// [`Container::arch`].
    arch: Arch,
    /// [`Container::image_base`].
    image_base: u64,
    /// [`Container::sections`], in header order.
    sections: Vec<Section<'a>>,
    /// [`Container::symbols`]: the static symbol table, then the dynamic
    /// entries it lacks (ELF), the exports the COFF table lacks, then COFF
    /// symbols (PE), or the nlist table (Mach-O).
    symbols: Vec<Symbol<'a>>,
    /// The symbol table's dominant [`MangleScheme`], voted on first use by
    /// [`Container::mangle_scheme`].
    mangle_scheme: OnceLock<Option<MangleScheme>>,
    /// [`Container::is_little_endian`].
    little_endian: bool,
    /// [`Container::pointer_bits`].
    pointer_bits: u8,
    /// [`Container::imports`].
    imports: Vec<Import<'a>>,
    /// [`Container::is_library`].
    library: bool,
    /// [`Container::pointer_fixups`].
    pointer_fixups: Vec<(u64, u64)>,
    /// [`Container::symbol_source_file`], one entry per symbol (empty when the
    /// format records none).
    source_files: Vec<Option<std::borrow::Cow<'a, str>>>,
}

impl<'a> Container<'a> {
    /// Parses `bytes` as an ELF, PE, or Mach-O binary.
    ///
    /// Returns [`Error::UnsupportedFormat`] if the input is neither.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let obj = goblin::Object::parse(bytes)?;
        match obj {
            goblin::Object::Elf(elf) => elf::build(bytes, elf),
            goblin::Object::PE(pe) => pe::build(bytes, pe),
            goblin::Object::Mach(mach) => macho::build(bytes, mach),
            _ => Err(Error::UnsupportedFormat),
        }
    }

    /// Builds a container from already-parsed parts, for input that
    /// [`Container::parse`] cannot read itself: images from another loader,
    /// unpacked memory dumps, or synthetic test data.
    ///
    /// Each section's `data` should be a sub-slice of `bytes`; scans that map
    /// a virtual address back to a file offset find nothing in sections
    /// that are not. Byte order defaults to little-endian (see
    /// [`Container::with_little_endian`]).
    ///
    /// ```
    /// use std::borrow::Cow;
    /// use nimrod::container::{Arch, Container, Format, Symbol, SymbolKind};
    ///
    /// let bytes = [0u8; 16];
    /// let symbols = vec![Symbol {
    ///     name: Cow::Borrowed("NimMain"),
    ///     vm_addr: 0x1000,
    ///     size: 0,
    ///     kind: SymbolKind::Function,
    /// }];
    /// let c = Container::from_parts(&bytes, Format::Elf, Arch::Amd64, 0, vec![], symbols);
    /// assert_eq!(c.symbols().len(), 1);
    /// assert!(c.is_little_endian());
    /// ```
    pub fn from_parts(
        bytes: &'a [u8],
        format: Format,
        arch: Arch,
        image_base: u64,
        sections: Vec<Section<'a>>,
        symbols: Vec<Symbol<'a>>,
    ) -> Self {
        Self {
            bytes,
            format,
            arch,
            image_base,
            sections,
            symbols,
            mangle_scheme: OnceLock::new(),
            little_endian: true,
            pointer_bits: arch.bits().unwrap_or(64),
            imports: Vec::new(),
            library: false,
            pointer_fixups: Vec::new(),
            source_files: Vec::new(),
        }
    }

    /// Sets the per-symbol source files returned by
    /// [`Container::symbol_source_file`], parallel to the symbol list.
    pub fn with_source_files(mut self, files: Vec<Option<std::borrow::Cow<'a, str>>>) -> Self {
        self.source_files = files;
        self
    }

    /// The source file the `index`-th symbol of [`Container::symbols`] was
    /// compiled from, e.g. `stdlib_system.nim.c` or `@mmain.nim.c`: on ELF
    /// the `STT_FILE` entry a local symbol is grouped under, else (functions)
    /// the base name of the DWARF compile unit whose `.debug_aranges` cover
    /// it; on PE the COFF `.file` record a symbol follows (mingw keeps only
    /// the first 14 bytes of short names that do not fit, e.g.
    /// `@palgorithm.ni`). `None` for other symbols and formats.
    pub fn symbol_source_file(&self, index: usize) -> Option<&str> {
        self.source_files.get(index)?.as_deref()
    }

    /// Sets the list returned by [`Container::pointer_fixups`] (default:
    /// empty).
    pub fn with_pointer_fixups(mut self, fixups: Vec<(u64, u64)>) -> Self {
        self.pointer_fixups = fixups;
        self
    }

    /// Pointer-sized words the loader fills in, as `(address, value)` pairs
    /// in link-time addresses: ELF `RELATIVE` relocations and `GLOB_DAT` /
    /// absolute relocations against symbols the image defines. A shared
    /// library's GOT holds 0 in the file and gets its values this way.
    pub fn pointer_fixups(&self) -> &[(u64, u64)] {
        &self.pointer_fixups
    }

    /// Sets the list returned by [`Container::imports`] (default: empty).
    pub fn with_imports(mut self, imports: Vec<Import<'a>>) -> Self {
        self.imports = imports;
        self
    }

    /// Sets the flag returned by [`Container::is_library`] (default: false).
    pub fn with_library(mut self, library: bool) -> Self {
        self.library = library;
        self
    }

    /// Returns the symbols imported from other images.
    pub fn imports(&self) -> &[Import<'a>] {
        &self.imports
    }

    /// Whether the image is a shared library rather than an executable:
    /// a PE with `IMAGE_FILE_DLL`, a Mach-O dylib or bundle, or an ELF
    /// `ET_DYN` object without a program interpreter (a PIE executable has
    /// one).
    pub fn is_library(&self) -> bool {
        self.library
    }

    /// Returns the underlying input byte slice.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the detected container format.
    pub fn format(&self) -> Format {
        self.format
    }

    /// Returns the detected CPU architecture.
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// Whether the image's data is little-endian (from the ELF `EI_DATA`
    /// byte or the Mach-O magic; PE is always little-endian).
    ///
    /// The data scanners read in this byte order. The instruction-level
    /// scanners (x86-64 and AArch64 code, whose instructions are
    /// little-endian in every mode) and the startup-code evaluation skip
    /// big-endian images.
    pub fn is_little_endian(&self) -> bool {
        self.little_endian
    }

    /// The width of a pointer in the image's data, in bits (32 or 64), from
    /// the header: the ELF class, PE32 / PE32+, the Mach-O magic. Unlike
    /// [`Arch::bits`] it is known for [`Arch::Other`] too.
    pub fn pointer_bits(&self) -> u8 {
        self.pointer_bits
    }

    /// Sets the width reported by [`Container::pointer_bits`] (default:
    /// [`Arch::bits`], else 64). Values other than 32 and 64 are ignored.
    pub fn with_pointer_bits(mut self, bits: u8) -> Self {
        if matches!(bits, 32 | 64) {
            self.pointer_bits = bits;
        }
        self
    }

    /// Sets the byte order reported by [`Container::is_little_endian`]
    /// (default: little-endian).
    pub fn with_little_endian(mut self, little_endian: bool) -> Self {
        self.little_endian = little_endian;
        self
    }

    /// Returns the image base address: the virtual address that the
    /// container's lowest loadable region maps to.
    ///
    /// - **PE**: `OptionalHeader.windows_fields.image_base` (the canonical
    ///   `ImageBase`).
    /// - **ELF**: lowest `PT_LOAD` `p_vaddr` (zero for typical PIE / shared
    ///   objects, non-zero for fixed-load executables).
    /// - **Mach-O**: lowest segment `vmaddr` (often the `__TEXT` segment).
    ///
    /// Subtracting this from any VA produced by nimrod yields the RVA used
    /// by Binary Ninja, Ghidra, IDA, and similar disassemblers.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Translates a virtual address into an image-relative address (RVA).
    ///
    /// Returns `None` when `va < image_base()` (e.g. a sentinel zero VA on
    /// an undefined symbol, or a VA from a different image).
    pub fn va_to_rva(&self, va: u64) -> Option<u64> {
        va.checked_sub(self.image_base)
    }

    /// Returns every parsed section.
    pub fn sections(&self) -> &[Section<'a>] {
        &self.sections
    }

    /// Returns every parsed symbol.
    pub fn symbols(&self) -> &[Symbol<'a>] {
        &self.symbols
    }

    /// Iterates only sections classified as read-only data.
    pub fn rodata_sections(&self) -> impl Iterator<Item = &Section<'a>> + '_ {
        self.sections
            .iter()
            .filter(|s| s.kind == SectionKind::RoData)
    }

    /// The section that holds `va` in the running image: the first in header
    /// order that contains it, skipping [`SectionKind::Other`] sections.
    /// Those are not loaded or not program memory (debug info at address 0,
    /// TLS templates overlapping `.data`), and must never answer an address
    /// lookup: in a debug-info build `.debug_info` would otherwise "contain"
    /// every low address.
    pub fn section_at(&self, va: u64) -> Option<&Section<'a>> {
        self.sections
            .iter()
            .find(|s| s.kind != SectionKind::Other && s.contains(va))
    }

    /// Finds the function symbol that contains the given virtual address.
    ///
    /// For ELF binaries (which have `st_size`), this checks
    /// `sym.vm_addr <= va < sym.vm_addr + sym.size`. For formats without
    /// size info, it finds the nearest preceding function symbol.
    pub fn function_at_va(&self, va: u64) -> Option<&Symbol<'a>> {
        // First try exact range match (ELF with sizes).
        if let Some(sym) = self.symbols.iter().find(|s| {
            s.kind == SymbolKind::Function
                && s.size > 0
                && va >= s.vm_addr
                && s.vm_addr.checked_add(s.size).is_some_and(|end| va < end)
        }) {
            return Some(sym);
        }

        // Fallback: nearest preceding function symbol.
        self.symbols
            .iter()
            .filter(|s| s.is_defined_function() && s.vm_addr <= va)
            .max_by_key(|s| s.vm_addr)
    }

    /// The Nim C-backend naming layout used by this binary's symbol table,
    /// decided by [`symbol::dominant_scheme`] over every symbol name.
    ///
    /// `None` when no symbol fits exactly one layout (stripped binaries,
    /// non-Nim binaries) or the vote is tied. Computed once and cached.
    pub fn mangle_scheme(&self) -> Option<MangleScheme> {
        *self
            .mangle_scheme
            .get_or_init(|| symbol::dominant_scheme(self.symbols.iter().map(|s| s.name.as_ref())))
    }

    /// Demangles a symbol name from this binary, resolving names that fit
    /// both layouts with the binary's [`Container::mangle_scheme`].
    pub fn demangle<'s>(&self, name: &'s str) -> Option<Demangled<'s>> {
        symbol::parse(name, self.mangle_scheme())
    }
}

impl std::fmt::Debug for Container<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Container")
            .field("format", &self.format)
            .field("arch", &self.arch)
            .field("sections", &self.sections.len())
            .field("symbols", &self.symbols.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_lookup_skips_non_program_sections() {
        let bytes: &'static [u8] = &[0; 64];
        let section = |name: &str, kind, vm_addr, vm_size| Section {
            name: name.into(),
            kind,
            vm_addr,
            vm_size,
            data: &bytes[..0],
        };
        let sections = vec![
            // Debug info at address 0 "covers" every low address.
            section(".debug_info", SectionKind::Other, 0, 0x10_0000),
            section(".text", SectionKind::Text, 0x1000, 0x100),
            section(".data", SectionKind::Data, 0x2000, 0x10),
        ];
        let c = Container::from_parts(bytes, Format::Elf, Arch::Amd64, 0, sections, vec![]);
        assert_eq!(c.section_at(0x1000).map(|s| s.name.as_str()), Some(".text"));
        assert_eq!(c.section_at(0x200f).map(|s| s.name.as_str()), Some(".data"));
        assert!(c.section_at(0x2010).is_none());
        assert!(c.section_at(0x500).is_none());
        // No overflow at the top of the address space.
        assert!(!section("x", SectionKind::Data, u64::MAX, 2).contains(0));
        assert!(section("x", SectionKind::Data, u64::MAX - 1, 2).contains(u64::MAX));
    }

    #[test]
    fn defined_functions_have_an_address() {
        let sym = |kind, vm_addr| Symbol {
            name: "f".into(),
            vm_addr,
            size: 0,
            kind,
        };
        assert!(sym(SymbolKind::Function, 0x1000).is_defined_function());
        assert!(!sym(SymbolKind::Function, 0).is_defined_function());
        assert!(!sym(SymbolKind::Object, 0x1000).is_defined_function());
    }
}
