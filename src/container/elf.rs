//! ELF backend for the container abstraction.
//!
//! Reads the section headers, `.symtab` then the `.dynsym` entries it does
//! not already list (an exported symbol is in both), the undefined
//! dynamic symbols as imports, and from the header the byte order
//! (`EI_DATA`), pointer width (`EI_CLASS`) and machine (`EM_RISCV` and
//! `EM_MIPS` are told 32- from 64-bit by the class).
//!
//! Two per-symbol extras feed the module map and the startup-code
//! evaluation:
//!
//! - Source files ([`Container::symbol_source_file`]): `.symtab` lists each
//!   object file's local symbols after an `STT_FILE` entry naming its
//!   source, so a local symbol takes the entry before it. Global symbols are
//!   moved to the end of the table by the linker and lose that grouping;
//!   for functions among them, the DWARF compile unit whose
//!   `.debug_aranges` cover their address names the file instead (debug
//!   builds only).
//! - Pointer fixups ([`Container::pointer_fixups`]): the values the dynamic
//!   loader writes for `RELATIVE`, `GLOB_DAT` and absolute relocations
//!   (x86-64 and AArch64), which a shared library's GOT holds as zero in
//!   the file.

use std::{borrow::Cow, collections::HashSet};

use goblin::elf::{
    Elf, Symtab,
    header::{EM_386, EM_AARCH64, EM_ARM, EM_MIPS, EM_PPC, EM_PPC64, EM_RISCV, EM_X86_64, ET_DYN},
    program_header::PT_LOAD,
    section_header::{
        SHF_ALLOC, SHF_COMPRESSED, SHF_EXECINSTR, SHF_TLS, SHF_WRITE, SHN_UNDEF, SHT_NOBITS,
        SHT_PROGBITS,
    },
    sym::{STB_LOCAL, STT_FILE, STT_FUNC, STT_OBJECT, STT_SECTION, st_bind, st_type},
};

use crate::{
    container::{Arch, Container, Format, Import, Section, SectionKind, Symbol, SymbolKind, dwarf},
    error::Result,
};

/// Builds the container for an ELF file goblin has parsed.
pub fn build<'a>(bytes: &'a [u8], elf: Elf<'a>) -> Result<Container<'a>> {
    let arch = map_arch(elf.header.e_machine, elf.is_64);
    let image_base = elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .map(|ph| ph.p_vaddr)
        .min()
        .unwrap_or(0);
    let sections = collect_sections(bytes, &elf);
    // Local symbols take the `STT_FILE` they are grouped under; other
    // functions, the compile unit whose DWARF ranges cover them.
    let units = dwarf::unit_ranges(&dwarf_sections(bytes, &elf), elf.little_endian);
    // `.dynsym` repeats the exported part of `.symtab`: an entry already
    // there (same name and address) is one symbol, listed once. A stripped
    // binary has only `.dynsym`.
    let symtab = collect_symbols(&elf, &elf.syms, &elf.strtab);
    let listed: HashSet<(&str, u64)> = symtab
        .iter()
        .map(|(s, _)| (s.name.as_ref(), s.vm_addr))
        .collect();
    let dynsym: Vec<_> = collect_symbols(&elf, &elf.dynsyms, &elf.dynstrtab)
        .into_iter()
        .filter(|(s, _)| !listed.contains(&(s.name.as_ref(), s.vm_addr)))
        .collect();
    let (symbols, source_files): (Vec<_>, Vec<_>) = symtab
        .into_iter()
        .chain(dynsym)
        .map(|(sym, file)| {
            let file = file.or_else(|| {
                sym.is_defined_function()
                    .then(|| dwarf::unit_at(&units, sym.vm_addr))
                    .flatten()
                    .map(|u| u.rsplit(['/', '\\']).next().unwrap_or(u))
            });
            (sym, file.map(Cow::Borrowed))
        })
        .unzip();
    let imports = elf
        .dynsyms
        .iter()
        .filter(|s| s.st_shndx == SHN_UNDEF as usize)
        .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
        .filter(|n| !n.is_empty())
        .map(|n| Import {
            name: Cow::Borrowed(n),
            library: None,
        })
        .collect();
    let library = elf.header.e_type == ET_DYN && elf.interpreter.is_none();
    let fixups = pointer_fixups(&elf);
    Ok(
        Container::from_parts(bytes, Format::Elf, arch, image_base, sections, symbols)
            .with_little_endian(elf.little_endian)
            .with_pointer_bits(if elf.is_64 { 64 } else { 32 })
            .with_imports(imports)
            .with_library(library)
            .with_pointer_fixups(fixups)
            .with_source_files(source_files),
    )
}

/// The uncompressed DWARF sections the compile-unit lookup reads.
fn dwarf_sections<'a>(bytes: &'a [u8], elf: &Elf<'a>) -> dwarf::DwarfSections<'a> {
    let get = |name: &str| -> &'a [u8] {
        elf.section_headers
            .iter()
            .find(|sh| {
                sh.sh_type != SHT_NOBITS
                    && sh.sh_flags & u64::from(SHF_COMPRESSED) == 0
                    && elf.shdr_strtab.get_at(sh.sh_name) == Some(name)
            })
            .and_then(|sh| {
                let start = usize::try_from(sh.sh_offset).ok()?;
                let len = usize::try_from(sh.sh_size).ok()?;
                bytes.get(start..start.checked_add(len)?)
            })
            .unwrap_or(&[])
    };
    dwarf::DwarfSections {
        aranges: get(".debug_aranges"),
        info: get(".debug_info"),
        abbrev: get(".debug_abbrev"),
        str: get(".debug_str"),
        line_str: get(".debug_line_str"),
    }
}

/// The architecture of `e_machine`; the ELF class tells 32- from 64-bit
/// RISC-V and MIPS, which share one machine value.
fn map_arch(e_machine: u16, is_64: bool) -> Arch {
    match e_machine {
        EM_386 => Arch::I386,
        EM_X86_64 => Arch::Amd64,
        EM_ARM => Arch::Arm,
        EM_AARCH64 => Arch::Aarch64,
        EM_PPC => Arch::PowerPc,
        EM_PPC64 => Arch::PowerPc64,
        EM_RISCV if is_64 => Arch::Riscv64,
        EM_RISCV => Arch::Riscv32,
        EM_MIPS if is_64 => Arch::Mips64,
        EM_MIPS => Arch::Mips,
        _ => Arch::Other,
    }
}

/// Every section header, at its `sh_addr`, with its file data (none for
/// `SHT_NOBITS`).
fn collect_sections<'a>(bytes: &'a [u8], elf: &Elf<'a>) -> Vec<Section<'a>> {
    let mut out = Vec::with_capacity(elf.section_headers.len());
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let vm_addr = sh.sh_addr;
        let vm_size = sh.sh_size;

        let file_offset = sh.sh_offset as usize;
        let file_size = sh.sh_size as usize;

        let data: &'a [u8] = if sh.sh_type == SHT_NOBITS {
            &[]
        } else {
            bytes
                .get(file_offset..file_offset.saturating_add(file_size))
                .unwrap_or(&[])
        };

        let kind = classify(&name, sh.sh_type, sh.sh_flags);

        out.push(Section {
            name,
            vm_addr,
            vm_size,
            data,
            kind,
        });
    }
    out
}

/// Maps a section's type, flags and name to a [`SectionKind`]. Only allocated
/// `PROGBITS` sections are program data: executable ones are text, read-only
/// ones (and RELRO, whose `SHF_WRITE` only serves the loader) read-only data,
/// the rest writable data; `NOBITS` is zero-fill. Thread-local templates,
/// unallocated sections (debug info, notes) and unwind tables are
/// [`SectionKind::Other`].
fn classify(name: &str, sh_type: u32, sh_flags: u64) -> SectionKind {
    let exec = sh_flags & u64::from(SHF_EXECINSTR) != 0;
    let write = sh_flags & u64::from(SHF_WRITE) != 0;

    // Thread-local templates (`.tdata`, `.tbss`): their addresses overlap
    // `.data` / `.bss` but are not image memory at run time (each thread gets
    // a copy elsewhere), so they must not answer address lookups.
    if sh_flags & u64::from(SHF_TLS) != 0 {
        return SectionKind::Other;
    }
    if sh_type == SHT_NOBITS {
        return SectionKind::Bss;
    }
    if sh_type != SHT_PROGBITS {
        return SectionKind::Other;
    }
    // Not loaded at run time: debug info (`.debug_*`), `.comment`, notes.
    // Their bytes are not program data and must not reach the data scans.
    if sh_flags & u64::from(SHF_ALLOC) == 0 {
        return SectionKind::Other;
    }

    // RELRO sections are written only by the dynamic loader's relocation
    // pass and are read-only afterwards, but carry SHF_WRITE on disk.
    // Constant data holding pointers (V2 string headers, RTTI, SSO
    // SmallStrings that point at long blocks) lives there.
    let relro = name == ".data.rel.ro" || name.starts_with(".data.rel.ro.");

    if exec {
        SectionKind::Text
    } else if !write || relro {
        // PROGBITS + allocated + not writable → read-only data.
        // Common names: .rodata, .rodata.str1.1, .rodata.cst16, .eh_frame, .data.rel.ro
        if name.starts_with(".rodata") || name == ".data.rel.ro" {
            SectionKind::RoData
        } else if name == ".eh_frame" || name == ".gcc_except_table" {
            SectionKind::Other
        } else {
            SectionKind::RoData
        }
    } else {
        SectionKind::Data
    }
}

/// Load-time pointer values from the dynamic relocations (`.rela.dyn`):
/// `RELATIVE` (value = addend) and `GLOB_DAT` / absolute 64-bit relocations
/// against symbols the image defines (value = symbol + addend), for x86-64
/// and AArch64. Other relocations are ignored.
fn pointer_fixups(elf: &Elf<'_>) -> Vec<(u64, u64)> {
    // (relative, glob_dat, abs64) relocation numbers per machine.
    let (relative, glob_dat, abs64) = match elf.header.e_machine {
        EM_X86_64 => (8, 6, 1),
        EM_AARCH64 => (1027, 1025, 257),
        _ => return Vec::new(),
    };
    elf.dynrelas
        .iter()
        .filter_map(|r| {
            let addend = r.r_addend.unwrap_or(0) as u64;
            let value = if r.r_type == relative {
                addend
            } else if r.r_type == glob_dat || r.r_type == abs64 {
                let sym = elf.dynsyms.get(r.r_sym)?;
                if sym.st_shndx == SHN_UNDEF as usize || sym.st_value == 0 {
                    return None;
                }
                sym.st_value.wrapping_add(addend)
            } else {
                return None;
            };
            Some((r.r_offset, value))
        })
        .collect()
}

/// Collects symbols with, for local symbols, the `STT_FILE` entry they
/// follow (the source file of their object file; `.symtab` groups each
/// object's locals after its `STT_FILE`).
fn collect_symbols<'a>(
    _elf: &Elf<'a>,
    syms: &Symtab<'a>,
    strtab: &goblin::strtab::Strtab<'a>,
) -> Vec<(Symbol<'a>, Option<&'a str>)> {
    let mut out = Vec::new();
    let mut file: Option<&'a str> = None;
    for sym in syms.iter() {
        let name = strtab.get_at(sym.st_name).unwrap_or("");
        if st_type(sym.st_info) == STT_FILE {
            file = (!name.is_empty()).then_some(name);
        }
        if name.is_empty() {
            continue;
        }
        let kind = match st_type(sym.st_info) {
            STT_FUNC => SymbolKind::Function,
            STT_OBJECT => SymbolKind::Object,
            STT_FILE => SymbolKind::File,
            STT_SECTION => SymbolKind::Section,
            _ => SymbolKind::Other,
        };
        let source = if st_bind(sym.st_info) == STB_LOCAL && kind != SymbolKind::File {
            file
        } else {
            None
        };
        out.push((
            Symbol {
                name: Cow::Borrowed(name),
                vm_addr: sym.st_value,
                size: sym.st_size,
                kind,
            },
            source,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_relro_as_read_only() {
        let a = u64::from(SHF_ALLOC);
        let rw = a | u64::from(SHF_WRITE);
        assert_eq!(
            classify(".data.rel.ro", SHT_PROGBITS, rw),
            SectionKind::RoData
        );
        assert_eq!(
            classify(".data.rel.ro.local", SHT_PROGBITS, rw),
            SectionKind::RoData
        );
        assert_eq!(classify(".data", SHT_PROGBITS, rw), SectionKind::Data);
        assert_eq!(classify(".data.rel", SHT_PROGBITS, rw), SectionKind::Data);
        assert_eq!(classify(".rodata", SHT_PROGBITS, a), SectionKind::RoData);
        assert_eq!(
            classify(".text", SHT_PROGBITS, a | u64::from(SHF_EXECINSTR)),
            SectionKind::Text
        );
        assert_eq!(classify(".bss", SHT_NOBITS, rw), SectionKind::Bss);
        // Non-loaded sections are not data.
        assert_eq!(classify(".debug_str", SHT_PROGBITS, 0), SectionKind::Other);
        assert_eq!(classify(".comment", SHT_PROGBITS, 0), SectionKind::Other);
    }
}
