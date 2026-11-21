//! PE backend for the container abstraction.
//!
//! Reads the section table, imports, exports and, when the file keeps one,
//! the COFF symbol table. mingw-linked binaries (the usual Nim toolchain on
//! Windows) keep it; MSVC-linked ones usually strip it in favour of a PDB,
//! leaving only the exports.
//!
//! The COFF table lists each object file's symbols after a `.file` record
//! naming its source (`@mmain.nim.c`), so every symbol gets the source file
//! of the record before it ([`Container::symbol_source_file`]). A long
//! `.file` name (19 bytes and up in the fixtures) is a string-table
//! reference in the auxiliary record: four zero bytes, then the offset. A
//! shorter one is inline, and the mingw toolchain keeps only its first 14
//! bytes (seen for 15 - 17 byte names: `@palgorithm.nim.c` is stored as
//! `@palgorithm.ni`).
//!
//! On 32-bit (i386) images, symbol names lose their C-level decoration
//! (`_name`, `_name@N`, fastcall `@name@N`, the form Nim procs take), as
//! Mach-O names lose their `_`.
//!
//! PE data is little-endian; the pointer width comes from the optional
//! header (PE32 or PE32+). No relocation-derived pointer values are
//! recorded ([`Container::pointer_fixups`] stays empty).

use std::{borrow::Cow, collections::HashSet};

use goblin::pe::{
    PE,
    characteristic::IMAGE_FILE_DLL,
    header::{
        COFF_MACHINE_ARM, COFF_MACHINE_ARM64, COFF_MACHINE_RISCV32, COFF_MACHINE_RISCV64,
        COFF_MACHINE_X86, COFF_MACHINE_X86_64,
    },
    section_table::{
        IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA,
        IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, SectionTable,
    },
    symbol::{COFF_SYMBOL_SIZE, IMAGE_SYM_CLASS_FILE, IMAGE_SYM_DTYPE_FUNCTION, SymbolTable},
};

use crate::{
    container::{Arch, Container, Format, Import, Section, SectionKind, Symbol, SymbolKind},
    error::Result,
};

/// Builds the container for a PE file goblin has parsed.
pub fn build<'a>(bytes: &'a [u8], pe: PE<'a>) -> Result<Container<'a>> {
    let arch = map_arch(pe.header.coff_header.machine);
    let image_base = pe.image_base;
    let sections = collect_sections(bytes, &pe);
    let (symbols, source_files): (Vec<_>, Vec<_>) =
        collect_symbols(bytes, &pe)?.into_iter().unzip();
    let imports = pe
        .imports
        .iter()
        .map(|i| Import {
            name: i.name.clone(),
            library: Some(Cow::Borrowed(i.dll)),
        })
        .collect();
    let library = pe.header.coff_header.characteristics & IMAGE_FILE_DLL != 0;
    Ok(
        Container::from_parts(bytes, Format::Pe, arch, image_base, sections, symbols)
            .with_pointer_bits(if pe.is_64 { 64 } else { 32 })
            .with_imports(imports)
            .with_library(library)
            .with_source_files(source_files),
    )
}

/// The architecture of a COFF `Machine` value.
fn map_arch(machine: u16) -> Arch {
    match machine {
        COFF_MACHINE_X86 => Arch::I386,
        COFF_MACHINE_X86_64 => Arch::Amd64,
        COFF_MACHINE_ARM => Arch::Arm,
        COFF_MACHINE_ARM64 => Arch::Aarch64,
        COFF_MACHINE_RISCV32 => Arch::Riscv32,
        COFF_MACHINE_RISCV64 => Arch::Riscv64,
        _ => Arch::Other,
    }
}

/// Every section table entry, at `image_base + VirtualAddress`, with its raw
/// file data (`SizeOfRawData` bytes, which may be shorter than the virtual
/// size, the rest being zero-fill, or longer, up to the file alignment).
fn collect_sections<'a>(bytes: &'a [u8], pe: &PE<'a>) -> Vec<Section<'a>> {
    let mut out = Vec::with_capacity(pe.sections.len());
    for s in &pe.sections {
        let name = section_name(s);
        let vm_addr = pe.image_base.wrapping_add(u64::from(s.virtual_address));
        let vm_size = u64::from(s.virtual_size);

        let file_offset = s.pointer_to_raw_data as usize;
        let file_size = s.size_of_raw_data as usize;
        let data = bytes
            .get(file_offset..file_offset.saturating_add(file_size))
            .unwrap_or(&[]);

        let kind = classify(&name, s.characteristics);
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

/// The section's name: the long name goblin resolved from the COFF string
/// table (`/4` style references, used by mingw for `.debug_*`), else the
/// 8-byte inline name.
fn section_name(s: &SectionTable) -> String {
    if let Some(ref real) = s.real_name {
        return real.clone();
    }
    // Inline name is 8 bytes, NUL-padded.
    let end = s.name.iter().position(|&b| b == 0).unwrap_or(s.name.len());
    let bytes = s.name.get(..end).unwrap_or(&[]);
    String::from_utf8_lossy(bytes).into_owned()
}

/// Maps section characteristics to a [`SectionKind`]: uninitialized data is
/// zero-fill, code or executable is text, discardable sections (debug info,
/// relocations) are not program data, initialized data is read-only or
/// writable by its write flag. The name decides only for sections with none
/// of these flags.
fn classify(name: &str, characteristics: u32) -> SectionKind {
    let exec = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
    let write = characteristics & IMAGE_SCN_MEM_WRITE != 0;
    let code = characteristics & IMAGE_SCN_CNT_CODE != 0;
    let init_data = characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0;
    let uninit_data = characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0;

    if uninit_data {
        return SectionKind::Bss;
    }
    if code || exec {
        return SectionKind::Text;
    }
    // Discardable sections are not needed once loaded: DWARF from mingw
    // (`.debug_*`), relocations. Their bytes are not program data and must
    // not reach the data scans.
    if characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0 {
        return SectionKind::Other;
    }
    if init_data && !write {
        return SectionKind::RoData;
    }
    if init_data && write {
        return SectionKind::Data;
    }

    match name {
        ".rdata" | ".rodata" => SectionKind::RoData,
        ".data" => SectionKind::Data,
        ".text" => SectionKind::Text,
        ".bss" => SectionKind::Bss,
        _ => SectionKind::Other,
    }
}

/// A symbol with the source file of the `.file` record it follows (COFF
/// lists each object file's symbols, static and external, after it).
type SourcedSymbol<'a> = (Symbol<'a>, Option<Cow<'a, str>>);

/// The export table, then the COFF symbol table when the file keeps one,
/// each symbol with the source file of the `.file` record it follows.
/// Auxiliary records are skipped (goblin's iterator does so), symbols with
/// empty or unreadable names dropped. An export the COFF table lists too
/// (same name and address) is one symbol: the COFF entry, which knows its
/// source file, is kept.
fn collect_symbols<'a>(bytes: &'a [u8], pe: &PE<'a>) -> Result<Vec<SourcedSymbol<'a>>> {
    let mut out = Vec::new();
    // 32-bit Windows decorates C-level names; strip it here so every scan
    // sees the names the source declared (as for Mach-O's leading `_`).
    let i386 = pe.header.coff_header.machine == COFF_MACHINE_X86;
    let plain = |name: Cow<'a, str>| -> Cow<'a, str> {
        if !i386 {
            return name;
        }
        match name {
            Cow::Borrowed(n) => undecorate_i386(n),
            Cow::Owned(n) => Cow::Owned(undecorate_i386(&n).into_owned()),
        }
    };
    let mut file: Option<Cow<'a, str>> = None;

    // Exported symbols surface even when the COFF symbol table is stripped.
    let mut exports = Vec::new();
    for exp in &pe.exports {
        if let Some(name) = exp.name {
            exports.push((
                Symbol {
                    name: plain(Cow::Borrowed(name)),
                    vm_addr: pe.image_base.wrapping_add(exp.rva as u64),
                    size: 0, // PE exports don't carry size
                    kind: SymbolKind::Function,
                },
                None,
            ));
        }
    }

    // COFF symbol table (typically present on MinGW-linked executables).
    let sym_ptr = pe.header.coff_header.pointer_to_symbol_table as usize;
    let nsyms = pe.header.coff_header.number_of_symbol_table as usize;
    if sym_ptr == 0 || nsyms == 0 {
        return Ok(exports);
    }

    // Goblin's `CoffHeader::strings` handles the 4-byte length prefix
    // correctly (advancing past it and subtracting 4 from the declared
    // length). Rolling the parse by hand leaves a classic off-by-4 that
    // makes every strtab-referenced symbol name come out as the final
    // 3 characters of the previous symbol.
    let strtab = match pe.header.coff_header.strings(bytes) {
        Ok(Some(s)) => s,
        _ => goblin::strtab::Strtab::new(&[], 0),
    };

    let symtab = match SymbolTable::parse(bytes, sym_ptr, nsyms) {
        Ok(t) => t,
        Err(_) => return Ok(exports),
    };

    for (index, _inline, sym) in symtab.iter() {
        // Resolve the symbol name. Long names live in the COFF string
        // table (borrow from `bytes` via strtab), short names are inline
        // in the symbol record and must be copied out.
        //
        // `.file` records are a special case: the short inline name is
        // literally ".file" and the actual source filename is stored in
        // one or more auxiliary symbol records that follow. Goblin's
        // `aux_file` reads them for us.
        let is_file_record =
            sym.storage_class == IMAGE_SYM_CLASS_FILE && sym.number_of_aux_symbols > 0;
        let name: Cow<'a, str> = if is_file_record {
            // Aux records live at `(main_index + 1) * COFF_SYMBOL_SIZE`,
            // and goblin's helper takes the aux record's own index. A name
            // too long for the record is a string-table reference instead.
            let aux =
                sym_ptr.saturating_add(index.saturating_add(1).saturating_mul(COFF_SYMBOL_SIZE));
            let long = bytes
                .get(aux..aux.saturating_add(8))
                .and_then(string_table_ref)
                .and_then(|o| strtab.get_at(o));
            let name = long.or_else(|| {
                symtab.aux_file(index.saturating_add(1), sym.number_of_aux_symbols as usize)
            });
            file = name.filter(|s| !s.is_empty()).map(Cow::Borrowed);
            match &file {
                Some(s) => s.clone(),
                None => continue,
            }
        } else if let Some(offset) = string_table_ref(&sym.name) {
            // Not goblin's `Symbol::name_offset`, which subtracts the length
            // prefix unchecked and panics on offsets below 4.
            match strtab.get_at(offset) {
                Some(s) if !s.is_empty() => Cow::Borrowed(s),
                _ => continue,
            }
        } else {
            let end = sym.name.iter().position(|&b| b == 0).unwrap_or(8);
            if end == 0 {
                continue;
            }
            Cow::Owned(String::from_utf8_lossy(sym.name.get(..end).unwrap_or(&[])).into_owned())
        };
        let kind = classify_symbol(sym.storage_class, sym.typ);
        let section_va = if sym.section_number > 0 {
            pe.sections
                .get((sym.section_number as usize).saturating_sub(1))
                .map(|s| pe.image_base.wrapping_add(u64::from(s.virtual_address)))
                .unwrap_or(0)
        } else {
            0
        };
        let source = if is_file_record { None } else { file.clone() };
        let name = if is_file_record { name } else { plain(name) };
        out.push((
            Symbol {
                name,
                vm_addr: section_va.wrapping_add(u64::from(sym.value)),
                size: 0, // COFF symbols don't carry size
                kind,
            },
            source,
        ));
    }

    let listed: HashSet<(&str, u64)> = out
        .iter()
        .map(|(s, _)| (s.name.as_ref(), s.vm_addr))
        .collect();
    exports.retain(|(s, _)| !listed.contains(&(s.name.as_ref(), s.vm_addr)));
    drop(listed);
    exports.append(&mut out);
    Ok(exports)
}

/// Removes the 32-bit Windows C name decoration: `_name` (cdecl),
/// `_name@N` (stdcall) and `@name@N` (fastcall, Nim's `N_NIMCALL` on i386)
/// become `name`. An `__imp_` prefix (import pointer) and a trailing
/// `.suffix` (compiler clones such as `.cold`) are kept around the
/// undecorated name; names starting with `.` (sections) are left alone.
fn undecorate_i386(name: &str) -> Cow<'_, str> {
    if name.starts_with('.') {
        return Cow::Borrowed(name);
    }
    let (imp, rest) = match name.strip_prefix("__imp_") {
        Some(rest) => ("__imp_", rest),
        None => ("", name),
    };
    let (base, clone) = rest.split_at(rest.find('.').unwrap_or(rest.len()));
    // `name@N` with a decimal byte count `N`.
    let drop_byte_count = |s: &'_ str| -> usize {
        match s.rsplit_once('@') {
            Some((n, d))
                if !n.is_empty() && !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()) =>
            {
                n.len()
            }
            _ => s.len(),
        }
    };
    let core = match base.strip_prefix('@').or_else(|| base.strip_prefix('_')) {
        Some(undecorated) => undecorated
            .get(..drop_byte_count(undecorated))
            .unwrap_or(undecorated),
        None => base,
    };
    // A bare `_` or `@` is not a decorated name.
    let core = if core.is_empty() { base } else { core };
    if imp.is_empty() && clone.is_empty() {
        Cow::Borrowed(core)
    } else {
        Cow::Owned(format!("{imp}{core}{clone}"))
    }
}

/// The string-table offset a COFF name field refers to: four zero bytes,
/// then a little-endian offset counted from the table's 4-byte length
/// prefix, which goblin's `Strtab` skips. `None` for an inline name or an
/// offset inside the prefix.
fn string_table_ref(field: &[u8]) -> Option<usize> {
    let (zero, offset) = field.get(..8)?.split_at(4);
    if zero != [0, 0, 0, 0] {
        return None;
    }
    let offset = u32::from_le_bytes(offset.try_into().ok()?).checked_sub(4)?;
    usize::try_from(offset).ok()
}

/// Maps a COFF storage class and type to a [`SymbolKind`]: `.file` records are
/// files, a derived type of `DTYPE_FUNCTION` marks a function.
fn classify_symbol(storage_class: u8, typ: u16) -> SymbolKind {
    if storage_class == IMAGE_SYM_CLASS_FILE {
        return SymbolKind::File;
    }
    // High nibble of typ describes the "derived type"; DTYPE_FUNCTION marks
    // a function.
    if (typ >> 4) == IMAGE_SYM_DTYPE_FUNCTION {
        SymbolKind::Function
    } else {
        SymbolKind::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i386_names_are_undecorated() {
        for (decorated, plain) in [
            ("_NimMain", "NimMain"),
            ("@NimMainModule@0", "NimMainModule"),
            ("@inner_u0__exceptions@4", "inner_u0__exceptions"),
            ("@atpsystemdotnim_Init000@0", "atpsystemdotnim_Init000"),
            ("@raiseExceptionEx@20.cold", "raiseExceptionEx.cold"),
            ("_GetProcAddress@8", "GetProcAddress"),
            ("__imp__memcpy", "__imp_memcpy"),
            ("___chkstk_ms", "__chkstk_ms"),
            (
                "_NTIv2__7xsYZDjhUlUJFVmSFObsig_",
                "NTIv2__7xsYZDjhUlUJFVmSFObsig_",
            ),
            (".text", ".text"),
            ("plain", "plain"),
            // `@` not followed by a byte count stays.
            ("_a@b", "a@b"),
            ("@", "@"),
            ("_", "_"),
        ] {
            assert_eq!(undecorate_i386(decorated), plain, "{decorated}");
        }
    }

    #[test]
    fn string_table_refs() {
        let field = |head: [u8; 4], offset: u32| -> Vec<u8> {
            let mut f = head.to_vec();
            f.extend_from_slice(&offset.to_le_bytes());
            f
        };
        assert_eq!(string_table_ref(&field([0; 4], 4)), Some(0));
        assert_eq!(string_table_ref(&field([0; 4], 0x8a)), Some(0x86));
        // Offsets inside the length prefix are invalid, not an underflow.
        assert_eq!(string_table_ref(&field([0; 4], 0)), None);
        assert_eq!(string_table_ref(&field([0; 4], 3)), None);
        // An inline name.
        assert_eq!(string_table_ref(b".text\0\0\0"), None);
        assert_eq!(string_table_ref(&[0; 4]), None);
    }
}
