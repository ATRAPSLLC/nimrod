//! Mach-O backend for the container abstraction.
//!
//! Reads single-architecture Mach-O images and, for fat (universal) files,
//! the first slice. A slice is a complete Mach-O image whose file offsets
//! count from its own start; its sections still borrow from the input
//! buffer, so their data sits at its true position in the file.
//!
//! Section names are qualified with their segment (`__DATA,__common`), the
//! leading `_` of C-level symbol names is stripped, imports come from the
//! bind opcodes, and byte order and pointer width from the header magic.
//! Mach-O records no per-symbol source file and no relocation-derived
//! pointer values here: [`Container::symbol_source_file`] and
//! [`Container::pointer_fixups`] stay empty.

use std::borrow::Cow;

use goblin::mach::{
    Mach, MachO,
    constants::cputype::{CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_I386, CPU_TYPE_X86_64},
    header::{MH_BUNDLE, MH_DYLIB},
    symbols::{N_SECT, Nlist},
};

use crate::{
    container::{Arch, Container, Format, Import, Section, SectionKind, Symbol, SymbolKind},
    error::{Error, Result},
};

/// Builds the container for a Mach-O file goblin has parsed: the image itself,
/// or the first slice of a fat file.
pub fn build<'a>(bytes: &'a [u8], mach: Mach<'a>) -> Result<Container<'a>> {
    // A fat file's slices are complete Mach-O images whose file offsets
    // count from the slice's start, so the first slice is parsed on its own
    // bytes (which still borrow from `bytes`, keeping section data at its
    // true position in the file).
    let (macho, image) = match mach {
        Mach::Binary(m) => (m, bytes),
        Mach::Fat(fat) => {
            let arches = fat.arches()?;
            let first = arches.first().ok_or(Error::UnsupportedFormat)?;
            let image = first.slice(bytes);
            if image.is_empty() {
                return Err(Error::UnsupportedFormat);
            }
            (MachO::parse(image, 0)?, image)
        }
    };

    let arch = map_arch(macho.header.cputype);
    let image_base = macho
        .segments
        .iter()
        .map(|seg| seg.vmaddr)
        .filter(|&v| v != 0)
        .min()
        .unwrap_or(0);
    let sections = collect_sections(image, &macho)?;
    let symbols = collect_symbols(&macho)?;
    // A malformed bind stream yields no imports rather than an error: the
    // rest of the image is still usable.
    let imports = macho
        .imports()
        .map(|list| {
            list.iter()
                .map(|i| Import {
                    // goblin's names borrow from the `MachO`, not the input.
                    name: Cow::Owned(i.name.strip_prefix('_').unwrap_or(i.name).to_owned()),
                    library: Some(Cow::Owned(i.dylib.to_owned())),
                })
                .collect()
        })
        .unwrap_or_default();
    let library = matches!(macho.header.filetype, MH_DYLIB | MH_BUNDLE);
    Ok(
        Container::from_parts(bytes, Format::MachO, arch, image_base, sections, symbols)
            .with_little_endian(macho.little_endian)
            .with_pointer_bits(if macho.is_64 { 64 } else { 32 })
            .with_imports(imports)
            .with_library(library),
    )
}

/// The architecture of a Mach-O `cputype`.
fn map_arch(cputype: u32) -> Arch {
    match cputype {
        CPU_TYPE_X86_64 => Arch::Amd64,
        CPU_TYPE_I386 => Arch::I386,
        CPU_TYPE_ARM64 => Arch::Aarch64,
        CPU_TYPE_ARM => Arch::Arm,
        _ => Arch::Other,
    }
}

/// Every section of every segment, named `<segment>,<section>`
/// (`__TEXT,__cstring`), with its data taken from `bytes`, the Mach-O image
/// (for a fat file, its slice). Zero-fill sections have no data.
fn collect_sections<'a>(bytes: &'a [u8], macho: &MachO<'a>) -> Result<Vec<Section<'a>>> {
    let mut out = Vec::new();
    for seg in &macho.segments {
        let segname = seg.name().unwrap_or("").to_string();
        for section in seg.into_iter() {
            let (sect, _data) = match section {
                Ok(s) => s,
                Err(_) => continue,
            };
            let sectname = sect.name().unwrap_or("").to_string();
            let qualified = format!("{segname},{sectname}");

            let vm_addr = sect.addr;
            let vm_size = sect.size;

            let file_offset = sect.offset as usize;
            let file_size = sect.size as usize;
            let data: &'a [u8] = if file_offset == 0 {
                // A zero offset on Mach-O usually means the section has no
                // file backing (__bss, __common).
                &[]
            } else {
                bytes
                    .get(file_offset..file_offset.saturating_add(file_size))
                    .unwrap_or(&[])
            };

            let kind = classify(&segname, &sectname);
            out.push(Section {
                name: qualified,
                vm_addr,
                vm_size,
                data,
                kind,
            });
        }
    }
    Ok(out)
}

/// Maps a segment and section name to a [`SectionKind`]: `__TEXT,__text` is
/// code and the rest of `__TEXT` read-only data, `__DATA_CONST` is read-only
/// data (pointers the loader binds once), `__DATA,__bss` and `__common` are
/// zero-fill, other `__DATA` sections writable data, and anything else
/// (`__LINKEDIT`, `__PAGEZERO`) not program data.
fn classify(segname: &str, sectname: &str) -> SectionKind {
    match segname {
        "__TEXT" => match sectname {
            "__text" => SectionKind::Text,
            "__cstring" | "__const" | "__ustring" | "__gcc_except_tab" | "__eh_frame" => {
                SectionKind::RoData
            }
            _ => SectionKind::RoData, // __TEXT is read-only by convention
        },
        "__DATA_CONST" => SectionKind::RoData,
        "__DATA" => match sectname {
            "__bss" | "__common" => SectionKind::Bss,
            _ => SectionKind::Data,
        },
        _ => SectionKind::Other,
    }
}

/// The nlist symbols, debugger (`stab`) entries skipped and the C-level
/// leading `_` stripped so names match the other formats (`NimMain`).
fn collect_symbols<'a>(macho: &MachO<'a>) -> Result<Vec<Symbol<'a>>> {
    let mut out = Vec::new();
    for result in macho.symbols() {
        let (name, nlist) = match result {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        if name.is_empty() || nlist.is_stab() {
            continue;
        }
        // Mach-O C-level symbols are prefixed with a leading underscore.
        // Strip it so that probes matching "NimMain" work uniformly across
        // all three formats.
        let normalised: Cow<'a, str> = if let Some(stripped) = name.strip_prefix('_') {
            Cow::Borrowed(stripped)
        } else {
            Cow::Borrowed(name)
        };
        let kind = classify_symbol(&nlist);
        out.push(Symbol {
            name: normalised,
            vm_addr: nlist.n_value,
            size: 0, // Mach-O nlist doesn't carry size
            kind,
        });
    }
    Ok(out)
}

/// Section-defined symbols (`N_SECT`) as functions, everything else
/// [`SymbolKind::Other`]: nlist records carry no function/data distinction.
fn classify_symbol(nlist: &Nlist) -> SymbolKind {
    if nlist.get_type() == N_SECT {
        // Distinguishing function vs data requires looking at the target
        // section; we report all defined symbols as functions by default
        // and rely on downstream consumers to refine.
        SymbolKind::Function
    } else {
        SymbolKind::Other
    }
}
