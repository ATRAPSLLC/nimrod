//! Static evaluation of the `DatInit000` functions.
//!
//! The legacy RTTI (`TNimType` / `TNimNode`, refc builds of every Nim
//! version) and the pre-2.0 `TNimTypeV2` objects are zero in the file: each
//! module's `DatInit000` fills them at startup. This module runs those
//! functions on a small emulator and records the bytes they write into the
//! image (an [`Overlay`]); [`Patched`] then serves the image with the writes
//! applied, so the RTTI readers see what the runtime would.
//!
//! The emulators ([`x86`], [`arm64`]) cover the instructions compilers emit
//! for these functions, which are long runs of constant stores. Values are
//! verified against runtime memory dumps of the fixtures (a gdb oracle,
//! `tests/build_fixtures/oracle/`).
//!
//! Safety rules, for adversarial input:
//! - only instructions the emulator fully understands execute; anything else
//!   stops that function, keeping the writes made so far (they are exact
//!   values, the object is just incomplete);
//! - every function runs under an instruction budget ([`STEP_BUDGET`]), all
//!   of them together under [`TOTAL_STEP_BUDGET`], the overlay under a size
//!   cap ([`OVERLAY_CAP`]), and a write outside the image's data sections and
//!   the emulated stack stops the function;
//! - nothing outside `DatInit000` functions is executed, except the
//!   `memcpy`/`memmove`/`memset` calls they make, which are emulated;
//! - big-endian images are not evaluated (the emulated memory is
//!   little-endian).

pub mod arm64;
pub mod x86;

use std::{borrow::Cow, collections::HashMap};

use crate::container::{Arch, Container, Section, SectionKind};

/// Instructions one `DatInit000` may execute.
pub const STEP_BUDGET: u64 = 2_000_000;

/// Instructions all `DatInit000` functions of a binary may execute together:
/// the symbol table decides how many there are, so a hostile one must not
/// multiply [`STEP_BUDGET`].
pub const TOTAL_STEP_BUDGET: u64 = 20_000_000;

/// Most image bytes the overlay may hold.
pub const OVERLAY_CAP: usize = 16 << 20;

/// Largest section [`Patched`] materialises (a huge `.bss` is not copied).
pub const SECTION_CAP: u64 = 64 << 20;

/// Bytes written into the image by the evaluated functions.
#[derive(Debug, Default, Clone)]
pub struct Overlay {
    /// Written bytes by virtual address; later writes replace earlier ones.
    writes: HashMap<u64, u8>,
}

impl Overlay {
    /// Whether nothing was written.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// The byte written at `va`, if any.
    pub fn get(&self, va: u64) -> Option<u8> {
        self.writes.get(&va).copied()
    }

    /// Addresses written.
    pub fn addresses(&self) -> impl Iterator<Item = u64> + '_ {
        self.writes.keys().copied()
    }

    /// Records a write; refuses once the cap is reached.
    pub fn put(&mut self, va: u64, byte: u8) -> bool {
        if self.writes.len() >= OVERLAY_CAP && !self.writes.contains_key(&va) {
            return false;
        }
        self.writes.insert(va, byte);
        true
    }
}

/// Reads a byte of the image as loaded: file bytes for file-backed
/// sections, zero inside `.bss`-like sections, `None` outside the image.
pub fn image_byte(container: &Container<'_>, va: u64) -> Option<u8> {
    let s = container.section_at(va)?;
    let off = usize::try_from(va.checked_sub(s.vm_addr)?).ok()?;
    Some(s.data.get(off).copied().unwrap_or(0))
}

/// Whether `va` lies inside a writable or zero-initialised image section
/// (the only places `DatInit000` legitimately writes).
pub fn is_writable_image(container: &Container<'_>, va: u64) -> bool {
    container.section_at(va).is_some_and(|s| s.kind.is_data())
}

/// Base of the emulated stack (outside any image).
pub const STACK_TOP: u64 = 0x7fff_f000_0000;
/// Emulated stack size.
pub const STACK_SIZE: u64 = 1 << 20;

/// Memory as seen by an emulated `DatInit000`: the overlay over the image,
/// plus a private stack. Writes outside writable image sections and the
/// stack are refused.
pub struct Mem<'c, 'a, 'o> {
    /// The image read through.
    pub container: &'c Container<'a>,
    /// Where image writes go.
    pub overlay: &'o mut Overlay,
    /// The emulated stack's bytes (unwritten ones read as zero).
    pub stack: HashMap<u64, u8>,
    /// Loader-filled pointer words ([`Container::pointer_fixups`]).
    pub fixups: &'c HashMap<u64, u64>,
}

impl Mem<'_, '_, '_> {
    /// Whether `va` is inside the emulated stack.
    fn in_stack(va: u64) -> bool {
        va < STACK_TOP && va >= STACK_TOP.wrapping_sub(STACK_SIZE)
    }

    /// One byte, or `None` outside the image and the stack.
    pub fn read_u8(&self, va: u64) -> Option<u8> {
        if Self::in_stack(va) {
            return Some(self.stack.get(&va).copied().unwrap_or(0));
        }
        self.overlay
            .get(va)
            .or_else(|| self.fixup_byte(va))
            .or_else(|| image_byte(self.container, va))
    }

    /// The byte at `va` of a loader-filled pointer word, if one covers it.
    fn fixup_byte(&self, va: u64) -> Option<u8> {
        (0..8u64).find_map(|k| {
            let start = va.checked_sub(k)?;
            let v = self.fixups.get(&start)?;
            Some((v >> (k.saturating_mul(8))) as u8)
        })
    }

    /// Writes one byte; `None` when the address is not writable.
    pub fn write_u8(&mut self, va: u64, b: u8) -> Option<()> {
        if Self::in_stack(va) {
            self.stack.insert(va, b);
            return Some(());
        }
        (is_writable_image(self.container, va) && self.overlay.put(va, b)).then_some(())
    }

    /// Little-endian read of `size` (1..=8) bytes.
    pub fn read(&self, va: u64, size: u32) -> Option<u64> {
        let mut v: u64 = 0;
        for i in (0..size).rev() {
            v = (v << 8) | u64::from(self.read_u8(va.wrapping_add(u64::from(i)))?);
        }
        Some(v)
    }

    /// Little-endian write of `size` (1..=8) bytes.
    pub fn write(&mut self, va: u64, size: u32, v: u64) -> Option<()> {
        for i in 0..size {
            self.write_u8(
                va.wrapping_add(u64::from(i)),
                (v >> (i.saturating_mul(8))) as u8,
            )?;
        }
        Some(())
    }

    /// 16-byte read.
    pub fn read128(&self, va: u64) -> Option<u128> {
        let lo = self.read(va, 8)?;
        let hi = self.read(va.wrapping_add(8), 8)?;
        Some(u128::from(lo) | (u128::from(hi) << 64))
    }

    /// 16-byte write.
    pub fn write128(&mut self, va: u64, v: u128) -> Option<()> {
        self.write(va, 8, v as u64)?;
        self.write(va.wrapping_add(8), 8, (v >> 64) as u64)
    }
}

/// Runs every `*DatInit000` function of the binary, sharing `step_budget`
/// instructions between them (at most [`STEP_BUDGET`] each; pass
/// [`TOTAL_STEP_BUDGET`] outside tests), and returns the bytes they wrote.
/// The overlay is empty for unsupported architectures, big-endian images
/// (the emulated memory is little-endian) and stripped binaries.
pub fn evaluate_datinits(container: &Container<'_>, step_budget: u64) -> Overlay {
    let mut overlay = Overlay::default();
    if !container.is_little_endian() {
        return overlay;
    }
    let mut inits: Vec<u64> = container
        .symbols()
        .iter()
        .filter(|s| s.is_defined_function())
        .filter(|s| s.name.ends_with("DatInit000"))
        .map(|s| s.vm_addr)
        .collect();
    inits.sort_unstable();
    inits.dedup();
    let fixups: HashMap<u64, u64> = container.pointer_fixups().iter().copied().collect();
    let helpers = match container.arch() {
        Arch::Amd64 => x86::helper_functions(container),
        Arch::Aarch64 => HashMap::new(),
        _ => return overlay,
    };
    let mut left = step_budget;
    for entry in inits {
        if left == 0 {
            break;
        }
        let budget = left.min(STEP_BUDGET);
        let used = match container.arch() {
            Arch::Amd64 => x86::run(container, entry, &mut overlay, &fixups, &helpers, budget),
            _ => arm64::run(container, entry, &mut overlay, &fixups, budget),
        };
        left = left.saturating_sub(used);
    }
    overlay
}

/// The image with an [`Overlay`] applied to its data sections.
pub struct Patched {
    /// A copy of the input file, with the patched sections' bytes appended.
    buf: Vec<u8>,
    /// Per original section: `(offset, len, kind)` of its bytes in `buf`.
    layout: Vec<Option<(usize, usize, SectionKind)>>,
}

impl Patched {
    /// Copies the image and applies `overlay` to every data, read-only data
    /// and `.bss` section it touches (up to [`SECTION_CAP`] each).
    pub fn new(container: &Container<'_>, overlay: &Overlay) -> Self {
        let bytes = container.bytes();
        let mut buf = bytes.to_vec();
        let mut layout = Vec::new();
        let sections = container.sections();
        let mut hit = vec![false; sections.len()];
        for va in overlay.addresses() {
            if let Some(hit_section) = container.section_at(va)
                && let Some(i) = sections.iter().position(|s| std::ptr::eq(s, hit_section))
                && let Some(h) = hit.get_mut(i)
            {
                *h = true;
            }
        }
        for (s, &was_hit) in sections.iter().zip(&hit) {
            let touched = was_hit && s.kind.is_data() && s.vm_size <= SECTION_CAP;
            if !touched {
                layout.push(None);
                continue;
            }
            let Ok(len) = usize::try_from(s.vm_size) else {
                layout.push(None);
                continue;
            };
            let off = buf.len();
            let mut data = vec![0u8; len];
            for (i, b) in data.iter_mut().enumerate() {
                let va = s.vm_addr.wrapping_add(i as u64);
                *b = overlay
                    .get(va)
                    .or_else(|| s.data.get(i).copied())
                    .unwrap_or(0);
            }
            buf.extend_from_slice(&data);
            let kind = if s.kind == SectionKind::Bss {
                SectionKind::Data
            } else {
                s.kind
            };
            layout.push(Some((off, len, kind)));
        }
        Self { buf, layout }
    }

    /// A container over the patched bytes; sections the overlay did not
    /// touch keep their original file bytes.
    pub fn container(&self, original: &Container<'_>) -> Container<'_> {
        let base = original.bytes().as_ptr() as usize;
        let sections = original
            .sections()
            .iter()
            .zip(&self.layout)
            .map(|(s, place)| {
                let (data, kind) = match place {
                    Some((off, len, kind)) => (
                        self.buf.get(*off..off.saturating_add(*len)).unwrap_or(&[]),
                        *kind,
                    ),
                    None => {
                        let start = (s.data.as_ptr() as usize).wrapping_sub(base);
                        let data = if s.data.is_empty() {
                            &[][..]
                        } else {
                            self.buf
                                .get(start..start.saturating_add(s.data.len()))
                                .unwrap_or(&[])
                        };
                        (data, s.kind)
                    }
                };
                Section {
                    name: s.name.clone(),
                    kind,
                    vm_addr: s.vm_addr,
                    vm_size: s.vm_size,
                    data,
                }
            })
            .collect();
        let symbols = original
            .symbols()
            .iter()
            .map(|s| crate::container::Symbol {
                name: Cow::Owned(s.name.clone().into_owned()),
                vm_addr: s.vm_addr,
                size: s.size,
                kind: s.kind,
            })
            .collect();
        Container::from_parts(
            &self.buf,
            original.format(),
            original.arch(),
            original.image_base(),
            sections,
            symbols,
        )
        .with_little_endian(original.is_little_endian())
        .with_pointer_bits(original.pointer_bits())
        .with_library(original.is_library())
        .with_imports(
            original
                .imports()
                .iter()
                .map(|i| crate::container::Import {
                    name: Cow::Owned(i.name.clone().into_owned()),
                    library: i
                        .library
                        .as_ref()
                        .map(|l| Cow::Owned(l.clone().into_owned())),
                })
                .collect(),
        )
        .with_pointer_fixups(original.pointer_fixups().to_vec())
        .with_source_files(
            (0..original.symbols().len())
                .map(|i| {
                    original
                        .symbol_source_file(i)
                        .map(|f| Cow::Owned(f.to_owned()))
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::container::{Format, Symbol, SymbolKind};

    pub const TEXT: u64 = 0x1000;
    pub const RODATA: u64 = 0x2000;
    pub const BSS: u64 = 0x3000;

    /// A container with `code` at `TEXT` (symbol `fooDatInit000`), 32 bytes
    /// of `rodata` at `RODATA` and 0x100 bytes of `.bss` at `BSS`.
    pub fn image(
        arch: Arch,
        code: &[u8],
        rodata: &[u8],
    ) -> (&'static [u8], Vec<Section<'static>>, Vec<Symbol<'static>>) {
        let mut bytes = code.to_vec();
        let ro_off = bytes.len();
        bytes.extend_from_slice(rodata);
        let bytes: &'static [u8] = Box::leak(bytes.into_boxed_slice());
        let _ = arch;
        let sections = vec![
            Section {
                name: ".text".into(),
                kind: SectionKind::Text,
                vm_addr: TEXT,
                vm_size: code.len() as u64,
                data: &bytes[..ro_off],
            },
            Section {
                name: ".rodata".into(),
                kind: SectionKind::RoData,
                vm_addr: RODATA,
                vm_size: rodata.len() as u64,
                data: &bytes[ro_off..],
            },
            Section {
                name: ".bss".into(),
                kind: SectionKind::Bss,
                vm_addr: BSS,
                vm_size: 0x100,
                data: &[],
            },
        ];
        let symbols = vec![Symbol {
            name: Cow::Borrowed("fooDatInit000"),
            vm_addr: TEXT,
            size: code.len() as u64,
            kind: SymbolKind::Function,
        }];
        (bytes, sections, symbols)
    }

    pub fn evaluate(arch: Arch, code: &[u8], rodata: &[u8]) -> Overlay {
        let (bytes, sections, symbols) = image(arch, code, rodata);
        let c = Container::from_parts(bytes, Format::Elf, arch, 0, sections, symbols);
        evaluate_datinits(&c, TOTAL_STEP_BUDGET)
    }

    pub fn bytes_at(o: &Overlay, va: u64, n: u64) -> Vec<Option<u8>> {
        (0..n).map(|i| o.get(va + i)).collect()
    }

    /// `rel32` from the end of an instruction of `len` bytes at `at`.
    pub fn rel(at: u64, len: u64, target: u64) -> [u8; 4] {
        ((target as i64 - (at + len) as i64) as i32).to_le_bytes()
    }

    #[test]
    fn patched_container_serves_overlay_bytes() {
        let mut o = Overlay::default();
        o.put(BSS + 4, 0xab);
        let (bytes, sections, symbols) = image(Arch::Amd64, &[0xc3], &[0; 4]);
        let n = symbols.len();
        let c = Container::from_parts(bytes, Format::Elf, Arch::Amd64, 0, sections, symbols)
            .with_pointer_bits(32)
            .with_library(true)
            .with_imports(vec![crate::container::Import {
                name: Cow::Borrowed("memcpy"),
                library: None,
            }])
            .with_pointer_fixups(vec![(BSS, 0x1234)])
            .with_source_files(vec![Some(Cow::Borrowed("@mmain.nim.c")); n]);
        let p = Patched::new(&c, &o);
        let pc = p.container(&c);
        let bss = pc.sections().iter().find(|s| s.vm_addr == BSS).unwrap();
        assert_eq!(bss.kind, SectionKind::Data);
        assert_eq!(bss.data.len(), 0x100);
        assert_eq!(bss.data[4], 0xab);
        assert_eq!(bss.data[5], 0);
        // Everything but the data carries over.
        assert_eq!(pc.pointer_bits(), 32);
        assert!(pc.is_library());
        assert_eq!(
            pc.imports().first().map(|i| i.name.as_ref()),
            Some("memcpy")
        );
        assert_eq!(pc.pointer_fixups(), &[(BSS, 0x1234)]);
        assert_eq!(pc.symbol_source_file(0), Some("@mmain.nim.c"));
    }

    #[test]
    fn many_endless_datinits_share_one_budget() {
        // 500 `DatInit000` functions at their own addresses, each looping
        // `inc dword [counter]; jmp back`: the shared counter in `.bss` ends
        // at half the instructions run over all of them.
        const N: u64 = 500;
        let mut code = Vec::new();
        for i in 0..N {
            let next = TEXT + 8 * i + 6;
            code.extend_from_slice(&[0xff, 0x05]);
            code.extend_from_slice(&((BSS as i64 - next as i64) as i32).to_le_bytes());
            code.extend_from_slice(&[0xeb, 0xf8]);
        }
        let (bytes, sections, _) = image(Arch::Amd64, &code, &[0; 4]);
        let symbols: Vec<Symbol<'static>> = (0..N)
            .map(|i| Symbol {
                name: Cow::Owned(format!("m{i}DatInit000")),
                vm_addr: TEXT + 8 * i,
                size: 8,
                kind: SymbolKind::Function,
            })
            .collect();
        let c = Container::from_parts(bytes, Format::Elf, Arch::Amd64, 0, sections, symbols);
        let overlay = evaluate_datinits(&c, 50_000);
        let counter = u32::from_le_bytes(
            bytes_at(&overlay, BSS, 4)
                .into_iter()
                .map(|b| b.unwrap_or(0))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        assert_eq!(counter, 25_000);
    }

    #[test]
    fn overlay_cap_refuses_new_addresses() {
        let mut o = Overlay::default();
        assert!(o.put(1, 1));
        assert!(
            o.put(1, 2),
            "rewriting a recorded address is always allowed"
        );
    }

    #[test]
    fn unloaded_sections_do_not_answer_lookups() {
        // A debug section at address 0 must not shadow `.rodata`.
        let (bytes, mut sections, symbols) = image(Arch::Amd64, &[0xc3], &[7; 4]);
        let debug: &'static [u8] = Box::leak(vec![9u8; 0x4000].into_boxed_slice());
        sections.insert(
            0,
            Section {
                name: ".debug_info".into(),
                kind: SectionKind::Other,
                vm_addr: 0,
                vm_size: 0x4000,
                data: debug,
            },
        );
        let c = Container::from_parts(bytes, Format::Elf, Arch::Amd64, 0, sections, symbols);
        assert_eq!(image_byte(&c, RODATA), Some(7));
        assert!(!is_writable_image(&c, 0x10));
    }
}
