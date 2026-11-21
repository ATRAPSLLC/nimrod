//! Low-level reading helpers shared by the scans.
//!
//! - [`DataLayout`]: words in an image's byte order and pointer width, the
//!   one reader every data scan uses (with [`DataLayout::LE64`] for
//!   instruction streams).
//! - [`slice_cstring`], [`cstrings`] and [`read_cstring_at_va`]: C strings in
//!   section bytes or at a virtual address.
//! - [`va_to_offset`]: a virtual address's offset in the input file.
//! - [`encode_unique_name`]: the compiler's `uniqueModuleName` encoding.
//!
//! The readers never panic: out-of-range reads give zero or `None`, since
//! the scans probe binary data where such reads are expected. The module is
//! private, so its `pub` items are crate-internal.

use crate::container::Container;

/// The `N` bytes at `offset`, if all are inside `data`.
#[inline(always)]
fn read_array<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let slice = data.get(offset..end)?;
    slice.try_into().ok()
}

/// Byte order and pointer width of an image's data, from its header
/// ([`Container::is_little_endian`], [`Container::pointer_bits`]). Every
/// scanner that decodes words from data reads through this, so big-endian
/// and 32-bit images decode like little-endian 64-bit ones. Reads out of
/// bounds return zero, like the other readers here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataLayout {
    /// Little-endian data.
    pub little_endian: bool,
    /// Pointer size in bytes (4 or 8).
    pub ptr_size: usize,
}

impl DataLayout {
    /// Little-endian with 8-byte words: for x86-64 and AArch64 instruction
    /// streams, which are little-endian in every mode, and for scanners that
    /// only run on little-endian images.
    pub const LE64: Self = Self {
        little_endian: true,
        ptr_size: 8,
    };

    /// The layout of `container`'s data.
    pub fn of(container: &Container<'_>) -> Self {
        Self {
            little_endian: container.is_little_endian(),
            ptr_size: if container.pointer_bits() == 32 { 4 } else { 8 },
        }
    }

    /// Whether pointers are 8 bytes.
    pub fn is_64(self) -> bool {
        self.ptr_size == 8
    }

    /// A pointer-sized word.
    pub fn ptr(self, data: &[u8], offset: usize) -> u64 {
        if self.is_64() {
            self.u64(data, offset)
        } else {
            u64::from(self.u32(data, offset))
        }
    }

    /// A 64-bit word.
    pub fn u64(self, data: &[u8], offset: usize) -> u64 {
        read_array::<8>(data, offset)
            .map(|b| {
                if self.little_endian {
                    u64::from_le_bytes(b)
                } else {
                    u64::from_be_bytes(b)
                }
            })
            .unwrap_or(0)
    }

    /// A 32-bit word.
    pub fn u32(self, data: &[u8], offset: usize) -> u32 {
        read_array::<4>(data, offset)
            .map(|b| {
                if self.little_endian {
                    u32::from_le_bytes(b)
                } else {
                    u32::from_be_bytes(b)
                }
            })
            .unwrap_or(0)
    }

    /// A signed 16-bit word.
    pub fn i16(self, data: &[u8], offset: usize) -> i16 {
        read_array::<2>(data, offset)
            .map(|b| {
                if self.little_endian {
                    i16::from_le_bytes(b)
                } else {
                    i16::from_be_bytes(b)
                }
            })
            .unwrap_or(0)
    }
}

/// Returns the NUL-terminated byte slice starting at `offset`, excluding the
/// NUL byte. Returns `None` if no NUL is found within `max_len` bytes or the
/// offset is out of range.
pub fn slice_cstring(data: &[u8], offset: usize, max_len: usize) -> Option<&[u8]> {
    let end = offset.checked_add(max_len)?.min(data.len());
    let slice = data.get(offset..end)?;
    let nul = memchr::memchr(0, slice)?;
    slice.get(..nul)
}

/// The NUL-terminated strings of `data`, in order, without their NUL.
/// Scanning starts at offset 0. Where no NUL follows within `max_len` bytes
/// (so strings of `max_len` bytes or more), and at empty strings, the scan
/// moves on one byte at a time, so a string starting inside a skipped run
/// is still found.
pub fn cstrings(data: &[u8], max_len: usize) -> impl Iterator<Item = &[u8]> {
    let mut offset = 0usize;
    std::iter::from_fn(move || {
        while offset < data.len() {
            let at = offset;
            match slice_cstring(data, at, max_len) {
                Some(s) if !s.is_empty() => {
                    offset = at.saturating_add(s.len()).saturating_add(1);
                    return Some(s);
                }
                _ => offset = at.saturating_add(1),
            }
        }
        None
    })
}

/// `addr`, unless it is the null pointer.
pub fn non_null(addr: u64) -> Option<u64> {
    (addr != 0).then_some(addr)
}

/// Whether `b` is printable ASCII (space to `~`).
pub fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

/// Reads the NUL-terminated UTF-8 string at virtual address `va` (at most
/// 256 bytes). `None` for a null `va`, an unmapped address or invalid UTF-8.
pub fn read_cstring_at_va(container: &Container<'_>, bytes: &[u8], va: u64) -> Option<String> {
    if va == 0 {
        return None;
    }
    let off = va_to_offset(container, va)?;
    let cstr = slice_cstring(bytes, off, 256)?;
    std::str::from_utf8(cstr).ok().map(|s| s.to_owned())
}

/// The file offset of `va`: inside the file bytes of the section
/// [`Container::section_at`] picks for it, or `None`.
pub fn va_to_offset(container: &Container<'_>, va: u64) -> Option<usize> {
    let section = container.section_at(va)?;
    let section_offset = usize::try_from(va.checked_sub(section.vm_addr)?).ok()?;
    if section_offset >= section.data.len() {
        return None;
    }
    // Recover the absolute offset into `container.bytes()` via pointer
    // arithmetic on the section's data sub-slice. Only valid when the
    // section's slice lies inside `bytes` (always true for
    // `Container::parse`, not guaranteed for `Container::from_parts`).
    let section_start =
        (section.data.as_ptr() as usize).checked_sub(container.bytes().as_ptr() as usize)?;
    let section_end = section_start.checked_add(section.data.len())?;
    if section_end > container.bytes().len() {
        return None;
    }
    section_start.checked_add(section_offset)
}

/// Encodes a plain module name the way `uniqueModuleName` does
/// (`compiler/modulegraphs.nim`): lowercase letters kept, `/` -> `Z`,
/// `.` -> `O`, anything else as its decimal code. Digits are kept from Nim
/// 2.0 on (`literal_digits`) and encoded by 1.6.
pub fn encode_unique_name(name: &str, literal_digits: bool) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            'a'..='z' => out.push(c),
            '0'..='9' if literal_digits => out.push(c),
            '/' | '\\' => out.push('Z'),
            '.' => out.push('O'),
            _ => out.push_str(&u32::from(c).to_string()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_name_encoding() {
        assert_eq!(encode_unique_name("stdlib_mix", true), "stdlib95mix");
        assert_eq!(encode_unique_name("ospaths2", true), "ospaths2");
        assert_eq!(encode_unique_name("ospaths2", false), "ospaths50");
        assert_eq!(
            encode_unique_name("std/private/digitsutils", true),
            "stdZprivateZdigitsutils"
        );
        assert_eq!(encode_unique_name("Foo.bar", true), "70ooObar");
    }
    use crate::container::{Arch, Format, Section, SectionKind};

    fn section(data: &[u8], vm_addr: u64) -> Section<'_> {
        Section {
            name: ".rodata".into(),
            kind: SectionKind::RoData,
            vm_addr,
            vm_size: data.len() as u64,
            data,
        }
    }

    #[test]
    fn va_to_offset_inside_and_outside_bytes() {
        let bytes = *b"0123456789abcdef";
        let inner = section(&bytes[4..12], 0x1000);
        let c = Container::from_parts(&bytes, Format::Elf, Arch::Amd64, 0, vec![inner], vec![]);
        assert_eq!(va_to_offset(&c, 0x1000), Some(4));
        assert_eq!(va_to_offset(&c, 0x1007), Some(11));
        assert_eq!(va_to_offset(&c, 0x1008), None);

        // A section slice outside `bytes` (here: past its end in the same
        // buffer) has no file offset.
        let mut buf = vec![0u8; 64];
        buf[40..48].copy_from_slice(b"outside\0");
        let (head, tail) = buf.split_at(16);
        let outside = section(&tail[24..32], 0x2000);
        let c = Container::from_parts(head, Format::Elf, Arch::Amd64, 0, vec![outside], vec![]);
        assert_eq!(va_to_offset(&c, 0x2000), None);
        assert_eq!(read_cstring_at_va(&c, &buf, 0x2000), None);
    }

    #[test]
    fn data_layout_reads_in_its_byte_order_and_width() {
        let b = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let le32 = DataLayout {
            little_endian: true,
            ptr_size: 4,
        };
        let be64 = DataLayout {
            little_endian: false,
            ptr_size: 8,
        };
        assert_eq!(DataLayout::LE64.u64(&b, 0), 0x0807_0605_0403_0201);
        assert_eq!(be64.u64(&b, 0), 0x0102_0304_0506_0708);
        assert_eq!(DataLayout::LE64.u32(&b, 4), 0x0807_0605);
        assert_eq!(be64.u32(&b, 4), 0x0506_0708);
        assert_eq!(DataLayout::LE64.i16(&[0xff, 0xfe], 0), -257);
        assert_eq!(be64.i16(&[0xff, 0xfe], 0), -2);
        // `ptr` follows the width.
        assert_eq!(le32.ptr(&b, 0), 0x0403_0201);
        assert_eq!(be64.ptr(&b, 0), 0x0102_0304_0506_0708);
    }

    #[test]
    fn out_of_bounds_reads_return_zero() {
        assert_eq!(DataLayout::LE64.i16(&[0x00], 0), 0);
        assert_eq!(DataLayout::LE64.u32(&[0x00, 0x01, 0x02], 0), 0);
        assert_eq!(DataLayout::LE64.u64(&[0; 4], 0), 0);
        assert_eq!(DataLayout::LE64.u64(&[0; 16], usize::MAX), 0);
    }

    #[test]
    fn cstrings_skip_gaps_and_overlong_runs() {
        let data = b"\0ab\0\0cdefgh\0x\0";
        let all: Vec<&[u8]> = cstrings(data, 16).collect();
        assert_eq!(all, [&b"ab"[..], b"cdefgh", b"x"]);
        // "cdefgh" has no NUL within 4 bytes: skipped byte by byte, so its
        // tail "fgh" (NUL as the 4th byte) is found.
        let short: Vec<&[u8]> = cstrings(data, 4).collect();
        assert_eq!(short, [&b"ab"[..], b"fgh", b"x"]);
        assert_eq!(cstrings(b"", 8).count(), 0);
        assert_eq!(cstrings(b"no nul", 8).count(), 0);
    }

    #[test]
    fn cstring_basic() {
        let data = b"hello\0world";
        assert_eq!(slice_cstring(data, 0, 32), Some(&b"hello"[..]));
    }

    #[test]
    fn cstring_offset() {
        let data = b"hello\0world\0";
        assert_eq!(slice_cstring(data, 6, 32), Some(&b"world"[..]));
    }

    #[test]
    fn cstring_no_nul_within_budget() {
        let data = b"hello";
        assert_eq!(slice_cstring(data, 0, 32), None);
    }

    #[test]
    fn cstring_max_len_limits_scan() {
        let data = b"hello\0world";
        // Budget of 3 from offset 0 never reaches the NUL.
        assert_eq!(slice_cstring(data, 0, 3), None);
    }

    #[test]
    fn cstring_offset_out_of_range() {
        let data = b"hello";
        assert_eq!(slice_cstring(data, 100, 32), None);
    }
}
