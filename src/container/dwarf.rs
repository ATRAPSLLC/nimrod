//! Minimal DWARF reader: which compile unit (source file) covers an address.
//!
//! Reads `.debug_aranges` (address ranges to compile-unit offsets) and the
//! `DW_AT_name` of each unit's first DIE from `.debug_info` and
//! `.debug_abbrev`, with names in `.debug_str` / `.debug_line_str` or
//! inline. DWARF 2 - 5, 32- and 64-bit offsets, either byte order. Every
//! read is bounds-checked; anything malformed or unsupported (compressed
//! sections, `strx` names) yields no ranges rather than an error. The work
//! is capped for hostile input: at most [`MAX_UNITS`] compile units, and
//! for each, [`MAX_ABBREVS`] abbreviation entries of up to [`MAX_ATTRS`]
//! attributes. Compilers that omit `.debug_aranges` (clang by default) give
//! no ranges.

use std::collections::HashMap;

/// Most compile units resolved (real binaries have one per C file, a few
/// hundred); further aranges sets are ignored.
const MAX_UNITS: usize = 4096;

/// Most abbreviation entries scanned for a unit's DIE. Compilers number
/// abbreviations in order of first use, so the unit DIE's is the first.
const MAX_ABBREVS: usize = 256;

/// Most attributes read from one abbreviation entry.
const MAX_ATTRS: usize = 256;

/// The raw DWARF sections the reader needs (absent ones are empty).
#[derive(Debug, Clone, Copy, Default)]
pub struct DwarfSections<'a> {
    /// `.debug_aranges`.
    pub aranges: &'a [u8],
    /// `.debug_info`.
    pub info: &'a [u8],
    /// `.debug_abbrev`.
    pub abbrev: &'a [u8],
    /// `.debug_str`.
    pub str: &'a [u8],
    /// `.debug_line_str` (DWARF 5).
    pub line_str: &'a [u8],
}

/// An address range `[start, end)` and the name of the compile unit that
/// covers it (as recorded, usually the full path of the C file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRange<'a> {
    /// First address.
    pub start: u64,
    /// One past the last address.
    pub end: u64,
    /// `DW_AT_name` of the compile unit.
    pub unit: &'a str,
}

/// Address ranges of every compile unit with a readable name, sorted by
/// start address.
pub fn unit_ranges<'a>(sections: &DwarfSections<'a>, little_endian: bool) -> Vec<UnitRange<'a>> {
    let r = Reader { little_endian };
    let mut names: HashMap<u64, Option<&'a str>> = HashMap::new();
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < sections.aranges.len() {
        let Some((sets, next)) = r.aranges_set(sections.aranges, pos) else {
            break;
        };
        pos = next;
        if names.len() >= MAX_UNITS && !names.contains_key(&sets.unit_offset) {
            continue;
        }
        let name = *names
            .entry(sets.unit_offset)
            .or_insert_with(|| r.unit_name(sections, sets.unit_offset));
        let Some(unit) = name else {
            continue;
        };
        out.extend(
            sets.ranges
                .into_iter()
                .map(|(start, end)| UnitRange { start, end, unit }),
        );
    }
    out.sort_by_key(|u| (u.start, u.end));
    out
}

/// The compile unit covering `addr` in ranges from [`unit_ranges`].
pub fn unit_at<'a>(ranges: &[UnitRange<'a>], addr: u64) -> Option<&'a str> {
    let pos = ranges.partition_point(|u| u.start <= addr);
    let r = ranges.get(pos.checked_sub(1)?)?;
    (addr < r.end).then_some(r.unit)
}

/// One `.debug_aranges` set: its compile unit and ranges.
struct ArangesSet {
    /// Offset of the set's compile unit in `.debug_info`.
    unit_offset: u64,
    /// Its address ranges, `[start, end)`.
    ranges: Vec<(u64, u64)>,
}

/// Bounds-checked reads in the file's byte order.
#[derive(Clone, Copy)]
struct Reader {
    /// The file's byte order.
    little_endian: bool,
}

impl Reader {
    /// An unsigned integer of `size` bytes (at most 8) at `pos`.
    fn uint(self, data: &[u8], pos: usize, size: usize) -> Option<u64> {
        if size > 8 {
            return None;
        }
        let bytes = data.get(pos..pos.checked_add(size)?)?;
        let mut buf = [0u8; 8];
        if self.little_endian {
            buf.get_mut(..size)?.copy_from_slice(bytes);
            Some(u64::from_le_bytes(buf))
        } else {
            buf.get_mut(8usize.checked_sub(size)?..)?
                .copy_from_slice(bytes);
            Some(u64::from_be_bytes(buf))
        }
    }

    /// Unit length and offset size at `pos`: `(length, offset_size, body)`.
    fn initial_length(self, data: &[u8], pos: usize) -> Option<(usize, usize, usize)> {
        let len = self.uint(data, pos, 4)?;
        if len == 0xffff_ffff {
            let len = usize::try_from(self.uint(data, pos.checked_add(4)?, 8)?).ok()?;
            Some((len, 8, pos.checked_add(12)?))
        } else if len >= 0xffff_fff0 {
            None
        } else {
            Some((usize::try_from(len).ok()?, 4, pos.checked_add(4)?))
        }
    }

    /// The `.debug_aranges` set at `pos` and the offset of the next one. Sets of
    /// another version, or with segment selectors or an unusual address size,
    /// come back with no ranges so the walk can step over them.
    fn aranges_set(self, data: &[u8], pos: usize) -> Option<(ArangesSet, usize)> {
        let (len, off_size, body) = self.initial_length(data, pos)?;
        let end = body.checked_add(len)?;
        let set = data.get(..end)?;
        let version = self.uint(set, body, 2)?;
        if version != 2 {
            return Some((
                ArangesSet {
                    unit_offset: u64::MAX,
                    ranges: Vec::new(),
                },
                end,
            ));
        }
        let mut p = body.checked_add(2)?;
        let unit_offset = self.uint(set, p, off_size)?;
        p = p.checked_add(off_size)?;
        let addr_size = usize::from(*set.get(p)?);
        let seg_size = usize::from(*set.get(p.checked_add(1)?)?);
        p = p.checked_add(2)?;
        if !matches!(addr_size, 4 | 8) || seg_size != 0 {
            return Some((
                ArangesSet {
                    unit_offset,
                    ranges: Vec::new(),
                },
                end,
            ));
        }
        // Tuples start at a multiple of their size from the set's start.
        let tuple = addr_size.checked_mul(2)?;
        let rel = p.checked_sub(pos)?;
        p = pos.checked_add(rel.div_ceil(tuple).checked_mul(tuple)?)?;
        let mut ranges = Vec::new();
        while p.checked_add(tuple)? <= end {
            let start = self.uint(set, p, addr_size)?;
            let length = self.uint(set, p.checked_add(addr_size)?, addr_size)?;
            p = p.checked_add(tuple)?;
            if start == 0 && length == 0 {
                break;
            }
            if let Some(stop) = start.checked_add(length).filter(|_| length != 0) {
                ranges.push((start, stop));
            }
        }
        Some((
            ArangesSet {
                unit_offset,
                ranges,
            },
            end,
        ))
    }

    /// `DW_AT_name` of the compile unit at `offset` in `.debug_info`.
    fn unit_name<'a>(self, s: &DwarfSections<'a>, offset: u64) -> Option<&'a str> {
        let info = s.info;
        let pos = usize::try_from(offset).ok()?;
        let (len, off_size, body) = self.initial_length(info, pos)?;
        let end = body.checked_add(len)?;
        let unit = info.get(..end)?;
        let version = self.uint(unit, body, 2)?;
        let mut p = body.checked_add(2)?;
        let (abbrev_offset, addr_size) = match version {
            2..=4 => {
                let a = self.uint(unit, p, off_size)?;
                p = p.checked_add(off_size)?;
                let size = *unit.get(p)?;
                p = p.checked_add(1)?;
                (a, size)
            }
            5 => {
                // unit_type, address_size, debug_abbrev_offset
                let size = *unit.get(p.checked_add(1)?)?;
                p = p.checked_add(2)?;
                let a = self.uint(unit, p, off_size)?;
                p = p.checked_add(off_size)?;
                (a, size)
            }
            _ => return None,
        };
        let ctx = FormCtx {
            off_size,
            addr_size: usize::from(addr_size),
            version,
        };
        let (code, n) = uleb(unit, p)?;
        p = p.checked_add(n)?;
        let specs = self.abbrev_attrs(s.abbrev, usize::try_from(abbrev_offset).ok()?, code)?;
        for (attr, form, _implicit) in specs {
            const DW_AT_NAME: u64 = 0x03;
            if attr == DW_AT_NAME {
                return self.string_form(s, unit, p, form, ctx);
            }
            p = self.skip_form(unit, p, form, ctx, 0)?;
        }
        None
    }

    /// The attribute specs `(attr, form, implicit_const)` of abbreviation
    /// `code` in the table at `offset`.
    #[allow(clippy::type_complexity)]
    fn abbrev_attrs(self, abbrev: &[u8], offset: usize, code: u64) -> Option<Vec<(u64, u64, i64)>> {
        let mut p = offset;
        for _ in 0..MAX_ABBREVS {
            let (c, n) = uleb(abbrev, p)?;
            p = p.checked_add(n)?;
            if c == 0 {
                return None;
            }
            let (_tag, n) = uleb(abbrev, p)?;
            p = p.checked_add(n)?.checked_add(1)?; // has_children
            let mut specs = Vec::new();
            loop {
                if specs.len() > MAX_ATTRS {
                    return None;
                }
                let (attr, n) = uleb(abbrev, p)?;
                p = p.checked_add(n)?;
                let (form, n) = uleb(abbrev, p)?;
                p = p.checked_add(n)?;
                if attr == 0 && form == 0 {
                    break;
                }
                let mut implicit = 0;
                if form == FORM_IMPLICIT_CONST {
                    let (v, n) = sleb(abbrev, p)?;
                    p = p.checked_add(n)?;
                    implicit = v;
                }
                specs.push((attr, form, implicit));
            }
            if c == code {
                return Some(specs);
            }
        }
        None
    }

    /// A string attribute value of `form` at `p`: inline (`DW_FORM_string`) or an
    /// offset into `.debug_str` (`strp`) or `.debug_line_str` (`line_strp`).
    /// Index forms (`strx*`) need `.debug_str_offsets` and are not read.
    fn string_form<'a>(
        self,
        s: &DwarfSections<'a>,
        unit: &'a [u8],
        p: usize,
        form: u64,
        ctx: FormCtx,
    ) -> Option<&'a str> {
        match form {
            0x08 => cstr(unit, p),
            0x0e => cstr(
                s.str,
                usize::try_from(self.uint(unit, p, ctx.off_size)?).ok()?,
            ),
            0x1f => cstr(
                s.line_str,
                usize::try_from(self.uint(unit, p, ctx.off_size)?).ok()?,
            ),
            _ => None,
        }
    }

    /// Position after an attribute value of `form` at `p`.
    fn skip_form(self, data: &[u8], p: usize, form: u64, ctx: FormCtx, depth: u8) -> Option<usize> {
        let fixed = |n: usize| p.checked_add(n);
        let leb = |p: usize| uleb(data, p).and_then(|(_, n)| p.checked_add(n));
        match form {
            0x01 => fixed(ctx.addr_size),
            0x03 => fixed(2)?.checked_add(usize::try_from(self.uint(data, p, 2)?).ok()?),
            0x04 => fixed(4)?.checked_add(usize::try_from(self.uint(data, p, 4)?).ok()?),
            0x05 | 0x12 | 0x26 | 0x2a => fixed(2),
            0x06 | 0x13 | 0x1c | 0x28 | 0x2c => fixed(4),
            0x07 | 0x14 | 0x20 | 0x24 => fixed(8),
            0x08 => {
                let len = data.get(p..)?.iter().position(|&b| b == 0)?;
                p.checked_add(len)?.checked_add(1)
            }
            0x09 | 0x18 => {
                let (len, n) = uleb(data, p)?;
                p.checked_add(n)?.checked_add(usize::try_from(len).ok()?)
            }
            0x0a => fixed(1)?.checked_add(usize::from(*data.get(p)?)),
            0x0b | 0x0c | 0x11 | 0x25 | 0x29 => fixed(1),
            0x0d => sleb(data, p).and_then(|(_, n)| p.checked_add(n)),
            0x0e | 0x17 | 0x1d | 0x1f => fixed(ctx.off_size),
            0x10 => fixed(if ctx.version <= 2 {
                ctx.addr_size
            } else {
                ctx.off_size
            }),
            0x0f | 0x15 | 0x1a | 0x1b | 0x22 | 0x23 => leb(p),
            0x16 if depth < 4 => {
                let (inner, n) = uleb(data, p)?;
                self.skip_form(data, p.checked_add(n)?, inner, ctx, depth.saturating_add(1))
            }
            0x19 | FORM_IMPLICIT_CONST => Some(p),
            0x1e => fixed(16),
            0x27 | 0x2b => fixed(3),
            _ => None,
        }
    }
}

/// `DW_FORM_implicit_const` (DWARF 5): the value lives in the abbreviation, not
/// in the DIE.
const FORM_IMPLICIT_CONST: u64 = 0x21;

/// Unit properties that decide form sizes.
#[derive(Clone, Copy)]
struct FormCtx {
    /// Offset size: 4 for 32-bit DWARF, 8 for 64-bit.
    off_size: usize,
    /// Target address size from the unit header.
    addr_size: usize,
    /// DWARF version (2 - 5); `DW_FORM_ref_addr` is address-sized in version 2.
    version: u64,
}

/// Unsigned LEB128 at `p`: `(value, bytes read)`.
fn uleb(data: &[u8], p: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for i in 0..10usize {
        let b = *data.get(p.checked_add(i)?)?;
        let shift = u32::try_from(i.checked_mul(7)?).ok()?;
        value |= u64::from(b & 0x7f).checked_shl(shift).unwrap_or(0);
        if b & 0x80 == 0 {
            return Some((value, i.checked_add(1)?));
        }
    }
    None
}

/// Signed LEB128 at `p`: `(value, bytes read)`.
fn sleb(data: &[u8], p: usize) -> Option<(i64, usize)> {
    let mut value = 0i64;
    for i in 0..10usize {
        let b = *data.get(p.checked_add(i)?)?;
        let shift = u32::try_from(i.checked_mul(7)?).ok()?;
        value |= i64::from(b & 0x7f).checked_shl(shift).unwrap_or(0);
        if b & 0x80 == 0 {
            let used = shift.saturating_add(7);
            if b & 0x40 != 0 && used < 64 {
                value |= (-1i64).checked_shl(used).unwrap_or(0);
            }
            return Some((value, i.checked_add(1)?));
        }
    }
    None
}

/// The NUL-terminated UTF-8 string at `p`.
fn cstr(data: &[u8], p: usize) -> Option<&str> {
    let rest = data.get(p..)?;
    let len = rest.iter().position(|&b| b == 0)?;
    std::str::from_utf8(rest.get(..len)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DWARF 4 unit named inline and one DWARF 5 unit named through
    /// `.debug_line_str`, with aranges for both.
    fn sample() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        // abbrev 1: compile_unit, no children, producer(strp) name(string)
        // abbrev 2: compile_unit, no children, language(data1) name(line_strp)
        let abbrev = vec![
            1, 0x11, 0, 0x25, 0x0e, 0x03, 0x08, 0, 0, //
            2, 0x11, 0, 0x13, 0x0b, 0x03, 0x1f, 0, 0, //
            0,
        ];
        let mut info = Vec::new();
        // unit 0: v4
        let body4: Vec<u8> = [
            &4u16.to_le_bytes()[..],
            &0u32.to_le_bytes(), // abbrev offset
            &[8],                // address size
            &[1],                // abbrev code
            &0u32.to_le_bytes(), // producer strp
            b"@mmain.nim.c\0",
        ]
        .concat();
        info.extend_from_slice(&(body4.len() as u32).to_le_bytes());
        info.extend_from_slice(&body4);
        let second = info.len() as u32;
        // unit 1: v5
        let body5: Vec<u8> = [
            &5u16.to_le_bytes()[..],
            &[1, 8],             // unit_type compile, address size
            &0u32.to_le_bytes(), // abbrev offset
            &[2],                // abbrev code
            &[0x0c],             // language
            &4u32.to_le_bytes(), // line_strp offset
        ]
        .concat();
        info.extend_from_slice(&(body5.len() as u32).to_le_bytes());
        info.extend_from_slice(&body5);
        let line_str = b"xxx\0/build/stdlib_io.nim.c\0".to_vec();
        let mut aranges = Vec::new();
        for (unit, start, len) in [(0u32, 0x1000u64, 0x100u64), (second, 0x2000, 0x80)] {
            let mut set = Vec::new();
            set.extend_from_slice(&2u16.to_le_bytes());
            set.extend_from_slice(&unit.to_le_bytes());
            set.extend_from_slice(&[8, 0]);
            set.extend_from_slice(&[0; 4]); // pad header (12 bytes) to 16
            for v in [start, len, 0, 0] {
                set.extend_from_slice(&v.to_le_bytes());
            }
            aranges.extend_from_slice(&(set.len() as u32).to_le_bytes());
            aranges.extend_from_slice(&set);
        }
        (aranges, info, abbrev, line_str)
    }

    #[test]
    fn ranges_name_their_units() {
        let (aranges, info, abbrev, line_str) = sample();
        let s = DwarfSections {
            aranges: &aranges,
            info: &info,
            abbrev: &abbrev,
            str: &[],
            line_str: &line_str,
        };
        let ranges = unit_ranges(&s, true);
        assert_eq!(
            ranges,
            [
                UnitRange {
                    start: 0x1000,
                    end: 0x1100,
                    unit: "@mmain.nim.c"
                },
                UnitRange {
                    start: 0x2000,
                    end: 0x2080,
                    unit: "/build/stdlib_io.nim.c"
                },
            ]
        );
        assert_eq!(unit_at(&ranges, 0x10ff), Some("@mmain.nim.c"));
        assert_eq!(unit_at(&ranges, 0x1100), None);
        assert_eq!(unit_at(&ranges, 0x2000), Some("/build/stdlib_io.nim.c"));
        assert_eq!(unit_at(&ranges, 0xfff), None);
    }

    #[test]
    fn truncated_and_garbage_input_yield_nothing() {
        let (aranges, info, abbrev, line_str) = sample();
        for cut in 0..aranges.len() {
            let s = DwarfSections {
                aranges: aranges.get(..cut).unwrap_or(&[]),
                info: &info,
                abbrev: &abbrev,
                str: &[],
                line_str: &line_str,
            };
            let _ = unit_ranges(&s, true);
        }
        for cut in 0..info.len() {
            let s = DwarfSections {
                aranges: &aranges,
                info: info.get(..cut).unwrap_or(&[]),
                abbrev: &abbrev,
                str: &[],
                line_str: &line_str,
            };
            let _ = unit_ranges(&s, true);
        }
        let junk: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let s = DwarfSections {
            aranges: &junk,
            info: &junk,
            abbrev: &junk,
            str: &junk,
            line_str: &junk,
        };
        let _ = unit_ranges(&s, true);
        let _ = unit_ranges(&s, false);
    }

    #[test]
    fn leb128() {
        assert_eq!(uleb(&[0xe5, 0x8e, 0x26], 0), Some((624_485, 3)));
        assert_eq!(sleb(&[0xc0, 0xbb, 0x78], 0), Some((-123_456, 3)));
        assert_eq!(sleb(&[0x7f], 0), Some((-1, 1)));
        assert_eq!(uleb(&[0x80; 11], 0), None);
    }

    #[test]
    fn many_units_are_capped() {
        // 10,000 aranges sets naming distinct (missing) units: bounded work,
        // no ranges.
        let mut aranges = Vec::new();
        for unit in 0..10_000u32 {
            let mut set = Vec::new();
            set.extend_from_slice(&2u16.to_le_bytes());
            set.extend_from_slice(&unit.wrapping_mul(64).to_le_bytes());
            set.extend_from_slice(&[8, 0, 0, 0, 0, 0]);
            for v in [0x1000u64, 0x10, 0, 0] {
                set.extend_from_slice(&v.to_le_bytes());
            }
            aranges.extend_from_slice(&(set.len() as u32).to_le_bytes());
            aranges.extend_from_slice(&set);
        }
        // A long abbreviation table that never names code 1.
        let mut abbrev = Vec::new();
        for code in 2..5000u16 {
            abbrev.extend_from_slice(&[
                (code & 0x7f) as u8 | 0x80,
                (code >> 7) as u8,
                0x11,
                0,
                0,
                0,
            ]);
        }
        // A DWARF 4 unit header every 64 bytes, each asking for code 1.
        let mut info = Vec::new();
        for _ in 0..10_000 {
            let mut unit = vec![0u8; 64];
            unit[..4].copy_from_slice(&60u32.to_le_bytes());
            unit[4..6].copy_from_slice(&4u16.to_le_bytes());
            unit[10] = 8; // address size
            unit[11] = 1; // abbrev code
            info.extend_from_slice(&unit);
        }
        let s = DwarfSections {
            aranges: &aranges,
            info: &info,
            abbrev: &abbrev,
            str: &[],
            line_str: &[],
        };
        let started = std::time::Instant::now();
        assert!(unit_ranges(&s, true).is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
}
