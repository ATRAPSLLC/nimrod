//! V3 string literal scanner (Nim 2.4 `--strings:sso`).
//!
//! With `--strings:sso` (ARC/ORC/YRC/atomicArc only) a Nim string is a
//! two-word `SmallString` (`lib/system/strs_v3.nim`) and no
//! `NIM_STRLIT_FLAG` payloads exist, so [`super::v2::scan`] finds nothing.
//! `compiler/ccgliterals.nim genStringLiteralV3` emits each literal as:
//!
//! - **short** (`len <= 7`) and **medium** (`len <= 7 + ptrSize - 1`):
//!   a `SmallString { bytes: NU, more: ptr }` constant holding the text
//!   itself. Byte 0 of `bytes` is the length, bytes 1..8 the first seven
//!   characters (zero padded); a medium string continues in the raw bytes
//!   of `more`, whose last byte is always zero.
//! - **long**: a block `[len][rc = 1][capImpl = 0][data][NUL]` (word-sized
//!   fields, emitted positionally) plus a `SmallString` whose length byte is
//!   the static-long sentinel 254, followed by the first seven characters,
//!   and whose `more` points at the block.
//!
//! An optimising C compiler may fold a short or medium constant into
//! instruction immediates instead (seen at `-O3`): x86-64 `movabs`, AArch64
//! `movz`/`movk` sequences (possibly interleaved with another register's).
//! Both are decoded too ([`SsoLiteralKind::Immediate`]).
//!
//! Inline `SmallString` constants are short, so on their own they are easy
//! to mistake for other data. The scan therefore reports nothing unless
//! the binary shows SSO structure: a 254-sentinel `SmallString` whose
//! `more` pointer resolves to a validated long block, or at least
//! [`MIN_LONG_BLOCKS`] long blocks.
//!
//! Little-endian targets only ([`Container::is_little_endian`]); inline
//! literals on 64-bit targets only. On 32-bit targets the 2.4 compiler
//! encodes seven inline characters into a 32-bit word (`ssoBytesLit` uses a
//! fixed `AlwaysAvail = 7`), which does not match the runtime's three, so
//! inline literals are not scanned there; long blocks are.

use std::collections::BTreeSet;

use crate::{
    container::{Arch, Container, SectionKind},
    isa::a64::{self, MoveWideOp},
    util,
};

/// Length byte marking a `SmallString` that points at a static long block.
const STATIC_SLEN: u8 = 254;

/// Inline characters held in the `bytes` word (`ccgliterals.nim AlwaysAvail`).
const ALWAYS_AVAIL: usize = 7;

/// Long blocks needed to accept SSO without a pointer cross-reference.
pub const MIN_LONG_BLOCKS: usize = 3;

/// How a V3 literal is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsoLiteralKind {
    /// Text held inside a `SmallString` constant (short and medium literals).
    Inline,
    /// Text held in a static long-string block.
    Long,
    /// Text folded into instruction immediates (x86-64 `movabs`, AArch64
    /// `movz`/`movk`): an optimising C compiler can turn a short or medium
    /// `SmallString` constant into instruction operands, leaving no data
    /// copy.
    Immediate,
}

impl SsoLiteralKind {
    /// Returns a stable, lowercase identifier for the kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Long => "long",
            Self::Immediate => "immediate",
        }
    }
}

impl core::fmt::Display for SsoLiteralKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A recovered V3 (SSO) string literal.
///
/// `addr` is a virtual address: of the `SmallString` for
/// [`SsoLiteralKind::Inline`], of the block for [`SsoLiteralKind::Long`],
/// of the (first) `movabs` instruction for [`SsoLiteralKind::Immediate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringLiteralV3 {
    /// The literal content.
    pub value: String,
    /// Virtual address of the storage (image load space).
    pub addr: u64,
    /// How the literal is stored.
    pub kind: SsoLiteralKind,
}

/// Scans read-only data for V3 (SSO) string literals.
///
/// Returns an empty list for binaries that show no SSO structure (see the
/// module docs). Sorted by address.
pub fn scan(container: &Container<'_>) -> Vec<StringLiteralV3> {
    if !container.is_little_endian() {
        // The SSO layouts are byte-order dependent (the length shares a word
        // with the first characters); big-endian builds are not decoded.
        return Vec::new();
    }
    let layout = util::DataLayout::of(container);

    let sections: Vec<_> = container
        .sections()
        .iter()
        .filter(|s| s.kind == SectionKind::RoData && !s.data.is_empty())
        .collect();

    let mut long = Vec::new();
    for s in &sections {
        scan_long_blocks(layout, s.data, s.vm_addr, &mut long);
    }
    let block_addrs: BTreeSet<u64> = long.iter().map(|l| l.addr).collect();

    let mut inline = Vec::new();
    let mut cross_refs: usize = 0;
    if layout.is_64() {
        for s in &sections {
            cross_refs = cross_refs.saturating_add(scan_small_strings(
                s.data,
                s.vm_addr,
                &block_addrs,
                &mut inline,
            ));
        }
    }

    if cross_refs == 0 && long.len() < MIN_LONG_BLOCKS {
        return Vec::new();
    }

    let mut immediate = Vec::new();
    for s in container
        .sections()
        .iter()
        .filter(|s| s.kind == SectionKind::Text)
    {
        match container.arch() {
            Arch::Amd64 => scan_immediates(s.data, s.vm_addr, &mut immediate),
            Arch::Aarch64 => scan_immediates_aarch64(s.data, s.vm_addr, &mut immediate),
            _ => {}
        }
    }

    let mut out = long;
    out.append(&mut inline);
    out.append(&mut immediate);
    out.sort_by_key(|l| l.addr);
    out
}

/// Finds `[len][1][0][data][NUL]` blocks at word-aligned offsets.
fn scan_long_blocks(
    layout: util::DataLayout,
    data: &[u8],
    base_va: u64,
    out: &mut Vec<StringLiteralV3>,
) {
    let word = layout.ptr_size;
    let read = |off: usize| layout.ptr(data, off);
    // Shortest literal the compiler stores as a long block.
    let payload_size = ALWAYS_AVAIL.saturating_add(word).saturating_sub(1);
    let header = word.saturating_mul(3);

    let mut off: usize = 0;
    while off.saturating_add(header) < data.len() {
        let len = read(off);
        if len as usize > payload_size
            && read(off.saturating_add(word)) == 1
            && read(off.saturating_add(word.saturating_mul(2))) == 0
            && let Some(start) = off.checked_add(header)
            && let Some(end) = usize::try_from(len).ok().and_then(|l| start.checked_add(l))
            && data.get(end) == Some(&0)
            && let Some(bytes) = data.get(start..end)
            && let Some(value) = literal_text(bytes)
        {
            out.push(StringLiteralV3 {
                value,
                addr: base_va.wrapping_add(off as u64),
                kind: SsoLiteralKind::Long,
            });
            let next = end.saturating_add(1);
            off = next.div_ceil(word).saturating_mul(word);
            continue;
        }
        off = off.saturating_add(word);
    }
}

/// Finds 64-bit `SmallString` constants. Inline literals go to `out`; the
/// return value counts 254-sentinel strings whose `more` pointer is a known
/// long block (the SSO structural fingerprint).
fn scan_small_strings(
    data: &[u8],
    base_va: u64,
    blocks: &BTreeSet<u64>,
    out: &mut Vec<StringLiteralV3>,
) -> usize {
    let mut cross_refs: usize = 0;
    let mut off: usize = 0;
    while off.saturating_add(16) <= data.len() {
        let (Some(bytes), Some(more)) = (
            data.get(off..off.saturating_add(8)),
            data.get(off.saturating_add(8)..off.saturating_add(16)),
        ) else {
            break;
        };
        let slen = bytes.first().copied().unwrap_or(0);
        if slen == STATIC_SLEN {
            if blocks.contains(&util::DataLayout::LE64.u64(more, 0)) {
                cross_refs = cross_refs.saturating_add(1);
                off = off.saturating_add(16);
                continue;
            }
        } else if let Some(value) = decode_inline(bytes, more, usize::from(slen)) {
            out.push(StringLiteralV3 {
                value,
                addr: base_va.wrapping_add(off as u64),
                kind: SsoLiteralKind::Inline,
            });
            off = off.saturating_add(16);
            continue;
        }
        off = off.saturating_add(8);
    }
    cross_refs
}

/// Shortest literal accepted from immediates; two-character strings fit
/// too many unrelated constants.
const MIN_IMMEDIATE_LEN: usize = 3;

/// Bytes after a medium string's first `movabs` searched for the second.
const MEDIUM_PAIR_WINDOW: usize = 32;

/// Finds `SmallString` words folded into x86-64 `movabs r64, imm64`
/// (`REX.W` `B8+r` `imm64`). A short string is one immediate; a medium
/// string's `more` word is the next `movabs` within
/// [`MEDIUM_PAIR_WINDOW`] bytes.
fn scan_immediates(text: &[u8], base_va: u64, out: &mut Vec<StringLiteralV3>) {
    let imm_at = |pos: usize| -> Option<&[u8]> {
        let rex = *text.get(pos)?;
        let op = *text.get(pos.checked_add(1)?)?;
        if matches!(rex, 0x48 | 0x49) && (0xB8..=0xBF).contains(&op) {
            text.get(pos.checked_add(2)?..pos.checked_add(10)?)
        } else {
            None
        }
    };
    let mut pos: usize = 0;
    while pos.saturating_add(10) <= text.len() {
        let Some(imm) = imm_at(pos) else {
            pos = pos.saturating_add(1);
            continue;
        };
        let slen = usize::from(imm.first().copied().unwrap_or(0));
        let value = if (MIN_IMMEDIATE_LEN..=ALWAYS_AVAIL).contains(&slen) {
            decode_inline(imm, &[0u8; 8], slen)
        } else if slen > ALWAYS_AVAIL {
            let start = pos.saturating_add(10);
            (start..start.saturating_add(MEDIUM_PAIR_WINDOW))
                .find_map(&imm_at)
                .and_then(|more| decode_inline(imm, more, slen))
        } else {
            None
        };
        if let Some(value) = value {
            out.push(StringLiteralV3 {
                value,
                addr: base_va.wrapping_add(pos as u64),
                kind: SsoLiteralKind::Immediate,
            });
            pos = pos.saturating_add(10);
            continue;
        }
        pos = pos.saturating_add(1);
    }
}

/// Instructions a `movz`/`movk` sequence may span on AArch64.
const MOVK_WINDOW: usize = 8;

/// The 64-bit value a `movz Xd` at word index `i` builds with the `movk Xd`
/// that follow within [`MOVK_WINDOW`] instructions, and the index after the
/// last `movk`. The sequence ends at any other instruction naming `Xd` in
/// its destination field (it may overwrite the register): a partial value
/// is never decoded.
fn movz_sequence(words: &[u32], i: usize) -> Option<(u64, usize)> {
    // movz Xd, #imm16 (64-bit, unshifted) starts a sequence.
    let first = a64::move_wide(*words.get(i)?)
        .filter(|m| m.op == MoveWideOp::Z && m.wide && m.shift == 0)?;
    let mut value = first.lane_value();
    let mut end = i.saturating_add(1);
    for j in i.saturating_add(1)..i.saturating_add(1).saturating_add(MOVK_WINDOW) {
        let Some(&w) = words.get(j) else { break };
        if a64::bits(w, 0, 5) != first.rd {
            continue;
        }
        // movk Xd, #imm16, lsl #(16 * hw)
        match a64::move_wide(w) {
            Some(k) if k.op == MoveWideOp::K && k.wide => {
                value = (value & !k.lane_mask()) | k.lane_value();
                end = j.saturating_add(1);
            }
            _ => break,
        }
    }
    Some((value, end))
}

/// Finds `SmallString` words built in registers by `movz`/`movk` on AArch64
/// (the equivalent of x86-64 `movabs`). A medium string's `more` word is
/// the next sequence within [`MOVK_WINDOW`] instructions.
fn scan_immediates_aarch64(text: &[u8], base_va: u64, out: &mut Vec<StringLiteralV3>) {
    let words: Vec<u32> = text
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect();
    let mut i: usize = 0;
    while i < words.len() {
        let Some((value, end)) = movz_sequence(&words, i) else {
            i = i.saturating_add(1);
            continue;
        };
        let bytes = value.to_le_bytes();
        let slen = usize::from(bytes[0]);
        let decoded = if (MIN_IMMEDIATE_LEN..=ALWAYS_AVAIL).contains(&slen) {
            decode_inline(&bytes, &[0u8; 8], slen)
        } else if slen > ALWAYS_AVAIL {
            (end..end.saturating_add(MOVK_WINDOW))
                .find_map(|j| movz_sequence(&words, j))
                .and_then(|(more, _)| decode_inline(&bytes, &more.to_le_bytes(), slen))
        } else {
            None
        };
        if let Some(value) = decoded {
            out.push(StringLiteralV3 {
                value,
                addr: base_va.wrapping_add((i as u64).wrapping_mul(4)),
                kind: SsoLiteralKind::Immediate,
            });
        }
        // Sequences interleave (one register's `movk`s between another's),
        // so scanning continues with the next instruction; only a `movz`
        // starts a sequence.
        i = i.saturating_add(1);
    }
}

/// Decodes a short or medium inline `SmallString` of length `slen`.
///
/// Requires every byte after the text to be zero (the runtime's SWAR
/// invariant), so a match is a tight structural fit, not just "some
/// printable bytes". Single-character strings are skipped as too weak.
fn decode_inline(bytes: &[u8], more: &[u8], slen: usize) -> Option<String> {
    let payload_size = ALWAYS_AVAIL.saturating_add(more.len()).saturating_sub(1);
    if !(2..=payload_size).contains(&slen) {
        return None;
    }
    let mut text = Vec::with_capacity(slen);
    let head = slen.min(ALWAYS_AVAIL);
    text.extend_from_slice(bytes.get(1..head.saturating_add(1))?);
    if bytes.get(head.saturating_add(1)..)?.iter().any(|&b| b != 0) {
        return None;
    }
    let tail = slen.saturating_sub(ALWAYS_AVAIL);
    text.extend_from_slice(more.get(..tail)?);
    if more.get(tail..)?.iter().any(|&b| b != 0) {
        return None;
    }
    literal_text(&text)
}

/// Accepts literal text: valid UTF-8, no NUL, and no control characters
/// other than tab, newline and carriage return.
fn literal_text(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    if s.chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        return None;
    }
    Some(s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small(s: &str) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0] = s.len() as u8;
        for (i, c) in s.bytes().enumerate() {
            if i < 7 {
                b[i + 1] = c;
            } else {
                b[8 + i - 7] = c;
            }
        }
        b
    }

    fn long_block(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(s.len() as u64).to_le_bytes());
        v.extend_from_slice(&1u64.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        while v.len() % 8 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn decodes_short_and_medium_inline() {
        for s in ["Hi", "cmd.exe", "powershell.exe", "alpha", "192.168.1.100"] {
            let b = small(s);
            assert_eq!(
                decode_inline(&b[..8], &b[8..], s.len()).as_deref(),
                Some(s),
                "{s}"
            );
        }
    }

    #[test]
    fn inline_rejects_loose_fits() {
        // Non-zero byte after the text.
        let mut b = small("abc");
        b[5] = b'x';
        assert_eq!(decode_inline(&b[..8], &b[8..], 3), None);
        // Medium string whose `more` does not end in zero.
        let mut b = small("powershell.exe");
        b[15] = b'!';
        assert_eq!(decode_inline(&b[..8], &b[8..], 14), None);
        // Too short, too long, control characters.
        assert_eq!(decode_inline(&small("a")[..8], &small("a")[8..], 1), None);
        assert_eq!(
            decode_inline(
                &[15, b'a', b'b', b'c', b'd', b'e', b'f', b'g'],
                &[b'h'; 8],
                15
            ),
            None
        );
        let b = small("a\u{1}b");
        assert_eq!(decode_inline(&b[..8], &b[8..], 3), None);
    }

    #[test]
    fn long_blocks_found_and_aligned() {
        let mut data = vec![0u8; 8];
        data.extend(long_block("http://198.51.100.7:8080/gate.php?id="));
        data.extend(long_block("bravo-charlie-delta"));
        // Too short for a long block (<= 14): ignored.
        data.extend(long_block("short"));
        let mut out = Vec::new();
        scan_long_blocks(util::DataLayout::LE64, &data, 0x1000, &mut out);
        let got: Vec<_> = out.iter().map(|l| (l.value.as_str(), l.addr)).collect();
        assert_eq!(
            got,
            [
                ("http://198.51.100.7:8080/gate.php?id=", 0x1008),
                ("bravo-charlie-delta", 0x1048)
            ]
        );
    }

    #[test]
    fn long_block_needs_rc_one_cap_zero_and_nul() {
        for (rc, cap, nul) in [(2u64, 0u64, 0u8), (1, 5, 0), (1, 0, b'x')] {
            let mut v = Vec::new();
            v.extend_from_slice(&20u64.to_le_bytes());
            v.extend_from_slice(&rc.to_le_bytes());
            v.extend_from_slice(&cap.to_le_bytes());
            v.extend_from_slice(b"twenty characters!!!");
            v.push(nul);
            v.extend_from_slice(&[0; 8]);
            let mut out = Vec::new();
            scan_long_blocks(util::DataLayout::LE64, &v, 0, &mut out);
            assert!(out.is_empty(), "rc={rc} cap={cap} nul={nul}");
        }
    }

    #[test]
    fn small_strings_count_cross_refs() {
        let mut blocks = BTreeSet::new();
        blocks.insert(0xd620u64);
        let mut data = Vec::new();
        let mut sentinel = [0u8; 16];
        sentinel[0] = STATIC_SLEN;
        sentinel[1..8].copy_from_slice(b"http://");
        sentinel[8..].copy_from_slice(&0xd620u64.to_le_bytes());
        data.extend_from_slice(&sentinel);
        data.extend_from_slice(&small("cmd.exe"));
        // Sentinel pointing nowhere known: no cross-reference.
        sentinel[8..].copy_from_slice(&0x9999u64.to_le_bytes());
        data.extend_from_slice(&sentinel);
        let mut out = Vec::new();
        let refs = scan_small_strings(&data, 0x2000, &blocks, &mut out);
        assert_eq!(refs, 1);
        let got: Vec<_> = out.iter().map(|l| (l.value.as_str(), l.addr)).collect();
        assert_eq!(got, [("cmd.exe", 0x2010)]);
    }

    #[test]
    fn immediates_short_and_medium() {
        let mut text = vec![0x90u8; 4];
        // movabs $0x6168706c6105, %rcx  ("alpha", from a 2.4.2 -O3 build)
        text.extend_from_slice(&[0x48, 0xb9, 0x05, 0x61, 0x6c, 0x70, 0x68, 0x61, 0, 0]);
        // "powershell.exe": first word in rax, `more` in rdx a few bytes on.
        let b = small("powershell.exe");
        text.extend_from_slice(&[0x48, 0xb8]);
        text.extend_from_slice(&b[..8]);
        text.extend_from_slice(&[0x48, 0x89, 0x07]);
        text.extend_from_slice(&[0x48, 0xba]);
        text.extend_from_slice(&b[8..]);
        // A division magic number and a two-character string are ignored.
        text.extend_from_slice(&[0x49, 0xb9, 0xc3, 0xf5, 0x28, 0x5c, 0x8f, 0xc2, 0xf5, 0x28]);
        text.extend_from_slice(&[0x48, 0xb8, 0x02, b'H', b'i', 0, 0, 0, 0, 0]);
        let mut out = Vec::new();
        scan_immediates(&text, 0x1000, &mut out);
        let got: Vec<_> = out.iter().map(|l| (l.value.as_str(), l.addr)).collect();
        assert_eq!(got, [("alpha", 0x1004), ("powershell.exe", 0x100e)]);
        assert!(out.iter().all(|l| l.kind == SsoLiteralKind::Immediate));
    }

    #[test]
    fn aarch64_interleaved_movz_movk_sequences() {
        // From the 2.4.2 arm64 SSO build: "beta" in x3 and "gamma" in x2,
        // built interleaved, with an unrelated `ldr` in between.
        let words: [u32; 8] = [
            0xd28c_4083, // mov x3, #0x6204
            0xf941_0084, // ldr x4, [x4, #512]
            0xd28c_e0a2, // mov x2, #0x6705
            0xf2ae_8ca3, // movk x3, #0x7465, lsl #16
            0xf2ad_ac22, // movk x2, #0x6d61, lsl #16
            0xf2c0_0c23, // movk x3, #0x61, lsl #32
            0xf2cc_2da2, // movk x2, #0x616d, lsl #32
            0xd65f_03c0, // ret
        ];
        let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut out = Vec::new();
        scan_immediates_aarch64(&text, 0x1000, &mut out);
        let got: Vec<_> = out.iter().map(|l| (l.value.as_str(), l.addr)).collect();
        assert_eq!(got, [("beta", 0x1000), ("gamma", 0x1008)]);
        // A write to the register between movz and movk ends the sequence:
        // the partial value is not decoded.
        let words: [u32; 3] = [
            0xd28c_4083,
            0xf940_0663, /* ldr x3, [x19, #8] */
            0xf2ae_8ca3,
        ];
        let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut out = Vec::new();
        scan_immediates_aarch64(&text, 0x1000, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn hostile_input_does_not_panic() {
        let mut out = Vec::new();
        for data in [&[][..], &[0xff; 7][..], &[0xff; 23][..], &[1u8; 64][..]] {
            scan_long_blocks(util::DataLayout::LE64, data, u64::MAX, &mut out);
            scan_long_blocks(
                util::DataLayout {
                    little_endian: true,
                    ptr_size: 4,
                },
                data,
                u64::MAX,
                &mut out,
            );
            scan_small_strings(data, u64::MAX, &BTreeSet::new(), &mut out);
            scan_immediates(data, u64::MAX, &mut out);
            scan_immediates_aarch64(data, u64::MAX, &mut out);
        }
        // A length word near usize::MAX must not overflow.
        let mut v = u64::MAX.to_le_bytes().to_vec();
        v.extend_from_slice(&1u64.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());
        v.extend_from_slice(&[b'a'; 16]);
        scan_long_blocks(util::DataLayout::LE64, &v, 0, &mut out);
        assert!(out.is_empty());
    }
}
