//! V2 string literal scanner (ARC/ORC builds).
//!
//! Nim V2 string literals are stored in `.rodata` as a two-object pair
//! (RESEARCH.md §4.1, §4.4):
//!
//! 1. **Payload**: `{ cap: NI | NIM_STRLIT_FLAG, data: [cap+1 x u8] }`
//! 2. **Header** : `NimStringV2 { len: NI, payload_ptr: *NimStrPayload }`
//!
//! `NIM_STRLIT_FLAG` is bit 62 on 64-bit systems (`0x4000_0000_0000_0000`)
//! and bit 30 on 32-bit (`0x4000_0000`). We scan rodata for `cap` words
//! with the flag set, then validate the trailing data as a NUL-terminated
//! UTF-8 string whose length matches `cap & ~flag`, followed by the zero
//! tail padding of a static struct up to the next word. The padding check
//! rejects data that merely starts with a flagged word: the `double` `2.0`
//! is `0x4000_0000_0000_0000`, an empty 64-bit payload's `cap`, and the
//! constant after it fills the padding. A flagged word preceded
//! by its own length is a V1 header (refc builds) and is left to
//! `strings::v1`. Words are read in the image's byte order and pointer
//! width.

use crate::{
    container::{Container, SectionKind},
    util,
};

/// A recovered V2 string literal.
///
/// `payload_addr` is a virtual address (image load space). To convert
/// to an RVA, subtract [`crate::NimBinary::image_base`] or use
/// [`crate::container::Container::va_to_rva`].
#[derive(Debug, Clone)]
pub struct StringLiteral {
    /// The literal content as a Rust string.
    pub value: String,
    /// Virtual address of the payload in the binary (image load space,
    /// not file offset).
    pub payload_addr: u64,
}

/// Scans read-only sections for V2 `NimStrPayload` literals.
///
/// Returns all string literals found, sorted by address. Empty strings
/// (cap == 0 with the flag set) are included.
pub fn scan(container: &Container<'_>) -> Vec<StringLiteral> {
    let layout = util::DataLayout::of(container);

    let mut result = Vec::new();

    for section in container.sections() {
        if section.kind != SectionKind::RoData {
            continue;
        }
        if section.data.is_empty() {
            continue;
        }

        scan_section(layout, section.data, section.vm_addr, &mut result);
    }

    result.sort_by_key(|s| s.payload_addr);
    result
}

/// Whether a flagged word is the `reserved` half of a V1 header
/// (`[len][len | NIM_STRLIT_FLAG][data]`, `strings::v1`) rather than a V2
/// payload capacity: the word before it repeats the length. Empty
/// strings are excluded: zero padding before an empty V2 payload looks the
/// same, and the V1 scanner skips empty matches for that reason.
fn follows_v1_length(cap: u64, prev: Option<u64>) -> bool {
    cap > 0 && prev == Some(cap)
}

/// The word before `offset`, if there is one.
fn prev_word(layout: util::DataLayout, data: &[u8], offset: usize) -> Option<u64> {
    let start = offset.checked_sub(layout.ptr_size)?;
    Some(layout.ptr(data, start))
}

/// Whether the bytes after the NUL at `nul` up to the next multiple of
/// `word_size` (the payload struct's tail padding, which C zero-fills in a
/// static object) are inside `data` and zero.
fn zero_padded(data: &[u8], nul: usize, word_size: usize) -> bool {
    let Some(start) = nul.checked_add(1) else {
        return false;
    };
    let Some(end) = start.checked_next_multiple_of(word_size) else {
        return false;
    };
    data.get(start..end)
        .is_some_and(|pad| pad.iter().all(|&b| b == 0))
}

/// Adds the V2 payloads in one section's bytes (at `base_va`), checking every
/// word-aligned capacity word and skipping past each literal found.
fn scan_section(layout: util::DataLayout, data: &[u8], base_va: u64, out: &mut Vec<StringLiteral>) {
    let word_size = layout.ptr_size;
    let flag = super::strlit_flag(layout);
    if data.len() < word_size {
        return;
    }

    let mut offset: usize = 0;
    while offset.saturating_add(word_size) <= data.len() {
        let raw_cap = layout.ptr(data, offset);

        if raw_cap & flag != 0
            && !follows_v1_length(raw_cap & !flag, prev_word(layout, data, offset))
        {
            let cap = (raw_cap & !flag) as usize;
            let Some(data_start) = offset.checked_add(word_size) else {
                break;
            };
            let Some(data_end) = data_start.checked_add(cap) else {
                offset = offset.saturating_add(word_size);
                continue;
            };

            if cap < data.len()
                && data_end < data.len()
                && data.get(data_end).copied() == Some(0)
                && zero_padded(data, data_end, word_size)
                && let Some(payload) = data.get(data_start..data_end)
                && let Ok(s) = std::str::from_utf8(payload)
            {
                out.push(StringLiteral {
                    value: s.to_owned(),
                    payload_addr: base_va.wrapping_add(offset as u64),
                });

                if let Some(after_nul) = cap.checked_add(1)
                    && let Some(next) = data_start.checked_add(after_nul)
                {
                    offset = next
                        .checked_next_multiple_of(word_size)
                        .unwrap_or(usize::MAX);
                    continue;
                }
            }
        }

        offset = offset.saturating_add(word_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LE64: util::DataLayout = util::DataLayout {
        little_endian: true,
        ptr_size: 8,
    };

    #[test]
    fn decode_cap_with_flag_64() {
        let raw: u64 = 5 | (1u64 << 62);
        assert_eq!(raw & (1u64 << 62), (1u64 << 62));
        assert_eq!((raw & !(1u64 << 62)) as usize, 5);
    }

    #[test]
    fn scan_synthetic_payload_64() {
        // Build a synthetic rodata section with one V2 string literal.
        // Layout: cap(8 bytes) | data | NUL
        let mut data = Vec::new();

        let cap: u64 = 5 | (1u64 << 62);
        data.extend_from_slice(&cap.to_le_bytes());
        data.extend_from_slice(b"hello\0");
        // Pad to 8-byte alignment.
        data.extend_from_slice(&[0; 2]);

        let mut result = Vec::new();
        scan_section(LE64, &data, 0x1000, &mut result);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "hello");
        assert_eq!(result[0].payload_addr, 0x1000);
    }

    #[test]
    fn padding_separates_payloads_from_float_constants() {
        // The doubles 2.0 and 1.5: the first is an empty payload's `cap`
        // word, the second fills what would be its padding.
        let mut data = Vec::new();
        data.extend_from_slice(&2.0f64.to_le_bytes());
        data.extend_from_slice(&1.5f64.to_le_bytes());
        let mut result = Vec::new();
        scan_section(LE64, &data, 0x1000, &mut result);
        assert!(result.is_empty(), "{result:?}");

        // A real empty payload: `cap` 0 | flag, the NUL, zero padding.
        let mut data = Vec::new();
        data.extend_from_slice(&(1u64 << 62).to_le_bytes());
        data.extend_from_slice(&[0; 8]);
        scan_section(LE64, &data, 0x1000, &mut result);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "");

        // Padding that runs past the section end is no payload's.
        let mut data = Vec::new();
        data.extend_from_slice(&(3u64 | 1u64 << 62).to_le_bytes());
        data.extend_from_slice(b"abc\0");
        let mut result = Vec::new();
        scan_section(LE64, &data, 0x1000, &mut result);
        assert!(result.is_empty(), "{result:?}");
    }

    #[test]
    fn v1_header_is_not_a_v2_payload() {
        // V1 literal "hello": [len=5][5 | flag]["hello\0"].
        let mut data = Vec::new();
        data.extend_from_slice(&5u64.to_le_bytes());
        data.extend_from_slice(&(5 | (1u64 << 62)).to_le_bytes());
        data.extend_from_slice(b"hello\0\0\0");
        let mut result = Vec::new();
        scan_section(LE64, &data, 0x1000, &mut result);
        assert!(result.is_empty());

        // A V2 payload after unrelated data is still found, and an empty
        // payload after zero padding too.
        let mut data = Vec::new();
        data.extend_from_slice(&7u64.to_le_bytes());
        data.extend_from_slice(&(5 | (1u64 << 62)).to_le_bytes());
        data.extend_from_slice(b"hello\0\0\0");
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&(1u64 << 62).to_le_bytes());
        data.extend_from_slice(&[0u8; 8]);
        let mut result = Vec::new();
        scan_section(LE64, &data, 0x1000, &mut result);
        let got: Vec<_> = result.iter().map(|l| l.value.as_str()).collect();
        assert_eq!(got, ["hello", ""]);
    }

    #[test]
    fn scan_rejects_non_utf8() {
        let mut data = Vec::new();
        let cap: u64 = 2 | (1u64 << 62);
        data.extend_from_slice(&cap.to_le_bytes());
        data.extend_from_slice(&[0xFF, 0xFE, 0x00]); // invalid UTF-8
        data.extend_from_slice(&[0; 5]); // padding

        let mut result = Vec::new();
        scan_section(LE64, &data, 0x1000, &mut result);
        assert!(result.is_empty());
    }

    #[test]
    fn big_endian_payloads_decode() {
        // cap | strlit flag, then "beta\0", both big-endian.
        let be = util::DataLayout {
            little_endian: false,
            ptr_size: 8,
        };
        let mut data = (4u64 | (1u64 << 62)).to_be_bytes().to_vec();
        data.extend_from_slice(b"beta\0\0\0\0");
        let mut result = Vec::new();
        scan_section(be, &data, 0x1000, &mut result);
        assert_eq!(result.first().map(|l| l.value.as_str()), Some("beta"));
        // The same bytes read little-endian are no payload.
        let mut result = Vec::new();
        scan_section(LE64, &data, 0x1000, &mut result);
        assert!(result.is_empty());
        // 32-bit big-endian (MIPS).
        let be32 = util::DataLayout {
            little_endian: false,
            ptr_size: 4,
        };
        let mut data = (5u32 | (1u32 << 30)).to_be_bytes().to_vec();
        data.extend_from_slice(b"gamma\0\0\0");
        let mut result = Vec::new();
        scan_section(be32, &data, 0x1000, &mut result);
        assert_eq!(result.first().map(|l| l.value.as_str()), Some("gamma"));
    }
}
