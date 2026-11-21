//! V1 string literal scanner (refc builds).
//!
//! Legacy Nim strings use an inline layout (RESEARCH.md §4.3):
//!
//! ```text
//! NimStringDesc {
//!     len:      NI,    // string length
//!     reserved: NI,    // capacity; strlitFlag in bit 62/30 for literals
//!     data:     [char] // NUL-terminated
//! }
//! ```
//!
//! We scan rodata for `(len, reserved)` pairs where `reserved` has the
//! `strlitFlag` set and `len <= reserved & ~flag`, then validate the
//! trailing data. This is less reliable than V2 scanning because the
//! two-word header is less distinctive. Words are read in the image's byte
//! order and pointer width.

use crate::{
    container::{Container, SectionKind},
    util,
};

/// A recovered V1 string literal.
///
/// `header_addr` is a virtual address (image load space). To convert
/// to an RVA, subtract [`crate::NimBinary::image_base`] or use
/// [`crate::container::Container::va_to_rva`].
#[derive(Debug, Clone)]
pub struct StringLiteralV1 {
    /// The literal content.
    pub value: String,
    /// Virtual address of the NimStringDesc header (image load space,
    /// not file offset).
    pub header_addr: u64,
}

/// Scans read-only sections for V1 `NimStringDesc` literals.
pub fn scan(container: &Container<'_>) -> Vec<StringLiteralV1> {
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

    result.sort_by_key(|s| s.header_addr);
    result
}

/// Adds the V1 literals in one section's bytes (at `base_va`), checking every
/// word-aligned `[len][reserved]` pair and skipping past each literal found.
fn scan_section(
    layout: util::DataLayout,
    data: &[u8],
    base_va: u64,
    out: &mut Vec<StringLiteralV1>,
) {
    let word_size = layout.ptr_size;
    let flag = super::strlit_flag(layout);
    let header_size = word_size.saturating_mul(2);
    if data.len() < header_size {
        return;
    }

    let mut offset: usize = 0;
    while offset.saturating_add(header_size) <= data.len() {
        let len = layout.ptr(data, offset) as usize;
        let reserved = layout.ptr(data, offset.saturating_add(word_size));

        if reserved & flag != 0 {
            let cap = (reserved & !flag) as usize;

            // Empty matches are skipped: zero padding before an empty V2
            // payload (`[flag][NUL]`) has the same bytes.
            if len > 0 && len <= cap && cap < 1_000_000 {
                let Some(data_start) = offset.checked_add(header_size) else {
                    break;
                };
                let Some(data_end) = data_start.checked_add(len) else {
                    offset = offset.saturating_add(word_size);
                    continue;
                };

                if data_end < data.len()
                    && data.get(data_end).copied() == Some(0)
                    && let Some(payload) = data.get(data_start..data_end)
                    && let Ok(s) = std::str::from_utf8(payload)
                {
                    out.push(StringLiteralV1 {
                        value: s.to_owned(),
                        header_addr: base_va.wrapping_add(offset as u64),
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
        }

        offset = offset.saturating_add(word_size);
    }
}
