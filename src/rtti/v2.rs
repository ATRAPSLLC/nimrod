//! `TNimTypeV2` (ARC/ORC/YRC RTTI) reader.
//!
//! Reads the fields of a `TNimTypeV2` struct at a given virtual address, in
//! the image's byte order and pointer width. The layout (RESEARCH.md §3.2):
//!
//! ```text
//! struct TNimTypeV2 {
//!     void*   destructor;    // ptr
//!     int     size;          // NI (pointer-sized int)
//!     int16   align;         // NI16
//!     int16   depth;         // NI16
//!     void*   display;       // ptr to UncheckedArray[uint32]
//!     char*   name;          // cstring (conditional on nimTypeNames)
//!     void*   traceImpl;     // ptr
//!     void*   typeInfoV1;    // ptr (usually nil)
//!     int     flags;         // NI
//! };
//! ```
//!
//! From Nim 2.0 these are static data. Before 2.0 they are zero in the file
//! and filled at startup like the legacy RTTI ([`crate::rtti::v1`]).

use crate::{
    container::Container,
    util::{DataLayout, non_null, read_cstring_at_va, va_to_offset},
};

/// Parsed fields of a `TNimTypeV2` RTTI record.
#[derive(Debug, Clone)]
pub struct TNimTypeV2Fields {
    /// Size of the described type in bytes.
    pub size: u64,
    /// Alignment in bytes.
    pub align: i16,
    /// Depth in the type inheritance hierarchy.
    pub depth: i16,
    /// Type flags (raw integer from the binary).
    pub flags: u64,
    /// The `name` cstring if present and decodable. Only populated when
    /// the binary was compiled with `nimTypeNames` (the default for debug
    /// builds, absent in release).
    pub name: Option<String>,
    /// Virtual address of the destructor, if non-null.
    pub destructor_addr: Option<u64>,
    /// Virtual address of the `display` (class-token array), if non-null.
    pub display_addr: Option<u64>,
    /// Virtual address of `traceImpl` (cycle-collector trace proc), if
    /// non-null.
    pub trace_impl_addr: Option<u64>,
    /// Virtual address of `typeInfoV1` (backwards-compat pointer to legacy
    /// RTTI), if non-null. Usually nil.
    pub type_info_v1_addr: Option<u64>,
}

/// Reads a `TNimTypeV2` struct from the container at the given virtual
/// address.
///
/// The `name` field is conditional on `nimTypeNames` (present in debug
/// builds, absent in release). We try the with-name layout first; if
/// the name pointer doesn't resolve to a valid cstring, we fall back
/// to the without-name layout.
///
/// Returns `None` if the address cannot be mapped to file bytes or the
/// data is too short.
pub fn read(container: &Container<'_>, va: u64) -> Option<TNimTypeV2Fields> {
    let words = DataLayout::of(container);
    let ptr_size = words.ptr_size;

    let bytes = container.bytes();
    let offset = va_to_offset(container, va)?;

    let min_size = ptr_size.saturating_mul(6).saturating_add(4); // without name field
    if offset.checked_add(min_size)? > bytes.len() {
        return None;
    }

    let mut pos = offset;

    let destructor = words.ptr(bytes, pos);
    pos = pos.saturating_add(ptr_size);

    let size = words.ptr(bytes, pos);
    pos = pos.saturating_add(ptr_size);

    let align = words.i16(bytes, pos);
    pos = pos.saturating_add(2);

    let depth = words.i16(bytes, pos);
    pos = pos.saturating_add(2);

    // Padding to pointer alignment after two i16s.
    if words.is_64() {
        pos = pos.saturating_add(4);
    }

    let display = words.ptr(bytes, pos);
    pos = pos.saturating_add(ptr_size);

    // Try the with-name layout first. If the pointer at this position
    // resolves to a valid cstring, the name field is present.
    let candidate_name_ptr = words.ptr(bytes, pos);
    let name = read_cstring_at_va(container, bytes, candidate_name_ptr);

    let (trace_impl, type_info_v1, flags) = if name.is_some() {
        // With-name layout: name, traceImpl, typeInfoV1, flags.
        pos = pos.saturating_add(ptr_size); // skip name
        let ti = words.ptr(bytes, pos);
        pos = pos.saturating_add(ptr_size);
        let tv1 = words.ptr(bytes, pos);
        pos = pos.saturating_add(ptr_size);
        let fl = words.ptr(bytes, pos);
        (ti, tv1, fl)
    } else {
        // Without-name layout: traceImpl, typeInfoV1, flags.
        // The pointer we read as candidate_name_ptr is actually traceImpl.
        let ti = candidate_name_ptr;
        pos = pos.saturating_add(ptr_size); // skip traceImpl
        let tv1 = words.ptr(bytes, pos);
        pos = pos.saturating_add(ptr_size);
        let fl = words.ptr(bytes, pos);
        (ti, tv1, fl)
    };

    Some(TNimTypeV2Fields {
        size,
        align,
        depth,
        flags,
        name,
        destructor_addr: non_null(destructor),
        display_addr: non_null(display),
        trace_impl_addr: non_null(trace_impl),
        type_info_v1_addr: non_null(type_info_v1),
    })
}
