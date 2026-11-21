//! `TNimType` (legacy RTTI) reader.
//!
//! Reads a `TNimType` (RESEARCH.md §3.1) and walks its `TNimNode` tree for
//! the field names of objects and tuples, the discriminator and branches of
//! object variants, and the values of enums.
//!
//! The struct changed over the releases, so the layout is detected per
//! binary ([`detect_layout`]) by how many of its `NTI` objects are
//! structurally valid under each candidate ([`V1Layout`]): Nim 1.4+ with
//! `align`, Nim 1.0 - 1.2 without it, and Nim 1.2 ARC's own struct under the
//! same names. [`TNimTypeFields::is_plausible`] rejects objects that still do
//! not fit.
//!
//! In the file these objects are zero (`.bss`) for refc builds: each
//! module's `DatInit000` fills them at startup. [`crate::types::build`]
//! evaluates those functions first (see `emu`) and reads the result.

use crate::{
    container::Container,
    util::{DataLayout, is_printable_ascii, non_null, read_cstring_at_va, va_to_offset},
};

/// `TNimKind`: mirrors `ast.TTypeKind` from `lib/system/hti.nim`.
///
/// Values are the ordinal positions in the enum (0-based). Only the
/// commonly encountered kinds are named; the rest are captured as
/// `Other(u8)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NimKind {
    /// `tyNone` (0)
    None,
    /// `tyBool` (1)
    Bool,
    /// `tyChar` (2)
    Char,
    /// `tyEnum` (14)
    Enum,
    /// `tyArray` (16)
    Array,
    /// `tyObject` (17)
    Object,
    /// `tyTuple` (18)
    Tuple,
    /// `tySet` (19)
    Set,
    /// `tyRange` (20)
    Range,
    /// `tyPtr` (21)
    Ptr,
    /// `tyRef` (22)
    Ref,
    /// `tySequence` (24)
    Sequence,
    /// `tyProc` (25)
    Proc,
    /// `tyPointer` (26)
    Pointer,
    /// `tyString` (28)
    String,
    /// `tyCstring` (29)
    Cstring,
    /// `tyInt` (31)
    Int,
    /// `tyInt8` (32)
    Int8,
    /// `tyInt16` (33)
    Int16,
    /// `tyInt32` (34)
    Int32,
    /// `tyInt64` (35)
    Int64,
    /// `tyFloat` (36)
    Float,
    /// `tyFloat32` (37)
    Float32,
    /// `tyFloat64` (38)
    Float64,
    /// `tyFloat128` (39)
    Float128,
    /// `tyUInt` (40)
    UInt,
    /// `tyUInt8` (41)
    UInt8,
    /// `tyUInt16` (42)
    UInt16,
    /// `tyUInt32` (43)
    UInt32,
    /// `tyUInt64` (44)
    UInt64,
    /// Any other kind not explicitly listed.
    Other(u8),
}

impl NimKind {
    /// Converts a raw ordinal to a `NimKind`.
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::None,
            1 => Self::Bool,
            2 => Self::Char,
            14 => Self::Enum,
            16 => Self::Array,
            17 => Self::Object,
            18 => Self::Tuple,
            19 => Self::Set,
            20 => Self::Range,
            21 => Self::Ptr,
            22 => Self::Ref,
            24 => Self::Sequence,
            25 => Self::Proc,
            26 => Self::Pointer,
            28 => Self::String,
            29 => Self::Cstring,
            31 => Self::Int,
            32 => Self::Int8,
            33 => Self::Int16,
            34 => Self::Int32,
            35 => Self::Int64,
            36 => Self::Float,
            37 => Self::Float32,
            38 => Self::Float64,
            39 => Self::Float128,
            40 => Self::UInt,
            41 => Self::UInt8,
            42 => Self::UInt16,
            43 => Self::UInt32,
            44 => Self::UInt64,
            n => Self::Other(n),
        }
    }

    /// Returns the stable string identifier for this kind.
    ///
    /// [`NimKind::Other`] returns `"Other"`; the raw ordinal is available via
    /// [`TNimTypeFields::kind_raw`].
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Bool => "Bool",
            Self::Char => "Char",
            Self::Enum => "Enum",
            Self::Array => "Array",
            Self::Object => "Object",
            Self::Tuple => "Tuple",
            Self::Set => "Set",
            Self::Range => "Range",
            Self::Ptr => "Ptr",
            Self::Ref => "Ref",
            Self::Sequence => "Sequence",
            Self::Proc => "Proc",
            Self::Pointer => "Pointer",
            Self::String => "String",
            Self::Cstring => "Cstring",
            Self::Int => "Int",
            Self::Int8 => "Int8",
            Self::Int16 => "Int16",
            Self::Int32 => "Int32",
            Self::Int64 => "Int64",
            Self::Float => "Float",
            Self::Float32 => "Float32",
            Self::Float64 => "Float64",
            Self::Float128 => "Float128",
            Self::UInt => "UInt",
            Self::UInt8 => "UInt8",
            Self::UInt16 => "UInt16",
            Self::UInt32 => "UInt32",
            Self::UInt64 => "UInt64",
            Self::Other(_) => "Other",
        }
    }
}

impl core::fmt::Display for NimKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `TNimTypeFlag`: from `lib/system/hti.nim`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NimTypeFlag {
    /// `ntfNoRefs` (bit 0): type contains no tyRef/tySequence/tyString.
    NoRefs,
    /// `ntfAcyclic` (bit 1): type cannot form a cycle.
    Acyclic,
    /// `ntfEnumHole` (bit 2): enum has holes; `$` needs the slow path.
    EnumHole,
}

/// Parsed fields of a legacy `TNimType` RTTI record.
#[derive(Debug, Clone)]
pub struct TNimTypeFields {
    /// Size of the described type in bytes.
    pub size: u64,
    /// Alignment.
    pub align: u64,
    /// Type kind.
    pub kind: NimKind,
    /// Raw kind byte (for round-tripping when `NimKind::Other`).
    pub kind_raw: u8,
    /// Type flags (raw byte, bits 0-2 are `TNimTypeFlag`).
    pub flags_raw: u8,
    /// Parsed type flags.
    pub flags: Vec<NimTypeFlag>,
    /// Virtual address of `base` (parent type), if non-null.
    pub base_addr: Option<u64>,
    /// Virtual address of the `node` (`TNimNode` tree root), if non-null.
    pub node_addr: Option<u64>,
    /// Virtual address of the `finalizer`, if non-null.
    pub finalizer_addr: Option<u64>,
    /// Virtual address of the `marker` proc, if non-null.
    pub marker_addr: Option<u64>,
    /// Virtual address of the `deepcopy` proc, if non-null.
    pub deepcopy_addr: Option<u64>,
    /// The `name` cstring if present (`nimTypeNames` defined).
    pub name: Option<String>,
    /// Destructor hook ([`V1Layout::Nim12Arc`] only).
    pub destructor_addr: Option<u64>,
    /// Trace hook ([`V1Layout::Nim12Arc`] only).
    pub trace_addr: Option<u64>,
    /// Dispose hook ([`V1Layout::Nim12Arc`] only).
    pub dispose_addr: Option<u64>,
    /// Field names recovered by walking the `TNimNode` tree (if the node
    /// pointer was valid and the tree was walkable).
    pub node_fields: Vec<NodeField>,
}

/// A field recovered from the `TNimNode` tree.
#[derive(Debug, Clone)]
pub struct NodeField {
    /// Field name (from the `name: cstring` in `TNimNode`).
    pub name: String,
    /// Byte offset of the field within the parent struct.
    pub offset: u64,
    /// Virtual address of the `TNimType` pointer for this field's type,
    /// if non-null.
    pub type_addr: Option<u64>,
}

/// `TNimNodeKind`: from `lib/system/hti.nim`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeKind {
    /// `nkNone`: unused by the compiler for fields, but the kind enum lists are
    /// left at it (see [`walk_node_tree`]).
    None,
    /// `nkSlot`: one field (or enum value).
    Slot,
    /// `nkList`: a sequence of child nodes.
    List,
    /// `nkCase`: an object variant's discriminator and its branches.
    Case,
}

impl NodeKind {
    /// The kind of a raw `TNimNode.kind` byte; unknown values read as
    /// [`NodeKind::None`].
    fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::None,
            1 => Self::Slot,
            2 => Self::List,
            3 => Self::Case,
            _ => Self::None,
        }
    }
}

/// `TNimType` field layout. Nim 1.4 added `align` after `size`; Nim 1.0 and
/// 1.2 go straight from `size` to `kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum V1Layout {
    /// `size, align, kind, flags, base, node, ...` (Nim 1.4+).
    WithAlign,
    /// `size, kind, flags, base, node, ...` (Nim 1.0 - 1.2).
    NoAlign,
    /// Nim 1.2 ARC (`nimV2`): `destructor, size, name, traceImpl,
    /// disposeImpl` under the same `NTI` names; no kind or member nodes.
    Nim12Arc,
}

impl V1Layout {
    /// Returns a stable, lowercase identifier for the layout.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WithAlign => "with-align",
            Self::NoAlign => "no-align",
            Self::Nim12Arc => "nim12-arc",
        }
    }
}

/// Picks the `TNimType` layout of a binary from its V1 RTTI objects at
/// `vas`, by counting the objects that are structurally valid under each:
/// a known kind, `base` null or another RTTI object, `node` null or inside
/// a data section, and (with `align`) a power-of-two alignment dividing the
/// size. A misread layout puts a small integer where `base` or `node`
/// belongs, so it fails these checks. Ties keep [`V1Layout::WithAlign`].
pub fn detect_layout(container: &Container<'_>, vas: &[u64]) -> V1Layout {
    let rtti: std::collections::HashSet<u64> = vas.iter().copied().collect();
    let in_data = |va: u64| container.section_at(va).is_some_and(|s| s.kind.is_data());
    let in_text = |va: u64| {
        container
            .section_at(va)
            .is_some_and(|s| s.kind == crate::container::SectionKind::Text)
    };
    // Nim 1.2 ARC: the first word is a destructor (null or code), where the
    // classic layouts hold a small size; hooks null or in code.
    let arc12 = vas
        .iter()
        .filter_map(|&va| read(container, va, V1Layout::Nim12Arc))
        .filter(|f| {
            f.size > 0
                && f.size < (1 << 24)
                && (f.destructor_addr.is_some() || f.trace_addr.is_some() || f.name.is_some())
                && [f.destructor_addr, f.trace_addr, f.dispose_addr]
                    .iter()
                    .all(|h| h.is_none_or(&in_text))
        })
        .count();
    let score = |layout: V1Layout| {
        vas.iter()
            .filter_map(|&va| read(container, va, layout))
            .filter(|f| f.size != 0 || f.kind_raw != 0)
            .filter(|f| {
                f.kind_raw <= MAX_KIND
                    && f.base_addr.is_none_or(|b| rtti.contains(&b))
                    && f.node_addr.is_none_or(&in_data)
                    && (layout == V1Layout::NoAlign
                        || (f.align.is_power_of_two()
                            && f.align <= 64
                            && f.size.checked_rem(f.align) == Some(0)))
            })
            .count()
    };
    let (with, without) = (score(V1Layout::WithAlign), score(V1Layout::NoAlign));
    if arc12 > with && arc12 > without {
        V1Layout::Nim12Arc
    } else if without > with {
        V1Layout::NoAlign
    } else {
        V1Layout::WithAlign
    }
}

impl TNimTypeFields {
    /// Whether the fields form a valid `TNimType`: a known kind and, when
    /// the layout records it, a power-of-two alignment that divides the
    /// size. Objects that fail this are not `TNimType` under the assumed
    /// layout (Nim 1.2 ARC, for one, emits a different struct under the
    /// same `NTI` names) and must not be reported.
    pub fn is_plausible(&self) -> bool {
        self.kind_raw <= MAX_KIND
            && (self.align == 0
                || (self.align.is_power_of_two()
                    && self.align <= 64
                    && self.size.checked_rem(self.align) == Some(0)))
    }
}

/// Most nodes walked for one type: far above any real type's field count.
const MAX_NODES: usize = 1 << 14;

/// Highest `TNimKind` ordinal (`tyInferredHidden` and neighbours, Nim 1.0 -
/// 2.4) plus headroom.
const MAX_KIND: u8 = 64;

/// Reads the `TNimType` at `va` under `layout` (see [`detect_layout`]) and
/// walks its `TNimNode` tree.
///
/// [`V1Layout::WithAlign`] is the Nim 1.4+ struct (no `gcHooks`):
///
/// ```text
/// size:      NI
/// align:     NI
/// kind:      u8  (TNimKind)
/// flags:     u8  (set[TNimTypeFlag])
/// <pad to ptr alignment>
/// base:      ptr TNimType
/// node:      ptr TNimNode
/// finalizer: ptr
/// marker:    ptr (proc)
/// deepcopy:  ptr (proc)
/// // conditional fields follow:
/// // typeInfoV2: ptr   (if nimSeqsV2)
/// // name:  cstring    (if nimTypeNames)
/// // nextType: ptr     (if nimTypeNames)
/// // instances: NI     (if nimTypeNames)
/// // sizes: NI         (if nimTypeNames)
/// ```
///
/// [`V1Layout::NoAlign`] (Nim 1.0 - 1.2) is the same without `align`, which
/// then reads as 0. [`V1Layout::Nim12Arc`] is Nim 1.2 ARC's own struct,
/// `destructor, size, name, traceImpl, disposeImpl`, one word each: it fills
/// `size`, `name` and the three hook addresses and leaves the rest empty.
///
/// Returns `None` when `va` is not in the file or the struct runs past its
/// end.
pub fn read(container: &Container<'_>, va: u64, layout: V1Layout) -> Option<TNimTypeFields> {
    let words = DataLayout::of(container);
    let ptr_size = words.ptr_size;
    let bytes = container.bytes();
    let offset = va_to_offset(container, va)?;

    if layout == V1Layout::Nim12Arc {
        if offset.checked_add(ptr_size.saturating_mul(5))? > bytes.len() {
            return None;
        }
        let word = |i: usize| words.ptr(bytes, offset.saturating_add(ptr_size.saturating_mul(i)));
        return Some(TNimTypeFields {
            size: word(1),
            align: 0,
            kind: NimKind::None,
            kind_raw: 0,
            flags_raw: 0,
            flags: Vec::new(),
            base_addr: None,
            node_addr: None,
            finalizer_addr: None,
            marker_addr: None,
            deepcopy_addr: None,
            name: try_read_name(
                container,
                bytes,
                offset.saturating_add(ptr_size.saturating_mul(2)),
                words,
            ),
            destructor_addr: non_null(word(0)),
            trace_addr: non_null(word(3)),
            dispose_addr: non_null(word(4)),
            node_fields: Vec::new(),
        });
    }

    // Need at least: size + align + kind + flags + pad + 5 pointers
    let min = ptr_size.saturating_mul(7).saturating_add(2);
    if offset.checked_add(min)? > bytes.len() {
        return None;
    }

    let mut pos = offset;

    let size = words.ptr(bytes, pos);
    pos = pos.saturating_add(ptr_size);

    let align = if layout == V1Layout::WithAlign {
        let a = words.ptr(bytes, pos);
        pos = pos.saturating_add(ptr_size);
        a
    } else {
        0
    };

    let kind_raw = bytes.get(pos).copied().unwrap_or(0);
    pos = pos.saturating_add(1);

    let flags_raw = bytes.get(pos).copied().unwrap_or(0);
    pos = pos.saturating_add(1);

    // Padding to pointer alignment.
    let misalign = pos.wrapping_sub(offset).checked_rem(ptr_size).unwrap_or(0);
    if misalign != 0 {
        pos = pos.saturating_add(ptr_size.saturating_sub(misalign));
    }

    let base = words.ptr(bytes, pos);
    pos = pos.saturating_add(ptr_size);

    let node = words.ptr(bytes, pos);
    pos = pos.saturating_add(ptr_size);

    let finalizer = words.ptr(bytes, pos);
    pos = pos.saturating_add(ptr_size);

    let marker = words.ptr(bytes, pos);
    pos = pos.saturating_add(ptr_size);

    let deepcopy = words.ptr(bytes, pos);
    pos = pos.saturating_add(ptr_size);

    // Try to find the `name` cstring. There may be a `typeInfoV2` pointer
    // first (if nimSeqsV2 is defined). We probe both positions.
    let name = try_read_name(container, bytes, pos, words).or_else(|| {
        pos.checked_add(ptr_size)
            .and_then(|p| try_read_name(container, bytes, p, words))
    });

    // Parse flags.
    let mut flags = Vec::new();
    if flags_raw & (1 << 0) != 0 {
        flags.push(NimTypeFlag::NoRefs);
    }
    if flags_raw & (1 << 1) != 0 {
        flags.push(NimTypeFlag::Acyclic);
    }
    if flags_raw & (1 << 2) != 0 {
        flags.push(NimTypeFlag::EnumHole);
    }

    // Walk the TNimNode tree for field names.
    let node_fields = if node != 0 {
        walk_node_tree(
            container,
            bytes,
            node,
            &mut std::collections::HashSet::new(),
            words,
            ptr_size,
            0,
        )
    } else {
        Vec::new()
    };

    Some(TNimTypeFields {
        size,
        align,
        kind: NimKind::from_raw(kind_raw),
        kind_raw,
        flags_raw,
        flags,
        base_addr: non_null(base),
        node_addr: non_null(node),
        finalizer_addr: non_null(finalizer),
        marker_addr: non_null(marker),
        deepcopy_addr: non_null(deepcopy),
        name,
        destructor_addr: None,
        trace_addr: None,
        dispose_addr: None,
        node_fields,
    })
}

/// The printable, non-empty type name the cstring pointer at `pos` points to.
fn try_read_name(
    container: &Container<'_>,
    bytes: &[u8],
    pos: usize,
    words: DataLayout,
) -> Option<String> {
    let name_ptr = words.ptr(bytes, pos);
    let name = read_cstring_at_va(container, bytes, name_ptr)?;
    // Basic validation: type names should be printable ASCII.
    if name.bytes().all(is_printable_ascii) && !name.is_empty() {
        Some(name)
    } else {
        None
    }
}

/// Recursively walks a `TNimNode` tree, collecting field entries.
///
/// `TNimNode` layout:
/// ```text
/// kind:   u8 (TNimNodeKind: 0=nkNone, 1=nkSlot, 2=nkList, 3=nkCase)
/// <pad>
/// offset: NI
/// typ:    ptr TNimType
/// name:   cstring
/// len:    NI
/// sons:   ptr array[0x7fff, ptr TNimNode]
/// ```
fn walk_node_tree(
    container: &Container<'_>,
    bytes: &[u8],
    node_va: u64,
    visited: &mut std::collections::HashSet<u64>,
    words: DataLayout,
    ptr_size: usize,
    depth: usize,
) -> Vec<NodeField> {
    // Guard against infinite recursion on malformed data.
    if depth > 16 {
        return Vec::new();
    }
    // Each node is walked once per type: a type's tree never shares a node
    // (case branches repeated across discriminant values are one branch),
    // and on hostile data, nodes listing each other as sons would otherwise
    // make the walk exponential. The budget caps the work on large ones.
    if visited.len() >= MAX_NODES || !visited.insert(node_va) {
        return Vec::new();
    }

    let Some(off) = va_to_offset(container, node_va) else {
        return Vec::new();
    };

    // Minimum node size: kind(1) + pad + offset + typ + name + len + sons
    let min = ptr_size.saturating_mul(5).saturating_add(1);
    let Some(end) = off.checked_add(min) else {
        return Vec::new();
    };
    if end > bytes.len() {
        return Vec::new();
    }

    let mut pos = off;

    let kind_raw = bytes.get(pos).copied().unwrap_or(0);
    let kind = NodeKind::from_raw(kind_raw);
    pos = pos.saturating_add(1);

    // Pad to pointer alignment.
    let misalign = pos.wrapping_sub(off).checked_rem(ptr_size).unwrap_or(0);
    if misalign != 0 {
        pos = pos.saturating_add(ptr_size.saturating_sub(misalign));
    }

    let field_offset = words.ptr(bytes, pos);
    pos = pos.saturating_add(ptr_size);

    let typ = words.ptr(bytes, pos);
    pos = pos.saturating_add(ptr_size);

    let name_ptr = words.ptr(bytes, pos);
    pos = pos.saturating_add(ptr_size);

    let len = words.ptr(bytes, pos) as usize;
    pos = pos.saturating_add(ptr_size);

    let sons_ptr = words.ptr(bytes, pos);

    let mut result = Vec::new();

    // Child node addresses: `sons[0..len]` for a list; `sons[0..=len]` for a
    // case node, whose last entry is the `else` branch (`genObjectFields`
    // allocates `lengthOrd + 1` slots). Branches shared by several
    // discriminant values repeat; `visited` walks them once.
    let children = |count: usize| -> Vec<u64> {
        let mut seen = Vec::new();
        if sons_ptr == 0 || count == 0 || count > 4097 {
            return seen;
        }
        let Some(sons_off) = va_to_offset(container, sons_ptr) else {
            return seen;
        };
        for i in 0..count {
            let Some(child_ptr_off) = i
                .checked_mul(ptr_size)
                .and_then(|d| sons_off.checked_add(d))
            else {
                break;
            };
            let child_va = words.ptr(bytes, child_ptr_off);
            if child_va != 0 {
                seen.push(child_va);
            }
        }
        seen
    };
    let mut walk = |child: u64| {
        walk_node_tree(
            container,
            bytes,
            child,
            visited,
            words,
            ptr_size,
            depth.saturating_add(1),
        )
    };

    match kind {
        NodeKind::Slot => {
            // A single field.
            if let Some(name) = read_cstring_at_va(container, bytes, name_ptr) {
                result.push(NodeField {
                    name,
                    offset: field_offset,
                    type_addr: non_null(typ),
                });
            }
        }
        // A list of child nodes. Enum types leave the list's kind at 0
        // (`nkNone`, `genEnumInfo` never sets it), so `None` with sons is a
        // list too.
        NodeKind::List | NodeKind::None => {
            for child in children(len) {
                result.extend(walk(child));
            }
        }
        // An object variant: the node itself is the discriminator field;
        // its sons are the branches, indexed by discriminant value.
        NodeKind::Case => {
            if let Some(name) = read_cstring_at_va(container, bytes, name_ptr) {
                result.push(NodeField {
                    name,
                    offset: field_offset,
                    type_addr: non_null(typ),
                });
            }
            for child in children(len.saturating_add(1)) {
                result.extend(walk(child));
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- node walker and layout, on hand-built objects ----

    const DATA: u64 = 0x4000;

    /// A data section at `DATA` built from `(offset, bytes)` patches, plus
    /// the cstrings "kInt", "kStr", "kind", "i", "s" at `DATA + 0x800 + 8*n`.
    fn image(patches: &[(u64, Vec<u8>)]) -> &'static [u8] {
        let mut buf = vec![0u8; 0x900];
        for (i, name) in ["kInt", "kStr", "kind", "i", "s"].iter().enumerate() {
            let at = 0x800 + 8 * i;
            buf[at..at + name.len()].copy_from_slice(name.as_bytes());
        }
        for (off, bytes) in patches {
            let o = *off as usize;
            buf[o..o + bytes.len()].copy_from_slice(bytes);
        }
        Box::leak(buf.into_boxed_slice())
    }

    fn name_va(i: u64) -> u64 {
        DATA + 0x800 + 8 * i
    }

    fn words(ws: &[u64]) -> Vec<u8> {
        ws.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// TNimNode: kind, offset, typ, name, len, sons.
    fn node(kind: u64, offset: u64, typ: u64, name: u64, len: u64, sons: u64) -> Vec<u8> {
        words(&[kind, offset, typ, name, len, sons])
    }

    fn container(bytes: &'static [u8]) -> Container<'static> {
        use crate::container::{Arch, Format, Section, SectionKind};
        let sections = vec![Section {
            name: ".data".into(),
            kind: SectionKind::Data,
            vm_addr: DATA,
            vm_size: bytes.len() as u64,
            data: bytes,
        }];
        Container::from_parts(bytes, Format::Elf, Arch::Amd64, 0, sections, vec![])
    }

    fn sample() -> &'static [u8] {
        image(&[
            // enum: size 1, align 1, kind 14, node -> list at +0x100
            (0x000, words(&[1, 1, 14, 0, DATA + 0x100, 0, 0, 0])),
            // list node with kind 0 (as genEnumInfo leaves it), 2 sons
            (0x100, node(0, 0, 0, 0, 2, DATA + 0x200)),
            (0x200, words(&[DATA + 0x300, DATA + 0x330])),
            (0x300, node(1, 0, 0, name_va(0), 0, 0)),
            (0x330, node(1, 1, 0, name_va(1), 0, 0)),
            // object: size 16, align 8, kind 17, node -> case at +0x500
            (0x400, words(&[16, 8, 17, 0, DATA + 0x500, 0, 0, 0])),
            // case node: discriminator `kind` @0 of the enum type, 2 values
            (0x500, node(3, 0, DATA, name_va(2), 2, DATA + 0x600)),
            // branches: i, s, and the `else` slot repeating `s`
            (0x600, words(&[DATA + 0x700, DATA + 0x730, DATA + 0x730])),
            (0x700, node(1, 8, 0, name_va(3), 0, 0)),
            (0x730, node(1, 8, 0, name_va(4), 0, 0)),
        ])
    }

    #[test]
    fn enum_list_of_kind_zero_and_case_discriminator() {
        let c = container(sample());
        let e = read(&c, DATA, V1Layout::WithAlign).unwrap();
        let names: Vec<_> = e
            .node_fields
            .iter()
            .map(|f| (f.name.as_str(), f.offset))
            .collect();
        assert_eq!(names, [("kInt", 0), ("kStr", 1)]);
        let o = read(&c, DATA + 0x400, V1Layout::WithAlign).unwrap();
        let fields: Vec<_> = o
            .node_fields
            .iter()
            .map(|f| (f.name.as_str(), f.offset))
            .collect();
        assert_eq!(fields, [("kind", 0), ("i", 8), ("s", 8)]);
        assert_eq!(o.node_fields[0].type_addr, Some(DATA));
    }

    #[test]
    fn layout_detection_and_plausibility() {
        let c = container(sample());
        assert_eq!(
            detect_layout(&c, &[DATA, DATA + 0x400]),
            V1Layout::WithAlign
        );
        // The same object without `align` (Nim 1.0 / 1.2).
        let old = image(&[
            (0x000, words(&[16, 17, 0, DATA + 0x500, 0, 0, 0])),
            (0x500, node(3, 0, 0, name_va(2), 2, DATA + 0x600)),
            (0x600, words(&[DATA + 0x700, DATA + 0x730, 0])),
            (0x700, node(1, 8, 0, name_va(3), 0, 0)),
            (0x730, node(1, 8, 0, name_va(4), 0, 0)),
        ]);
        let c = container(old);
        assert_eq!(detect_layout(&c, &[DATA]), V1Layout::NoAlign);
        let f = read(&c, DATA, V1Layout::NoAlign).unwrap();
        assert_eq!((f.size, f.kind, f.align), (16, NimKind::Object, 0));
        assert!(f.is_plausible());
        // Read with the wrong layout the object is rejected.
        assert!(!read(&c, DATA, V1Layout::WithAlign).is_some_and(|f| f.is_plausible()));
    }

    #[test]
    fn nim12_arc_layout_detected_and_read() {
        use crate::container::{Arch, Format, Section, SectionKind};
        // text at 0x1000 (hooks point here), data at DATA holding
        // `destructor, size, name, traceImpl, disposeImpl`.
        let data = image(&[
            (0x000, words(&[0x1010, 64, name_va(0), 0x1020, 0])),
            (0x040, words(&[0x1030, 16, 0, 0, 0])),
        ]);
        let text: &'static [u8] = Box::leak(vec![0xc3u8; 0x100].into_boxed_slice());
        let mut bytes = text.to_vec();
        bytes.extend_from_slice(data);
        let bytes: &'static [u8] = Box::leak(bytes.into_boxed_slice());
        let sections = vec![
            Section {
                name: ".text".into(),
                kind: SectionKind::Text,
                vm_addr: 0x1000,
                vm_size: 0x100,
                data: &bytes[..0x100],
            },
            Section {
                name: ".data".into(),
                kind: SectionKind::Data,
                vm_addr: DATA,
                vm_size: data.len() as u64,
                data: &bytes[0x100..],
            },
        ];
        let c = Container::from_parts(bytes, Format::Elf, Arch::Amd64, 0, sections, vec![]);
        assert_eq!(detect_layout(&c, &[DATA, DATA + 0x40]), V1Layout::Nim12Arc);
        let f = read(&c, DATA, V1Layout::Nim12Arc).unwrap();
        assert_eq!((f.size, f.name.as_deref()), (64, Some("kInt")));
        assert_eq!(
            (f.destructor_addr, f.trace_addr, f.dispose_addr),
            (Some(0x1010), Some(0x1020), None)
        );
    }

    #[test]
    fn nodes_listing_each_other_are_walked_once() {
        // Eight list nodes whose sons are all eight nodes: without a visited
        // set the depth-16 walk visits 8^16 nodes.
        const N: u64 = 8;
        let sons = DATA + 0x100;
        let mut patches = vec![
            (0x000, words(&[16, 8, 17, 0, DATA + 0x200, 0, 0, 0])),
            (
                0x100,
                words(&(0..N).map(|i| DATA + 0x200 + 0x30 * i).collect::<Vec<_>>()),
            ),
        ];
        for i in 0..N {
            patches.push((0x200 + 0x30 * i, node(2, 0, 0, 0, N, sons)));
        }
        let c = container(image(&patches));
        let started = std::time::Instant::now();
        let t = read(&c, DATA, V1Layout::WithAlign).unwrap();
        assert!(t.node_fields.is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
