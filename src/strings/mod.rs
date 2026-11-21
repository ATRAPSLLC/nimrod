//! Nim string literal scanning.
//!
//! Covers the V1 (`NimStringDesc` / `TGenericSeq`), V2
//! (`NimStringV2` / `NimStrPayload`) and V3 (Nim 2.4 `--strings:sso`
//! `SmallString`) layouts. See `RESEARCH.md` section 4.
//!
//! - [`v2::scan`] finds V2 literals via the `NIM_STRLIT_FLAG` pattern.
//! - [`v1::scan`] finds legacy V1 literals (best-effort).
//! - [`v3::scan`] finds SSO literals (inline `SmallString`s and static long
//!   blocks), gated on SSO structure being present.

pub mod v1;
pub mod v2;
pub mod v3;

use crate::util::DataLayout;

/// `strlitFlag` (`NIM_STRLIT_FLAG`): the bit a string literal sets in its
/// capacity word so the runtime never frees or grows it, the
/// second-highest bit of a word (`1 << 62` on 64-bit, `1 << 30` on
/// 32-bit). V1 headers and V2 payloads carry it alike.
fn strlit_flag(layout: DataLayout) -> u64 {
    if layout.is_64() { 1 << 62 } else { 1 << 30 }
}
