//! Symbol and module-path demangling.
//!
//! Three layers, matching the Nim compiler's mangling pipeline:
//!
//! - [`identifier::demangle`]: inverse of `ccgutils.nim proc mangle*`
//!   (character-level substitution reversal).
//! - [`symbol::parse`]: splits routine and global names in every layout
//!   the C backend has used (1.0 - 1.4 signature hash, 1.6 - 2.3, 2.4+, and
//!   Itanium for debug-info builds).
//! - [`modpath::decode`]: decodes the `atm…ats…` (encoded `@m…@s…`)
//!   module-path tokens used in init-function symbol names.
//!
//! See `RESEARCH.md` sections 8 and 10 for the format specification.

pub mod identifier;
pub mod modpath;
pub mod symbol;
