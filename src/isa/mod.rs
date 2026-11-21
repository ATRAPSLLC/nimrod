//! Instruction-set facts shared by the code scanners and the startup-code
//! emulators: AArch64 instruction decoding ([`a64`]), x86-64 register
//! numbers and calling conventions ([`x64`]).
//!
//! The module is private, so its `pub` items are crate-internal.

pub mod a64;
pub mod x64;
