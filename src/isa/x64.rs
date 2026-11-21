//! x86-64 registers and calling conventions.
//!
//! Register numbers are as encoded in ModRM, SIB and REX (`rax` = 0 ..
//! `r15` = 15). [`Abi`] picks the convention of an image: Microsoft x64 for
//! PE, System V everywhere else.

use crate::container::{Container, Format};

/// `rax`: the return value.
pub const RAX: usize = 0;
/// `rcx`.
pub const RCX: usize = 1;
/// `rdx`.
pub const RDX: usize = 2;
/// `rsp`: the stack pointer.
pub const RSP: usize = 4;
/// `rbp`: the frame pointer.
pub const RBP: usize = 5;
/// `rsi`.
pub const RSI: usize = 6;
/// `rdi`.
pub const RDI: usize = 7;
/// `r8`.
pub const R8: usize = 8;
/// `r9`.
pub const R9: usize = 9;
/// `r10`.
pub const R10: usize = 10;
/// `r11`.
pub const R11: usize = 11;

/// A calling convention for integer arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abi {
    /// System V AMD64 (ELF, Mach-O): `rdi, rsi, rdx, rcx, r8, r9`.
    SysV,
    /// Microsoft x64 (PE): `rcx, rdx, r8, r9`, then the stack from
    /// `[rsp + 0x20]` at the call (after the 32-byte shadow space).
    Microsoft,
}

impl Abi {
    /// The convention of `container`'s code.
    pub fn of(container: &Container<'_>) -> Self {
        if container.format() == Format::Pe {
            Self::Microsoft
        } else {
            Self::SysV
        }
    }

    /// The registers of the first four integer arguments.
    pub fn int_args(self) -> [usize; 4] {
        match self {
            Self::SysV => [RDI, RSI, RDX, RCX],
            Self::Microsoft => [RCX, RDX, R8, R9],
        }
    }

    /// The register of the fifth integer argument, or `None` when it is
    /// passed on the stack (Microsoft x64: at `[rsp + 0x20]` at the call).
    pub fn fifth_arg(self) -> Option<usize> {
        match self {
            Self::SysV => Some(R8),
            Self::Microsoft => None,
        }
    }

    /// The integer registers a call may overwrite.
    pub fn caller_saved(self) -> &'static [usize] {
        match self {
            Self::SysV => &[RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11],
            Self::Microsoft => &[RAX, RCX, RDX, R8, R9, R10, R11],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conventions_match_the_abi_documents() {
        // System V AMD64 psABI §3.2.3; Microsoft x64 calling convention.
        assert_eq!(Abi::SysV.int_args(), [RDI, RSI, RDX, RCX]);
        assert_eq!(Abi::SysV.fifth_arg(), Some(R8));
        assert_eq!(Abi::Microsoft.int_args(), [RCX, RDX, R8, R9]);
        assert_eq!(Abi::Microsoft.fifth_arg(), None);
        // rsi and rdi are callee-saved under Microsoft x64 only.
        assert!(Abi::SysV.caller_saved().contains(&RSI));
        assert!(!Abi::Microsoft.caller_saved().contains(&RSI));
        assert!(!Abi::Microsoft.caller_saved().contains(&RDI));
        for abi in [Abi::SysV, Abi::Microsoft] {
            for r in abi.int_args() {
                assert!(abi.caller_saved().contains(&r), "{abi:?} r{r}");
            }
        }
    }
}
