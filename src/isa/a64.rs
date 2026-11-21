//! AArch64 (A64) instruction decoding shared by the raise-site scanner, the
//! SSO immediate scanner and the startup-code emulator.
//!
//! Each decoder recognises one instruction class from its fixed 32-bit
//! encoding (Arm ARM, "A64 Instruction Set Encoding") and returns its
//! operands, or `None` for any other instruction. Execution stays with the
//! callers; this module only says what an instruction is.

/// The `len`-bit field of `insn` starting at bit `lo`.
pub fn bits(insn: u32, lo: u32, len: u32) -> u32 {
    (insn >> lo) & low_mask(len) as u32
}

/// Sign-extends the low `len` bits of `v`.
pub fn sext(v: u64, len: u32) -> i64 {
    let spare = 64u32.saturating_sub(len);
    ((v << spare) as i64) >> spare
}

/// The low `len` bits set (`len` >= 64: all bits).
pub fn low_mask(len: u32) -> u64 {
    if len >= 64 {
        u64::MAX
    } else {
        (1u64 << len).wrapping_sub(1)
    }
}

/// Whether the instruction's `sf` bit (31) selects 64-bit operands.
fn sf(insn: u32) -> bool {
    insn & 0x8000_0000 != 0
}

/// A `b` or `bl` (unconditional branch, immediate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Branch {
    /// `bl`: a call (writes the return address to `x30`).
    pub link: bool,
    /// The branch target.
    pub target: u64,
}

/// Decodes `b` / `bl` at `pc`: `imm26`, scaled by 4, from the instruction.
pub fn branch(insn: u32, pc: u64) -> Option<Branch> {
    let link = match insn & 0xFC00_0000 {
        0x9400_0000 => true,
        0x1400_0000 => false,
        _ => return None,
    };
    let offset = sext(u64::from(bits(insn, 0, 26)), 26).wrapping_mul(4);
    Some(Branch {
        link,
        target: pc.wrapping_add(offset as u64),
    })
}

/// The 21-bit `immhi:immlo` offset of `adr` / `adrp`, sign-extended.
fn pc_rel_imm(insn: u32) -> i64 {
    let imm = (u64::from(bits(insn, 5, 19)) << 2) | u64::from(bits(insn, 29, 2));
    sext(imm, 21)
}

/// Decodes `adrp Xd, <page>` at `pc`: `(rd, page)`, the 4 KiB page of `pc`
/// plus the offset in pages.
pub fn adrp(insn: u32, pc: u64) -> Option<(u32, u64)> {
    (insn & 0x9F00_0000 == 0x9000_0000).then(|| {
        let page = (pc & !0xfff).wrapping_add((pc_rel_imm(insn) as u64) << 12);
        (bits(insn, 0, 5), page)
    })
}

/// Decodes `adr Xd, <label>` at `pc`: `(rd, address)`.
pub fn adr(insn: u32, pc: u64) -> Option<(u32, u64)> {
    (insn & 0x9F00_0000 == 0x1000_0000)
        .then(|| (bits(insn, 0, 5), pc.wrapping_add(pc_rel_imm(insn) as u64)))
}

/// An `add` / `adds` / `sub` / `subs` with an immediate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddSubImm {
    /// Destination; 31 is `sp` without flags, the zero register with them
    /// (`cmp` / `cmn`).
    pub rd: u32,
    /// Source; 31 is `sp`.
    pub rn: u32,
    /// The immediate, shifted (`imm12`, or `imm12 << 12`).
    pub imm: u64,
    /// `sub` / `subs`.
    pub sub: bool,
    /// `adds` / `subs`: the flags are set.
    pub set_flags: bool,
    /// 64-bit operands.
    pub wide: bool,
}

/// Decodes `add`/`adds`/`sub`/`subs` (immediate): bits 28..23 are
/// `100010`.
pub fn add_sub_imm(insn: u32) -> Option<AddSubImm> {
    if insn & 0x1F80_0000 != 0x1100_0000 {
        return None;
    }
    let imm12 = u64::from(bits(insn, 10, 12));
    Some(AddSubImm {
        rd: bits(insn, 0, 5),
        rn: bits(insn, 5, 5),
        imm: if bits(insn, 22, 1) == 1 {
            imm12 << 12
        } else {
            imm12
        },
        sub: insn & 0x4000_0000 != 0,
        set_flags: insn & 0x2000_0000 != 0,
        wide: sf(insn),
    })
}

/// The move-wide operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveWideOp {
    /// `movz`: the immediate, other bits zero.
    Z,
    /// `movn`: the inverted immediate.
    N,
    /// `movk`: the immediate into one 16-bit lane, other bits kept.
    K,
}

/// A `movz` / `movn` / `movk`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveWide {
    /// The operation.
    pub op: MoveWideOp,
    /// Destination register.
    pub rd: u32,
    /// The 16-bit immediate.
    pub imm16: u16,
    /// Its position: `lsl #shift`, a multiple of 16.
    pub shift: u32,
    /// 64-bit operands (`x` register).
    pub wide: bool,
}

impl MoveWide {
    /// The lane the immediate occupies.
    pub fn lane_mask(&self) -> u64 {
        0xffff_u64 << self.shift
    }

    /// The immediate in its lane.
    pub fn lane_value(&self) -> u64 {
        u64::from(self.imm16) << self.shift
    }
}

/// Decodes `movz` / `movn` / `movk` (bits 28..23 `100101`; `opc` 01 is
/// unallocated).
pub fn move_wide(insn: u32) -> Option<MoveWide> {
    let op = match insn & 0x7F80_0000 {
        0x5280_0000 => MoveWideOp::Z,
        0x1280_0000 => MoveWideOp::N,
        0x7280_0000 => MoveWideOp::K,
        _ => return None,
    };
    Some(MoveWide {
        op,
        rd: bits(insn, 0, 5),
        imm16: bits(insn, 5, 16) as u16,
        shift: bits(insn, 21, 2).saturating_mul(16),
        wide: sf(insn),
    })
}

/// Decodes the register `mov Rd, Rm` (`orr Rd, zr, Rm` with no shift
/// amount): `(rd, rm, wide)`.
pub fn mov_reg(insn: u32) -> Option<(u32, u32, bool)> {
    (insn & 0x7F20_FFE0 == 0x2A00_03E0).then(|| (bits(insn, 0, 5), bits(insn, 16, 5), sf(insn)))
}

/// `DecodeBitMasks` for logical immediates (`N:immr:imms`), `width` 32/64.
pub fn decode_bitmask(n: u32, immr: u32, imms: u32, width: u32) -> Option<u64> {
    let combined = (n << 6) | (!imms & 0x3f);
    let len = 31u32.checked_sub(combined.leading_zeros())?;
    if len < 1 {
        return None;
    }
    let esize = 1u32 << len;
    let levels = esize.wrapping_sub(1);
    let s = imms & levels;
    let r = immr & levels;
    if s == levels {
        return None;
    }
    let welem: u64 = (1u64 << (s.saturating_add(1))).wrapping_sub(1);
    let emask = low_mask(esize);
    let rotated = if r == 0 {
        welem
    } else {
        ((welem >> r) | (welem << esize.wrapping_sub(r))) & emask
    };
    let mut v = 0u64;
    let mut pos = 0u32;
    while pos < width {
        v |= rotated << pos;
        pos = pos.saturating_add(esize);
    }
    Some(if width == 32 { v & 0xffff_ffff } else { v })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branches() {
        // bl #+0x800 at 0x1000; b #-4 at 0x1000.
        assert_eq!(
            branch(0x9400_0200, 0x1000),
            Some(Branch {
                link: true,
                target: 0x1800
            })
        );
        assert_eq!(
            branch(0x17ff_ffff, 0x1000),
            Some(Branch {
                link: false,
                target: 0xffc
            })
        );
        assert_eq!(branch(0xd65f_03c0, 0x1000), None); // ret
    }

    #[test]
    fn pc_relative() {
        // adrp x1 at 0x1234: its page 0x1000, plus one page.
        assert_eq!(adrp(0xb000_0001, 0x1234), Some((1, 0x2000)));
        // adrp x0, -1 page.
        assert_eq!(adrp(0xf0ff_ffe0, 0x5000), Some((0, 0x4000)));
        // adr x2, #+8 at 0x1000.
        assert_eq!(adr(0x1000_0042, 0x1000), Some((2, 0x1008)));
        assert_eq!(adr(0xb000_0001, 0x1000), None);
    }

    #[test]
    fn add_sub_immediates() {
        // add x1, x1, #0x10
        let a = add_sub_imm(0x9100_4021).unwrap();
        assert_eq!(
            (a.rd, a.rn, a.imm, a.sub, a.set_flags, a.wide),
            (1, 1, 0x10, false, false, true)
        );
        // sub sp, sp, #1, lsl #12
        let s = add_sub_imm(0xd140_07ff).unwrap();
        assert_eq!((s.rd, s.rn, s.imm, s.sub), (31, 31, 0x1000, true));
        // cmp w0, #3 (subs wzr, w0, #3)
        let c = add_sub_imm(0x7100_0c1f).unwrap();
        assert_eq!((c.rd, c.imm, c.set_flags, c.wide), (31, 3, true, false));
        // addg (MTE, bit 23 set) is another instruction.
        assert_eq!(add_sub_imm(0x9180_0000), None);
    }

    #[test]
    fn move_wides() {
        // mov x4, #9 (movz)
        let z = move_wide(0xd280_0124).unwrap();
        assert_eq!(
            (z.op, z.rd, z.imm16, z.shift, z.wide),
            (MoveWideOp::Z, 4, 9, 0, true)
        );
        // movk x3, #0x7465, lsl #16
        let k = move_wide(0xf2ae_8ca3).unwrap();
        assert_eq!(
            (k.op, k.rd, k.imm16, k.shift),
            (MoveWideOp::K, 3, 0x7465, 16)
        );
        assert_eq!(k.lane_value(), 0x7465_0000);
        // movn w0, #0
        let n = move_wide(0x1280_0000).unwrap();
        assert_eq!((n.op, n.wide), (MoveWideOp::N, false));
        // opc = 01 is unallocated.
        assert_eq!(move_wide(0x3280_0000), None);
    }

    #[test]
    fn register_moves_and_masks() {
        // mov x0, x19 / mov w1, w2
        assert_eq!(mov_reg(0xaa13_03e0), Some((0, 19, true)));
        assert_eq!(mov_reg(0x2a02_03e1), Some((1, 2, false)));
        // orr x0, x1, x2 is not a move.
        assert_eq!(mov_reg(0xaa02_0020), None);
        assert_eq!(decode_bitmask(1, 0, 7, 64), Some(0xff));
        assert_eq!(decode_bitmask(0, 0, 0x3c, 32), Some(0x5555_5555));
        assert_eq!(bits(0xffff_ffff, 5, 5), 31);
        assert_eq!(sext(0x3ff_ffff, 26), -1);
        assert_eq!(low_mask(64), u64::MAX);
    }
}
