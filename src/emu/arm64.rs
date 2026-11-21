//! AArch64 subset emulator for `DatInit000`.
//!
//! Covers what clang and gcc emit for runs of constant assignments:
//!
//! - address and integer arithmetic: `adrp`/`adr`, `add`/`sub`/`adds`/`subs`
//!   (immediate and shifted register), `madd`/`msub`, logical operations
//!   (shifted register and bitmask immediate), `ubfm` (`lsl`/`lsr`),
//!   `movz`/`movn`/`movk` and register `mov`;
//! - control flow: `b`, `b.cond`, `cbz`/`cbnz`, `ret`, and hints;
//! - memory: loads and stores of general and SIMD registers (`b` to `q`) in
//!   unsigned-offset, unscaled, pre/post-index and register-offset forms,
//!   `ldr` literal, `stp`/`ldp` of `x`, `w`, `d` and `q` registers;
//! - SIMD moves: `dup v.2d`, `ins v.d[1]`, `fmov d` from a general register.
//!
//! Anything else (atomics, floating-point arithmetic, calls) ends the
//! evaluation of the function. Instructions are fetched as little-endian
//! words, which A64 code is in every mode.

use std::collections::HashMap;

use super::{Mem, Overlay, STACK_TOP, image_byte};
use crate::container::Container;
use crate::isa::a64::{self, MoveWideOp, bits, decode_bitmask, low_mask, sext};

/// Runs the function at `entry` for at most `budget` instructions,
/// recording its image writes into `overlay`, and returns how many
/// instructions it executed.
pub fn run(
    container: &Container<'_>,
    entry: u64,
    overlay: &mut Overlay,
    fixups: &HashMap<u64, u64>,
    budget: u64,
) -> u64 {
    let mut cpu = Cpu {
        container,
        mem: Mem {
            container,
            overlay,
            stack: HashMap::new(),
            fixups,
        },
        x: [0; 31],
        sp: STACK_TOP,
        v: [0; 32],
        pc: entry,
        nzcv: [false; 4],
    };
    // x30 = 0: returning to it ends the function.
    let mut steps = 0;
    while steps < budget {
        steps = steps.saturating_add(1);
        if cpu.step() != Some(true) {
            break;
        }
    }
    steps
}

/// Register state of the function being evaluated, over the shared [`Mem`].
struct Cpu<'c, 'a, 'o> {
    /// The image the code is fetched from.
    container: &'c Container<'a>,
    /// Image, overlay and stack memory.
    mem: Mem<'c, 'a, 'o>,
    /// `x0`..`x30`; register 31 is the zero register or `sp` by context. `x30`
    /// starts at 0, so returning to it ends the run.
    x: [u64; 31],
    /// The stack pointer, starting at [`STACK_TOP`].
    sp: u64,
    /// The SIMD registers `v0`..`v31` (`q`, `d`, `s`, `h`, `b` views).
    v: [u128; 32],
    /// Address of the next instruction.
    pc: u64,
    /// N, Z, C, V.
    nzcv: [bool; 4],
}

/// Applies a register shift (`LSL`, `LSR`, `ASR`, `ROR`) of `amount`.
fn shift_reg(v: u64, kind: u32, amount: u32, width: u32) -> u64 {
    let m = if width == 32 {
        0xffff_ffffu64
    } else {
        u64::MAX
    };
    let v = v & m;
    let amount = amount.checked_rem(width).unwrap_or(0);
    (match kind {
        0 => v.checked_shl(amount).unwrap_or(0),
        1 => v.checked_shr(amount).unwrap_or(0),
        2 => (sext(v, width) >> amount) as u64,
        _ => {
            v.rotate_right(amount)
                | if width == 32 {
                    v.checked_shl(width.wrapping_sub(amount)).unwrap_or(0)
                } else {
                    0
                }
        }
    }) & m
}

impl Cpu<'_, '_, '_> {
    /// General register read; 31 is the zero register.
    fn xr(&self, r: u32) -> u64 {
        if r == 31 {
            0
        } else {
            self.x.get(r as usize).copied().unwrap_or(0)
        }
    }

    /// General register write; writes to 31 (zero register) vanish.
    fn xw(&mut self, r: u32, v: u64) {
        if let Some(slot) = self.x.get_mut(r as usize) {
            *slot = v;
        }
    }

    /// Base register read: 31 is the stack pointer.
    fn base(&self, r: u32) -> u64 {
        if r == 31 { self.sp } else { self.xr(r) }
    }

    /// Base register write (pre/post-index writeback): 31 is the stack pointer.
    fn base_w(&mut self, r: u32, v: u64) {
        if r == 31 {
            self.sp = v;
        } else {
            self.xw(r, v);
        }
    }

    /// SIMD register read.
    fn vr(&self, r: u32) -> u128 {
        self.v.get(r as usize).copied().unwrap_or(0)
    }

    /// SIMD register write (the whole 128 bits).
    fn vw(&mut self, r: u32, v: u128) {
        if let Some(slot) = self.v.get_mut(r as usize) {
            *slot = v;
        }
    }

    /// Add or subtract with optional flag update (`adds`/`subs`).
    fn addsub(&mut self, a: u64, b: u64, sub: bool, width: u32, set_flags: bool) -> u64 {
        let m = if width == 32 {
            0xffff_ffffu64
        } else {
            u64::MAX
        };
        let (a, b) = (a & m, b & m);
        let r = if sub {
            a.wrapping_sub(b)
        } else {
            a.wrapping_add(b)
        } & m;
        if set_flags {
            let sign = 1u64 << width.saturating_sub(1);
            let carry = if sub { a >= b } else { r < a };
            let overflow = if sub {
                (a ^ b) & (a ^ r) & sign != 0
            } else {
                !(a ^ b) & (a ^ r) & sign != 0
            };
            self.nzcv = [r & sign != 0, r == 0, carry, overflow];
        }
        r
    }

    /// Whether condition code `cc` (`eq`, `ne`, ... `al`) holds under the current
    /// `nzcv` flags.
    fn cond(&self, cc: u32) -> bool {
        let [n, z, c, v] = self.nzcv;
        let base = match cc >> 1 {
            0 => z,
            1 => c,
            2 => n,
            3 => v,
            4 => c && !z,
            5 => n == v,
            6 => n == v && !z,
            _ => true,
        };
        if cc & 1 == 1 && cc != 15 { !base } else { base }
    }

    /// Stores general register `rt` (`size` bytes) at `addr`.
    fn store_x(&mut self, rt: u32, addr: u64, size: u32) -> Option<()> {
        let v = self.xr(rt);
        self.mem.write(addr, size, v)
    }

    /// Executes one instruction. `Some(true)`: continue; `Some(false)`: the
    /// function returned; `None`: unsupported, stop.
    fn step(&mut self) -> Option<bool> {
        let mut w = [0u8; 4];
        for (i, b) in w.iter_mut().enumerate() {
            *b = image_byte(self.container, self.pc.wrapping_add(i as u64))?;
        }
        let insn = u32::from_le_bytes(w);
        let pc = self.pc;
        let mut next = pc.wrapping_add(4);
        let rd = bits(insn, 0, 5);
        let rn = bits(insn, 5, 5);
        let rt2 = bits(insn, 10, 5);

        let width_mask = |wide: bool, v: u64| if wide { v } else { v & 0xffff_ffff };

        if let Some((rd, page)) = a64::adrp(insn, pc) {
            self.xw(rd, page);
        } else if let Some((rd, addr)) = a64::adr(insn, pc) {
            self.xw(rd, addr);
        } else if let Some(op) = a64::add_sub_imm(insn) {
            if op.set_flags {
                // adds / subs; `cmp`/`cmn` write the zero register
                let width = if op.wide { 64 } else { 32 };
                let r = self.addsub(self.base(op.rn), op.imm, op.sub, width, true);
                self.xw(op.rd, r);
            } else {
                // add / sub; 31 = sp on both sides
                let a = self.base(op.rn);
                let r = if op.sub {
                    a.wrapping_sub(op.imm)
                } else {
                    a.wrapping_add(op.imm)
                };
                self.base_w(op.rd, width_mask(op.wide, r));
            }
        } else if let Some(mw) = a64::move_wide(insn) {
            let v = match mw.op {
                MoveWideOp::Z => mw.lane_value(),
                MoveWideOp::N => !mw.lane_value(),
                MoveWideOp::K => (self.xr(mw.rd) & !mw.lane_mask()) | mw.lane_value(),
            };
            self.xw(mw.rd, width_mask(mw.wide, v));
        } else if let Some((rd, rm, wide)) = a64::mov_reg(insn) {
            let v = self.xr(rm);
            self.xw(rd, width_mask(wide, v));
        } else if insn == 0xD65F_03C0 {
            // ret
            let lr = self.xr(30);
            if lr == 0 {
                return Some(false);
            }
            next = lr;
        } else if let Some(b) = a64::branch(insn, pc).filter(|b| !b.link) {
            next = b.target;
        } else if insn & 0xFFFF_F01F == 0xD503_201F {
            // hint space: nop, bti, pac*
        } else if insn & 0xFFFF_FC00 == 0x4E08_0C00 {
            // dup vd.2d, xn
            let v = u128::from(self.xr(rn));
            self.vw(rd, v | (v << 64));
        } else if insn & 0xFFFF_FC00 == 0x4E18_1C00 {
            // ins vd.d[1], xn
            let lo = self.vr(rd) & u128::from(u64::MAX);
            self.vw(rd, lo | (u128::from(self.xr(rn)) << 64));
        } else if insn & 0xFFFF_FC00 == 0x9E67_0000 {
            // fmov dd, xn
            self.vw(rd, u128::from(self.xr(rn)));
        } else if insn & 0x1F20_0000 == 0x0B00_0000 {
            // add / adds / sub / subs (shifted register)
            let width: u32 = if insn & 0x8000_0000 == 0 { 32 } else { 64 };
            let b = shift_reg(
                self.xr(bits(insn, 16, 5)),
                bits(insn, 22, 2),
                bits(insn, 10, 6),
                width,
            );
            let r = self.addsub(
                self.xr(rn),
                b,
                insn & 0x4000_0000 != 0,
                width,
                insn & 0x2000_0000 != 0,
            );
            self.xw(rd, r);
        } else if insn & 0x1F00_0000 == 0x0A00_0000 && bits(insn, 21, 1) == 0 {
            // and / orr / eor / ands (shifted register, not negated)
            let width: u32 = if insn & 0x8000_0000 == 0 { 32 } else { 64 };
            let a = self.xr(rn);
            let b = shift_reg(
                self.xr(bits(insn, 16, 5)),
                bits(insn, 22, 2),
                bits(insn, 10, 6),
                width,
            );
            let r = match bits(insn, 29, 2) {
                0 | 3 => a & b,
                1 => a | b,
                _ => a ^ b,
            };
            let r = if width == 32 { r & 0xffff_ffff } else { r };
            if bits(insn, 29, 2) == 3 {
                let sign = 1u64 << width.saturating_sub(1);
                self.nzcv = [r & sign != 0, r == 0, false, false];
            }
            self.xw(rd, r);
        } else if insn & 0x1F80_0000 == 0x1200_0000 {
            // and / orr / eor / ands (immediate)
            let width: u32 = if insn & 0x8000_0000 == 0 { 32 } else { 64 };
            let imm = decode_bitmask(
                bits(insn, 22, 1),
                bits(insn, 16, 6),
                bits(insn, 10, 6),
                width,
            )?;
            let a = self.xr(rn);
            let r = match bits(insn, 29, 2) {
                0 | 3 => a & imm,
                1 => a | imm,
                _ => a ^ imm,
            };
            if bits(insn, 29, 2) == 3 {
                let sign = 1u64 << width.saturating_sub(1);
                self.nzcv = [r & sign != 0, r == 0, false, false];
                self.xw(rd, r);
            } else {
                self.base_w(rd, r);
            }
        } else if insn & 0x7F80_0000 == 0x5300_0000 {
            // ubfm (lsl, lsr, ubfx, uxtb, uxth)
            let width: u32 = if insn & 0x8000_0000 == 0 { 32 } else { 64 };
            let (immr, imms) = (bits(insn, 16, 6), bits(insn, 10, 6));
            let src = self.xr(rn) & if width == 32 { 0xffff_ffff } else { u64::MAX };
            let r = if imms >= immr {
                let len = imms.wrapping_sub(immr).wrapping_add(1);
                (src >> immr) & low_mask(len)
            } else {
                let field = src & low_mask(imms.wrapping_add(1));
                field.checked_shl(width.wrapping_sub(immr)).unwrap_or(0)
            };
            self.xw(rd, if width == 32 { r & 0xffff_ffff } else { r });
        } else if insn & 0x7FE0_0000 == 0x1B00_0000 {
            // madd / msub (`mul` is madd with the zero register)
            let width_mask = if insn & 0x8000_0000 == 0 {
                0xffff_ffffu64
            } else {
                u64::MAX
            };
            let product = self.xr(rn).wrapping_mul(self.xr(bits(insn, 16, 5)));
            let acc = self.xr(bits(insn, 10, 5));
            let r = if insn & 0x8000 == 0 {
                acc.wrapping_add(product)
            } else {
                acc.wrapping_sub(product)
            };
            self.xw(rd, r & width_mask);
        } else if insn & 0xFF00_0010 == 0x5400_0000 {
            // b.cond
            if self.cond(bits(insn, 0, 4)) {
                next = pc.wrapping_add((sext(u64::from(bits(insn, 5, 19)), 19) as u64) << 2);
            }
        } else if insn & 0x7E00_0000 == 0x3400_0000 {
            // cbz / cbnz
            let width_mask = if insn & 0x8000_0000 == 0 {
                0xffff_ffffu64
            } else {
                u64::MAX
            };
            let zero = self.xr(rd) & width_mask == 0;
            if zero == (insn & 0x0100_0000 == 0) {
                next = pc.wrapping_add((sext(u64::from(bits(insn, 5, 19)), 19) as u64) << 2);
            }
        } else {
            self.mem_op(insn, pc, rd, rn, rt2)?;
        }
        self.pc = next;
        Some(true)
    }

    /// Loads and stores. `rd` is `Rt` here.
    fn mem_op(&mut self, insn: u32, pc: u64, rt: u32, rn: u32, rt2: u32) -> Option<()> {
        let size_field = bits(insn, 30, 2);
        // Literal loads: ldr xt / ldr qt, label.
        if insn & 0xFF00_0000 == 0x5800_0000 || insn & 0xFF00_0000 == 0x9C00_0000 {
            let addr = pc.wrapping_add((sext(u64::from(bits(insn, 5, 19)), 19) as u64) << 2);
            if insn & 0xFF00_0000 == 0x5800_0000 {
                let v = self.mem.read(addr, 8)?;
                self.xw(rt, v);
            } else {
                let v = self.mem.read128(addr)?;
                self.vw(rt, v);
            }
            return Some(());
        }
        // Pair: stp / ldp, general (opc 10 = 64-bit, 00 = 32-bit) or q (opc 10, V=1).
        if insn & 0x3A00_0000 == 0x2800_0000 {
            let vec = bits(insn, 26, 1) == 1;
            let opc = bits(insn, 30, 2);
            let load = bits(insn, 22, 1) == 1;
            let mode = bits(insn, 23, 2); // 01 post, 10 offset, 11 pre
            let size: u32 = match (vec, opc) {
                (false, 0) => 4,
                (false, 2) => 8,
                (true, 2) => 16,
                (true, 1) => 8,
                _ => return None,
            };
            if mode == 0 {
                return None;
            }
            let off = sext(u64::from(bits(insn, 15, 7)), 7).wrapping_mul(i64::from(size)) as u64;
            let base = self.base(rn);
            let addr = if mode == 1 {
                base
            } else {
                base.wrapping_add(off)
            };
            let second = addr.wrapping_add(u64::from(size));
            match (vec, load) {
                (false, false) => {
                    self.store_x(rt, addr, size)?;
                    self.store_x(rt2, second, size)?;
                }
                (false, true) => {
                    let a = self.mem.read(addr, size)?;
                    let b = self.mem.read(second, size)?;
                    self.xw(rt, a);
                    self.xw(rt2, b);
                }
                (true, false) => {
                    let (a, b) = (self.vr(rt), self.vr(rt2));
                    if size == 16 {
                        self.mem.write128(addr, a)?;
                        self.mem.write128(second, b)?;
                    } else {
                        self.mem.write(addr, size, a as u64)?;
                        self.mem.write(second, size, b as u64)?;
                    }
                }
                (true, true) => return None,
            }
            if mode != 2 {
                self.base_w(rn, base.wrapping_add(off));
            }
            return Some(());
        }
        // Single register, general or SIMD (V bit 26).
        if insn & 0x3A00_0000 != 0x3800_0000 {
            return None;
        }
        let vec = bits(insn, 26, 1) == 1;
        let opc = bits(insn, 22, 2);
        // Access size and direction.
        let (size, load): (u32, bool) = if vec {
            match (size_field, opc) {
                (0, 2) => (16, false),
                (0, 3) => (16, true),
                // b, h, s, d registers
                (n, 0) => (1u32 << n, false),
                (n, 1) => (1u32 << n, true),
                _ => return None,
            }
        } else {
            match opc {
                0 => (1u32 << size_field, false),
                1 => (1u32 << size_field, true),
                _ => return None, // sign-extending loads: not needed
            }
        };
        let base = self.base(rn);
        let (addr, writeback) = if insn & 0x0100_0000 != 0 {
            // unsigned scaled immediate
            (
                base.wrapping_add(u64::from(bits(insn, 10, 12)).wrapping_mul(u64::from(size))),
                None,
            )
        } else {
            // Bit 21 set: register offset (bits 10-11 = 10) or an atomic
            // memory operation (`ldadd` & co.), which is not emulated.
            if bits(insn, 21, 1) == 1 {
                if bits(insn, 10, 2) != 2 {
                    return None;
                }
                let rm = self.xr(bits(insn, 16, 5));
                let extended = match bits(insn, 13, 3) {
                    2 => rm & 0xffff_ffff,                 // uxtw
                    3 | 7 => rm,                           // lsl / sxtx
                    6 => (rm as u32 as i32 as i64) as u64, // sxtw
                    _ => return None,
                };
                let shift = if bits(insn, 12, 1) == 1 {
                    size.trailing_zeros()
                } else {
                    0
                };
                let addr = base.wrapping_add(extended << shift);
                return self.access(vec, load, rt, addr, size);
            }
            let imm9 = sext(u64::from(bits(insn, 12, 9)), 9) as u64;
            match bits(insn, 10, 2) {
                0 => (base.wrapping_add(imm9), None),       // stur / ldur
                1 => (base, Some(base.wrapping_add(imm9))), // post-index
                3 => (base.wrapping_add(imm9), Some(base.wrapping_add(imm9))), // pre-index
                _ => return None,                           // register offset / unprivileged
            }
        };
        self.access(vec, load, rt, addr, size)?;
        if let Some(wb) = writeback {
            self.base_w(rn, wb);
        }
        Some(())
    }

    /// One load or store of `size` bytes between `rt` and `addr`.
    fn access(&mut self, vec: bool, load: bool, rt: u32, addr: u64, size: u32) -> Option<()> {
        match (vec, load) {
            (false, false) => self.store_x(rt, addr, size)?,
            (false, true) => {
                let v = self.mem.read(addr, size)?;
                self.xw(rt, v);
            }
            (true, false) => {
                let v = self.vr(rt);
                if size == 16 {
                    self.mem.write128(addr, v)?;
                } else {
                    self.mem.write(addr, size, v as u64)?;
                }
            }
            (true, true) => {
                let v = if size == 16 {
                    self.mem.read128(addr)?
                } else {
                    u128::from(self.mem.read(addr, size)?)
                };
                self.vw(rt, v);
            }
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{BSS, RODATA, TEXT, bytes_at, evaluate};
    use crate::container::Arch;

    fn adrp(rd: u32, at: u64, target: u64) -> u32 {
        let pages = ((target & !0xfff) as i64 - (at & !0xfff) as i64) >> 12;
        0x9000_0000 | ((pages as u32 & 3) << 29) | (((pages as u32 >> 2) & 0x7ffff) << 5) | rd
    }

    #[test]
    fn adrp_stores_pairs_q_and_a_loop() {
        let mut code: Vec<u32> = Vec::new();
        let at = |code: &Vec<u32>| TEXT + 4 * code.len() as u64;
        let a = adrp(8, at(&code), BSS);
        code.push(a); // adrp x8, BSS
        let a = adrp(9, at(&code), RODATA);
        code.push(a); // adrp x9, RODATA
        code.push(0xd280_0600 | 10); // mov x10, #48
        code.push(0xf900_0100 | 10); // str x10, [x8]
        code.push(0x5280_0220 | 11); // mov w11, #0x11
        code.push(0x3900_4100 | 11); // strb w11, [x8, #0x10]
        code.push(0x3dc0_0120); // ldr q0, [x9]
        code.push(0x3d80_0900); // str q0, [x8, #0x20]
        code.push(0xa904_210a); // stp x10, x8, [x8, #0x40]
        // loop: mov x12, #0 ; add x13, x8, #0x60 ; L: strb w11, [x13, x12] ;
        // add x12, x12, #1 ; cmp x12, #3 ; b.ne L
        code.push(0xd280_0000 | 12);
        code.push(0x9101_810d); // add x13, x8, #0x60
        let l = code.len();
        code.push(0x382c_69ab); // strb w11, [x13, x12]
        code.push(0x9100_058c); // add x12, x12, #1
        code.push(0xf100_0d9f); // cmp x12, #3
        let off = (l as i64 - code.len() as i64) as u32 & 0x7ffff;
        code.push(0x5400_0001 | (off << 5)); // b.ne L
        code.push(0xd65f_03c0); // ret
        let bytes: Vec<u8> = code.iter().flat_map(|i| i.to_le_bytes()).collect();
        let rodata: Vec<u8> = (1..=16).collect();
        let o = evaluate(Arch::Aarch64, &bytes, &rodata);
        assert_eq!(bytes_at(&o, BSS, 8), [48, 0, 0, 0, 0, 0, 0, 0].map(Some));
        assert_eq!(o.get(BSS + 0x10), Some(0x11));
        assert_eq!(
            bytes_at(&o, BSS + 0x20, 16),
            rodata.iter().map(|&b| Some(b)).collect::<Vec<_>>()
        );
        assert_eq!(bytes_at(&o, BSS + 0x40, 8), 48u64.to_le_bytes().map(Some));
        assert_eq!(bytes_at(&o, BSS + 0x48, 8), BSS.to_le_bytes().map(Some));
        assert_eq!(
            bytes_at(&o, BSS + 0x60, 4),
            [Some(0x11), Some(0x11), Some(0x11), None]
        );
    }

    #[test]
    fn unknown_instruction_stops() {
        // brk #0 is not emulated; nothing after it runs.
        let bytes: Vec<u8> = [0xd420_0000u32, 0xd65f_03c0]
            .iter()
            .flat_map(|i| i.to_le_bytes())
            .collect();
        assert!(evaluate(Arch::Aarch64, &bytes, &[0; 4]).is_empty());
    }
}
