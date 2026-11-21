//! x86-64 subset emulator for `DatInit000`.
//!
//! Covers what C compilers emit for long runs of constant assignments:
//!
//! - integer moves (`mov`, `movzx`/`movsx`, `movsxd`, `lea`), ALU operations,
//!   `inc`/`dec` and shifts with flags, `cmp`/`test`;
//! - control flow: conditional and unconditional jumps (debug-build loops),
//!   `push`/`pop`/`leave`/`ret`;
//! - the SSE moves used to store 16 bytes at a time (`movaps`, `movups`,
//!   `movdqa`, `movdqu`, `movd`/`movq`, `punpcklqdq`, `movhps`,
//!   `pxor`/`xorps`);
//! - `rep movs`/`rep stos`, and calls to `memcpy`/`memmove`/`memset`, whose
//!   arguments are taken in the image's calling convention (System V, or
//!   Microsoft x64 for PE).
//!
//! Any other instruction, including a call to anything else, ends the
//! evaluation of the function; the writes made until then are kept.

use std::collections::HashMap;

use super::{Mem, Overlay, STACK_TOP, image_byte};
use crate::{
    container::Container,
    isa::x64::{Abi, RAX, RBP, RCX, RDI, RSI, RSP},
};

/// Runs the function at `entry` for at most `budget` instructions,
/// recording its image writes into `overlay`, and returns how many
/// instructions it executed. `helpers` comes from [`helper_functions`].
pub fn run(
    container: &Container<'_>,
    entry: u64,
    overlay: &mut Overlay,
    fixups: &HashMap<u64, u64>,
    helpers: &HashMap<u64, Helper>,
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
        regs: [0; 16],
        xmm: [0; 16],
        flags: Flags::default(),
        rip: entry,
        helpers,
    };
    cpu.regs[RSP] = STACK_TOP;
    // A return address the function will `ret` to: the end marker.
    if cpu.push(0).is_none() {
        return 0;
    }
    let mut steps = 0;
    while steps < budget {
        steps = steps.saturating_add(1);
        if cpu.step() != Some(true) {
            break;
        }
    }
    steps
}

/// `memcpy` / `memmove` / `memset` entry points, by address.
pub fn helper_functions(container: &Container<'_>) -> HashMap<u64, Helper> {
    container
        .symbols()
        .iter()
        .filter(|s| s.is_defined_function())
        .filter_map(|s| {
            let h = match s.name.as_ref() {
                "memcpy" | "memmove" => Helper::Copy,
                "memset" => Helper::Set,
                _ => return None,
            };
            Some((s.vm_addr, h))
        })
        .collect()
}

/// A C library helper the emulated code may call.
#[derive(Debug, Clone, Copy)]
pub enum Helper {
    /// `memcpy` / `memmove`.
    Copy,
    /// `memset`.
    Set,
}

/// The status flags the supported instructions set and conditional jumps
/// read (parity and auxiliary carry are not tracked).
#[derive(Default, Clone, Copy)]
struct Flags {
    /// Zero.
    zf: bool,
    /// Sign.
    sf: bool,
    /// Carry (unsigned overflow / borrow).
    cf: bool,
    /// Signed overflow.
    of: bool,
}

/// Register state of the function being evaluated, over the shared [`Mem`].
struct Cpu<'c, 'a, 'o> {
    /// The image the code is fetched from.
    container: &'c Container<'a>,
    /// Image, overlay and stack memory.
    mem: Mem<'c, 'a, 'o>,
    /// `rax`..`r15`, indexed by register number.
    regs: [u64; 16],
    /// `xmm0`..`xmm15`.
    xmm: [u128; 16],
    /// Status flags.
    flags: Flags,
    /// Address of the next instruction.
    rip: u64,
    /// C library helpers by address, emulated instead of executed on `call`.
    helpers: &'c HashMap<u64, Helper>,
}

/// A decoded memory or register operand.
#[derive(Clone, Copy)]
enum Rm {
    /// A register, by number.
    Reg(usize),
    /// Memory, by effective address.
    Mem(u64),
}

/// Prefix state of the instruction being decoded.
#[derive(Default, Clone, Copy)]
struct Pfx {
    /// Operand-size override (`0x66`): 16-bit operands, or SSE `66` forms.
    opsize: bool,
    /// `rep` / `0xf3`: string repetition, or the SSE `f3` forms.
    rep: bool,
    /// `repne` / `0xf2`: the SSE `f2` forms.
    repne: bool,
    /// The REX byte, 0 when absent.
    rex: u8,
}

impl Pfx {
    /// `REX.W`: 64-bit operand size.
    fn w(&self) -> bool {
        self.rex & 8 != 0
    }
    /// `REX.R` as a register-number offset for ModRM `reg`.
    fn r(&self) -> usize {
        if self.rex & 4 != 0 { 8 } else { 0 }
    }
    /// `REX.X` as a register-number offset for SIB `index`.
    fn x(&self) -> usize {
        if self.rex & 2 != 0 { 8 } else { 0 }
    }
    /// `REX.B` as a register-number offset for ModRM `rm` / SIB `base`.
    fn b(&self) -> usize {
        if self.rex & 1 != 0 { 8 } else { 0 }
    }
    /// Operand size in bytes for non-byte integer instructions.
    fn osz(&self) -> u32 {
        if self.w() {
            8
        } else if self.opsize {
            2
        } else {
            4
        }
    }
}

/// The value mask of a `size`-byte operand.
fn mask(size: u32) -> u64 {
    match size {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

/// The sign bit of a `size`-byte operand.
fn sign_bit(size: u32) -> u64 {
    1u64 << (size.saturating_mul(8).saturating_sub(1))
}

impl Cpu<'_, '_, '_> {
    // ---- stack ----

    /// Pushes a 64-bit value.
    fn push(&mut self, v: u64) -> Option<()> {
        let sp = self.regs.get(RSP)?.wrapping_sub(8);
        self.mem.write(sp, 8, v)?;
        *self.regs.get_mut(RSP)? = sp;
        Some(())
    }

    /// Pops a 64-bit value.
    fn pop(&mut self) -> Option<u64> {
        let sp = *self.regs.get(RSP)?;
        let v = self.mem.read(sp, 8)?;
        *self.regs.get_mut(RSP)? = sp.wrapping_add(8);
        Some(v)
    }

    // ---- registers ----

    /// The full 64 bits of register `r`.
    fn reg(&self, r: usize) -> u64 {
        self.regs.get(r).copied().unwrap_or(0)
    }

    /// Reads a general register at `size`; with no REX, byte registers 4-7
    /// are `ah`..`bh`.
    fn get_reg(&self, r: usize, size: u32, p: Pfx) -> u64 {
        if size == 1 && p.rex == 0 && (4..8).contains(&r) {
            return (self.reg(r.wrapping_sub(4)) >> 8) & 0xff;
        }
        self.reg(r) & mask(size)
    }

    /// Writes a general register: 32-bit writes zero the upper half, 8/16
    /// bit writes merge.
    fn set_reg(&mut self, r: usize, size: u32, v: u64, p: Pfx) {
        let (r, shift) = if size == 1 && p.rex == 0 && (4..8).contains(&r) {
            (r.wrapping_sub(4), 8)
        } else {
            (r, 0)
        };
        let Some(slot) = self.regs.get_mut(r) else {
            return;
        };
        *slot = match size {
            8 => v,
            4 => v & 0xffff_ffff,
            _ => {
                let m = mask(size) << shift;
                (*slot & !m) | ((v << shift) & m)
            }
        };
    }

    /// Reads a ModRM operand of `size` bytes.
    fn get_rm(&self, rm: Rm, size: u32, p: Pfx) -> Option<u64> {
        match rm {
            Rm::Reg(r) => Some(self.get_reg(r, size, p)),
            Rm::Mem(a) => self.mem.read(a, size),
        }
    }

    /// Writes a ModRM operand of `size` bytes.
    fn set_rm(&mut self, rm: Rm, size: u32, v: u64, p: Pfx) -> Option<()> {
        match rm {
            Rm::Reg(r) => {
                self.set_reg(r, size, v, p);
                Some(())
            }
            Rm::Mem(a) => self.mem.write(a, size, v),
        }
    }

    // ---- decoding ----

    /// The code byte at `*at`, advancing it.
    fn fetch(&self, at: &mut u64) -> Option<u8> {
        let b = image_byte(self.container, *at)?;
        *at = at.wrapping_add(1);
        Some(b)
    }

    /// `n` little-endian code bytes at `*at` (an immediate or displacement),
    /// advancing it.
    fn fetch_n(&self, at: &mut u64, n: u32) -> Option<u64> {
        let mut v: u64 = 0;
        for i in 0..n {
            v |= u64::from(self.fetch(at)?) << (i.saturating_mul(8));
        }
        Some(v)
    }

    /// Decodes a ModRM operand. `imm_len` is the number of immediate bytes
    /// that follow (RIP-relative addresses count from the instruction end).
    /// Returns `(reg field, operand)`.
    fn modrm(&self, at: &mut u64, p: Pfx, imm_len: u64) -> Option<(usize, Rm)> {
        let m = self.fetch(at)?;
        let md = m >> 6;
        let reg = usize::from((m >> 3) & 7) | p.r();
        let rm = usize::from(m & 7);
        if md == 3 {
            return Some((reg, Rm::Reg(rm | p.b())));
        }
        let mut addr: u64;
        if rm == 4 {
            let sib = self.fetch(at)?;
            let scale = 1u64 << (sib >> 6);
            let index = usize::from((sib >> 3) & 7) | p.x();
            let base = usize::from(sib & 7);
            addr = if index == 4 {
                0
            } else {
                self.reg(index).wrapping_mul(scale)
            };
            if base == 5 && md == 0 {
                addr = addr.wrapping_add(self.fetch_n(at, 4)? as i32 as i64 as u64);
            } else {
                addr = addr.wrapping_add(self.reg(base | p.b()));
            }
        } else if rm == 5 && md == 0 {
            let disp = self.fetch_n(at, 4)? as i32 as i64 as u64;
            // RIP-relative: from the end of the instruction.
            return Some((reg, Rm::Mem(at.wrapping_add(disp).wrapping_add(imm_len))));
        } else {
            addr = self.reg(rm | p.b());
        }
        match md {
            1 => addr = addr.wrapping_add(self.fetch_n(at, 1)? as i8 as i64 as u64),
            2 => addr = addr.wrapping_add(self.fetch_n(at, 4)? as i32 as i64 as u64),
            _ => {}
        }
        Some((reg, Rm::Mem(addr)))
    }

    // ---- flags ----

    /// Flags after a logical operation: ZF and SF from the result, CF and OF
    /// clear.
    fn set_logic_flags(&mut self, r: u64, size: u32) {
        let r = r & mask(size);
        self.flags = Flags {
            zf: r == 0,
            sf: r & sign_bit(size) != 0,
            cf: false,
            of: false,
        };
    }

    /// `a op b` for the ALU operation in the opcode's `reg` field (`add`, `or`,
    /// `and`, `sub`, `xor`, `cmp`), setting the flags. `adc` and `sbb` are not
    /// supported.
    fn alu(&mut self, op: u8, a: u64, b: u64, size: u32) -> Option<u64> {
        let m = mask(size);
        let (a, b) = (a & m, b & m);
        let sb = sign_bit(size);
        let r = match op {
            0 => {
                let r = a.wrapping_add(b) & m;
                self.flags = Flags {
                    zf: r == 0,
                    sf: r & sb != 0,
                    cf: r < a,
                    of: (a ^ r) & (b ^ r) & sb != 0,
                };
                r
            }
            1 => {
                let r = a | b;
                self.set_logic_flags(r, size);
                r
            }
            4 => {
                let r = a & b;
                self.set_logic_flags(r, size);
                r
            }
            5 | 7 => {
                let r = a.wrapping_sub(b) & m;
                self.flags = Flags {
                    zf: r == 0,
                    sf: r & sb != 0,
                    cf: a < b,
                    of: (a ^ b) & (a ^ r) & sb != 0,
                };
                r
            }
            6 => {
                let r = a ^ b;
                self.set_logic_flags(r, size);
                r
            }
            _ => return None,
        };
        Some(r)
    }

    /// Whether condition code `cc` holds; `None` for the parity conditions.
    fn cond(&self, cc: u8) -> Option<bool> {
        let f = self.flags;
        Some(match cc & 0xf {
            0x0 => f.of,
            0x1 => !f.of,
            0x2 => f.cf,
            0x3 => !f.cf,
            0x4 => f.zf,
            0x5 => !f.zf,
            0x6 => f.cf || f.zf,
            0x7 => !f.cf && !f.zf,
            0x8 => f.sf,
            0x9 => !f.sf,
            0xc => f.sf != f.of,
            0xd => f.sf == f.of,
            0xe => f.zf || f.sf != f.of,
            0xf => !f.zf && f.sf == f.of,
            _ => return None, // parity: not tracked
        })
    }

    /// XMM register read.
    fn xmm_get(&self, r: usize) -> u128 {
        self.xmm.get(r).copied().unwrap_or(0)
    }

    /// XMM register write (all 128 bits).
    fn xmm_set(&mut self, r: usize, v: u128) {
        if let Some(slot) = self.xmm.get_mut(r) {
            *slot = v;
        }
    }

    // ---- execution ----

    /// Executes one instruction. `Some(true)`: continue; `Some(false)`: the
    /// function returned; `None`: unsupported or invalid, stop.
    fn step(&mut self) -> Option<bool> {
        let mut at = self.rip;
        let mut p = Pfx::default();
        let mut op;
        loop {
            op = self.fetch(&mut at)?;
            match op {
                0x66 => p.opsize = true,
                0xf3 => p.rep = true,
                0xf2 => p.repne = true,
                0x2e | 0x3e => {}
                0x40..=0x4f => {
                    p.rex = op;
                    op = self.fetch(&mut at)?;
                    break;
                }
                _ => break,
            }
        }
        let osz = p.osz();

        match op {
            // ALU r/m, r and r, r/m forms: add, or, and, sub, xor, cmp.
            0x00..=0x03 | 0x08..=0x0b | 0x20..=0x23 | 0x28..=0x2b | 0x30..=0x33 | 0x38..=0x3b => {
                let group = op >> 3;
                let size = if op & 1 == 0 { 1 } else { osz };
                let (reg, rm) = self.modrm(&mut at, p, 0)?;
                let (dst_is_rm, a, b) = if op & 2 == 0 {
                    (true, self.get_rm(rm, size, p)?, self.get_reg(reg, size, p))
                } else {
                    (false, self.get_reg(reg, size, p), self.get_rm(rm, size, p)?)
                };
                let r = self.alu(group, a, b, size)?;
                if group != 7 {
                    if dst_is_rm {
                        self.set_rm(rm, size, r, p)?;
                    } else {
                        self.set_reg(reg, size, r, p);
                    }
                }
            }
            // ALU rax, imm32 (add, sub, cmp).
            0x05 | 0x2d | 0x3d => {
                let imm = self.fetch_n(&mut at, osz.min(4))?;
                let imm = if osz == 8 {
                    imm as i32 as i64 as u64
                } else {
                    imm
                };
                let r = self.alu(op >> 3, self.get_reg(RAX, osz, p), imm, osz)?;
                if op != 0x3d {
                    self.set_reg(RAX, osz, r, p);
                }
            }
            // Group 1: ALU r/m, imm.
            0x80 | 0x81 | 0x83 => {
                let size = if op == 0x80 { 1 } else { osz };
                let imm_len = if op == 0x81 { u64::from(osz.min(4)) } else { 1 };
                let (reg, rm) = self.modrm(&mut at, p, imm_len)?;
                let imm = self.fetch_n(&mut at, imm_len as u32)?;
                let imm = match (op, imm_len) {
                    (0x83, _) | (0x80, _) => imm as i8 as i64 as u64,
                    (_, 4) => imm as i32 as i64 as u64,
                    _ => imm,
                };
                let a = self.get_rm(rm, size, p)?;
                let r = self.alu((reg & 7) as u8, a, imm, size)?;
                if reg & 7 != 7 {
                    self.set_rm(rm, size, r, p)?;
                }
            }
            // inc / dec r/m (`fe`/`ff` /0, /1); CF is left unchanged.
            0xfe | 0xff => {
                let size = if op == 0xfe { 1 } else { osz };
                let (reg, rm) = self.modrm(&mut at, p, 0)?;
                let cf = self.flags.cf;
                let a = self.get_rm(rm, size, p)?;
                let r = match reg & 7 {
                    0 => self.alu(0, a, 1, size)?,
                    1 => self.alu(5, a, 1, size)?,
                    _ => return None,
                };
                self.flags.cf = cf;
                self.set_rm(rm, size, r, p)?;
            }
            // test r/m, r
            0x84 | 0x85 => {
                let size = if op == 0x84 { 1 } else { osz };
                let (reg, rm) = self.modrm(&mut at, p, 0)?;
                let r = self.get_rm(rm, size, p)? & self.get_reg(reg, size, p);
                self.set_logic_flags(r, size);
            }
            // mov
            0x88 | 0x89 => {
                let size = if op == 0x88 { 1 } else { osz };
                let (reg, rm) = self.modrm(&mut at, p, 0)?;
                let v = self.get_reg(reg, size, p);
                self.set_rm(rm, size, v, p)?;
            }
            0x8a | 0x8b => {
                let size = if op == 0x8a { 1 } else { osz };
                let (reg, rm) = self.modrm(&mut at, p, 0)?;
                let v = self.get_rm(rm, size, p)?;
                self.set_reg(reg, size, v, p);
            }
            // lea
            0x8d => {
                let (reg, rm) = self.modrm(&mut at, p, 0)?;
                let Rm::Mem(a) = rm else { return None };
                self.set_reg(reg, osz, a, p);
            }
            // movsxd
            0x63 => {
                let (reg, rm) = self.modrm(&mut at, p, 0)?;
                let v = self.get_rm(rm, 4, p)? as u32 as i32 as i64 as u64;
                self.set_reg(reg, osz, v, p);
            }
            0x90 => {}
            // cdqe / cqo-class sign extensions: rax only matters here.
            0x98 => {
                let v = if p.w() {
                    self.reg(RAX) as u32 as i32 as i64 as u64
                } else {
                    u64::from(self.reg(RAX) as u16 as i16 as i32 as u32)
                };
                self.set_reg(RAX, osz, v, p);
            }
            // push / pop
            0x50..=0x57 => {
                let v = self.reg(usize::from(op & 7) | p.b());
                self.push(v)?;
            }
            0x58..=0x5f => {
                let v = self.pop()?;
                self.set_reg(usize::from(op & 7) | p.b(), 8, v, p);
            }
            // mov r8, imm8 / mov r, imm
            0xb0..=0xb7 => {
                let v = self.fetch_n(&mut at, 1)?;
                self.set_reg(usize::from(op & 7) | p.b(), 1, v, p);
            }
            0xb8..=0xbf => {
                let n = if p.w() { 8 } else { osz };
                let v = self.fetch_n(&mut at, n)?;
                self.set_reg(usize::from(op & 7) | p.b(), osz, v, p);
            }
            // shifts by imm8 / by 1
            0xc1 | 0xd1 | 0xc0 | 0xd0 => {
                let size = if op & 1 == 0 { 1 } else { osz };
                let imm_len = if op <= 0xc1 { 1 } else { 0 };
                let (reg, rm) = self.modrm(&mut at, p, imm_len)?;
                let count = if imm_len == 1 {
                    self.fetch_n(&mut at, 1)?
                } else {
                    1
                };
                let count = (count & if size == 8 { 63 } else { 31 }) as u32;
                let a = self.get_rm(rm, size, p)?;
                let r = match reg & 7 {
                    4 => a.checked_shl(count).unwrap_or(0),
                    5 => (a & mask(size)).checked_shr(count).unwrap_or(0),
                    7 => {
                        // Sign-extend from `size` bytes, then shift.
                        let spare = 64u32.saturating_sub(size.saturating_mul(8));
                        let signed = ((a << spare) as i64) >> spare;
                        (signed >> count) as u64
                    }
                    _ => return None,
                };
                self.set_logic_flags(r, size);
                self.set_rm(rm, size, r & mask(size), p)?;
            }
            // ret / leave
            0xc3 => {
                let target = self.pop()?;
                if target == 0 {
                    return Some(false);
                }
                self.rip = target;
                return Some(true);
            }
            0xc9 => {
                *self.regs.get_mut(RSP)? = self.reg(RBP);
                let v = self.pop()?;
                self.set_reg(RBP, 8, v, p);
            }
            // mov r/m, imm
            0xc6 | 0xc7 => {
                let size = if op == 0xc6 { 1 } else { osz };
                let imm_len = u64::from(size.min(4));
                let (reg, rm) = self.modrm(&mut at, p, imm_len)?;
                if reg & 7 != 0 {
                    return None;
                }
                let imm = self.fetch_n(&mut at, imm_len as u32)?;
                let imm = if size == 8 {
                    imm as i32 as i64 as u64
                } else {
                    imm
                };
                self.set_rm(rm, size, imm, p)?;
            }
            // jcc rel8 / jmp rel8 / jmp rel32
            0x70..=0x7f => {
                let d = self.fetch_n(&mut at, 1)? as i8 as i64 as u64;
                if self.cond(op)? {
                    at = at.wrapping_add(d);
                }
            }
            0xeb => {
                let d = self.fetch_n(&mut at, 1)? as i8 as i64 as u64;
                at = at.wrapping_add(d);
            }
            0xe9 => {
                let d = self.fetch_n(&mut at, 4)? as i32 as i64 as u64;
                at = at.wrapping_add(d);
            }
            // call: only the memory helpers.
            0xe8 => {
                let d = self.fetch_n(&mut at, 4)? as i32 as i64 as u64;
                let target = at.wrapping_add(d);
                let helper = *self.helpers.get(&target)?;
                self.call_helper(helper)?;
            }
            // rep movs / rep stos
            0xa4 | 0xa5 | 0xaa | 0xab if p.rep => {
                let size = if op & 1 == 0 { 1 } else { osz };
                self.rep_string(op, size)?;
            }
            0x0f => {
                let op2 = self.fetch(&mut at)?;
                self.step_0f(op2, p, &mut at)?;
            }
            _ => return None,
        }
        self.rip = at;
        Some(true)
    }

    /// Executes a two-byte (`0f`) opcode `op2`: `endbr64` and multi-byte `nop`s,
    /// `jcc rel32`, `movzx`/`movsx`, and the SSE moves.
    fn step_0f(&mut self, op2: u8, p: Pfx, at: &mut u64) -> Option<()> {
        let osz = p.osz();
        match op2 {
            // endbr64 (f3 0f 1e fa) and multi-byte nops
            0x1e if p.rep => {
                self.fetch(at)?;
            }
            0x1f => {
                self.modrm(at, p, 0)?;
            }
            // jcc rel32
            0x80..=0x8f => {
                let d = self.fetch_n(at, 4)? as i32 as i64 as u64;
                if self.cond(op2)? {
                    *at = at.wrapping_add(d);
                }
            }
            // movzx / movsx
            0xb6 | 0xb7 | 0xbe | 0xbf => {
                let src = if op2 & 1 == 0 { 1 } else { 2 };
                let (reg, rm) = self.modrm(at, p, 0)?;
                let v = self.get_rm(rm, src, p)?;
                let v = match op2 {
                    0xbe => v as u8 as i8 as i64 as u64,
                    0xbf => v as u16 as i16 as i64 as u64,
                    _ => v,
                };
                self.set_reg(reg, osz, v, p);
            }
            // movups/movupd/movss/movsd load and store
            0x10 | 0x11 => {
                let (reg, rm) = self.modrm(at, p, 0)?;
                let width = if p.rep {
                    4
                } else if p.repne {
                    8
                } else {
                    16
                };
                self.xmm_move(op2 == 0x11, reg, rm, width)?;
            }
            // movaps/movapd load and store
            0x28 | 0x29 => {
                let (reg, rm) = self.modrm(at, p, 0)?;
                self.xmm_move(op2 == 0x29, reg, rm, 16)?;
            }
            // movdqa/movdqu load, store
            0x6f if p.opsize || p.rep => {
                let (reg, rm) = self.modrm(at, p, 0)?;
                self.xmm_move(false, reg, rm, 16)?;
            }
            0x7f if p.opsize || p.rep => {
                let (reg, rm) = self.modrm(at, p, 0)?;
                self.xmm_move(true, reg, rm, 16)?;
            }
            // movd/movq r/m -> xmm
            0x6e if p.opsize => {
                let (reg, rm) = self.modrm(at, p, 0)?;
                let v = self.get_rm(rm, if p.w() { 8 } else { 4 }, p)?;
                self.xmm_set(reg, u128::from(v));
            }
            // movq xmm/m64 -> xmm (f3 0f 7e)
            0x7e if p.rep => {
                let (reg, rm) = self.modrm(at, p, 0)?;
                let v = match rm {
                    Rm::Reg(r) => self.xmm_get(r) as u64,
                    Rm::Mem(a) => self.mem.read(a, 8)?,
                };
                self.xmm_set(reg, u128::from(v));
            }
            // movd/movq xmm -> r/m (66 0f 7e)
            0x7e if p.opsize => {
                let (reg, rm) = self.modrm(at, p, 0)?;
                let size = if p.w() { 8 } else { 4 };
                let v = self.xmm_get(reg) as u64;
                match rm {
                    Rm::Reg(r) => self.set_reg(r, size, v, p),
                    Rm::Mem(a) => self.mem.write(a, size, v)?,
                }
            }
            // movq xmm -> xmm/m64 (66 0f d6)
            0xd6 if p.opsize => {
                let (reg, rm) = self.modrm(at, p, 0)?;
                let v = self.xmm_get(reg) as u64;
                match rm {
                    Rm::Reg(r) => self.xmm_set(r, u128::from(v)),
                    Rm::Mem(a) => self.mem.write(a, 8, v)?,
                }
            }
            // punpcklqdq xmm, xmm/m128
            0x6c if p.opsize => {
                let (reg, rm) = self.modrm(at, p, 0)?;
                let src = match rm {
                    Rm::Reg(r) => self.xmm_get(r),
                    Rm::Mem(a) => self.mem.read128(a)?,
                };
                let lo = self.xmm_get(reg) & u128::from(u64::MAX);
                self.xmm_set(reg, lo | (src << 64));
            }
            // movhps/movhpd xmm, m64 (load high half) and m64, xmm (store)
            0x16 | 0x17 => {
                let (reg, rm) = self.modrm(at, p, 0)?;
                let Rm::Mem(a) = rm else { return None };
                if op2 == 0x16 {
                    let hi = self.mem.read(a, 8)?;
                    let lo = self.xmm_get(reg) & u128::from(u64::MAX);
                    self.xmm_set(reg, lo | (u128::from(hi) << 64));
                } else {
                    self.mem.write(a, 8, (self.xmm_get(reg) >> 64) as u64)?;
                }
            }
            // pxor / xorps / xorpd (zeroing idiom and general)
            0xef | 0x57 => {
                let (reg, rm) = self.modrm(at, p, 0)?;
                let src = match rm {
                    Rm::Reg(r) => self.xmm_get(r),
                    Rm::Mem(a) => self.mem.read128(a)?,
                };
                self.xmm_set(reg, self.xmm_get(reg) ^ src);
            }
            _ => return None,
        }
        Some(())
    }

    /// Moves `width` bytes between an xmm register and `rm`.
    fn xmm_move(&mut self, store: bool, reg: usize, rm: Rm, width: u32) -> Option<()> {
        match (store, rm) {
            (false, Rm::Reg(r)) => self.xmm_set(reg, self.xmm_get(r)),
            (true, Rm::Reg(r)) => self.xmm_set(r, self.xmm_get(reg)),
            (false, Rm::Mem(a)) => {
                let v = if width == 16 {
                    self.mem.read128(a)?
                } else {
                    u128::from(self.mem.read(a, width)?)
                };
                // Scalar loads from memory zero the rest of the register.
                self.xmm_set(reg, v);
            }
            (true, Rm::Mem(a)) => {
                let v = self.xmm_get(reg);
                if width == 16 {
                    self.mem.write128(a, v)?;
                } else {
                    self.mem.write(a, width, v as u64)?;
                }
            }
        }
        Some(())
    }

    /// Performs a `memcpy`/`memmove`/`memset` call on the emulated memory (at
    /// most 1 MiB) and returns as the function would (the destination in `rax`).
    fn call_helper(&mut self, helper: Helper) -> Option<()> {
        // (dst, src or byte, count): the first three integer arguments in
        // the image's calling convention.
        let [a0, a1, a2, _] = Abi::of(self.container).int_args();
        let (dst, src, n) = (self.reg(a0), self.reg(a1), self.reg(a2));
        if n > (1 << 20) {
            return None;
        }
        match helper {
            Helper::Copy => {
                let bytes: Vec<u8> = (0..n)
                    .map(|i| self.mem.read_u8(src.wrapping_add(i)))
                    .collect::<Option<_>>()?;
                for (i, b) in bytes.into_iter().enumerate() {
                    self.mem.write_u8(dst.wrapping_add(i as u64), b)?;
                }
            }
            Helper::Set => {
                let b = src as u8;
                for i in 0..n {
                    self.mem.write_u8(dst.wrapping_add(i), b)?;
                }
            }
        }
        *self.regs.get_mut(RAX)? = dst;
        Some(())
    }

    /// Executes `rep movs` / `rep stos` (opcode `op`, `size`-byte elements) for
    /// the `rcx` count (at most 2^20), forward only.
    fn rep_string(&mut self, op: u8, size: u32) -> Option<()> {
        let count = self.reg(RCX);
        if count > (1 << 20) {
            return None;
        }
        let step = u64::from(size);
        for _ in 0..count {
            let di = self.reg(RDI);
            if op <= 0xa5 {
                let si = self.reg(RSI);
                let v = self.mem.read(si, size)?;
                self.mem.write(di, size, v)?;
                *self.regs.get_mut(RSI)? = si.wrapping_add(step);
            } else {
                let v = self.reg(RAX) & mask(size);
                self.mem.write(di, size, v)?;
            }
            *self.regs.get_mut(RDI)? = di.wrapping_add(step);
        }
        *self.regs.get_mut(RCX)? = 0;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::super::tests::{BSS, RODATA, TEXT, bytes_at, evaluate, image, rel};
    use crate::container::{Arch, Container, Format, Symbol, SymbolKind};

    fn lea_rip(code: &mut Vec<u8>, rex: u8, modrm: u8, target: u64) {
        let at = TEXT + code.len() as u64;
        code.extend_from_slice(&[rex, 0x8d, modrm]);
        code.extend_from_slice(&rel(at, 7, target));
    }

    #[test]
    fn stores_moves_sse_and_a_loop() {
        let mut c = Vec::new();
        lea_rip(&mut c, 0x48, 0x05, BSS); // lea BSS(%rip), %rax
        c.extend_from_slice(&[0x48, 0xc7, 0x00, 48, 0, 0, 0]); // movq $48, (%rax)
        c.extend_from_slice(&[0xc6, 0x40, 0x10, 0x11]); // movb $0x11, 0x10(%rax)
        // movdqa RODATA(%rip), %xmm0 ; movaps %xmm0, 0x20(%rax)
        let at = TEXT + c.len() as u64;
        c.extend_from_slice(&[0x66, 0x0f, 0x6f, 0x05]);
        c.extend_from_slice(&rel(at, 8, RODATA));
        c.extend_from_slice(&[0x0f, 0x29, 0x40, 0x20]);
        // movq %rax, %xmm1 ; movq %rax,%xmm2? -> punpcklqdq %xmm1, %xmm1 ; movups %xmm1, 0x40(%rax)
        c.extend_from_slice(&[0x66, 0x48, 0x0f, 0x6e, 0xc8]);
        c.extend_from_slice(&[0x66, 0x0f, 0x6c, 0xc9]);
        c.extend_from_slice(&[0x0f, 0x11, 0x48, 0x40]);
        // xor %ecx,%ecx ; L: movb $7, 0x60(%rax,%rcx) ; inc %rcx ; cmp $3,%rcx ; jne L ; ret
        c.extend_from_slice(&[0x31, 0xc9]);
        let l = c.len();
        c.extend_from_slice(&[0xc6, 0x44, 0x08, 0x60, 7]);
        c.extend_from_slice(&[0x48, 0xff, 0xc1]);
        c.extend_from_slice(&[0x48, 0x83, 0xf9, 3]);
        let back = (l as i64 - (c.len() as i64 + 2)) as i8 as u8;
        c.extend_from_slice(&[0x75, back]);
        c.push(0xc3);
        let rodata: Vec<u8> = (1..=16).collect();
        let o = evaluate(Arch::Amd64, &c, &rodata);
        assert_eq!(bytes_at(&o, BSS, 8), [48, 0, 0, 0, 0, 0, 0, 0].map(Some));
        assert_eq!(o.get(BSS + 0x10), Some(0x11));
        assert_eq!(
            bytes_at(&o, BSS + 0x20, 16),
            rodata.iter().map(|&b| Some(b)).collect::<Vec<_>>()
        );
        let ptr = BSS.to_le_bytes();
        assert_eq!(bytes_at(&o, BSS + 0x40, 8), ptr.map(Some));
        assert_eq!(bytes_at(&o, BSS + 0x48, 8), ptr.map(Some));
        assert_eq!(
            bytes_at(&o, BSS + 0x60, 4),
            [Some(7), Some(7), Some(7), None]
        );
    }

    #[test]
    fn got_slot_filled_by_pointer_fixup() {
        use super::super::tests::image;
        use crate::container::{Container, Format};
        // mov GOT(%rip), %rax ; movb $0x42, (%rax) ; ret
        // GOT is the first rodata word; the file leaves it 0 and the fixup
        // (a GLOB_DAT relocation) makes it point at BSS.
        let mut c = Vec::new();
        let at = TEXT;
        c.extend_from_slice(&[0x48, 0x8b, 0x05]);
        c.extend_from_slice(&rel(at, 7, RODATA));
        c.extend_from_slice(&[0xc6, 0x00, 0x42, 0xc3]);
        let (bytes, sections, symbols) = image(Arch::Amd64, &c, &[0; 8]);
        let plain = Container::from_parts(
            bytes,
            Format::Elf,
            Arch::Amd64,
            0,
            sections.clone(),
            symbols.clone(),
        );
        assert!(
            super::super::evaluate_datinits(&plain, super::super::TOTAL_STEP_BUDGET).is_empty()
        );
        let fixed = Container::from_parts(bytes, Format::Elf, Arch::Amd64, 0, sections, symbols)
            .with_pointer_fixups(vec![(RODATA, BSS)]);
        assert_eq!(
            super::super::evaluate_datinits(&fixed, super::super::TOTAL_STEP_BUDGET).get(BSS),
            Some(0x42)
        );
    }

    #[test]
    fn unknown_instruction_stops_but_keeps_earlier_writes() {
        let mut c = Vec::new();
        lea_rip(&mut c, 0x48, 0x05, BSS);
        c.extend_from_slice(&[0xc6, 0x00, 0x42]); // movb $0x42, (%rax)
        c.extend_from_slice(&[0x0f, 0x0b]); // ud2: not supported
        c.extend_from_slice(&[0xc6, 0x40, 0x01, 0x43]); // never reached
        c.push(0xc3);
        let o = evaluate(Arch::Amd64, &c, &[0; 4]);
        assert_eq!(o.get(BSS), Some(0x42));
        assert_eq!(o.get(BSS + 1), None);
    }

    #[test]
    fn helper_arguments_follow_the_image_abi() {
        // memset(BSS + 8, 'A', 4), arguments in rcx, rdx, r8 (Microsoft x64)
        // and in rdi, rsi, rdx (System V); the other registers hold BSS, so
        // reading the wrong ones would fill from BSS.
        let mov = |code: &mut Vec<u8>, reg: u8, v: u64| {
            // mov r32, imm32 (zero-extends)
            if reg >= 8 {
                code.push(0x41);
            }
            code.push(0xb8 + (reg & 7));
            code.extend_from_slice(&(v as u32).to_le_bytes());
        };
        let call = |abi_regs: [u8; 3], format| {
            let mut code = Vec::new();
            for reg in [0, 1, 2, 6, 7, 8] {
                mov(&mut code, reg, BSS);
            }
            for (reg, v) in abi_regs.into_iter().zip([BSS + 8, 0x41, 4]) {
                mov(&mut code, reg, v);
            }
            let call_at = TEXT + code.len() as u64;
            code.push(0xe8);
            code.extend_from_slice(&rel(call_at, 5, TEXT + 0x80));
            code.push(0xc3);
            code.resize(0x80, 0x90);
            code.push(0xc3); // memset itself: never executed
            let (bytes, sections, mut symbols) = image(Arch::Amd64, &code, &[0; 4]);
            symbols.push(Symbol {
                name: Cow::Borrowed("memset"),
                vm_addr: TEXT + 0x80,
                size: 1,
                kind: SymbolKind::Function,
            });
            let c = Container::from_parts(bytes, format, Arch::Amd64, 0, sections, symbols);
            super::super::evaluate_datinits(&c, super::super::TOTAL_STEP_BUDGET)
        };
        let want: Vec<Option<u8>> = [None; 8]
            .into_iter()
            .chain([Some(0x41); 4])
            .chain([None])
            .collect();
        let pe = call([1, 2, 8], Format::Pe);
        assert_eq!(bytes_at(&pe, BSS, 13), want);
        let elf = call([7, 6, 2], Format::Elf);
        assert_eq!(bytes_at(&elf, BSS, 13), want);
    }

    #[test]
    fn writes_outside_the_image_and_endless_loops_stop() {
        // movb $1, 0x10 (absolute low address: not image memory)
        let o = evaluate(
            Arch::Amd64,
            &[0xc6, 0x04, 0x25, 0x10, 0, 0, 0, 1, 0xc3],
            &[0; 4],
        );
        assert!(o.is_empty());
        // jmp . : ends at the step budget without writing.
        let o = evaluate(Arch::Amd64, &[0xeb, 0xfe], &[0; 4]);
        assert!(o.is_empty());
    }
}
