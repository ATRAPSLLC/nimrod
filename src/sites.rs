//! Exception raise-site recovery.
//!
//! Recovers `(exception_type, proc_name, file, line)` for each call to
//! `raiseExceptionEx` (or its tail jump) by decoding the instructions that
//! load its arguments before the call.
//!
//! ## Calling convention
//!
//! `raiseExceptionEx(e, ename, procname, filename, line)`:
//!
//! | Arg   | x86-64 System V | x86-64 Microsoft (PE) | AArch64 | Content              |
//! |-------|-----------------|-----------------------|---------|----------------------|
//! | e     | `rdi`           | `rcx`                 | `x0`    | Exception object ptr |
//! | ename | `rsi`           | `rdx`                 | `x1`    | Type name cstring    |
//! | proc  | `rdx`           | `r8`                  | `x2`    | Proc name cstring    |
//! | file  | `rcx`           | `r9`                  | `x3`    | File path cstring    |
//! | line  | `r8`            | `[rsp + 0x20]`        | `x4`    | Line number (int)    |
//!
//! ## Supported architectures
//!
//! - **x86-64**: finds `call` and tail `jmp` (`e8`/`e9 <rel32>`) to
//!   `raiseExceptionEx`, then tracks the argument registers over a backward
//!   window: RIP-relative `lea`, register `mov`, immediate `mov`, and calls
//!   that clobber them. A call clobbers only when its target is a known
//!   function, so stray `e8` bytes inside other instructions do not.
//! - **AArch64**: finds `bl` and tail `b` to `raiseExceptionEx`, then matches
//!   `adrp`+`add` pairs for the string arguments and `mov`/`movz` for the
//!   line. Calls to `OUTLINED_FUNCTION_*` (code the macOS toolchain's
//!   machine outliner factored out) are not treated as clobbering: on the
//!   macOS fixtures the arguments loaded before them reach the raise call.
//!
//! Other architectures yield no raise sites. Instructions are read as
//! little-endian words, which both instruction sets are in every mode.

use std::collections::HashSet;

use crate::{
    container::{Arch, Container, SectionKind},
    isa::{
        a64::{self, MoveWideOp},
        x64::Abi,
    },
    util::{self, read_cstring_at_va},
};

/// A fully recovered raise site.
///
/// `call_addr` is a virtual address (image load space). To convert to an
/// RVA for disassembler use, call [`crate::NimBinary::raise_rva`].
#[derive(Debug, Clone)]
pub struct RaiseSite {
    /// Virtual address of the call instruction (image load space, not
    /// file offset).
    pub call_addr: u64,
    /// Exception type name (e.g. `"ValueError"`).
    pub exception_type: Option<String>,
    /// Enclosing proc name (from instruction analysis).
    pub proc_name: Option<String>,
    /// Source file path (from instruction analysis).
    pub file: Option<String>,
    /// Source line number.
    pub line: Option<u32>,
    /// Enclosing function symbol (from symbol table VA lookup).
    /// This is recovered independently of instruction analysis and
    /// provides the mangled/demangled function name even when the
    /// proc_name argument wasn't recovered.
    pub enclosing_function: Option<String>,
    /// Virtual address of that enclosing function, the key it has in
    /// [`crate::NimBinary::procs`].
    pub enclosing_va: Option<u64>,
}

/// Scans the binary for `raiseExceptionEx` call sites and recovers
/// the argument tuples.
///
/// After instruction-level recovery, each site is enriched with the
/// enclosing function name from the symbol table (independent of
/// whether the instruction analysis found the proc_name argument).
pub fn scan(container: &Container<'_>) -> Vec<RaiseSite> {
    // Find the raiseExceptionEx symbol(s).
    let targets = find_raise_targets(container);
    if targets.is_empty() {
        return Vec::new();
    }

    let mut sites = match container.arch() {
        Arch::Amd64 => scan_x86_64(container, &targets),
        Arch::Aarch64 => scan_aarch64(container, &targets),
        _ => return Vec::new(),
    };

    // Enrich each site with the enclosing function from the symbol table.
    for site in &mut sites {
        if let Some(func) = container.function_at_va(site.call_addr) {
            site.enclosing_function = Some(func.name.to_string());
            site.enclosing_va = Some(func.vm_addr);
        }
    }

    sites
}

/// Returns the virtual addresses of `raiseExceptionEx` (and variants
/// like `raiseExceptionEx.constprop.0`).
fn find_raise_targets(container: &Container<'_>) -> Vec<u64> {
    container
        .symbols()
        .iter()
        .filter(|s| {
            let name = s.name.as_ref();
            name == "raiseExceptionEx" || name.starts_with("raiseExceptionEx.")
        })
        .map(|s| s.vm_addr)
        .collect()
}

/// How far backwards from a call site to track argument registers.
const X86_BACKWARD_WINDOW: usize = 256;

/// Raise sites in x86-64 code: every `call`/`jmp rel32` to one of `targets`,
/// with its arguments recovered by tracking the argument registers over the
/// [`X86_BACKWARD_WINDOW`] bytes before it.
fn scan_x86_64(container: &Container<'_>, targets: &[u64]) -> Vec<RaiseSite> {
    let abi = Abi::of(container);
    let mut sites = Vec::new();
    let bytes = container.bytes();
    let calls = clobbering_calls(container);

    for section in container.sections() {
        if section.kind != SectionKind::Text || section.data.len() < 5 {
            continue;
        }
        let sec_data = section.data;
        let sec_va = section.vm_addr;

        // `e8 <rel32>` (call) and `e9 <rel32>` (tail jump: a noreturn raise
        // at the end of a path is often compiled into a jump).
        let mut i: usize = 0;
        while i.saturating_add(5) <= sec_data.len() {
            if let Some(0xe8 | 0xe9) = sec_data.get(i).copied()
                && let Some(target_va) = rel32_target(sec_data, i, sec_va)
                && targets.contains(&target_va)
            {
                let call_va = sec_va.wrapping_add(i as u64);
                sites.push(recover_args_x86_64(
                    container, bytes, sec_data, i, call_va, abi, &calls,
                ));
            }
            i = i.saturating_add(1);
        }
    }
    sites
}

/// Function starts that clobber the caller-saved registers when called:
/// every function symbol except the fragments of LLVM's machine outliner
/// (`OUTLINED_FUNCTION_<n>`), which by construction leave the caller's live
/// registers intact. A call to anything else is not treated as a call at
/// all: the opcode bytes may lie inside another instruction.
fn clobbering_calls(container: &Container<'_>) -> HashSet<u64> {
    container
        .symbols()
        .iter()
        .filter(|s| s.is_defined_function())
        .filter(|s| !s.name.starts_with("OUTLINED_FUNCTION"))
        .map(|s| s.vm_addr)
        .collect()
}

/// Target of the `rel32` branch whose opcode byte is at `pos`.
fn rel32_target(data: &[u8], pos: usize, sec_va: u64) -> Option<u64> {
    let disp = i32::from_le_bytes(
        data.get(pos.checked_add(1)?..pos.checked_add(5)?)?
            .try_into()
            .ok()?,
    );
    let next = sec_va.wrapping_add(pos as u64).wrapping_add(5);
    Some((next as i64).wrapping_add(i64::from(disp)) as u64)
}

/// Tracks the argument registers over the instructions before a call.
///
/// Recognised, applied in address order (a greedy left-to-right match
/// stands in for a full decoder):
/// - `REX.W 8d /r` RIP-relative `lea` into any register (`48`/`4c 8d`)
/// - `REX.W 89|8b /r` register-to-register `mov` (`48`/`49`/`4c`/`4d`)
/// - `41 b8+r imm32` / `REX.W c7 c0+r imm32` immediate `mov`
/// - `[REX.W] c7 44 24 20 imm32`: the fifth argument on the Microsoft stack
/// - `e8 <rel32>` to a known, non-outlined function: clobbers the
///   caller-saved registers
fn recover_args_x86_64(
    container: &Container<'_>,
    bytes: &[u8],
    sec_data: &[u8],
    call_offset: usize,
    call_va: u64,
    abi: Abi,
    calls: &HashSet<u64>,
) -> RaiseSite {
    let start = call_offset.saturating_sub(X86_BACKWARD_WINDOW);
    let window = sec_data.get(start..call_offset).unwrap_or(&[]);
    let window_va = call_va.wrapping_sub(window.len() as u64);

    let mut regs: [Option<u64>; 16] = [None; 16];
    let mut stack_arg5: Option<u64> = None;

    let at = |k: usize| window.get(k).copied();
    let imm32 = |k: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            window.get(k..k.checked_add(4)?)?.try_into().ok()?,
        ))
    };

    let mut j: usize = 0;
    while j < window.len() {
        let b0 = at(j);
        let b1 = at(j.saturating_add(1));
        let b2 = at(j.saturating_add(2));

        // lea disp32(%rip), %reg
        if let (Some(rex @ (0x48 | 0x4c)), Some(0x8d), Some(modrm)) = (b0, b1, b2)
            && modrm & 0xC7 == 0x05
            && let Some(disp) = imm32(j.saturating_add(3))
        {
            let reg = usize::from((modrm >> 3) & 7) | if rex == 0x4c { 8 } else { 0 };
            let next = window_va.wrapping_add(j as u64).wrapping_add(7);
            if let Some(slot) = regs.get_mut(reg) {
                *slot = Some((next as i64).wrapping_add(i64::from(disp as i32)) as u64);
            }
            j = j.saturating_add(7);
            continue;
        }

        // mov %src, %dst (64-bit, register form)
        if let (Some(rex @ 0x48..=0x4f), Some(op @ (0x89 | 0x8b)), Some(modrm)) = (b0, b1, b2)
            && rex & 0x08 != 0
            && modrm & 0xC0 == 0xC0
        {
            let reg = usize::from((modrm >> 3) & 7) | if rex & 0x04 != 0 { 8 } else { 0 };
            let rm = usize::from(modrm & 7) | if rex & 0x01 != 0 { 8 } else { 0 };
            let (dst, src) = if op == 0x89 { (rm, reg) } else { (reg, rm) };
            let val = regs.get(src).copied().flatten();
            if let Some(slot) = regs.get_mut(dst) {
                *slot = val;
            }
            j = j.saturating_add(3);
            continue;
        }

        // mov $imm32, 0x20(%rsp)  (fifth argument, Microsoft x64)
        let (stack_store, len) = match (b0, b1) {
            (Some(0x48), Some(0xc7)) => (true, 9),
            (Some(0xc7), _) => (true, 8),
            _ => (false, 0),
        };
        if stack_store {
            let base = if len == 9 { j.saturating_add(1) } else { j };
            if at(base.saturating_add(1)) == Some(0x44)
                && at(base.saturating_add(2)) == Some(0x24)
                && at(base.saturating_add(3)) == Some(0x20)
                && let Some(v) = imm32(base.saturating_add(4))
            {
                stack_arg5 = Some(u64::from(v));
                j = j.saturating_add(len);
                continue;
            }
        }

        // mov $imm32, %r8d..%r15d / %reg64. The bare one-byte `b8+r` form
        // is not matched: those bytes are too common inside other
        // instructions and would desynchronise the scan (`0f 85 bb 01 00 00`
        // then swallows the `41` of a following `41 b8`).
        if let (Some(0x41), Some(op @ 0xb8..=0xbf)) = (b0, b1)
            && let Some(v) = imm32(j.saturating_add(2))
        {
            if let Some(slot) = regs.get_mut(usize::from(op & 7) | 8) {
                *slot = Some(u64::from(v));
            }
            j = j.saturating_add(6);
            continue;
        }
        if let (Some(rex @ (0x48 | 0x49)), Some(0xc7), Some(modrm)) = (b0, b1, b2)
            && modrm & 0xF8 == 0xC0
            && let Some(v) = imm32(j.saturating_add(3))
        {
            let reg = usize::from(modrm & 7) | if rex == 0x49 { 8 } else { 0 };
            if let Some(slot) = regs.get_mut(reg) {
                *slot = Some(u64::from(v));
            }
            j = j.saturating_add(7);
            continue;
        }

        // An intervening call to a known function clobbers the
        // caller-saved registers.
        if b0 == Some(0xe8)
            && j.saturating_add(5) <= window.len()
            && rel32_target(window, j, window_va).is_some_and(|t| calls.contains(&t))
        {
            for &r in abi.caller_saved() {
                if let Some(slot) = regs.get_mut(r) {
                    *slot = None;
                }
            }
            j = j.saturating_add(5);
            continue;
        }

        j = j.saturating_add(1);
    }

    let reg = |r: usize| regs.get(r).copied().flatten();
    // raiseExceptionEx(e, ename, procname, filename, line)
    let [_, ename, procname, filename] = abi.int_args();
    let line = abi.fifth_arg().map_or(stack_arg5, reg);
    site_from_values(
        container,
        bytes,
        call_va,
        reg(ename),
        reg(procname),
        reg(filename),
        line,
    )
}

/// Builds a [`RaiseSite`] from recovered argument values.
fn site_from_values(
    container: &Container<'_>,
    bytes: &[u8],
    call_va: u64,
    etype_va: Option<u64>,
    proc_va: Option<u64>,
    file_va: Option<u64>,
    line: Option<u64>,
) -> RaiseSite {
    RaiseSite {
        call_addr: call_va,
        exception_type: etype_va
            .and_then(|va| read_cstring_at_va(container, bytes, va))
            .filter(|t| is_type_name(t)),
        proc_name: proc_va.and_then(|va| read_cstring_at_va(container, bytes, va)),
        file: file_va.and_then(|va| read_cstring_at_va(container, bytes, va)),
        line: line
            .filter(|&l| l > 0 && l < 1_000_000)
            .and_then(|l| u32::try_from(l).ok()),
        // Populated by scan() after instruction recovery.
        enclosing_function: None,
        enclosing_va: None,
    }
}

/// An exception type name is a Nim identifier (`ValueError`, `MyError`).
/// Anything else came from a register that held something unrelated.
fn is_type_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// How far backwards (in bytes) from a call site to scan on AArch64.
const AARCH64_BACKWARD_WINDOW: usize = 256;

/// Raise sites in AArch64 code: every `bl`/`b` to one of `targets`, with its
/// arguments recovered from the [`AARCH64_BACKWARD_WINDOW`] bytes before it.
fn scan_aarch64(container: &Container<'_>, targets: &[u64]) -> Vec<RaiseSite> {
    let mut sites = Vec::new();
    let bytes = container.bytes();
    let calls = clobbering_calls(container);

    for section in container.sections() {
        if section.kind != SectionKind::Text {
            continue;
        }
        if section.data.len() < 4 {
            continue;
        }

        let sec_data = section.data;
        let sec_va = section.vm_addr;

        // AArch64 instructions are 4 bytes, aligned, and little-endian in
        // every mode (aarch64_be included).
        let mut i: usize = 0;
        while i.saturating_add(4) <= sec_data.len() {
            let insn = util::DataLayout::LE64.u32(sec_data, i);

            // `bl` (call) or `b` (tail branch).
            let call_va = sec_va.wrapping_add(i as u64);
            if let Some(branch) = a64::branch(insn, call_va)
                && targets.contains(&branch.target)
            {
                let site = recover_args_aarch64(container, bytes, sec_data, i, call_va, &calls);
                sites.push(site);
            }

            i = i.saturating_add(4); // AArch64 instructions are fixed 4 bytes
        }
    }

    sites
}

/// Walks backwards from a BL to find ADRP+ADD pairs loading string
/// addresses into x1-x3, and MOV/MOVZ loading line into x4/w4.
fn recover_args_aarch64(
    container: &Container<'_>,
    bytes: &[u8],
    sec_data: &[u8],
    call_offset: usize,
    call_va: u64,
    calls: &HashSet<u64>,
) -> RaiseSite {
    let start = call_offset.saturating_sub(AARCH64_BACKWARD_WINDOW);
    // Align start to 4 bytes.
    let start = start & !3;

    // Collect ADRP results: reg -> page_base
    let mut adrp_pages: [Option<u64>; 32] = [None; 32];
    // Collect final register values: x1=etype, x2=proc, x3=file, x4/w4=line
    let mut reg_vals: [Option<u64>; 32] = [None; 32];
    let mut line: Option<u32> = None;

    let mut j = start;
    while j < call_offset {
        let insn = util::DataLayout::LE64.u32(sec_data, j);
        let insn_va = call_va.wrapping_sub(call_offset.wrapping_sub(j) as u64);

        // adrp Xd, <page>
        if let Some((rd, page)) = a64::adrp(insn, insn_va)
            && let Some(slot) = adrp_pages.get_mut(rd as usize)
        {
            *slot = Some(page);
        }

        // add Xd, Xn, #imm: a page plus its offset
        if let Some(op) = a64::add_sub_imm(insn)
            && op.wide
            && !op.sub
            && !op.set_flags
            && let Some(Some(page)) = adrp_pages.get(op.rn as usize).copied()
            && let Some(slot) = reg_vals.get_mut(op.rd as usize)
        {
            *slot = Some(page.wrapping_add(op.imm));
        }

        // movz Wd|Xd, #imm16 (unshifted): the line, or a small constant
        if let Some(mw) = a64::move_wide(insn)
            && mw.op == MoveWideOp::Z
            && mw.shift == 0
        {
            if mw.rd == 4 {
                line = Some(u32::from(mw.imm16));
            }
            if let Some(slot) = reg_vals.get_mut(mw.rd as usize) {
                *slot = Some(u64::from(mw.imm16));
            }
        }

        // `bl` to a known, non-outlined function clobbers x0 - x18.
        if a64::branch(insn, insn_va).is_some_and(|b| b.link && calls.contains(&b.target)) {
            for slot in reg_vals.iter_mut().take(19) {
                *slot = None;
            }
            for slot in adrp_pages.iter_mut().take(19) {
                *slot = None;
            }
            line = None;
        }

        // mov Xd, Xm
        if let Some((rd, rm, true)) = a64::mov_reg(insn)
            && let Some(Some(val)) = reg_vals.get(rm as usize).copied()
            && let Some(slot) = reg_vals.get_mut(rd as usize)
        {
            *slot = Some(val);
        }

        j = j.saturating_add(4);
    }

    // x1 = etype, x2 = proc, x3 = file, x4 = line
    let reg = |r: usize| reg_vals.get(r).copied().flatten();
    let line = line.map(u64::from).or(reg(4));
    site_from_values(container, bytes, call_va, reg(1), reg(2), reg(3), line)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::container::{Format, Section, Symbol, SymbolKind};

    const TEXT_VA: u64 = 0x1000;
    const RODATA_VA: u64 = 0x2000;
    const RAISE_VA: u64 = 0x1800;

    /// `rel32` from the end of an instruction of `len` bytes at `at`.
    fn rel(at: u64, len: u64, target: u64) -> [u8; 4] {
        ((target as i64 - (at + len) as i64) as i32).to_le_bytes()
    }

    /// Builds a container from `text` (at `TEXT_VA`) and the strings
    /// "MyError", "inner", "x.nim" (at `RODATA_VA`, offsets 0, 8, 14).
    fn run(text: &[u8], format: Format, arch: Arch, extra: Vec<Symbol<'static>>) -> Vec<RaiseSite> {
        let mut bytes = text.to_vec();
        bytes.resize(0x400, 0);
        let rodata = b"MyError\0inner\0x.nim\0";
        let ro_off = bytes.len();
        bytes.extend_from_slice(rodata);
        let bytes: &'static [u8] = Box::leak(bytes.into_boxed_slice());
        let sections = vec![
            Section {
                name: ".text".into(),
                kind: SectionKind::Text,
                vm_addr: TEXT_VA,
                vm_size: 0x400,
                data: &bytes[..0x400],
            },
            Section {
                name: ".rodata".into(),
                kind: SectionKind::RoData,
                vm_addr: RODATA_VA,
                vm_size: rodata.len() as u64,
                data: &bytes[ro_off..],
            },
        ];
        let mut symbols = vec![Symbol {
            name: Cow::Borrowed("raiseExceptionEx"),
            vm_addr: RAISE_VA,
            size: 16,
            kind: SymbolKind::Function,
        }];
        symbols.extend(extra);
        let c = Container::from_parts(bytes, format, arch, 0, sections, symbols);
        scan(&c)
    }

    /// Appends a RIP-relative `lea` (`rex 8d modrm`) to `target`.
    fn lea(code: &mut Vec<u8>, rex: u8, modrm: u8, target: u64) {
        let at = TEXT_VA + code.len() as u64;
        code.extend_from_slice(&[rex, 0x8d, modrm]);
        code.extend_from_slice(&rel(at, 7, target));
    }

    fn branch(code: &mut Vec<u8>, op: u8, target: u64) {
        let at = TEXT_VA + code.len() as u64;
        code.push(op);
        code.extend_from_slice(&rel(at, 5, target));
    }

    fn assert_site(site: &RaiseSite) {
        assert_eq!(site.exception_type.as_deref(), Some("MyError"));
        assert_eq!(site.proc_name.as_deref(), Some("inner"));
        assert_eq!(site.file.as_deref(), Some("x.nim"));
        assert_eq!(site.line, Some(9));
    }

    #[test]
    fn sysv_tail_jump_with_register_moves_and_desync_traps() {
        let mut code = Vec::new();
        // `mov -0x18(%rbp),%rax` ends in an `e8` byte that is not a call.
        code.extend_from_slice(&[0x48, 0x8b, 0x45, 0xe8]);
        code.extend_from_slice(&[0x41, 0xb8, 9, 0, 0, 0]); // mov $9,%r8d
        // `jne` whose displacement bytes look like `mov $imm,%ebx`.
        code.extend_from_slice(&[0x0f, 0x85, 0xbb, 0x01, 0x00, 0x00]);
        lea(&mut code, 0x48, 0x0d, RODATA_VA + 14); // lea file,%rcx
        lea(&mut code, 0x48, 0x15, RODATA_VA + 8); // lea proc,%rdx
        lea(&mut code, 0x4c, 0x3d, RODATA_VA); // lea type,%r15
        code.extend_from_slice(&[0x4c, 0x89, 0xfe]); // mov %r15,%rsi
        branch(&mut code, 0xe9, RAISE_VA); // jmp raiseExceptionEx
        let sites = run(&code, Format::Elf, Arch::Amd64, vec![]);
        assert_eq!(sites.len(), 1);
        assert_site(&sites[0]);
    }

    #[test]
    fn microsoft_x64_registers_and_stack_line() {
        let mut code = Vec::new();
        lea(&mut code, 0x48, 0x15, RODATA_VA); // lea type,%rdx
        lea(&mut code, 0x4c, 0x05, RODATA_VA + 8); // lea proc,%r8
        lea(&mut code, 0x4c, 0x0d, RODATA_VA + 14); // lea file,%r9
        code.extend_from_slice(&[0x48, 0xc7, 0x44, 0x24, 0x20, 9, 0, 0, 0]);
        branch(&mut code, 0xe8, RAISE_VA);
        let sites = run(&code, Format::Pe, Arch::Amd64, vec![]);
        assert_eq!(sites.len(), 1);
        assert_site(&sites[0]);
        // The same bytes read with System V registers give no type.
        let sysv = run(&code, Format::Elf, Arch::Amd64, vec![]);
        assert_ne!(sysv[0].exception_type.as_deref(), Some("MyError"));
    }

    #[test]
    fn calls_to_known_functions_clobber_argument_registers() {
        let helper = 0x1700;
        let func = |name: &'static str| Symbol {
            name: Cow::Borrowed(name),
            vm_addr: helper,
            size: 16,
            kind: SymbolKind::Function,
        };
        let mut code = Vec::new();
        lea(&mut code, 0x48, 0x35, RODATA_VA); // lea type,%rsi
        branch(&mut code, 0xe8, helper); // call helper
        code.extend_from_slice(&[0x41, 0xb8, 9, 0, 0, 0]);
        branch(&mut code, 0xe8, RAISE_VA);
        let clobbered = run(&code, Format::Elf, Arch::Amd64, vec![func("newObj")]);
        assert_eq!(clobbered[0].exception_type, None);
        // An LLVM outlined fragment leaves the registers alone.
        let kept = run(
            &code,
            Format::Elf,
            Arch::Amd64,
            vec![func("OUTLINED_FUNCTION_1")],
        );
        assert_eq!(kept[0].exception_type.as_deref(), Some("MyError"));
    }

    #[test]
    fn aarch64_tail_branch() {
        let mut code: Vec<u8> = Vec::new();
        let mut put = |insn: u32| code.extend_from_slice(&insn.to_le_bytes());
        // adrp x1, page(RODATA); add x1, x1, #0 (type) ...
        let adrp = |rd: u32, at: u64| {
            let pages = ((RODATA_VA & !0xfff) as i64 - (at & !0xfff) as i64) >> 12;
            0x9000_0000 | ((pages as u32 & 3) << 29) | (((pages as u32 >> 2) & 0x7ffff) << 5) | rd
        };
        let add = |rd: u32, rn: u32, imm: u32| 0x9100_0000 | (imm << 10) | (rn << 5) | rd;
        put(adrp(1, TEXT_VA));
        put(add(1, 1, 0));
        put(adrp(2, TEXT_VA + 8));
        put(add(2, 2, 8));
        put(adrp(3, TEXT_VA + 16));
        put(add(3, 3, 14));
        put(0xd280_0000 | (9 << 5) | 4); // mov x4, #9 (64-bit movz)
        let at = TEXT_VA + 28;
        put(0x1400_0000 | ((((RAISE_VA - at) / 4) as u32) & 0x03ff_ffff)); // b raise
        let sites = run(&code, Format::Elf, Arch::Aarch64, vec![]);
        assert_eq!(sites.len(), 1);
        assert_site(&sites[0]);
    }

    #[test]
    fn non_type_names_are_rejected() {
        assert!(is_type_name("ValueError"));
        assert!(!is_type_name("+"));
        assert!(!is_type_name("\u{17}"));
        assert!(!is_type_name(""));
    }
}
