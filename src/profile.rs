//! Build-configuration inference.
//!
//! Recovers how a Nim binary was compiled from artifacts the configuration
//! leaves behind. Every field is evidence-based: where the evidence is
//! absent rather than contrary, the answer is "unknown", not "off".
//!
//! | Field | Evidence |
//! |---|---|
//! | [`BuildProfile::exceptions`] | goto: `nimTestErrorFlag` / `nimInErrorMode`; setjmp: the `excHandler` global or an imported `setjmp`; C++: the C++ EH runtime (`__cxa_throw`, `_CxxThrowException`) |
//! | [`BuildProfile::stack_traces`] | share of routine names that reappear as stack-frame strings (`--stackTrace:on` stores every proc's name); without symbols, a large number of stack-trace paths |
//! | [`BuildProfile::runtime_checks`] | check raisers (`raiseIndexError2`, `raiseRangeErrorI`, ...) or their messages (`index out of bounds`); `-d:danger` removes them |
//! | [`BuildProfile::library`] | [`Container::is_library`] (`--app:lib`) |
//!
//! Thresholds were set on the fixture matrix (Nim 1.0.10 - 2.4.2, refc /
//! ARC / ORC, debug / release / danger, ELF / PE).

use core::fmt;
use std::collections::HashSet;

use memchr::memmem;

use crate::{
    container::{Container, SectionKind, SymbolKind},
    stacktrace::StackTraceHarvest,
};

/// Without a symbol table, stack-trace paths needed to report
/// `--stackTrace:on` (debug fixtures: 13 or more; release builds keep a few
/// basenames from assertion messages, up to 7 in the fixtures).
pub const MIN_STACK_TRACE_PATHS: usize = 12;

/// Distinct routine names in the symbol table needed to judge stack
/// traces from the symbols.
pub const MIN_ROUTINES: usize = 20;

/// Share of routine names that must appear as stack-frame strings to report
/// `--stackTrace:on`. Fixtures: at least 0.60 in every debug build, at most
/// 0.07 in every other build.
pub const MIN_FRAME_NAME_SHARE: f64 = 0.25;

/// Infers `--stackTrace:on`. With it, every proc stores its own name in a
/// frame (`nimfr_`), so most routine names from the symbol table reappear
/// among the stack-trace proc-name strings. Without symbols, only a large
/// path count decides.
fn stack_traces(stack: &StackTraceHarvest, routine_names: &HashSet<String>) -> Option<bool> {
    if routine_names.len() >= MIN_ROUTINES {
        let frames: HashSet<&str> = stack.proc_names.iter().map(String::as_str).collect();
        let hits = routine_names
            .iter()
            .filter(|n| frames.contains(n.as_str()))
            .count();
        #[allow(clippy::cast_precision_loss)] // counts far below 2^52
        let share = hits as f64 / routine_names.len() as f64;
        Some(share >= MIN_FRAME_NAME_SHARE)
    } else if stack.file_paths.len() >= MIN_STACK_TRACE_PATHS {
        Some(true)
    } else {
        None
    }
}

/// Distinct check raisers needed to report runtime checks as on. `-d:danger`
/// builds still contain `raiseOverflow` from the allocator.
pub const MIN_CHECK_RAISERS: usize = 2;

/// Demangled names of the runtime-check raisers in `lib/system/chcks.nim`.
const CHECK_RAISERS: &[&str] = &[
    "raiseIndexError",
    "raiseIndexError2",
    "raiseIndexError3",
    "raiseIndexError4",
    "raiseRangeError",
    "raiseRangeErrorI",
    "raiseRangeErrorF",
    "raiseRangeErrorU",
    "raiseRangeErrorNoArgs",
    "raiseFieldError",
    "raiseFieldError2",
    "raiseFieldErrorStr",
    "raiseDivByZero",
    "raiseOverflow",
    "raiseFloatInvalidOp",
    "raiseFloatOverflow",
    "raiseObjectConversionError",
];

/// Messages only the bounds and range checks produce.
const CHECK_MESSAGES: &[&[u8]] = &[b"index out of bounds", b"value out of range"];

/// Runtime symbols of goto-based exceptions (`--exceptions:goto`, the ARC/ORC
/// default): the error flag every call site tests.
const GOTO_MARKERS: &[&str] = &["nimTestErrorFlag", "nimInErrorMode", "nimErrorFlag"];
/// The C library's `setjmp` entry points across libcs and toolchains, called
/// by setjmp-based exception handling (`--exceptions:setjmp`, the refc
/// default).
const SETJMP_FUNCTIONS: &[&str] = &[
    "setjmp",
    "_setjmp",
    "__sigsetjmp",
    "sigsetjmp",
    "_setjmp3",
    "_setjmpex",
    "__intrinsic_setjmp",
    "__intrinsic_setjmpex",
    "__mingw_setjmp",
];
/// C++ exception runtime functions (Itanium ABI: `__cxa_*`, the GCC
/// personalities; MSVC: `_CxxThrowException`, the frame handlers), linked
/// when Nim exceptions map to C++ ones (`--exceptions:cpp`, the C++
/// backend).
const CPP_EH_FUNCTIONS: &[&str] = &[
    "__cxa_throw",
    "__cxa_begin_catch",
    "__gxx_personality_v0",
    "__gxx_personality_seh0",
    "_CxxThrowException",
    "__CxxFrameHandler3",
    "__CxxFrameHandler4",
];

/// The exception-handling implementation (`--exceptions:`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExceptionModel {
    /// `goto`: error flag checked after calls (ARC/ORC default from 1.4).
    Goto,
    /// `setjmp`: `setjmp`/`longjmp` (refc default).
    Setjmp,
    /// `cpp`: native C++ exceptions (C++ backend default).
    Cpp,
    /// No evidence either way (e.g. a stripped, statically linked binary).
    Unknown,
}

impl ExceptionModel {
    /// Returns a stable, lowercase identifier for the model.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Goto => "goto",
            Self::Setjmp => "setjmp",
            Self::Cpp => "cpp",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for ExceptionModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a Nim binary was built, as far as its artifacts show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildProfile {
    /// Exception-handling implementation.
    pub exceptions: ExceptionModel,
    /// Whether `--stackTrace:on` was in effect (debug builds): `None` when
    /// neither the symbol table nor the stack-trace strings decide it.
    pub stack_traces: Option<bool>,
    /// Whether runtime checks were compiled in: `Some(true)` with positive
    /// evidence, `Some(false)` when the symbol table lists Nim routines but
    /// at most one check raiser and no check message (consistent with
    /// `-d:danger`), `None` without enough evidence.
    pub runtime_checks: Option<bool>,
    /// Whether the binary is a shared library (`--app:lib`).
    pub library: bool,
}

/// Infers the build profile from the container and its stack-trace harvest.
pub fn detect(container: &Container<'_>, stack: &StackTraceHarvest) -> BuildProfile {
    let mut goto = false;
    let mut setjmp_global = false;
    let mut setjmp_call = false;
    let mut cpp = false;
    let mut nim_routines: usize = 0;
    let mut routine_names: HashSet<String> = HashSet::new();
    let mut raisers: Vec<&str> = Vec::new();

    for sym in container.symbols() {
        let raw = sym.name.as_ref();
        goto |= GOTO_MARKERS.contains(&raw);
        setjmp_call |= SETJMP_FUNCTIONS.contains(&raw);
        cpp |= CPP_EH_FUNCTIONS.contains(&raw);

        let demangled = container.demangle(raw).filter(|d| d.is_scheme_name());
        let ident = demangled.as_ref().map_or(raw, |d| d.identifier.as_ref());
        if let Some(d) = &demangled {
            nim_routines = nim_routines.saturating_add(1);
            if sym.kind == SymbolKind::Function && d.clone_suffix.is_none() {
                routine_names.insert(d.identifier.clone().into_owned());
            }
        }
        setjmp_global |= ident == "excHandler";
        // Check raisers are compilerprocs: exported unmangled, or mangled
        // where they were not.
        if let Some(&r) = CHECK_RAISERS.iter().find(|&&r| r == ident)
            && !raisers.contains(&r)
        {
            raisers.push(r);
        }
    }
    for imp in container.imports() {
        let name = imp.name.as_ref();
        setjmp_call |= SETJMP_FUNCTIONS.contains(&name);
        cpp |= CPP_EH_FUNCTIONS.contains(&name);
    }

    // `excHandler` is declared for every mode up to 2.0, so it is evidence
    // of setjmp only when no goto marker is present.
    let exceptions = if cpp {
        ExceptionModel::Cpp
    } else if goto {
        ExceptionModel::Goto
    } else if setjmp_global || setjmp_call {
        ExceptionModel::Setjmp
    } else {
        ExceptionModel::Unknown
    };

    let check_message = container
        .sections()
        .iter()
        .filter(|s| s.kind == SectionKind::RoData)
        .any(|s| {
            CHECK_MESSAGES
                .iter()
                .any(|m| memmem::find(s.data, m).is_some())
        });
    let runtime_checks = if check_message || raisers.len() >= MIN_CHECK_RAISERS {
        Some(true)
    } else if nim_routines >= MIN_ROUTINES {
        Some(false)
    } else {
        None
    };

    BuildProfile {
        exceptions,
        stack_traces: stack_traces(stack, &routine_names),
        runtime_checks,
        library: container.is_library(),
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::container::{Arch, Format, Import, Symbol, SymbolKind};
    use crate::stacktrace::FilePath;

    fn func(name: &'static str) -> Symbol<'static> {
        Symbol {
            name: Cow::Borrowed(name),
            vm_addr: 0x1000,
            size: 4,
            kind: SymbolKind::Function,
        }
    }

    fn harvest(paths: usize) -> StackTraceHarvest {
        StackTraceHarvest {
            file_paths: (0..paths)
                .map(|i| FilePath {
                    path: format!("m{i}.nim"),
                    is_absolute: false,
                })
                .collect(),
            proc_names: Vec::new(),
        }
    }

    fn profile(
        symbols: Vec<Symbol<'static>>,
        imports: Vec<Import<'static>>,
        paths: usize,
    ) -> BuildProfile {
        let c = Container::from_parts(&[], Format::Elf, Arch::Amd64, 0, vec![], symbols)
            .with_imports(imports);
        detect(&c, &harvest(paths))
    }

    fn import(name: &'static str) -> Import<'static> {
        Import {
            name: Cow::Borrowed(name),
            library: None,
        }
    }

    const ROUTINES: [&str; 20] = [
        "a_u1__m", "b_u1__m", "c_u1__m", "d_u1__m", "e_u1__m", "f_u1__m", "g_u1__m", "h_u1__m",
        "i_u1__m", "j_u1__m", "k_u1__m", "l_u1__m", "n_u1__m", "o_u1__m", "p_u1__m", "q_u1__m",
        "r_u1__m", "s_u1__m", "t_u1__m", "v_u1__m",
    ];

    #[test]
    fn exception_models() {
        let goto = profile(vec![func("nimTestErrorFlag")], vec![], 0);
        assert_eq!(goto.exceptions, ExceptionModel::Goto);
        let setjmp = profile(
            vec![func("excHandler__system_u2311")],
            vec![import("_setjmp")],
            0,
        );
        assert_eq!(setjmp.exceptions, ExceptionModel::Setjmp);
        // Stripped dynamic binary: only the import is left.
        assert_eq!(
            profile(vec![], vec![import("_setjmp")], 0).exceptions,
            ExceptionModel::Setjmp
        );
        let cpp = profile(vec![], vec![import("__cxa_throw")], 0);
        assert_eq!(cpp.exceptions, ExceptionModel::Cpp);
        assert_eq!(
            profile(vec![], vec![], 0).exceptions,
            ExceptionModel::Unknown
        );
        // Up to 2.0 goto builds declare `excHandler` too: the marker wins.
        let both = profile(
            vec![func("nimTestErrorFlag"), func("excHandler__system_u1")],
            vec![],
            0,
        );
        assert_eq!(both.exceptions, ExceptionModel::Goto);
    }

    #[test]
    fn stack_traces_evidence() {
        // No symbols: only many paths decide.
        assert_eq!(profile(vec![], vec![], 7).stack_traces, None);
        assert_eq!(
            profile(vec![], vec![], MIN_STACK_TRACE_PATHS).stack_traces,
            Some(true)
        );
        // With routines, the share of names found in frames decides.
        let routines: Vec<Symbol<'static>> = ROUTINES.iter().copied().map(func).collect();
        let c = Container::from_parts(&[], Format::Elf, Arch::Amd64, 0, vec![], routines);
        let mut h = harvest(30);
        h.proc_names = vec!["a".into(), "unrelated".into()];
        assert_eq!(detect(&c, &h).stack_traces, Some(false));
        h.proc_names = ["a", "b", "c", "d", "e", "f"].map(String::from).to_vec();
        assert_eq!(detect(&c, &h).stack_traces, Some(true));
    }

    #[test]
    fn runtime_checks_evidence() {
        let mut syms: Vec<Symbol<'static>> = [
            "a_u1__m", "b_u1__m", "c_u1__m", "d_u1__m", "e_u1__m", "f_u1__m", "g_u1__m", "h_u1__m",
            "i_u1__m", "j_u1__m", "k_u1__m", "l_u1__m", "n_u1__m", "o_u1__m", "p_u1__m", "q_u1__m",
            "r_u1__m", "s_u1__m", "t_u1__m", "v_u1__m",
        ]
        .into_iter()
        .map(func)
        .collect();
        // Many routines, only `raiseOverflow`: consistent with danger.
        syms.push(func("raiseOverflow"));
        assert_eq!(profile(syms.clone(), vec![], 0).runtime_checks, Some(false));
        syms.push(func("raiseIndexError2"));
        assert_eq!(profile(syms, vec![], 0).runtime_checks, Some(true));
        // Too little to judge.
        assert_eq!(profile(vec![func("main")], vec![], 0).runtime_checks, None);
    }
}
