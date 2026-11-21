//! Exception type names from read-only data.
//!
//! Every `raise` statement in Nim compiles to a call to
//! `raiseExceptionEx(e, "<TypeName>", "<proc>", "<file>", <line>)`.
//! All four string arguments are embedded as `.rodata` cstrings
//! (RESEARCH.md §5.5).
//!
//! This module recovers the exception type names only, by scanning rodata
//! for cstrings matching known Nim exception types and the naming patterns
//! (`*Error`, `*Defect`, `*Exception`). It needs no instruction analysis
//! and works on every architecture; [`crate::sites`] decodes the calls
//! themselves for the full `(type, proc, file, line)` of each raise.

use crate::{
    container::{Container, SectionKind},
    util,
};

/// A recovered exception type reference.
#[derive(Debug, Clone)]
pub struct ExceptionRef {
    /// The exception type name (e.g. `ValueError`, `MyError`).
    pub type_name: String,
}

/// Known Nim stdlib exception type names. These are always present as
/// cstrings when the exception infrastructure is compiled in.
const KNOWN_EXCEPTION_TYPES: &[&str] = &[
    "AssertionDefect",
    "ArithmeticDefect",
    "DivByZeroDefect",
    "OverflowDefect",
    "RangeDefect",
    "IndexDefect",
    "FieldDefect",
    "ObjectConversionDefect",
    "ReraiseDefect",
    "AccessViolationDefect",
    "DeadThreadDefect",
    "NilAccessDefect",
    "OutOfMemDefect",
    "StackOverflowDefect",
    "ValueError",
    "IOError",
    "EOFError",
    "OSError",
    "KeyError",
    "CatchableError",
    "Exception",
    "Defect",
    "FloatingPointDefect",
    "FloatInvalidOpDefect",
    "FloatDivByZeroDefect",
    "FloatOverflowDefect",
    "FloatUnderflowDefect",
    "FloatInexactDefect",
    "ResourceExhaustedError",
    "ObjectAssignmentDefect",
];

/// Scans read-only sections for exception type name cstrings.
///
/// Finds both known Nim stdlib exception types and user-defined types
/// matching the `*Error`, `*Defect`, or `*Exception` suffix pattern.
pub fn scan(container: &Container<'_>) -> Vec<ExceptionRef> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for section in container.sections() {
        if section.kind != SectionKind::RoData {
            continue;
        }
        scan_section(section.data, &mut results, &mut seen);
    }

    results
}

/// Adds the exception type names among `data`'s cstrings to `out`, each
/// name once (`seen` spans all sections).
fn scan_section(
    data: &[u8],
    out: &mut Vec<ExceptionRef>,
    seen: &mut std::collections::HashSet<String>,
) {
    for cstr in util::cstrings(data, 256) {
        if let Ok(s) = std::str::from_utf8(cstr)
            && is_exception_type_name(s)
            && seen.insert(s.to_owned())
        {
            out.push(ExceptionRef {
                type_name: s.to_owned(),
            });
        }
    }
}

/// Returns `true` if the string looks like a Nim exception type name.
fn is_exception_type_name(s: &str) -> bool {
    // Must be a valid identifier: starts with uppercase, alphanumeric.
    if s.len() < 3 || !s.as_bytes().first().is_some_and(u8::is_ascii_uppercase) {
        return false;
    }
    if !s.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }

    // Check known names first (exact match).
    if KNOWN_EXCEPTION_TYPES.contains(&s) {
        return true;
    }

    // Suffix pattern: *Error, *Defect, *Exception (user-defined types
    // typically follow Nim convention of naming exceptions this way).
    s.ends_with("Error") || s.ends_with("Defect") || s.ends_with("Exception")
}
