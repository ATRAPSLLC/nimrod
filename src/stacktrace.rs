//! Stack-trace metadata harvester.
//!
//! Every Nim proc compiled with `--stackTrace:on` (the default for debug
//! builds) embeds a `procname` and `filename` cstring pair via the
//! `nimfr_()` frame-init macro (RESEARCH.md §5.2). This module scans
//! read-only sections for those cstrings.
//!
//! **File paths** end with `.nim` and may be absolute (revealing the
//! build host) or relative (basename only).
//!
//! **Proc names** are the remaining short, printable cstrings that look
//! like Nim identifiers.

use std::collections::HashSet;

use crate::{
    container::{Container, SectionKind},
    util::{self, encode_unique_name},
};

/// Harvested stack-trace metadata from a Nim binary.
#[derive(Debug, Clone)]
pub struct StackTraceHarvest {
    /// Nim source-file paths found in rodata (deduplicated).
    pub file_paths: Vec<FilePath>,
    /// Nim proc names found in rodata (deduplicated).
    pub proc_names: Vec<String>,
}

/// A `.nim` file path found in the binary.
#[derive(Debug, Clone)]
pub struct FilePath {
    /// The path as found in the binary.
    pub path: String,
    /// Whether the path is absolute (starts with `/` or a drive letter).
    pub is_absolute: bool,
}

/// Scans read-only sections for Nim stack-trace file paths and proc names.
pub fn harvest(container: &Container<'_>) -> StackTraceHarvest {
    let mut file_paths = Vec::new();
    let mut proc_names = Vec::new();
    let mut seen_files = std::collections::HashSet::new();
    let mut seen_procs = std::collections::HashSet::new();

    let modules = known_module_names(container);
    for section in container.sections() {
        if section.kind != SectionKind::RoData {
            continue;
        }
        harvest_section(
            section.data,
            &modules,
            &mut file_paths,
            &mut proc_names,
            &mut seen_files,
            &mut seen_procs,
        );
    }

    StackTraceHarvest {
        file_paths,
        proc_names,
    }
}

/// Adds the stack-trace file paths and proc names among `data`'s cstrings,
/// each once (the `seen_*` sets span all sections). `modules` recovers file
/// names glued to the string before them.
fn harvest_section(
    data: &[u8],
    modules: &HashSet<String>,
    file_paths: &mut Vec<FilePath>,
    proc_names: &mut Vec<String>,
    seen_files: &mut std::collections::HashSet<String>,
    seen_procs: &mut std::collections::HashSet<String>,
) {
    for cstr in util::cstrings(data, 4096) {
        if let Ok(s) = std::str::from_utf8(cstr) {
            // File path: ends with ".nim". Strip a leading `@`: in V2 builds
            // the byte before a literal's data is the top byte of its
            // `cap | NIM_STRLIT_FLAG` word (0x40), which reads as part of
            // the NUL-terminated cstring.
            let path = s.strip_prefix('@').unwrap_or(s);
            if path.ends_with(".nim") {
                let accepted = if is_stack_trace_path(path) {
                    Some(path.to_owned())
                } else {
                    recover_glued_basename(path, modules)
                };
                if let Some(path) = accepted
                    && seen_files.insert(path.clone())
                {
                    file_paths.push(FilePath {
                        is_absolute: is_absolute(&path),
                        path,
                    });
                }
            }
            // Proc name: short, printable, looks like a Nim identifier.
            else if s.len() <= 128
                && s.len() >= 2
                && is_nim_proc_name(s)
                && !looks_like_path(s)
                && seen_procs.insert(s.to_owned())
            {
                proc_names.push(s.to_owned());
            }
        }
    }
}

/// Module names the binary proves it contains: the last path component of
/// every unique module name in the symbol table (`pureZjsonutils` ->
/// `jsonutils`), in `uniqueModuleName` encoding.
fn known_module_names(container: &Container<'_>) -> HashSet<String> {
    container
        .symbols()
        .iter()
        .filter_map(|s| container.demangle(s.name.as_ref()))
        .filter(|d| d.is_scheme_name())
        .filter_map(|d| d.module)
        .map(|m| m.rsplit('Z').next().unwrap_or(m).to_owned())
        .collect()
}

/// Recovers a source basename glued onto preceding unterminated data
/// (`cannot read from` + `jsonutils.nim`, a fixed-size char array directly
/// before the cstring). The identifier suffixes of the last token are tried
/// longest first; one is accepted only when it names a module of this
/// binary, because `fromjsonutils` is just as valid an identifier.
fn recover_glued_basename(path: &str, modules: &HashSet<String>) -> Option<String> {
    let stem = path.strip_suffix(".nim")?;
    let start = stem
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_alphanumeric() || *c == '_')
        .last()
        .map(|(i, _)| i)?;
    let token = stem.get(start..)?;
    token
        .char_indices()
        .filter(|(_, c)| c.is_ascii_alphabetic())
        .map(|(i, _)| token.get(i..).unwrap_or(""))
        .find(|cand| {
            is_nim_identifier(cand)
                && (modules.contains(&encode_unique_name(cand, true))
                    || modules.contains(&encode_unique_name(cand, false)))
        })
        .map(|cand| format!("{cand}.nim"))
}

/// Whether a `.nim`-terminated cstring is a plausible source-file path.
///
/// The basename's stem must be a Nim identifier, because the compiler
/// rejects any module (the main module included) whose name is not one
/// ("a module name must be a valid Nim identifier", `compiler/modules.nim`).
/// That rules out string literals that merely end in `.nim` (`$#_examples_$#.nim`,
/// a bare `.nim`) and runs of unterminated string data that happen to end
/// in a file name (`cannot read fromjsonutils.nim`). Directory components
/// may hold spaces and non-ASCII text (`C:\Users\Jane Doe\...`), but no
/// control characters.
fn is_stack_trace_path(path: &str) -> bool {
    if path.chars().any(char::is_control) {
        return false;
    }
    let basename = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let Some(stem) = basename.strip_suffix(".nim") else {
        return false;
    };
    is_nim_identifier(stem)
}

/// `compiler/lexbase` identifier rule: a letter, `_` or non-ASCII
/// character, followed by letters, digits, `_` or non-ASCII characters.
fn is_nim_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let start = |c: char| c.is_ascii_alphabetic() || c == '_' || !c.is_ascii();
    start(first) && chars.all(|c| start(c) || c.is_ascii_digit())
}

/// Whether a path is absolute: POSIX root, Windows drive (`C:\`, `C:/`) or
/// UNC (`\\host\share`).
fn is_absolute(path: &str) -> bool {
    let b = path.as_bytes();
    path.starts_with('/')
        || path.starts_with("\\\\")
        || (b.len() >= 3
            && b.first().is_some_and(u8::is_ascii_alphabetic)
            && b.get(1) == Some(&b':')
            && matches!(b.get(2), Some(b'\\' | b'/')))
}

/// Heuristic: does this string look like a Nim proc name?
///
/// Nim proc names are identifiers: start with a letter, contain letters,
/// digits, and underscores. Some operators are mangled but the stack-trace
/// `procname` field stores the original Nim name.
fn is_nim_proc_name(s: &str) -> bool {
    let Some(&first) = s.as_bytes().first() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Reject strings that look like file paths or URLs rather than proc names.
fn looks_like_path(s: &str) -> bool {
    s.contains('/') || s.contains('\\') || s.contains("://") || s.ends_with(".nim")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_paths_are_accepted() {
        for p in [
            "system.nim",
            "/home/runner/work/nightlies/nightlies/nim-2.4.2/compiler/msgs.nim",
            "C:\\Users\\Jane Doe\\.nimble\\pkgs2\\winim-3.9.4\\winim\\inc\\windef.nim",
            "/home/иван/proj/src/main.nim",
            "../lib/pure/os.nim",
            "_private.nim",
            "ospaths2.nim",
        ] {
            assert!(is_stack_trace_path(p), "{p}");
        }
    }

    #[test]
    fn non_paths_are_rejected() {
        for p in [
            ".nim",
            "$#_examples_$#.nim",
            "$1_group$2_examples.nim",
            "cannot read fromjsonutils.nim",
            "too many fields unknown field for object of typecannot marshal amath.nim",
            "/tmp/2fast.nim",
            "/tmp/my-app.nim",
            "/tmp/a\tb/x.nim\n.nim",
            "dir/.nim",
        ] {
            assert!(!is_stack_trace_path(p), "{p:?}");
        }
    }

    #[test]
    fn glued_basename_recovered_only_for_known_modules() {
        let modules: HashSet<String> = ["jsonutils", "tables", "math", "stdlib95mix"]
            .map(String::from)
            .into();
        let r = |p| recover_glued_basename(p, &modules);
        assert_eq!(
            r("cannot read fromjsonutils.nim").as_deref(),
            Some("jsonutils.nim")
        );
        assert_eq!(
            r("format string: ktables.nim").as_deref(),
            Some("tables.nim")
        );
        assert_eq!(r("cannot marshal amath.nim").as_deref(), Some("math.nim"));
        assert_eq!(
            r("main loop instdlib_mix.nim").as_deref(),
            Some("stdlib_mix.nim")
        );
        // Unknown module, no identifier tail, template text.
        assert_eq!(r("cannot read fromnowhere.nim"), None);
        assert_eq!(r("$#_examples_$#.nim"), None);
        assert_eq!(r(".nim"), None);
    }

    #[test]
    fn absolute_path_forms() {
        assert!(is_absolute("/usr/lib/nim/system.nim"));
        assert!(is_absolute("C:\\nim\\lib\\system.nim"));
        assert!(is_absolute("d:/nim/lib/system.nim"));
        assert!(is_absolute("\\\\build01\\src\\main.nim"));
        assert!(!is_absolute("lib/system.nim"));
        assert!(!is_absolute("system.nim"));
        assert!(!is_absolute("x:y.nim"));
    }

    #[test]
    fn harvest_section_filters_and_strips_strlit_flag_byte() {
        let mut data = Vec::new();
        for s in [
            &b"@/home/u/proj/main.nim"[..],
            b"@$#_examples_$#.nim",
            b"@.nim",
            b"cannot read fromjsonutils.nim",
            b"parseCmdLine",
        ] {
            data.extend_from_slice(s);
            data.push(0);
        }
        let (mut files, mut procs) = (Vec::new(), Vec::new());
        let (mut seen_f, mut seen_p) = Default::default();
        harvest_section(
            &data,
            &HashSet::new(),
            &mut files,
            &mut procs,
            &mut seen_f,
            &mut seen_p,
        );
        let paths: Vec<_> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["/home/u/proj/main.nim"]);
        assert!(files.iter().all(|f| f.is_absolute));
        assert_eq!(procs, ["parseCmdLine"]);
    }
}
