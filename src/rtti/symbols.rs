//! RTTI symbol enumeration.
//!
//! Scans the symbol table for `NTIv2_` (ARC/ORC) and `NTI_` (refc)
//! globals, returning structured entries for each. See RESEARCH.md §3.4.

use crate::container::Container;
use core::fmt;

/// Which RTTI generation a symbol belongs to.
///
/// # Stability
///
/// The string returned by [`Display`](fmt::Display) is part of nimrod's
/// stable API. Changes are SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RttiVersion {
    /// Legacy `TNimType` (refc GC). Symbol format: `NTI<typespec><hash>_`.
    V1,
    /// Modern `TNimTypeV2` (ARC/ORC). Symbol format: `NTIv2<hash>_`.
    V2,
}

impl RttiVersion {
    /// Returns the stable string identifier for this RTTI version.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1 => "V1",
            Self::V2 => "V2",
        }
    }
}

impl fmt::Display for RttiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A located RTTI symbol.
///
/// `address` is a virtual address (image load space). To convert to an
/// RVA for disassembler use, call [`crate::NimBinary::rtti_rva`].
#[derive(Debug, Clone)]
pub struct RttiSymbol {
    /// V1 or V2.
    pub version: RttiVersion,
    /// The full symbol name (e.g. `NTIv2__abc123_`).
    pub symbol_name: String,
    /// Virtual address of the RTTI global (image load space, not file
    /// offset).
    pub address: u64,
    /// For V1 symbols, the type-name fragment between `NTI` and the hash.
    /// E.g. `NTIseqLintT<hash>_` → `Some("seqLintT")`.
    /// Always `None` for V2 symbols.
    pub type_fragment: Option<String>,
}

/// Scans the container's symbol table for all RTTI globals.
pub fn scan(container: &Container<'_>) -> Vec<RttiSymbol> {
    let mut result = Vec::new();

    for sym in container.symbols() {
        let name = sym.name.as_ref();
        if !name.ends_with('_') {
            continue;
        }

        if let Some(_inner) = name.strip_prefix("NTIv2") {
            result.push(RttiSymbol {
                version: RttiVersion::V2,
                symbol_name: name.to_string(),
                address: sym.vm_addr,
                type_fragment: None,
            });
        } else if let Some(inner) = name.strip_prefix("NTI") {
            let body = inner.strip_suffix('_').unwrap_or(inner);
            let type_fragment = extract_v1_type_fragment(body).map(|s| s.to_string());
            result.push(RttiSymbol {
                version: RttiVersion::V1,
                symbol_name: name.to_string(),
                address: sym.vm_addr,
                type_fragment,
            });
        }
    }

    result
}

/// Extracts the type-name fragment from a V1 RTTI symbol body.
///
/// V1 symbols are `NTI<typeToC(t)><hash>_` where `typeToC` produces a
/// lowercase representation with substitutions (`,→_`, `.→O`, etc.).
/// The hash is an opaque suffix. We split at the boundary where the
/// readable type name ends and the hash begins. The hash is typically
/// `__<SigHash>` but the format isn't guaranteed, so we do best-effort.
fn extract_v1_type_fragment(body: &str) -> Option<&str> {
    // The body is `<typename>__<hash>`. An anonymous type has an empty
    // `typeToC` part (`NTI__<hash>_`): no fragment, not the hash.
    if let Some(pos) = body.find("__") {
        return body.get(..pos).filter(|frag| !frag.is_empty());
    }
    // Fallback: the entire body is the type name (no hash separator found).
    if !body.is_empty() { Some(body) } else { None }
}

/// Decodes a V1 type fragment (`typeToC` output, `compiler/ccgtypes.nim`)
/// back into a Nim type expression.
///
/// `typeToC` keeps lowercase letters, lowercases uppercase ones, drops
/// spaces, writes `,` as `_`, `.` as `O`, `[({` as `L`, `])}` as `T`, and any
/// other character (digits included) as its decimal code. Because every
/// letter comes out lowercase, `L`, `T` and `O` are unambiguous, and the
/// only characters coded with three digits are `|` (124) and `~` (126).
/// Lost for good: letter case and spaces (re-inserted after `,`, after `:`
/// inside brackets, and before a pragma). The bracket kind is recovered
/// from context: `(` after `proc`, `{` before a pragma's `.`, `[` otherwise.
///
/// ```
/// use nimrod::rtti::symbols::decode_type_fragment;
///
/// assert_eq!(decode_type_fragment("seqLintT"), "seq[int]");
/// assert_eq!(decode_type_fragment("arrayL48OO51_stringT"), "array[0..3, string]");
/// assert_eq!(decode_type_fragment("int5150"), "int32");
/// ```
pub fn decode_type_fragment(fragment: &str) -> String {
    let bytes = fragment.as_bytes();
    let mut out = String::with_capacity(fragment.len().saturating_add(8));
    let mut open: Vec<char> = Vec::new();
    let mut i: usize = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'L' => {
                let opener = if out.ends_with("proc") {
                    '('
                } else if bytes.get(i.saturating_add(1)) == Some(&b'O') {
                    if !out.is_empty() && !out.ends_with(' ') {
                        out.push(' ');
                    }
                    '{'
                } else {
                    '['
                };
                open.push(opener);
                out.push(opener);
            }
            b'T' => out.push(match open.pop() {
                Some('(') => ')',
                Some('{') => '}',
                _ => ']',
            }),
            b'O' => out.push('.'),
            b'_' => out.push_str(", "),
            b'0'..=b'9' => {
                let three = bytes
                    .get(i..i.saturating_add(3))
                    .filter(|d| *d == b"124" || *d == b"126");
                let (code, len) = match three {
                    Some(d) => (
                        std::str::from_utf8(d)
                            .ok()
                            .and_then(|t| t.parse::<u8>().ok()),
                        3,
                    ),
                    None => (
                        bytes
                            .get(i..i.saturating_add(2))
                            .filter(|d| d.iter().all(u8::is_ascii_digit))
                            .and_then(|d| std::str::from_utf8(d).ok())
                            .and_then(|t| t.parse::<u8>().ok())
                            .filter(|c| (32..=99).contains(c)),
                        2,
                    ),
                };
                match code {
                    Some(c) => {
                        // `name: type` in parameter and field lists and
                        // `): result` after a proc's parameters;
                        // `Variant:ObjectType` (the object behind a `ref
                        // object`) has no space.
                        let spaced = c == b':' && (!open.is_empty() || out.ends_with(')'));
                        out.push(char::from(c));
                        if spaced {
                            out.push(' ');
                        }
                        i = i.saturating_add(len);
                        continue;
                    }
                    None => out.push(char::from(b)),
                }
            }
            _ => out.push(char::from(b)),
        }
        i = i.saturating_add(1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_v1_fragment_with_hash() {
        assert_eq!(
            extract_v1_type_fragment("seqLintT__abc123"),
            Some("seqLintT")
        );
    }

    #[test]
    fn decode_real_fragments() {
        // From Nim 1.4 - 2.4 fixture symbol tables.
        for (frag, want) in [
            ("seqLintT", "seq[int]"),
            ("int5150", "int32"),
            ("arrayL48OO51_stringT", "array[0..3, string]"),
            ("variant58objecttype", "variant:objecttype"),
            ("refassertiondefect", "refassertiondefect"),
            (
                "seqLprocLTLOclosure_gcsafeOTT",
                "seq[proc() {.closure, gcsafe.}]",
            ),
            (
                "procLs58stream_buffer58pointer_buflen58intT58intLOnimcall_gcsafeOT",
                "proc(s: stream, buffer: pointer, buflen: int): int {.nimcall, gcsafe.}",
            ),
            (
                "tupleLkey58string_val58intT",
                "tuple[key: string, val: int]",
            ),
            ("set124", "set|"),
        ] {
            assert_eq!(decode_type_fragment(frag), want, "{frag}");
        }
    }

    #[test]
    fn decode_degenerate_fragments() {
        for frag in ["", "T", "TTT", "LLL", "9", "99999", "1", "_", "O"] {
            let _ = decode_type_fragment(frag);
        }
        assert_eq!(decode_type_fragment("TT"), "]]");
        assert_eq!(decode_type_fragment("5"), "5");
    }

    #[test]
    fn anonymous_type_has_no_fragment() {
        assert_eq!(extract_v1_type_fragment("__0zjE9c6eTrq224F5wMcaFA"), None);
    }

    #[test]
    fn extract_v1_fragment_no_hash() {
        assert_eq!(extract_v1_type_fragment("int"), Some("int"));
    }

    #[test]
    fn extract_v1_fragment_empty() {
        assert_eq!(extract_v1_type_fragment(""), None);
    }
}
