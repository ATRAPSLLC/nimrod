//! Nim symbol-name parser.
//!
//! The C backend names routines and globals from the Nim identifier plus a
//! disambiguating suffix (`compiler/ccgtypes.nim proc fillBackendName`,
//! `compiler/mangleutils.nim proc mangleProcNameExt`, RESEARCH.md §8.2).
//! The layout has changed twice, and debug builds use a fourth one:
//!
//! | Scheme | Compilers | Layout | Example |
//! |---|---|---|---|
//! | [`MangleScheme::SigHash`] | 1.0 - 1.4 | `<ident>__<sighash>[_<n>][<module>]` | `add__8FwY5enLGB0dFerO6Ny9caw` |
//! | [`MangleScheme::Nim16`] | 1.6 - 2.3 | `<ident>__<module>_u<itemId>` | `abs__int128_u714` |
//! | [`MangleScheme::Nim24`] | 2.4+ | `<ident>_u<disamb>__<module>` | `abs_u0__int128` |
//! | [`MangleScheme::Itanium`] | 1.6+, with debug info | `_ZN<owner><name>E<params>` | `_ZN10assertions11raiseAssertE6string` |
//!
//! - **SigHash**: `<sighash>` is the routine's MD5 signature hash in 22
//!   base64 symbols (`A-Z a-z 0-8`, with `9a` `9b` `9c` for 61-63;
//!   `compiler/modulegraphs.nim toBase64a`). A collision counter `_<n>` and,
//!   for inline procs, the current module's name may follow. There is no
//!   module, so [`Demangled::module`] is `None`.
//! - **Nim24**: symbols minted by the incremental-compilation backend use
//!   `_c<n>` in place of `_u<n>` ([`Demangled::backend_minted`]). The number
//!   is a small per-(module, name) `disamb`, not the global `itemId.item`.
//! - **Itanium**: `--debugger:native` / `-g` / `--debuginfo` with the
//!   default `--mangle:cpp` (`ccgutils.nim encodeSym`, `encodeType`). The
//!   owner is the module, or the generic routine itself for a generic
//!   instance (then [`Demangled::module`] is `None`). Parameter types are
//!   decoded into [`Demangled::params`].
//!
//! A few names fit more than one layout (`foo_u3__bar_u5`: identifier
//! `foo_u3` in module `bar` under `Nim16`, or `foo` in module `bar_u5`
//! under `Nim24`). [`parse`] takes the scheme to prefer in such ties, and
//! [`dominant_scheme`] votes over a whole symbol table to find it. The
//! higher-level scans use the per-binary vote through
//! [`crate::container::Container::demangle`].
//!
//! Compiler clone suffixes (`.part.0`, `.cold`, `.constprop.0`, `.isra.0`,
//! `.lto_priv.0`, `.llvm.<n>`) are split off first and reported in
//! [`Demangled::clone_suffix`]; Nim's mangling never emits `.`.

use std::{borrow::Cow, fmt};

use crate::demangle::identifier;

/// Which Nim C-backend naming layout a symbol uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MangleScheme {
    /// Nim 1.0 - 1.4: `<ident>__<sighash>[_<n>][<module>]`.
    SigHash,
    /// Nim 1.6 - 2.3: `<ident>__<module>_u<itemId>`.
    Nim16,
    /// Nim 2.4+: `<ident>_u<disamb>__<module>` (or `_c<n>`).
    Nim24,
    /// Itanium C++ style, used for routines in debug-info builds (1.6+).
    Itanium,
}

impl MangleScheme {
    /// Returns a stable, lowercase identifier for the scheme.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SigHash => "sighash",
            Self::Nim16 => "nim16",
            Self::Nim24 => "nim24",
            Self::Itanium => "itanium",
        }
    }

    /// The Nim compiler releases that emit this layout, as text.
    pub fn compiler_range(&self) -> &'static str {
        match self {
            Self::SigHash => "1.0 - 1.4",
            Self::Nim16 => "1.6 - 2.3",
            Self::Nim24 => "2.4+",
            Self::Itanium => "1.6+ (debug info)",
        }
    }
}

impl fmt::Display for MangleScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed Nim symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Demangled<'a> {
    /// Demangled Nim identifier (inverse of `ccgutils.nim mangle`).
    pub identifier: Cow<'a, str>,
    /// Raw module unique name. May contain `Z`-encoded path separators
    /// (e.g. `OOZdistZchecksumsZsrcZchecksumsZmd5`). `None` where the
    /// layout carries no module ([`MangleScheme::SigHash`], Itanium names
    /// of generic instances).
    pub module: Option<&'a str>,
    /// The numeric disambiguator: `itemId.item` under
    /// [`MangleScheme::Nim16`], the per-(module, name) `disamb` under
    /// [`MangleScheme::Nim24`], the collision counter under
    /// [`MangleScheme::SigHash`] (when present).
    pub disambiguator: Option<u64>,
    /// The base64 signature hash ([`MangleScheme::SigHash`] only).
    pub signature_hash: Option<&'a str>,
    /// Decoded parameter types ([`MangleScheme::Itanium`] only), e.g.
    /// `["var[string]", "int64"]`.
    pub params: Option<Vec<String>>,
    /// The layout the symbol was parsed as. `None` for the bare
    /// `<ident>__<module>` form, which carries no layout information.
    pub scheme: Option<MangleScheme>,
    /// `true` for the 2.4 `_c<n>` form (a symbol minted by the
    /// incremental-compilation backend rather than by semantic analysis).
    pub backend_minted: bool,
    /// Compiler clone suffix split off the symbol, including its leading
    /// dot (e.g. `.part.0`, `.cold`, `.constprop.0`).
    pub clone_suffix: Option<&'a str>,
    /// The raw mangled identifier, without disambiguator or module.
    pub raw_identifier: &'a str,
}

impl Demangled<'_> {
    /// Whether the name was recognised as a compiler-generated routine or
    /// global name (any [`MangleScheme`]), as opposed to the bare
    /// `<ident>__<module>` form.
    pub fn is_scheme_name(&self) -> bool {
        self.scheme.is_some()
    }
}

/// Parses a Nim symbol name.
///
/// `prefer` is the layout to choose when the name fits more than one (see
/// the module docs): the binary's dominant scheme, as
/// [`crate::container::Container::demangle`] passes it, or `None` without
/// such context, which breaks ties toward [`MangleScheme::Nim16`] (the
/// layout of Nim 1.6 - 2.3). A name that fits one layout parses as that
/// layout whatever `prefer` says.
///
/// Returns `None` if the symbol matches no layout and not the bare
/// `<ident>__<module>` form.
///
/// # Examples
///
/// ```
/// use nimrod::demangle::symbol::{parse, MangleScheme};
///
/// let d = parse("genNimMainInner__cgen_u41496", None).unwrap();
/// assert_eq!(&*d.identifier, "genNimMainInner");
/// assert_eq!(d.module, Some("cgen"));
/// assert_eq!(d.disambiguator, Some(41496));
/// assert_eq!(d.scheme, Some(MangleScheme::Nim16));
///
/// let d = parse("parseInt_u3__pureZstrutils", None).unwrap();
/// assert_eq!((&*d.identifier, d.module), ("parseInt", Some("pureZstrutils")));
/// assert_eq!(d.scheme, Some(MangleScheme::Nim24));
///
/// let d = parse("add__8FwY5enLGB0dFerO6Ny9caw", None).unwrap();
/// assert_eq!((&*d.identifier, d.module), ("add", None));
/// assert_eq!(d.scheme, Some(MangleScheme::SigHash));
///
/// let d = parse("_ZN11digitsutils6addIntE3varI6stringE5int64", None).unwrap();
/// assert_eq!((&*d.identifier, d.module), ("addInt", Some("digitsutils")));
/// assert_eq!(d.params.as_deref(), Some(&["var[string]".to_owned(), "int64".to_owned()][..]));
/// ```
pub fn parse(symbol: &str, prefer: Option<MangleScheme>) -> Option<Demangled<'_>> {
    let preferred = prefer.unwrap_or(MangleScheme::Nim16);
    let (base, clone_suffix) = split_clone_suffix(symbol);
    if let Some(mut d) = parse_itanium(base) {
        d.clone_suffix = clone_suffix;
        return Some(d);
    }
    let (raw_ident, suffix) = rightmost_split(base)?;
    let candidates = candidates(raw_ident, suffix);
    let pick = candidates
        .iter()
        .flatten()
        .find(|c| c.scheme == Some(preferred))
        .or_else(|| candidates.iter().flatten().next());

    let split = match pick {
        Some(c) => c.clone(),
        None => Split {
            raw_ident,
            module: Some(suffix),
            disambiguator: None,
            signature_hash: None,
            scheme: None,
            backend_minted: false,
        },
    };

    Some(Demangled {
        identifier: identifier::demangle(split.raw_ident),
        module: split.module,
        disambiguator: split.disambiguator,
        signature_hash: split.signature_hash,
        params: None,
        scheme: split.scheme,
        backend_minted: split.backend_minted,
        clone_suffix,
        raw_identifier: split.raw_ident,
    })
}

/// Votes on the layout used by a symbol table.
///
/// Counts the names that fit exactly one of the non-debug layouts
/// ([`MangleScheme::SigHash`], [`MangleScheme::Nim16`],
/// [`MangleScheme::Nim24`]) and returns the one with most votes; ties give
/// `None`. refc's `Marker_` procs do not vote: every version names them in
/// the signature-hash style. Debug-info builds name routines in the Itanium style but keep
/// one of the other layouts for globals and helpers, so
/// [`MangleScheme::Itanium`] is returned only when no other layout voted
/// and at least one Itanium name was seen.
///
/// ```
/// use nimrod::demangle::symbol::{dominant_scheme, MangleScheme};
///
/// let names = ["abs_u0__int128", "add_u2__system", "main", "foo_u3__bar_u5"];
/// assert_eq!(dominant_scheme(names), Some(MangleScheme::Nim24));
/// ```
pub fn dominant_scheme<'a, I>(names: I) -> Option<MangleScheme>
where
    I: IntoIterator<Item = &'a str>,
{
    // SigHash, Nim16, Nim24
    let mut votes = [0usize; 3];
    let mut itanium: usize = 0;
    for name in names {
        let (base, _) = split_clone_suffix(name);
        if parse_itanium(base).is_some() {
            itanium = itanium.saturating_add(1);
            continue;
        }
        let Some((raw_ident, suffix)) = rightmost_split(base) else {
            continue;
        };
        // refc's GC marker procs keep the signature-hash naming in every
        // release, so they say nothing about the compiler version (in a 1.6
        // refc debug build they tied with the genuine 1.6 names).
        if raw_ident.starts_with(VERSIONLESS_PREFIX) {
            continue;
        }
        let [s, l, n] = candidates(raw_ident, suffix);
        let hits = [s.is_some(), l.is_some(), n.is_some()];
        if hits.iter().filter(|&&h| h).count() == 1
            && let Some(i) = hits.iter().position(|&h| h)
            && let Some(v) = votes.get_mut(i)
        {
            *v = v.saturating_add(1);
        }
    }
    let max = votes.iter().copied().max().unwrap_or(0);
    if max == 0 {
        return (itanium > 0).then_some(MangleScheme::Itanium);
    }
    if votes.iter().filter(|&&v| v == max).count() > 1 {
        return None;
    }
    match votes.iter().position(|&v| v == max) {
        Some(0) => Some(MangleScheme::SigHash),
        Some(1) => Some(MangleScheme::Nim16),
        Some(2) => Some(MangleScheme::Nim24),
        _ => None,
    }
}

/// Identifier prefix of names emitted in the signature-hash style by every
/// compiler version (`Marker_tyRef__<hash>`, refc GC marker procs).
const VERSIONLESS_PREFIX: &str = "Marker_";

/// Splits a compiler clone suffix (`foo.part.0` -> `foo`, `.part.0`).
fn split_clone_suffix(symbol: &str) -> (&str, Option<&str>) {
    match symbol.find('.') {
        Some(pos) if pos > 0 => (
            symbol.get(..pos).unwrap_or(symbol),
            symbol.get(pos..).filter(|s| s.len() > 1),
        ),
        _ => (symbol, None),
    }
}

/// One reading of a `<raw_ident>__<suffix>` name under a layout: the parts
/// [`Demangled`] is built from.
#[derive(Clone)]
struct Split<'a> {
    /// The identifier as mangled (before [`identifier::demangle`]).
    raw_ident: &'a str,
    /// The module part (`None` for signature-hash names).
    module: Option<&'a str>,
    /// The `_u<n>` / `_c<n>` id, or a signature-hash name's `_<n>` counter.
    disambiguator: Option<u64>,
    /// The 22-symbol signature hash (Nim 1.0 - 1.4).
    signature_hash: Option<&'a str>,
    /// The layout this reading assumes (`None`: the bare `<ident>__<module>`
    /// form).
    scheme: Option<MangleScheme>,
    /// Whether the id is a `_c<n>` (backend-minted, Nim 2.4+).
    backend_minted: bool,
}

/// The readings of `<raw_ident>__<suffix>` under `[SigHash, Nim16, Nim24]`.
fn candidates<'a>(raw_ident: &'a str, suffix: &'a str) -> [Option<Split<'a>>; 3] {
    let sighash = sighash_suffix(suffix)
        // `TM__<hash>_<n>` are the C backend's literal temporaries, not
        // routines; their hash has the same shape.
        .filter(|_| raw_ident != "TM")
        .map(|(hash, counter, _inline_module)| Split {
            raw_ident,
            module: None,
            disambiguator: counter,
            signature_hash: Some(hash),
            scheme: Some(MangleScheme::SigHash),
            backend_minted: false,
        });
    let nim16 = nim16_suffix(suffix).map(|(module, id)| Split {
        raw_ident,
        module: Some(module),
        disambiguator: Some(id),
        signature_hash: None,
        scheme: Some(MangleScheme::Nim16),
        backend_minted: false,
    });
    let nim24 = nim24_ident(raw_ident)
        .filter(|_| is_valid_module_name(suffix))
        .map(|(ident, id, backend_minted)| Split {
            raw_ident: ident,
            module: Some(suffix),
            disambiguator: Some(id),
            signature_hash: None,
            scheme: Some(MangleScheme::Nim24),
            backend_minted,
        });
    [sighash, nim16, nim24]
}

/// Finds the rightmost `__` such that the identifier part is non-empty and
/// the right-hand side is a plausible suffix for some layout.
///
/// A trailing `_` on the identifier (the substitution marker from `mangle`)
/// makes the separator look like `___`; scanning from the right picks the
/// last two underscores, leaving the marker on the identifier.
fn rightmost_split(symbol: &str) -> Option<(&str, &str)> {
    let bytes = symbol.as_bytes();
    // At least `X__Y`.
    if bytes.len() < 4 {
        return None;
    }
    let start = bytes.len().saturating_sub(2);
    for i in (1..=start).rev() {
        if bytes.get(i) != Some(&b'_') || bytes.get(i.saturating_add(1)) != Some(&b'_') {
            continue;
        }
        let raw_ident = symbol.get(..i).unwrap_or("");
        let suffix = symbol.get(i.saturating_add(2)..).unwrap_or("");
        if raw_ident.is_empty() || suffix.is_empty() {
            continue;
        }
        if nim16_suffix(suffix).is_some() || is_valid_module_name(suffix) {
            return Some((raw_ident, suffix));
        }
    }
    None
}

/// Parses a 1.0 - 1.4 signature-hash suffix into `(hash, counter,
/// inline_module)`.
///
/// The hash is exactly 22 base64 symbols from `A-Z a-z 0-8` or the escapes
/// `9a` `9b` `9c`. It encodes 16 bytes, so the last symbol holds only two
/// bits (`(a and 3) shl 4`) and must be `A`, `Q`, `g` or `w`.
fn sighash_suffix(suffix: &str) -> Option<(&str, Option<u64>, Option<&str>)> {
    let bytes = suffix.as_bytes();
    let mut pos: usize = 0;
    let mut last = 0u8;
    for _ in 0..22 {
        let b = *bytes.get(pos)?;
        if b == b'9' {
            if !matches!(bytes.get(pos.saturating_add(1)), Some(b'a' | b'b' | b'c')) {
                return None;
            }
            last = b'9';
            pos = pos.saturating_add(2);
        } else if b.is_ascii_alphabetic() || (b'0'..=b'8').contains(&b) {
            last = b;
            pos = pos.saturating_add(1);
        } else {
            return None;
        }
    }
    if !matches!(last, b'A' | b'Q' | b'g' | b'w') {
        return None;
    }
    let hash = suffix.get(..pos)?;
    let mut rest = suffix.get(pos..)?;

    let mut counter = None;
    if let Some(after) = rest.strip_prefix('_') {
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        counter = after.get(..digits)?.parse().ok();
        rest = after.get(digits..)?;
    }
    let inline_module = if rest.is_empty() {
        None
    } else if is_valid_module_name(rest)
        && rest.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
    {
        Some(rest)
    } else {
        return None;
    };
    Some((hash, counter, inline_module))
}

/// Parses the 1.6 - 2.3 `<module>_u<id>` suffix. The digits may be followed
/// by a hot-code-reloading signature (`_<hash>`), which is ignored.
fn nim16_suffix(suffix: &str) -> Option<(&str, u64)> {
    let pos = suffix.rfind("_u")?;
    let after_u = suffix.get(pos.saturating_add(2)..)?;
    let digit_end = after_u
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(after_u.len());
    if digit_end == 0 {
        return None;
    }
    let rest = after_u.get(digit_end..)?;
    if !rest.is_empty() && !rest.starts_with('_') {
        return None;
    }
    let id: u64 = after_u.get(..digit_end)?.parse().ok()?;
    let module = suffix.get(..pos)?;
    is_valid_module_name(module).then_some((module, id))
}

/// Parses a 2.4 `<ident>_u<disamb>` / `<ident>_c<n>` identifier part into
/// `(ident, number, backend_minted)`.
fn nim24_ident(raw: &str) -> Option<(&str, u64, bool)> {
    let digit_start = raw
        .bytes()
        .rposition(|b| !b.is_ascii_digit())
        .map_or(0, |p| p.saturating_add(1));
    if digit_start == raw.len() {
        return None;
    }
    let marker_start = digit_start.checked_sub(2)?;
    let marker = raw.get(marker_start..digit_start)?;
    let backend_minted = match marker {
        "_u" => false,
        "_c" => true,
        _ => return None,
    };
    let ident = raw.get(..marker_start)?;
    if ident.is_empty() {
        return None;
    }
    let id: u64 = raw.get(digit_start..)?.parse().ok()?;
    Some((ident, id, backend_minted))
}

/// Quick validity check for a module name. Module names are mangled
/// identifiers containing alphanumeric chars, underscores, and `Z`
/// (used as path separator encoding in `mangleModuleName`).
fn is_valid_module_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

// ---- Itanium ----

/// Most nesting the Itanium type decoder follows before giving up.
const MAX_TYPE_DEPTH: usize = 16;

/// Parses `_ZN<owner><name>E<params>` as emitted by `ccgutils.nim encodeSym`
/// / `encodeType`.
fn parse_itanium(symbol: &str) -> Option<Demangled<'_>> {
    let mut cur = Cursor { s: symbol, pos: 0 };
    cur.expect("_ZN")?;
    let owner = cur.name()?;
    let name = cur.name()?;
    cur.expect("E")?;

    let mut params = Vec::new();
    while cur.pos < symbol.len() {
        if cur.rest().starts_with("_s") {
            // `staticLists`: rendered static arguments; not decoded.
            break;
        }
        params.push(cur.ty(0)?);
    }

    // With `makeUnique` the name itself carries a Nim16/Nim24 suffix.
    let (raw_ident, disambiguator, inner_module) =
        match rightmost_split(name).map(|(ident, suffix)| (ident, candidates(ident, suffix))) {
            Some((_, [_, Some(l), _])) => (l.raw_ident, l.disambiguator, l.module),
            Some((_, [_, _, Some(n)])) => (n.raw_ident, n.disambiguator, n.module),
            _ => (name, None, None),
        };
    let module = inner_module.or((owner != name).then_some(owner));

    Some(Demangled {
        identifier: identifier::demangle(raw_ident),
        module,
        disambiguator,
        signature_hash: None,
        params: Some(params),
        scheme: Some(MangleScheme::Itanium),
        backend_minted: false,
        clone_suffix: None,
        raw_identifier: raw_ident,
    })
}

/// A forward reader over an Itanium mangled name.
struct Cursor<'a> {
    /// The whole name.
    s: &'a str,
    /// Byte offset of the next unread character.
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// The unread remainder.
    fn rest(&self) -> &'a str {
        self.s.get(self.pos..).unwrap_or("")
    }

    /// Consumes `lit` if the remainder starts with it.
    fn expect(&mut self, lit: &str) -> Option<()> {
        self.rest().starts_with(lit).then(|| {
            self.pos = self.pos.saturating_add(lit.len());
        })
    }

    /// `<decimal length><bytes>`.
    fn name(&mut self) -> Option<&'a str> {
        let rest = self.rest();
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 || rest.starts_with('0') {
            return None;
        }
        let len: usize = rest.get(..digits)?.parse().ok()?;
        let start = self.pos.checked_add(digits)?;
        let end = start.checked_add(len)?;
        let name = self.s.get(start..end)?;
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return None;
        }
        self.pos = end;
        Some(name)
    }

    /// One encoded type: `N<owner><name>E`, or `<name>` optionally followed
    /// by `I<type>*E`.
    fn ty(&mut self, depth: usize) -> Option<String> {
        if depth > MAX_TYPE_DEPTH {
            return None;
        }
        if self.expect("N").is_some() {
            let owner = self.name()?;
            let name = self.name()?;
            self.expect("E")?;
            return Some(format!("{owner}.{}", identifier::demangle(name)));
        }
        let name = identifier::demangle(self.name()?).into_owned();
        if self.expect("I").is_none() {
            return Some(name);
        }
        let mut args = Vec::new();
        while self.expect("E").is_none() {
            if self.pos >= self.s.len() {
                return None;
            }
            args.push(self.ty(depth.saturating_add(1))?);
        }
        Some(format!("{name}[{}]", args.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Option<MangleScheme> = Some(MangleScheme::SigHash);
    const L: Option<MangleScheme> = Some(MangleScheme::Nim16);
    const N: Option<MangleScheme> = Some(MangleScheme::Nim24);
    const I: Option<MangleScheme> = Some(MangleScheme::Itanium);

    fn check(
        sym: &str,
        ident: &str,
        module: Option<&str>,
        id: Option<u64>,
        scheme: Option<MangleScheme>,
    ) {
        let d = parse(sym, None).unwrap_or_else(|| panic!("failed to parse {sym}"));
        assert_eq!(&*d.identifier, ident, "identifier of {sym}");
        assert_eq!(d.module, module, "module of {sym}");
        assert_eq!(d.disambiguator, id, "disambiguator of {sym}");
        assert_eq!(d.scheme, scheme, "scheme of {sym}");
    }

    // ---- 1.0 - 1.4 signature hash ----

    #[test]
    fn sighash_symbols() {
        // Real names from Nim 1.0.10 / 1.2.18 / 1.4.8 fixture builds.
        check("add__8FwY5enLGB0dFerO6Ny9caw", "add", None, None, S);
        check(
            "allocImpl__KzdpcuLT9aef9bsiSHlIu9aFg_2",
            "allocImpl",
            None,
            Some(2),
            S,
        );
        check(
            "genericAssignAux__69cRBG8C28ydeYlu49a9aOJCQ",
            "genericAssignAux",
            None,
            None,
            S,
        );
        check(
            "Marker_tyRef__dJLgQyYmAVYQWHiOSBBTyA",
            "Marker_tyRef",
            None,
            None,
            S,
        );
        check(
            "murmurHash__CiCiZV9c7F9alrF1xV3QD1ag",
            "murmurHash",
            None,
            None,
            S,
        );
        let d = parse("decRef__AT1eRuflKWyTTBdLjEDZbgsystem.part.0", None).unwrap();
        assert_eq!((&*d.identifier, d.scheme), ("decRef", S));
        assert_eq!(d.signature_hash, Some("AT1eRuflKWyTTBdLjEDZbg"));
        assert_eq!(d.clone_suffix, Some(".part.0"));
    }

    #[test]
    fn sighash_shape_is_exact() {
        // 21 symbols, `_` without a counter, bad final symbol, bad escape.
        for sym in [
            "add__8FwY5enLGB0dFerO6Ny9ca",
            "add__8FwY5enLGB0dFerO6Ny9caw_",
            "add__8FwY5enLGB0dFerO6Ny9cab",
            "add__8FwY5enLGB0dFerO6Ny9daw",
        ] {
            assert_ne!(parse(sym, None).and_then(|d| d.scheme), S, "{sym}");
        }
    }

    #[test]
    fn literal_temporaries_are_not_routines() {
        let d = parse("TM__5k6IkY2vlXKD249ajWmt9brg_11", None).unwrap();
        assert_eq!(d.scheme, None);
        assert!(!d.is_scheme_name());
    }

    // ---- 1.6 - 2.3 ----

    #[test]
    fn nim16_symbols() {
        check(
            "genNimMainInner__cgen_u41496",
            "genNimMainInner",
            Some("cgen"),
            Some(41496),
            L,
        );
        check("amp___docgen_u11299", "&", Some("docgen"), Some(11299), L);
        check(
            "ampeq___sighashes_u12",
            "&=",
            Some("sighashes"),
            Some(12),
            L,
        );
        check(
            "colonanonymous___cgen_u4206",
            ":anonymous",
            Some("cgen"),
            Some(4206),
            L,
        );
        check(
            "colonOrEquals__parser_u350",
            "colonOrEquals",
            Some("parser"),
            Some(350),
            L,
        );
        check(
            "FF__OOZdistZchecksumsZsrcZchecksumsZmd5_u42",
            "FF",
            Some("OOZdistZchecksumsZsrcZchecksumsZmd5"),
            Some(42),
            L,
        );
        check(
            "GC_getStatistics__system_u7819",
            "GC_getStatistics",
            Some("system"),
            Some(7819),
            L,
        );
        check("foo__bar_u12_abc123", "foo", Some("bar"), Some(12), L);
    }

    // ---- 2.4 ----

    #[test]
    fn nim24_symbols() {
        check("abs_u0__int128", "abs", Some("int128"), Some(0), N);
        check(
            "absolutePath_u0__stdZprivateZospaths2",
            "absolutePath",
            Some("stdZprivateZospaths2"),
            Some(0),
            N,
        );
        check("dollar__u2__system", "$", Some("system"), Some(2), N);
        check(
            "colonanonymous__u7__cgen",
            ":anonymous",
            Some("cgen"),
            Some(7),
            N,
        );
        check("foo_u3_u1__mod", "foo_u3", Some("mod"), Some(1), N);
        let d = parse("readAll_c4__system", None).unwrap();
        assert!(d.backend_minted);
        assert_eq!((d.disambiguator, d.scheme), (Some(4), N));
    }

    // ---- Itanium ----

    #[test]
    fn itanium_symbols() {
        // Real names from a Nim 1.6.20 `--debugger:native` build.
        let d = parse("_ZN10assertions11raiseAssertE6string", None).unwrap();
        assert_eq!(
            (&*d.identifier, d.module, d.scheme),
            ("raiseAssert", Some("assertions"), I)
        );
        assert_eq!(d.params, Some(vec!["string".to_owned()]));

        let d = parse(
            "_ZN10stdlib_mix15colonanonymous_E5tupleI6string3intE5tupleI6string3intE",
            None,
        )
        .unwrap();
        assert_eq!(
            (&*d.identifier, d.module),
            (":anonymous", Some("stdlib_mix"))
        );
        assert_eq!(
            d.params,
            Some(vec![
                "tuple[string, int]".to_owned(),
                "tuple[string, int]".to_owned()
            ])
        );

        // Generic instance: the owner is the generic routine, no module.
        let d = parse(
            "_ZN11ctRawInsert11ctRawInsertE10CountTableI6stringE3varI3seqI5tupleI6string3intEEE6string3int",
            None,
        )
        .unwrap();
        assert_eq!((&*d.identifier, d.module), ("ctRawInsert", None));
        assert_eq!(
            d.params.as_deref(),
            Some(
                &[
                    "CountTable[string]".to_owned(),
                    "var[seq[tuple[string, int]]]".to_owned(),
                    "string".to_owned(),
                    "int".to_owned(),
                ][..]
            )
        );

        // No parameters, object type parameter, makeUnique name, clone.
        assert_eq!(
            parse("_ZN6system4quitE", None).unwrap().params,
            Some(vec![])
        );
        let d = parse("_ZN4json7newJIntEN4json8JsonNodeE", None).unwrap();
        assert_eq!(d.params, Some(vec!["json.JsonNode".to_owned()]));
        let d = parse("_ZN6system16foo_u3__mymoduleE3int.cold", None).unwrap();
        assert_eq!(
            (&*d.identifier, d.module, d.disambiguator),
            ("foo", Some("mymodule"), Some(3))
        );
        assert_eq!(d.clone_suffix, Some(".cold"));
    }

    #[test]
    fn itanium_rejects_malformed() {
        for sym in [
            "_Z",
            "_ZN",
            "_ZN6system",
            "_ZN6system4quit",
            "_ZN99system4quitE",
            "_ZN06system4quitE",
            "_ZN6system4quitE3varI3int",
            "_ZN6syst-m4quitE",
            "_ZNSt6vectorIiE9push_backERKi",
        ] {
            assert!(parse(sym, None).is_none_or(|d| d.scheme != I), "{sym}");
        }
    }

    #[test]
    fn itanium_depth_is_bounded() {
        let mut sym = String::from("_ZN1a1bE");
        for _ in 0..64 {
            sym.push_str("3seqI");
        }
        sym.push_str("3int");
        for _ in 0..64 {
            sym.push('E');
        }
        assert!(parse(&sym, None).is_none());
    }

    // ---- ambiguity and per-binary preference ----

    #[test]
    fn ambiguous_name_follows_preference() {
        let sym = "foo_u3__bar_u5";
        let l = parse(sym, Some(MangleScheme::Nim16)).unwrap();
        assert_eq!(
            (&*l.identifier, l.module, l.disambiguator),
            ("foo_u3", Some("bar"), Some(5))
        );
        let n = parse(sym, Some(MangleScheme::Nim24)).unwrap();
        assert_eq!(
            (&*n.identifier, n.module, n.disambiguator),
            ("foo", Some("bar_u5"), Some(3))
        );
        assert_eq!(parse(sym, None).unwrap(), l);
    }

    #[test]
    fn unambiguous_names_ignore_preference() {
        for pref in [
            MangleScheme::SigHash,
            MangleScheme::Nim16,
            MangleScheme::Nim24,
            MangleScheme::Itanium,
        ] {
            assert_eq!(parse("abs__int128_u714", Some(pref)).unwrap().scheme, L);
            assert_eq!(parse("abs_u0__int128", Some(pref)).unwrap().scheme, N);
            assert_eq!(
                parse("add__8FwY5enLGB0dFerO6Ny9caw", Some(pref))
                    .unwrap()
                    .scheme,
                S
            );
            assert_eq!(parse("_ZN6system4quitE", Some(pref)).unwrap().scheme, I);
        }
    }

    #[test]
    fn dominant_scheme_votes() {
        let nim16 = [
            "abs__int128_u714",
            "add__system_u2",
            "main",
            "foo_u3__bar_u5",
        ];
        assert_eq!(dominant_scheme(nim16), L);
        let nim24 = [
            "abs_u0__int128",
            "add_u2__system",
            "printf",
            "foo_u3__bar_u5",
        ];
        assert_eq!(dominant_scheme(nim24), N);
        let sighash = [
            "add__8FwY5enLGB0dFerO6Ny9caw",
            "TM__5k6IkY2vlXKD249ajWmt9brg_11",
        ];
        assert_eq!(dominant_scheme(sighash), S);
        // Debug build: Itanium routines, Nim24 globals -> Nim24.
        let debug = ["_ZN6system4quitE", "_ZN6system4echoE", "gEnv_u0__system"];
        assert_eq!(dominant_scheme(debug), N);
        assert_eq!(dominant_scheme(["_ZN6system4quitE", "main"]), I);
        // Marker procs keep the signature-hash style in every version.
        let nim16_refc = [
            "Marker_tyRef__3zg5FDH1W2wydWVnUWPMkA",
            "Marker_tyRef__4akRIEfHuYJ9by9cHv0TUmOg",
            "currException__system_u2566",
        ];
        assert_eq!(dominant_scheme(nim16_refc), L);
        assert_eq!(dominant_scheme(["foo_u3__bar_u5", "main"]), None);
        assert_eq!(dominant_scheme(["abs_u0__int128", "add__system_u2"]), None);
        assert_eq!(dominant_scheme(std::iter::empty()), None);
    }

    // ---- shared behaviour ----

    #[test]
    fn bare_form_has_no_scheme() {
        check(
            "NimStrlitFlag__system",
            "NimStrlitFlag",
            Some("system"),
            None,
            None,
        );
        check("foo__my_utils", "foo", Some("my_utils"), None, None);
        assert_eq!(parse("foo__bar_u12x", None).unwrap().scheme, None);
    }

    #[test]
    fn clone_suffixes_are_split_off() {
        for (sym, suffix) in [
            ("acceptsAllTypes_u0__concepts.part.0", ".part.0"),
            ("eval_u2__vm.cold", ".cold"),
            ("raiseExceptionEx__system_u4810.constprop.0", ".constprop.0"),
            (
                "rawNewObj__ehkAaLROrd0Hc9aLROWt1nQ.constprop.0",
                ".constprop.0",
            ),
            ("foo_u1__bar.lto_priv.0", ".lto_priv.0"),
        ] {
            let d = parse(sym, None).unwrap_or_else(|| panic!("failed to parse {sym}"));
            assert_eq!(d.clone_suffix, Some(suffix), "{sym}");
            assert!(d.is_scheme_name(), "{sym}");
        }
    }

    #[test]
    fn rejects_non_nim() {
        for sym in [
            "main",
            "_start",
            "printf",
            "__libc_start_main",
            "__do_global_dtors_aux",
        ] {
            assert!(parse(sym, None).is_none(), "{sym}");
        }
    }

    #[test]
    fn rejects_degenerate_input() {
        for sym in [
            "", "_", "__", "___", "foo__", "__foo", ".part.0", "_u1__", "a__.cold",
        ] {
            assert!(parse(sym, None).is_none(), "{sym:?}");
        }
    }
}
