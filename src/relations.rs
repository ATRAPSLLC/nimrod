//! Nim relations between types and procs.
//!
//! [`build`] lists edges Nim metadata records and machine code does not show
//! as direct calls. A call-graph tool adds them to the calls it decodes.
//!
//! - **Hooks** ([`RelationKind::Hook`]): a type to a proc the runtime calls
//!   for it (destructor, trace proc, GC marker, deep-copy hook, finalizer).
//!   They come from the type's RTTI slots ([`NimType::hooks`]): the
//!   runtime calls them through the type info (`nimDestroyAndDispose`, the
//!   cycle collector, the refc GC), so they are indirect calls. refc
//!   markers are also linked by name (`Marker_<type>__<hash>` shares the
//!   hash of the type's `NTI*__<hash>_` symbol), which works where the RTTI
//!   cannot be read, such as big-endian builds.
//! - **Startup calls** ([`RelationKind::StartupCall`]): the call structure the
//!   code generator always emits (`compiler/cgen.nim`, the same in every
//!   release from 1.0 to 2.4: `genMainProc` and `registerModuleToMain`):
//!
//!   | Caller | Callees |
//!   |---|---|
//!   | `NimMain` | `PreMain`, `NimMainInner` |
//!   | `PreMain` | every `*DatInit000`, the system module's `*Init000`, `PreMainInner` |
//!   | `PreMainInner` | every other module's `*Init000` |
//!   | `NimMainInner` | `NimMainModule` (the main module's init) |
//!
//!   The order of a caller's callees is not recorded anywhere but the code,
//!   so the edges have none. They describe the generated C: an optimising
//!   compiler inlines most init functions into their caller (then the
//!   callee has no symbol and no edge), and may keep a function while
//!   inlining its call. Hot-code-reload builds call module inits through
//!   `hcrInit` and get no edges to them. A shim that appears more than once
//!   (only a crafted symbol table has two `PreMain`s) gives no edges.
//!
//! - **Async procs** ([`RelationKind::Async`]): the `{.async.}` macro turns
//!   `foo` into a proc that creates a closure iterator holding `foo`'s body
//!   and a callback, `fooNimAsyncContinue`, that resumes the iterator
//!   through the closure each time an awaited future completes. The edges
//!   link the three by name ([`AsyncPart`]): `foo` to its iterator
//!   ([`AsyncLink::Body`]) and the callback to the iterator it calls
//!   ([`AsyncLink::Resume`]). A name with more than one candidate (async
//!   procs of one name in modules a pre-1.6 symbol does not tell apart)
//!   links nothing.
//!
//! Method dispatch is not covered: the dispatcher and the methods carry the
//! same name and the RTTI holds no method table, so only code tells them
//! apart.
//!
//! Every edge carries its [`Provenance`]. Identical edges from several
//! sources are merged into the most direct one; edges that disagree are all
//! kept.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    inits::{InitFunction, InitKind},
    procs::{AsyncPart, NimProc, ProcRole},
    rtti::symbols::{RttiSymbol, RttiVersion},
    shims::{EntryShim, ShimKind},
    types::{HookKind, NimType},
};

/// What a [`Relation`] links.
///
/// # Stability
///
/// The string returned by [`as_str`](RelationKind::as_str) /
/// [`Display`](core::fmt::Display) is part of nimrod's stable API. Changes are
/// SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RelationKind {
    /// `from` is a type (its RTTI global's VA), `to` the proc the runtime
    /// calls for it.
    Hook(HookKind),
    /// `from` calls `to` during startup (see the module docs). The order
    /// among one caller's callees is not known.
    StartupCall,
    /// Links the procs of one async proc (see the module docs).
    Async(AsyncLink),
}

/// Which link between the procs of an async proc a [`RelationKind::Async`]
/// is.
///
/// # Stability
///
/// The string returned by [`as_str`](AsyncLink::as_str) /
/// [`Display`](core::fmt::Display) is part of nimrod's stable API. Changes are
/// SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AsyncLink {
    /// `from` is the async proc, `to` the closure iterator holding its body.
    Body,
    /// `from` is the `NimAsyncContinue` callback, `to` the iterator it
    /// resumes through the closure (an indirect call).
    Resume,
}

impl AsyncLink {
    /// Returns the stable string identifier for this link.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Body => "Body",
            Self::Resume => "Resume",
        }
    }
}

impl core::fmt::Display for AsyncLink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RelationKind {
    /// Returns the stable string identifier of the kind's category
    /// (`"Hook"` for every [`RelationKind::Hook`]).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hook(_) => "Hook",
            Self::StartupCall => "StartupCall",
            Self::Async(_) => "Async",
        }
    }
}

/// Writes the category and its detail: `Hook(Destroy)`, `Async(Resume)`,
/// `StartupCall`.
impl core::fmt::Display for RelationKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())?;
        match self {
            Self::Hook(kind) => write!(f, "({kind})"),
            Self::Async(link) => write!(f, "({link})"),
            Self::StartupCall => Ok(()),
        }
    }
}

/// Where a [`Relation`] was read from, most direct first.
///
/// # Stability
///
/// The string returned by [`as_str`](Provenance::as_str) /
/// [`Display`](core::fmt::Display) is part of nimrod's stable API. Changes are
/// SemVer-major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Provenance {
    /// A pointer stored in the file's RTTI.
    Rtti,
    /// A pointer the `DatInit000` functions write into the RTTI at startup,
    /// recovered by evaluating them ([`crate::types::CodeRef::emulated`]).
    Emulated,
    /// Two symbol names the compiler derives from the same source.
    SymbolName,
    /// The code generator's fixed structure, applied to the symbols present.
    Codegen,
}

impl Provenance {
    /// Returns the stable string identifier for this provenance.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rtti => "Rtti",
            Self::Emulated => "Emulated",
            Self::SymbolName => "SymbolName",
            Self::Codegen => "Codegen",
        }
    }
}

impl core::fmt::Display for Provenance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A directed edge between two virtual addresses.
///
/// `from` and `to` are **virtual addresses** in the image's load space: a
/// type's RTTI global ([`NimType::address`]) or a proc ([`NimProc::va`]), as
/// [`kind`](Relation::kind) says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Relation {
    /// What the edge means.
    pub kind: RelationKind,
    /// Source address.
    pub from: u64,
    /// Target address.
    pub to: u64,
    /// Where the edge was read from.
    pub source: Provenance,
}

/// Builds the relations, sorted by kind, then source and target address.
pub fn build(
    procs: &[NimProc],
    shims: &[EntryShim],
    inits: &[InitFunction],
    types: &[NimType],
    rtti: &[RttiSymbol],
) -> Vec<Relation> {
    let mut edges: BTreeMap<(RelationKind, u64, u64), Provenance> = BTreeMap::new();
    let mut add = |kind, from, to, source| {
        edges
            .entry((kind, from, to))
            .and_modify(|best: &mut Provenance| *best = (*best).min(source))
            .or_insert(source);
    };

    for t in types {
        for (kind, r) in t.hooks() {
            let source = if r.emulated {
                Provenance::Emulated
            } else {
                Provenance::Rtti
            };
            add(RelationKind::Hook(kind), t.address, r.address, source);
        }
    }

    // refc markers by name. A hash shared by V1 RTTI symbols at different
    // addresses names no single type and links nothing.
    let mut by_hash: BTreeMap<&str, Option<u64>> = BTreeMap::new();
    for s in rtti.iter().filter(|s| s.version == RttiVersion::V1) {
        if let Some(hash) = rtti_hash(&s.symbol_name) {
            unique(&mut by_hash, hash, s.address);
        }
    }
    for p in procs {
        if p.role != ProcRole::Hook(HookKind::Marker) {
            continue;
        }
        let hash = p.symbol_name.as_deref().and_then(marker_hash);
        if let Some(&Some(ty)) = hash.and_then(|h| by_hash.get(h)) {
            add(
                RelationKind::Hook(HookKind::Marker),
                ty,
                p.va,
                Provenance::SymbolName,
            );
        }
    }

    // One binary has one set of shims; several addresses for a kind (a
    // crafted symbol table) leave the structure unknown, and no cross
    // product is built.
    let shim = |kind| {
        let at: BTreeSet<u64> = shims
            .iter()
            .filter(|s| s.kind == kind)
            .map(|s| s.address)
            .collect();
        only(at.into_iter())
    };
    let pairs = [
        (ShimKind::NimMain, ShimKind::PreMain),
        (ShimKind::NimMain, ShimKind::NimMainInner),
        (ShimKind::PreMain, ShimKind::PreMainInner),
        (ShimKind::NimMainInner, ShimKind::NimMainModule),
    ];
    for (caller, callee) in pairs {
        if let (Some(from), Some(to)) = (shim(caller), shim(callee)) {
            add(RelationKind::StartupCall, from, to, Provenance::Codegen);
        }
    }
    let (pre_main, pre_main_inner) = (shim(ShimKind::PreMain), shim(ShimKind::PreMainInner));
    for f in inits {
        let caller = match f.kind {
            InitKind::DatInit => pre_main,
            InitKind::Init if is_system_module(&f.module_path.path) => pre_main,
            InitKind::Init => pre_main_inner,
            InitKind::HcrInit => None,
        };
        if let Some(from) = caller {
            add(
                RelationKind::StartupCall,
                from,
                f.address,
                Provenance::Codegen,
            );
        }
    }

    // Async procs, by name. `None` marks a name with several candidates.
    let mut iterators: BTreeMap<(&str, Option<&str>), Option<u64>> = BTreeMap::new();
    let mut owners: BTreeMap<(&str, Option<&str>), Option<u64>> = BTreeMap::new();
    let mut owners_any_module: BTreeMap<&str, Option<u64>> = BTreeMap::new();
    for p in procs {
        if p.role == ProcRole::Async(AsyncPart::Iterator)
            && let Some(base) = p.async_base()
        {
            unique(&mut iterators, (base, p.module.as_deref()), p.va);
        } else if p.role == ProcRole::User {
            unique(&mut owners, (p.name.as_str(), p.module.as_deref()), p.va);
            unique(&mut owners_any_module, p.name.as_str(), p.va);
        }
    }
    for c in procs {
        if c.role != ProcRole::Async(AsyncPart::Continuation) {
            continue;
        }
        let Some(base) = c.async_base() else {
            continue;
        };
        // The iterator shares the callback's scope. The async proc shares it
        // too, or is it: Itanium names give the generated procs the async
        // proc as owner, read as their module.
        let scope = c.module.as_deref();
        let Some(&Some(iterator)) = iterators.get(&(base, scope)) else {
            continue;
        };
        add(
            RelationKind::Async(AsyncLink::Resume),
            c.va,
            iterator,
            Provenance::SymbolName,
        );
        let owner = if scope == Some(base) {
            owners_any_module.get(base)
        } else {
            owners.get(&(base, scope))
        };
        if let Some(&Some(owner)) = owner {
            add(
                RelationKind::Async(AsyncLink::Body),
                owner,
                iterator,
                Provenance::SymbolName,
            );
        }
    }

    edges
        .into_iter()
        .map(|((kind, from, to), source)| Relation {
            kind,
            from,
            to,
            source,
        })
        .collect()
}

/// Records `va` under `key`, or marks the key ambiguous (`None`) when it
/// already holds another address.
fn unique<K: Ord>(map: &mut BTreeMap<K, Option<u64>>, key: K, va: u64) {
    map.entry(key)
        .and_modify(|v| {
            if *v != Some(va) {
                *v = None;
            }
        })
        .or_insert(Some(va));
}

/// The single item of `items`, or `None` for none or several.
fn only<T>(mut items: impl Iterator<Item = T>) -> Option<T> {
    let first = items.next()?;
    items.next().is_none().then_some(first)
}

/// The signature hash of a refc marker proc: `Marker_tyRef__<hash>`
/// (`ccgtypes.nim genTraverseProc`: `"Marker_" & getTypeName`).
fn marker_hash(symbol: &str) -> Option<&str> {
    let rest = symbol.strip_prefix("Marker_")?;
    let (_, hash) = rest.rsplit_once("__")?;
    (!hash.is_empty()).then_some(hash)
}

/// The signature hash of a V1 RTTI symbol: `NTI<fragment>__<hash>_`, or
/// `NTI__<hash>_` before 1.6.
fn rtti_hash(symbol: &str) -> Option<&str> {
    let rest = symbol.strip_prefix("NTI")?.strip_suffix('_')?;
    let (_, hash) = rest.rsplit_once("__")?;
    (!hash.is_empty()).then_some(hash)
}

/// Whether an init function's module path is the system module's
/// (`system.nim` directly, or `system` for 1.0 - 1.4 names), whose
/// `Init000` the code generator calls from `PreMain` right after its
/// `DatInit000`. `lib/system/*.nim` are other modules.
fn is_system_module(path: &str) -> bool {
    let file = path.rsplit(['/', '\\']).next().unwrap_or(path);
    file.strip_suffix(".nim").unwrap_or(file) == "system"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{demangle::modpath::ModulePath, types::CodeRef};

    fn shim(kind: ShimKind, address: u64) -> EntryShim {
        EntryShim {
            kind,
            symbol_name: kind.as_str().to_owned(),
            address,
        }
    }

    fn init(kind: InitKind, path: &str, address: u64) -> InitFunction {
        InitFunction {
            kind,
            symbol_name: format!("{path}{kind}000"),
            address,
            module_path: ModulePath {
                path: path.to_owned(),
                prefix: None,
            },
        }
    }

    fn marker(symbol: &str, va: u64) -> NimProc {
        named(symbol, None, ProcRole::Hook(HookKind::Marker), va)
    }

    fn named(name: &str, module: Option<&str>, role: ProcRole, va: u64) -> NimProc {
        NimProc {
            va,
            size: None,
            symbol_name: Some(name.to_owned()),
            name: name.to_owned(),
            module: module.map(str::to_owned),
            role,
            hook_type: None,
        }
    }

    fn rtti(symbol: &str, address: u64) -> RttiSymbol {
        RttiSymbol {
            version: RttiVersion::V1,
            symbol_name: symbol.to_owned(),
            address,
            type_fragment: None,
        }
    }

    fn code_ref(address: u64, emulated: bool) -> CodeRef {
        CodeRef {
            address,
            function: None,
            module: None,
            symbol_name: None,
            emulated,
        }
    }

    fn edges(rels: &[Relation], kind: RelationKind) -> Vec<(u64, u64, Provenance)> {
        rels.iter()
            .filter(|r| r.kind == kind)
            .map(|r| (r.from, r.to, r.source))
            .collect()
    }

    #[test]
    fn hash_extraction() {
        assert_eq!(
            marker_hash("Marker_tyRef__C0A9bPZSVeyr2BWpBf4Jxqw"),
            Some("C0A9bPZSVeyr2BWpBf4Jxqw")
        );
        assert_eq!(marker_hash("Marker_tyRef"), None);
        assert_eq!(marker_hash("tyRef__abc"), None);
        assert_eq!(
            rtti_hash("NTI__C0A9bPZSVeyr2BWpBf4Jxqw_"),
            Some("C0A9bPZSVeyr2BWpBf4Jxqw")
        );
        assert_eq!(
            rtti_hash("NTIrefoverflowdefect__1h7MLAbrCooz5UXE41RUwA_"),
            Some("1h7MLAbrCooz5UXE41RUwA")
        );
        assert_eq!(rtti_hash("NTI__abc"), None, "no trailing underscore");
        assert_eq!(rtti_hash("NTI___"), None, "empty hash");
    }

    #[test]
    fn system_module_paths() {
        assert!(is_system_module("system"));
        assert!(is_system_module("system.nim"));
        assert!(is_system_module("../../opt/nim-1.6.20/lib/system.nim"));
        assert!(is_system_module(r"C:\nim\lib\system.nim"));
        assert!(!is_system_module("system/exceptions.nim"));
        assert!(!is_system_module("stdlib_mix.nim"));
    }

    #[test]
    fn marker_names_join_rtti_by_hash() {
        let procs = [
            marker("Marker_tyRef__AAA", 0x100),
            marker("Marker_tyRef__BBB", 0x200),
            marker("Marker_tyRef__CCC", 0x300),
            marker("Marker_tyRef__EEE", 0x500),
        ];
        let rtti = [
            rtti("NTI__AAA_", 0x9000),
            // Two types sharing a hash link nothing.
            rtti("NTIfoo__BBB_", 0x9100),
            rtti("NTIbar__BBB_", 0x9200),
            // The same symbol listed twice is one type.
            rtti("NTI__EEE_", 0x9300),
            rtti("NTI__EEE_", 0x9300),
        ];
        let rels = build(&procs, &[], &[], &[], &rtti);
        assert_eq!(
            edges(&rels, RelationKind::Hook(HookKind::Marker)),
            [
                (0x9000, 0x100, Provenance::SymbolName),
                (0x9300, 0x500, Provenance::SymbolName),
            ],
            "BBB is ambiguous, CCC has no type"
        );
    }

    #[test]
    fn data_provenance_wins_and_conflicts_stay() {
        let procs = [
            marker("Marker_tyRef__AAA", 0x100),
            marker("Marker_tyRef__DDD", 0x400),
        ];
        let rtti = [rtti("NTI__AAA_", 0x9000), rtti("NTI__DDD_", 0x9400)];
        let mut agree = NimType::synthetic(0x9000);
        agree.marker = Some(code_ref(0x100, true));
        // The RTTI names another marker than the symbol does.
        let mut disagree = NimType::synthetic(0x9400);
        disagree.marker = Some(code_ref(0x500, false));
        let rels = build(&procs, &[], &[], &[agree, disagree], &rtti);
        assert_eq!(
            edges(&rels, RelationKind::Hook(HookKind::Marker)),
            [
                (0x9000, 0x100, Provenance::Emulated),
                (0x9400, 0x400, Provenance::SymbolName),
                (0x9400, 0x500, Provenance::Rtti),
            ]
        );
    }

    #[test]
    fn startup_structure() {
        let shims = [
            shim(ShimKind::NimMain, 0x10),
            shim(ShimKind::NimMainInner, 0x20),
            shim(ShimKind::PreMain, 0x30),
            shim(ShimKind::PreMainInner, 0x40),
            shim(ShimKind::NimMainModule, 0x50),
        ];
        let inits = [
            init(InitKind::DatInit, "system.nim", 0x60),
            init(InitKind::Init, "system.nim", 0x70),
            init(InitKind::DatInit, "system/exceptions.nim", 0x80),
            init(InitKind::Init, "pure/strutils.nim", 0x90),
            init(InitKind::HcrInit, "pure/os.nim", 0xa0),
        ];
        let rels = build(&[], &shims, &inits, &[], &[]);
        let calls: Vec<(u64, u64)> = edges(&rels, RelationKind::StartupCall)
            .into_iter()
            .map(|(f, t, s)| {
                assert_eq!(s, Provenance::Codegen);
                (f, t)
            })
            .collect();
        assert_eq!(
            calls,
            [
                (0x10, 0x20),
                (0x10, 0x30),
                (0x20, 0x50),
                (0x30, 0x40),
                (0x30, 0x60),
                (0x30, 0x70),
                (0x30, 0x80),
                (0x40, 0x90),
            ]
        );
    }

    #[test]
    fn async_procs_link_within_their_scope() {
        let it = ProcRole::Async(AsyncPart::Iterator);
        let cont = ProcRole::Async(AsyncPart::Continuation);
        let procs = [
            // Nim16 / Nim24: all three in the module.
            named("fetch", Some("m"), ProcRole::User, 0x10),
            named("fetch (Async)", Some("m"), it, 0x11),
            named("fetchNimAsyncContinue", Some("m"), cont, 0x12),
            // Itanium: the generated procs are owned by the async proc.
            named("load", Some("m"), ProcRole::User, 0x20),
            named("loadIter", Some("load"), it, 0x21),
            named("loadNimAsyncContinue", Some("load"), cont, 0x22),
            // Two async `get` in modules SigHash names cannot tell apart.
            named("get", None, ProcRole::User, 0x30),
            named("get", None, ProcRole::User, 0x31),
            named("get (Async)", None, it, 0x32),
            named("getNimAsyncContinue", None, cont, 0x33),
            // An iterator in another scope is not this callback's.
            named("put (Async)", Some("a"), it, 0x40),
            named("putNimAsyncContinue", Some("b"), cont, 0x41),
        ];
        let rels = build(&procs, &[], &[], &[], &[]);
        let links: Vec<(RelationKind, u64, u64)> =
            rels.iter().map(|r| (r.kind, r.from, r.to)).collect();
        let body = RelationKind::Async(AsyncLink::Body);
        let resume = RelationKind::Async(AsyncLink::Resume);
        assert_eq!(
            links,
            [
                (body, 0x10, 0x11),
                (body, 0x20, 0x21),
                (resume, 0x12, 0x11),
                (resume, 0x22, 0x21),
                (resume, 0x33, 0x32),
            ],
            "`get` has two owners, `put` no iterator in its scope"
        );
    }

    #[test]
    fn duplicated_shims_give_no_startup_edges() {
        let shims = [
            shim(ShimKind::NimMain, 0x10),
            shim(ShimKind::PreMain, 0x30),
            shim(ShimKind::PreMain, 0x31),
            shim(ShimKind::PreMainInner, 0x40),
        ];
        let inits = [
            init(InitKind::DatInit, "system.nim", 0x60),
            init(InitKind::Init, "pure/strutils.nim", 0x90),
        ];
        let rels = build(&[], &shims, &inits, &[], &[]);
        let calls: Vec<(u64, u64)> = rels.iter().map(|r| (r.from, r.to)).collect();
        assert_eq!(calls, [(0x40, 0x90)], "only PreMainInner is unique");
    }

    #[test]
    fn startup_skips_missing_callers_and_callees() {
        // Inlined: no PreMainInner and no NimMainModule symbol.
        let shims = [
            shim(ShimKind::NimMain, 0x10),
            shim(ShimKind::NimMainInner, 0x20),
            shim(ShimKind::PreMain, 0x30),
        ];
        let inits = [init(InitKind::Init, "pure/strutils.nim", 0x90)];
        let rels = build(&[], &shims, &inits, &[], &[]);
        let calls: Vec<(u64, u64)> = rels.iter().map(|r| (r.from, r.to)).collect();
        assert_eq!(calls, [(0x10, 0x20), (0x10, 0x30)]);
    }
}
