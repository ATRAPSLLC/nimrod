//! Fuzzes the demanglers on arbitrary UTF-8: identifier demangling and
//! mangling (and their round trip), symbol parsing under both tie-breaks,
//! the per-table layout vote, and module-path decoding. Run with
//! `cargo fuzz run demangle`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nimrod::demangle::{identifier, modpath, symbol};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let _ = identifier::demangle(s);
    let _ = identifier::mangle(s);
    let _ = symbol::parse(s, None);
    let _ = symbol::parse(s, Some(symbol::MangleScheme::Nim24));
    let _ = symbol::dominant_scheme(s.split(' '));
    let _ = modpath::decode(s);

    // Round-trip: mangle then demangle should not panic.
    let mangled = identifier::mangle(s);
    let _ = identifier::demangle(&mangled);
});
