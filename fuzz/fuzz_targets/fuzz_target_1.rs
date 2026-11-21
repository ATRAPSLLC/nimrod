//! Fuzzes the whole binary pipeline: parsing, detection, and every scan
//! accessor of [`NimBinary`] on arbitrary input (up to 1 MiB). Inputs that
//! do not parse or do not detect as Nim stop early; the rest must run every
//! scan without panicking. Run with `cargo fuzz run fuzz_target_1`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nimrod::NimBinary;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }

    let Ok(bin) = NimBinary::from_bytes(data) else {
        return;
    };

    let _ = bin.format();
    let _ = bin.arch();
    let _ = bin.detection_matches();

    if !bin.is_nim() {
        return;
    }

    let _ = bin.gc_mode();
    let _ = bin.nim_main_prefix();
    let _ = bin.entry_shims();
    let _ = bin.init_functions();
    let _ = bin.rtti_symbols();
    let _ = bin.exception_types();
    let _ = bin.stack_trace();
    let _ = bin.nimble_paths();
    let _ = bin.string_literals_v2();
    let _ = bin.string_literals_v1();
    let _ = bin.raise_sites();
    let _ = bin.module_map();
    let _ = bin.nim_version();
    let _ = bin.mangle_scheme();
    let _ = bin.build_profile();
    let _ = bin.string_literals_v3();
    // Runs the startup-code evaluation when RTTI is left zero in the file.
    let _ = bin.types();
    let _ = bin.procs();
    let _ = bin.relations();
});
