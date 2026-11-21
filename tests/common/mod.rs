//! Helpers shared by the integration test crates.
//!
//! Fixtures live under `tests/fixtures/`: the Docker-built version matrix in
//! `nim-<version>/` (`tests/build_fixtures/build_versions.sh`), the
//! `native/` and `mingw/` sets (`tests/build_fixtures/build.sh`), and the
//! upstream nightly release binaries in `nightly/`. A test whose fixture is
//! absent skips rather than fails, so a checkout without fixtures passes.

// Every test crate compiles its own copy of this module and uses a subset
// of it.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The path of fixture `rel`, relative to `tests/fixtures/`.
pub fn fixture_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

/// The bytes of fixture `rel`, or `None` (with a note on stderr) when it is
/// not present.
pub fn fixture(rel: &str) -> Option<Vec<u8>> {
    let data = std::fs::read(fixture_path(rel)).ok();
    if data.is_none() {
        eprintln!("skip: fixture {rel} not present");
    }
    data
}
