#![cfg(target_os = "linux")]

//! Tripwire for bd-7s4j33: unit tests inside `src/malloc_abi.rs` can never run.
//!
//! `pub mod malloc_abi` is declared `#[cfg(not(test))]` in `lib.rs`, because the module
//! exports `#[no_mangle]` `malloc`/`free`/`memcpy`/`strlen` that would shadow the system
//! allocator inside a test binary and deadlock it. That gate is correct — but it also
//! excludes the whole module from the `--lib` test target, so a `#[cfg(test)] mod tests`
//! written there is compiled out and **silently never executes**.
//!
//! Two tests lived in exactly that position until 2026-07-26 and had never once run;
//! `cargo test -p frankenlibc-abi --lib` reported success without executing either. This
//! is the same failure class the perf campaign's V3 criterion exists to catch ("the bench
//! never executed the code under test"), except in the test suite rather than the bench
//! suite — which is worse, because a green test run is exactly what people trust.
//!
//! Nothing in the language stops it recurring: the mistake produces no warning, no error,
//! and a passing run. So it needs an external check, which is this file.

use std::path::Path;

/// Modules gated out of the lib test target. A `#[cfg(test)]` block in any of these is
/// dead code that will never execute — its tests belong in `tests/`.
const CFG_NOT_TEST_MODULES: &[&str] = &["src/malloc_abi.rs"];

#[test]
fn cfg_not_test_modules_contain_no_unit_tests() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));

    for rel in CFG_NOT_TEST_MODULES {
        let path = crate_root.join(rel);
        let read = std::fs::read_to_string(&path);
        assert!(
            read.is_ok(),
            "cannot read {}: {:?}",
            path.display(),
            read.as_ref().err()
        );
        let src = read.unwrap_or_default();

        let mut offenders = Vec::new();
        for (idx, line) in src.lines().enumerate() {
            let trimmed = line.trim_start();
            // Only attributes, not the word appearing inside a comment or doc block.
            if trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("#[cfg(all(test") {
                offenders.push(idx + 1);
            }
        }

        assert!(
            offenders.is_empty(),
            "{rel} is gated `#[cfg(not(test))]` in lib.rs, so it is excluded from the \
             --lib test target. A `#[cfg(test)]` block here is compiled out and will \
             NEVER RUN, while `cargo test --lib` still reports success.\n\
             Offending line(s): {offenders:?}\n\
             Put the test in crates/frankenlibc-abi/tests/malloc_abi_test.rs instead, \
             adding a `#[doc(hidden)] pub` hook if it needs a private item. (bd-7s4j33)"
        );
    }
}

/// The guard is only meaningful while the `#[cfg(not(test))]` gate is actually present.
/// If someone removes the gate, unit tests in that module would start running and this
/// tripwire should be retired deliberately rather than left asserting something vacuous.
#[test]
fn lib_rs_still_gates_the_module_out_of_the_test_target() {
    let lib = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let src = std::fs::read_to_string(&lib).expect("cannot read src/lib.rs");

    let gated = src
        .lines()
        .zip(src.lines().skip(1))
        .any(|(a, b)| a.trim() == "#[cfg(not(test))]" && b.trim_start().contains("mod malloc_abi"));

    assert!(
        gated,
        "src/lib.rs no longer declares `pub mod malloc_abi` under `#[cfg(not(test))]`.\n\
         If that gate was removed deliberately, unit tests in malloc_abi.rs now DO run and \
         this tripwire (bd-7s4j33) should be removed along with it. If it was removed by \
         accident, the module's #[no_mangle] malloc/free will shadow the system allocator \
         in the test binary and deadlock it — restore the gate."
    );
}
