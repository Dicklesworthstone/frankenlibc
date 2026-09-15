//! Build script: compiles the C va_list forwarder shim used by the wave-06
//! fortify checked-wrapper fixtures (bd-reality-202609-lx578q.6.1).
//!
//! Rust cannot construct a C `va_list`, so the harness drives fl's `__v*_chk`
//! members through thin C forwarders that receive their own varargs, open a
//! `va_list` with `va_start`, and hand it to the fl implementation.
//!
//! The shim is compiled into a STATIC ARCHIVE and registered with
//! `cargo:rustc-link-search` + `cargo:rustc-link-lib=static` — directives
//! that propagate to every downstream final link (harness tests, bins).
//! `cargo:rustc-link-obj` deliberately is NOT used: it does not survive the
//! rlib dependency chain, which left the shim symbols undefined in test
//! binaries (bd-reality-202609-lx578q.6.1).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    println!("cargo:rerun-if-changed=src/fortify_va_shim.c");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR unset"));
    let obj = out_dir.join("fortify_va_shim.o");
    let archive = out_dir.join("libfortify_va_shim.a");

    let status = Command::new("cc")
        .args([
            "-c",
            "-O1",
            "-fPIC",
            "-Wall",
            "-Wextra",
            "-Werror",
            "src/fortify_va_shim.c",
            "-o",
            obj.to_str().expect("non-UTF8 OUT_DIR"),
        ])
        .status()
        .expect("cc not found for fortify va shim");
    if !status.success() {
        panic!("cc failed compiling src/fortify_va_shim.c");
    }

    let ar_status = Command::new("ar")
        .args(["rcs"])
        .arg(&archive)
        .arg(&obj)
        .status()
        .expect("ar not found for fortify va shim");
    if !ar_status.success() {
        panic!("ar failed archiving libfortify_va_shim.a");
    }

    println!(
        "cargo:rustc-link-search=native={}",
        out_dir.to_str().expect("non-UTF8 OUT_DIR")
    );
    println!("cargo:rustc-link-lib=static=fortify_va_shim");
}
