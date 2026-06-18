#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc system-count oracle

//! Differential gate for the stable system-count queries get_nprocs /
//! get_nprocs_conf / get_phys_pages (bd-zl4ico) — all had no differential gate
//! (only fl-internal). These return stable system values (online/configured CPU
//! count, total physical RAM pages) that do not change during a test, so fl's
//! result must equal glibc's exactly. (get_avphys_pages and getcpu fluctuate
//! moment-to-moment and are intentionally excluded.) No mocks.

use std::ffi::{c_int, c_long};

unsafe extern "C" {
    fn get_nprocs() -> c_int;
    fn get_nprocs_conf() -> c_int;
    fn get_phys_pages() -> c_long;
}

#[test]
fn get_nprocs_matches_glibc() {
    let g = unsafe { get_nprocs() };
    let f = frankenlibc_abi::stdlib_abi::get_nprocs();
    assert_eq!(f, g, "get_nprocs: fl={f} glibc={g}");
    assert!(g >= 1, "online CPU count must be >= 1");
}

#[test]
fn get_nprocs_conf_matches_glibc() {
    let g = unsafe { get_nprocs_conf() };
    let f = frankenlibc_abi::stdlib_abi::get_nprocs_conf();
    assert_eq!(f, g, "get_nprocs_conf: fl={f} glibc={g}");
    // Configured CPUs is always >= online CPUs.
    assert!(g >= unsafe { get_nprocs() }, "configured >= online");
}

#[test]
fn get_phys_pages_matches_glibc() {
    let g = unsafe { get_phys_pages() };
    let f = frankenlibc_abi::stdlib_abi::get_phys_pages();
    assert_eq!(f, g, "get_phys_pages: fl={f} glibc={g}");
    assert!(g > 0, "total physical pages must be > 0");
}
