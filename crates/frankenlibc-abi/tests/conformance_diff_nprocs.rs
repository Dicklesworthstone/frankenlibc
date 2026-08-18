#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live glibc oracle + affinity manipulation

//! `get_nprocs` / `get_nprocs_conf` / `get_phys_pages` / `get_avphys_pages`
//! against live glibc.
//!
//! bd-zl4ico: no differential coverage. The counts agree trivially on any
//! ordinary box, so the arm that earns its place is the one that does NOT.
//!
//! ## `get_nprocs` must ignore the affinity mask
//!
//! Measured by running the same probe under `taskset`:
//!
//! ```text
//!   unrestricted    affinity=64  get_nprocs=64  sysconf(_SC_NPROCESSORS_ONLN)=64
//!   taskset -c 0-3  affinity=4   get_nprocs=64  sysconf=64
//!   taskset -c 0    affinity=1   get_nprocs=64  sysconf=64
//! ```
//!
//! `get_nprocs` reports ONLINE processors system-wide; it does not follow the
//! calling thread's affinity. That matters because the idiomatic Rust answer —
//! `std::thread::available_parallelism()` — DOES honour affinity, and so does
//! `sched_getaffinity`. An implementation built on either agrees perfectly on an
//! unrestricted machine and diverges the moment the process is pinned or
//! cgroup-limited, which is exactly the environment this library runs its own
//! benchmarks in.
//!
//! fl reads `/sys/devices/system/cpu/online` and `.../present`, which is
//! affinity-independent, so it is correct today. This gate is what keeps it that
//! way when someone reaches for the shorter spelling.
//!
//! ## Free memory is volatile, total memory is not
//!
//! `get_phys_pages` is compared exactly. `get_avphys_pages` is NOT: it reports
//! free RAM, which moves between two calls on a busy host, so comparing it
//! exactly would produce a gate that fails for reasons unrelated to fl. It is
//! checked for plausibility instead, and the reason is recorded here rather
//! than left as an unexplained weaker assertion.

use std::ffi::{c_int, c_long};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

type NprocsFn = unsafe extern "C" fn() -> c_int;
type PagesFn = unsafe extern "C" fn() -> c_long;

fn host_nprocs() -> NprocsFn {
    // SAFETY: `int get_nprocs(void)`, fl's own export supplied as the guard.
    unsafe {
        host_fn(
            c"get_nprocs",
            frankenlibc_abi::stdlib_abi::get_nprocs as *const (),
        )
    }
}

fn host_nprocs_conf() -> NprocsFn {
    // SAFETY: `int get_nprocs_conf(void)`.
    unsafe {
        host_fn(
            c"get_nprocs_conf",
            frankenlibc_abi::stdlib_abi::get_nprocs_conf as *const (),
        )
    }
}

fn host_phys_pages() -> PagesFn {
    // SAFETY: `long get_phys_pages(void)`.
    unsafe {
        host_fn(
            c"get_phys_pages",
            frankenlibc_abi::stdlib_abi::get_phys_pages as *const (),
        )
    }
}

#[test]
fn processor_and_memory_counts_match_glibc() {
    // SAFETY: all four take no arguments and return scalars.
    unsafe {
        assert_eq!(
            frankenlibc_abi::stdlib_abi::get_nprocs(),
            host_nprocs()(),
            "get_nprocs"
        );
        assert_eq!(
            frankenlibc_abi::stdlib_abi::get_nprocs_conf(),
            host_nprocs_conf()(),
            "get_nprocs_conf"
        );
        assert_eq!(
            frankenlibc_abi::stdlib_abi::get_phys_pages(),
            host_phys_pages()(),
            "get_phys_pages — total RAM does not move, so this is exact"
        );
    }
}

/// The arm that actually discriminates: pin the calling thread to one CPU and
/// require `get_nprocs` not to notice.
#[test]
fn get_nprocs_ignores_the_affinity_mask() {
    // SAFETY: reading and setting this thread's own affinity, restored below.
    unsafe {
        let mut original: libc::cpu_set_t = std::mem::zeroed();
        assert_eq!(
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut original),
            0,
            "sched_getaffinity failed"
        );

        let unrestricted = frankenlibc_abi::stdlib_abi::get_nprocs();
        assert!(unrestricted > 0, "get_nprocs must be positive");

        // A single-CPU mask. If the count followed affinity it would drop to 1.
        let mut pinned: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut pinned);
        libc::CPU_SET(0, &mut pinned);
        let set_ok =
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &pinned) == 0;

        let restricted = frankenlibc_abi::stdlib_abi::get_nprocs();
        let host_restricted = host_nprocs()();

        // Restore BEFORE asserting, so a failure does not leave this thread
        // pinned for every arm that runs after it.
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &original);

        assert!(
            set_ok,
            "could not pin to CPU 0; the arm proves nothing without it"
        );
        assert_eq!(
            restricted, host_restricted,
            "fl and glibc must agree under a restricted mask too"
        );
        assert_eq!(
            restricted, unrestricted,
            "get_nprocs followed the affinity mask ({unrestricted} -> {restricted}). \
             It must report ONLINE processors system-wide — an implementation \
             built on available_parallelism() or sched_getaffinity passes every \
             other arm here and fails this one (bd-zl4ico)"
        );
    }
}

/// Free RAM moves between calls, so this checks the shape rather than equality.
#[test]
fn available_pages_are_plausible_rather_than_pinned() {
    // SAFETY: no arguments.
    let (avail, total) = unsafe {
        (
            frankenlibc_abi::stdlib_abi::get_avphys_pages(),
            frankenlibc_abi::stdlib_abi::get_phys_pages(),
        )
    };
    assert!(avail > 0, "available pages must be positive");
    assert!(
        avail <= total,
        "available ({avail}) cannot exceed total ({total})"
    );
}

/// `get_nprocs_conf` counts configured CPUs, which is `>=` the online count.
/// Equal on most machines, so this pins the RELATION rather than the values.
#[test]
fn configured_is_at_least_online() {
    // SAFETY: no arguments.
    let (online, configured) = unsafe {
        (
            frankenlibc_abi::stdlib_abi::get_nprocs(),
            frankenlibc_abi::stdlib_abi::get_nprocs_conf(),
        )
    };
    assert!(
        configured >= online,
        "configured ({configured}) must be >= online ({online}); a CPU cannot be \
         online without being present"
    );
}
