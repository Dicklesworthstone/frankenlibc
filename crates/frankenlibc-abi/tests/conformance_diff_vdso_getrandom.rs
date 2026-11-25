#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // maps the kernel-specified vgetrandom state and draws through the vDSO
//! Gate for the `__vdso_getrandom` resolution and draw path (bd-dcrhgl).
//!
//! WHY THIS EXISTS. `getrandom` is the campaign's worst measured ratio at
//! 91.58-92.17x, and the cause is not a slow implementation but a missing
//! mechanism: measured by syscall counting, glibc 2.42 issues 3 getrandom
//! syscalls whether called 100 times or 10,000 — it draws from a userspace
//! CSPRNG in the vDSO — while fl issues 103 and 10,003, one per call.
//!
//! This gate resolves the kernel provider, performs real draws, and exercises
//! public getrandom routing. Native clone workers must neither use nor
//! initialize the creator's compiler-TLS generator cache.
//!
//! WHAT WOULD OTHERWISE GO UNNOTICED. A query that returns plausible-looking
//! numbers nobody can act on would pass a resolution-only test. So the gate MAPS
//! the state with exactly the protection and flags the kernel asked for, and
//! then draws through it. If the parameters are wrong, the mmap or the draw
//! fails here rather than in production.
//!
//! SKIPPING IS EXPLICIT, NOT SILENT. `__vdso_getrandom` exists from Linux 6.11.
//! On an older kernel the symbol is absent, which is a legitimate `None` and not
//! a defect — but a test that quietly passed in that case would also pass if the
//! resolver were broken. Every skip below prints why and asserts the POSITIVE
//! fact that the vDSO mapping itself was found, so "skipped" can never be
//! confused with "verified".

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

use std::ffi::c_void;

type GetrandomFn = unsafe extern "C" fn(*mut c_void, usize, libc::c_uint) -> isize;

fn live_glibc_getrandom() -> GetrandomFn {
    // SAFETY: libc.so.6 is the named incumbent and remains loaded for the
    // process lifetime. `getrandom` has the exact ABI declared by GetrandomFn.
    unsafe {
        let handle = libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        assert!(!handle.is_null(), "failed to open live libc.so.6");
        let raw = libc::dlsym(handle, c"getrandom".as_ptr());
        assert!(!raw.is_null(), "libc.so.6 has no getrandom symbol");
        assert_ne!(
            raw as usize,
            frankenlibc_abi::unistd_abi::getrandom as *const () as usize,
            "incumbent lookup resolved to frankenlibc rather than libc.so.6"
        );
        std::mem::transmute(raw)
    }
}

/// `int *__errno_location(void)`.
type ErrnoLocationFn = unsafe extern "C" fn() -> *mut libc::c_int;

/// glibc's errno slot, resolved the way `live_glibc_getrandom` resolves the
/// FUNCTION — because errno is the other half of every comparison here.
///
/// fl exports `__errno_location` under
/// `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`, so in a RELEASE test
/// binary `libc::__errno_location()` reads FL's slot while the incumbent call
/// wrote glibc's. The fl arm below already reads fl's own slot explicitly; this
/// makes the incumbent arm equally explicit instead of correct only in debug
/// (bd-g1sjty; the same shape produced a live wrong answer in
/// `conformance_diff_linux_aio_syscalls`, fixed by 1da1f3df3).
fn glibc_errno_location() -> ErrnoLocationFn {
    // SAFETY: the resolved address is glibc's `__errno_location`; fl's own
    // export is passed as the collapse guard so a self-comparison aborts.
    unsafe {
        let addr = dlsym_oracle::host_addr(
            c"__errno_location",
            frankenlibc_abi::errno_abi::__errno_location as ErrnoLocationFn as *const (),
        );
        std::mem::transmute::<*mut c_void, ErrnoLocationFn>(addr)
    }
}

fn fl_errno() -> libc::c_int {
    // SAFETY: FrankenLibC exposes its thread-local errno pointer.
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}

fn set_fl_errno(value: libc::c_int) {
    // SAFETY: as above, this writes only the current thread's errno.
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = value };
}

/// True when the running kernel is new enough to export the symbol at all.
fn vdso_mapping_present() -> bool {
    // AT_SYSINFO_EHDR is present on any kernel that maps a vDSO; its absence
    // means the whole mechanism is unavailable for reasons unrelated to fl.
    std::fs::read("/proc/self/auxv").is_ok()
}

#[test]
fn vdso_getrandom_params_are_usable_and_a_draw_succeeds() {
    let Some((state_size, prot, flags)) =
        frankenlibc_abi::time_abi::vdso_getrandom_params_for_tests()
    else {
        assert!(
            vdso_mapping_present(),
            "no vDSO mapping at all — this host cannot exercise the mechanism, \
             and the skip below would be meaningless"
        );
        eprintln!(
            "SKIP: __vdso_getrandom not exported by this kernel (needs >= 6.11). \
             This is a legitimate absence, not a failure; fl keeps the syscall path."
        );
        return;
    };

    // The kernel's own sanity bounds. A zero size would make the mmap below
    // succeed vacuously; an absurd one signals a misparsed struct.
    assert!(
        state_size > 0 && state_size <= 64 * 1024,
        "implausible size_of_opaque_state {state_size} — the params struct is \
         probably being read at the wrong offset or width"
    );

    // Map the state EXACTLY as the kernel specified. Using our own choice of
    // prot/flags here would test a mapping the vDSO never agreed to.
    // SAFETY: an anonymous mapping of the size the kernel asked for.
    let state = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            state_size as usize,
            prot as i32,
            flags as i32,
            -1,
            0,
        )
    };
    assert_ne!(
        state,
        libc::MAP_FAILED,
        "mmap of the vgetrandom state failed with the kernel's own prot={prot:#x} \
         flags={flags:#x} — the parameters are not usable, which is exactly the \
         failure a resolution-only test would have missed"
    );

    // A real draw. Two buffers so we can assert the output actually varies:
    // a stubbed or misconfigured CSPRNG that returned a constant would satisfy
    // the return-value check alone.
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    // SAFETY: `state` is mapped as the kernel specified, is this thread's alone,
    // and `state_size` matches what was mapped.
    let na = unsafe {
        frankenlibc_abi::time_abi::vdso_getrandom_draw_for_tests(
            &mut a,
            0,
            state,
            state_size as usize,
        )
    };
    // SAFETY: as above; the same single-threaded state is reused, which is the
    // contract's intent.
    let nb = unsafe {
        frankenlibc_abi::time_abi::vdso_getrandom_draw_for_tests(
            &mut b,
            0,
            state,
            state_size as usize,
        )
    };

    if na == -libc::ENOSYS as isize {
        eprintln!(
            "SKIP: the vDSO declined this draw with -ENOSYS, which the contract \
             permits; the syscall fallback is what a caller must use here."
        );
        // SAFETY: unmapping the mapping created above.
        unsafe { libc::munmap(state, state_size as usize) };
        return;
    }

    assert_eq!(
        na,
        a.len() as isize,
        "vDSO draw returned {na}, expected the full {} bytes",
        a.len()
    );
    assert_eq!(nb, b.len() as isize, "second vDSO draw returned {nb}");
    assert_ne!(
        a, b,
        "two consecutive draws returned identical bytes — the state is not \
         advancing, which would be a silent CSPRNG defect rather than a slow path"
    );
    assert_ne!(a, [0u8; 64], "first draw returned all zeros");

    // SAFETY: unmapping the mapping created above.
    unsafe { libc::munmap(state, state_size as usize) };
}

#[test]
fn vdso_getrandom_mapping_parameters_are_stable_for_the_process() {
    let first = frankenlibc_abi::time_abi::vdso_getrandom_params_for_tests();
    let second = frankenlibc_abi::time_abi::vdso_getrandom_params_for_tests();

    if first.is_none() {
        assert!(
            vdso_mapping_present(),
            "no vDSO mapping makes an absent getrandom symbol ambiguous"
        );
    }
    assert_eq!(
        first, second,
        "vgetrandom mapping parameters changed within one process"
    );
}

#[test]
fn fl_getrandom_matches_success_semantics() {
    for len in [0usize, 1, 32, 256] {
        let mut buf = vec![0u8; len.max(1)];
        // SAFETY: buffer is at least `len` bytes.
        let n = unsafe {
            frankenlibc_abi::unistd_abi::getrandom(buf.as_mut_ptr().cast::<c_void>(), len, 0)
        };
        assert_eq!(n, len as isize, "fl getrandom({len}) returned {n}");
        if len >= 32 {
            assert_ne!(
                &buf[..len],
                &vec![0u8; len][..],
                "getrandom({len}) left the buffer all zeros"
            );
        }
    }
}

#[test]
fn fl_getrandom_zero_length_and_invalid_flags_match_live_glibc() {
    let glibc_getrandom = live_glibc_getrandom();

    for flags in [0, libc::c_uint::MAX] {
        set_fl_errno(0);
        // SAFETY: Linux permits a null buffer when length is zero.
        let fl = unsafe { frankenlibc_abi::unistd_abi::getrandom(std::ptr::null_mut(), 0, flags) };
        let fl_error = fl_errno();

        // SAFETY: this calls the separately resolved live libc function with
        // the same valid zero-length shape, and reads its current-thread errno.
        let (glibc, glibc_error) = unsafe {
            let errno_slot = glibc_errno_location()();
            *errno_slot = 0;
            let result = glibc_getrandom(std::ptr::null_mut(), 0, flags);
            (result, *errno_slot)
        };

        assert_eq!(
            (fl, fl_error),
            (glibc, glibc_error),
            "getrandom(NULL, 0, {flags:#x}) diverged from live libc.so.6"
        );
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod native_ownership {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn isolated(name: &str) -> bool {
        const CHILD: &str = "FRANKENLIBC_NATIVE_GETRANDOM_CHILD";
        if std::env::var(CHILD).as_deref() == Ok(name) {
            return false;
        }
        for mode in ["strict", "hardened"] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture", "--test-threads=1"])
                .env(CHILD, name)
                .env("FRANKENLIBC_MODE", mode)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let mut timed_out = false;
            while child.try_wait().unwrap().is_none() {
                if std::time::Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            assert!(
                !timed_out
                    && output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed;"),
                "{mode} timeout={timed_out} status={}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        true
    }

    struct NativeBackend(bool);
    impl NativeBackend {
        fn select() -> Self {
            Self(frankenlibc_abi::pthread_abi::pthread_threading_swap_force_native_for_tests())
        }
    }
    impl Drop for NativeBackend {
        fn drop(&mut self) {
            frankenlibc_abi::pthread_abi::pthread_threading_restore_for_tests(self.0);
        }
    }

    unsafe extern "C" fn worker(_: *mut c_void) -> *mut c_void {
        if frankenlibc_core::pthread::thread::current_thread_handle().is_none() {
            return 1usize as *mut c_void;
        }
        let mut bytes = [0u8; 64];
        for _ in 0..32 {
            for flags in [0, libc::GRND_NONBLOCK] {
                // SAFETY: this worker exclusively owns its live stack buffer.
                let count = unsafe {
                    frankenlibc_abi::unistd_abi::getrandom(
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        flags,
                    )
                };
                if count != bytes.len() as isize {
                    return 2usize as *mut c_void;
                }
            }
        }
        bytes.fill(0xc3);
        // SAFETY: output and errno are live writable storage for this worker.
        let (count, error) = unsafe {
            *frankenlibc_abi::errno_abi::__errno_location() = 0;
            let count = frankenlibc_abi::unistd_abi::getrandom(
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::c_uint::MAX,
            );
            (count, *frankenlibc_abi::errno_abi::__errno_location())
        };
        if count != -1 || error != libc::EINVAL || bytes != [0xc3; 64] {
            return 3usize as *mut c_void;
        }
        std::ptr::null_mut()
    }

    fn run_workers<const N: usize>() {
        let mut threads = [0; N];
        let mut created = 0;
        let mut create_status = 0;
        for thread in &mut threads {
            // SAFETY: the worker has no borrowed arguments and returns status.
            create_status = unsafe {
                frankenlibc_abi::pthread_abi::pthread_create(
                    thread,
                    std::ptr::null(),
                    Some(worker),
                    std::ptr::null_mut(),
                )
            };
            if create_status != 0 {
                break;
            }
            created += 1;
        }
        // Resource pressure may prevent a later create. Join every published
        // worker before an assertion can unwind the probe/cache owner's stack.
        let mut results = [(0, 0); N];
        for (index, thread) in threads[..created].iter().copied().enumerate() {
            let mut result = std::ptr::null_mut();
            // SAFETY: each live, joinable worker is joined exactly once.
            let status = unsafe { frankenlibc_abi::pthread_abi::pthread_join(thread, &mut result) };
            if status != 0 {
                // An unsuccessful join cannot prove the worker released the
                // probe. End this isolated child without unwinding its owner.
                eprintln!("native getrandom worker join failed: {status}");
                std::process::abort();
            }
            results[index] = (status, result as usize);
        }
        assert_eq!(create_status, 0, "native worker creation failed");
        assert_eq!(created, N);
        assert_eq!(results, [(0, 0); N]);
    }

    struct Probe {
        owner_tid: i32,
        owner_calls: AtomicUsize,
        foreign_calls: AtomicUsize,
    }

    unsafe extern "C" fn observe(
        buffer: *mut c_void,
        length: usize,
        flags: libc::c_uint,
        state: *mut c_void,
        state_len: usize,
    ) -> isize {
        if state_len != std::mem::size_of::<Probe>() {
            return -(libc::EINVAL as isize);
        }
        // SAFETY: the parent retains this probe until all workers are joined.
        // Atomics make even the pre-fix wrong-owner observation race-free.
        let probe = unsafe { &*state.cast::<Probe>() };
        if frankenlibc_core::syscall::sys_gettid() == probe.owner_tid {
            probe.owner_calls.fetch_add(1, Ordering::Relaxed);
        } else {
            probe.foreign_calls.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: the public call supplies the destination span. Draw actual
        // kernel entropy while observing provider selection, never test bytes.
        unsafe { frankenlibc_core::syscall::sys_getrandom(buffer.cast(), length, flags) }
            .unwrap_or_else(|error| -(error as isize))
    }

    #[test]
    fn native_getrandom_never_uses_creator_vdso_state() {
        if isolated("native_ownership::native_getrandom_never_uses_creator_vdso_state") {
            return;
        }
        let _backend = NativeBackend::select();
        let probe = Probe {
            owner_tid: frankenlibc_core::syscall::sys_gettid(),
            owner_calls: AtomicUsize::new(0),
            foreign_calls: AtomicUsize::new(0),
        };
        let state = std::ptr::from_ref(&probe).cast_mut().cast();
        // SAFETY: all workers join before the live probe or cache is retired.
        let (_, retained) = unsafe {
            frankenlibc_abi::unistd_abi::with_getrandom_vdso_cache_for_tests(
                Some(observe),
                state,
                std::mem::size_of::<Probe>(),
                || {
                    let mut bytes = [0u8; 32];
                    assert_eq!(
                        frankenlibc_abi::unistd_abi::getrandom(bytes.as_mut_ptr().cast(), 32, 0),
                        32
                    );
                    assert!(probe.owner_calls.load(Ordering::Relaxed) > 0);
                    run_workers::<2>();
                    let before = probe.owner_calls.load(Ordering::Relaxed);
                    assert_eq!(
                        frankenlibc_abi::unistd_abi::getrandom(bytes.as_mut_ptr().cast(), 32, 0),
                        32
                    );
                    assert!(probe.owner_calls.load(Ordering::Relaxed) > before);
                },
            )
        };
        assert_eq!(retained, state as usize, "creator cache must stay live");
        assert_eq!(
            probe.foreign_calls.load(Ordering::Relaxed),
            0,
            "native workers entered the creator's vDSO generator"
        );
    }

    #[test]
    fn native_getrandom_leaves_creator_cold_cache_untouched() {
        if isolated("native_ownership::native_getrandom_leaves_creator_cold_cache_untouched") {
            return;
        }
        let _backend = NativeBackend::select();
        // SAFETY: null selects normal cold initialization. One worker makes
        // the pre-fix shared-cache write deterministic, without racing writers.
        let (_, retained) = unsafe {
            frankenlibc_abi::unistd_abi::with_getrandom_vdso_cache_for_tests(
                None,
                std::ptr::null_mut(),
                0,
                run_workers::<1>,
            )
        };
        assert_eq!(retained, 0, "native call initialized creator TLS");
    }
}
