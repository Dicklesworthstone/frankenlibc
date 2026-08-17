#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // guard-page mmap/mprotect + fork isolation

//! Do the BOUNDED string scans read past the terminator, and from which `n`?
//!
//! Every function gated here takes an explicit bound alongside a NUL-terminated
//! argument: `strnlen(s, n)`, `strncmp(s1, s2, n)`, `strncpy(dst, src, n)`, and
//! their wide analogues. For all of them `n` is a CEILING on the read footprint,
//! not a promise about the buffer — the read must stop at the terminator if one
//! appears first. `strnlen(p, 64)` on a 2-byte string is a conforming call, and
//! the caller is entitled to place that string 2 bytes from the end of its
//! mapping. glibc is careful never to touch a page it was not obliged to touch.
//!
//! An implementation that loads a fixed-width window before testing for the NUL
//! is not careful in that way, and the fault only appears when the window
//! crosses into an unmapped page — which ordinary tests, allocating with room to
//! spare, never arrange. Hence the guard page.
//!
//! ## What this found
//!
//! Written first for `wcsnlen` alone, on the theory that 79899b3f0
//! ("perf(wide): vectorize bounded wcsnlen scan") had introduced the footprint
//! with its three new bounded fast paths (`limit` in `[4,8)`, `[8,16)`,
//! `[16,32)`). That theory was WRONG, and the gate is family-wide because the
//! first run refuted it: `wcsnlen` faulted at `n = 31` as well, which no fast
//! path from that commit covers, and the same `i + W <= limit` shape — advance a
//! whole window if it fits under the BOUND, without regard for the terminator —
//! is what the pre-existing folded scan and the narrow `scan_c_string_for_byte`
//! bounded arm both do. The bound is the wrong quantity to gate a load on. Any
//! function reachable from those scans is a candidate, so each is asked directly
//! rather than argued about.
//!
//! Each case is forked because the failure mode is a SIGSEGV, which would
//! otherwise take the whole test binary with it. The wait is bounded for the
//! reason recorded in `conformance_diff_fortify_fgets.rs` — a child that neither
//! exits nor dies once hung an invocation for hours at zero CPU.

use std::ffi::{c_char, c_int};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

const PAGE: usize = 4096;

/// Bounds every probe: the string is 2 elements (`'a'`, NUL) and every `n` below
/// exceeds it, so any window wider than 2 elements crosses the guard page.
const AVAIL: usize = 2;
/// Index of the terminator within the readable region, so every arm's correct
/// answer is derived from the same place.
const NUL_AT: usize = 1;

/// Exit statuses at or above this encode a fixture failure, not a result.
const FIXTURE_BASE: c_int = 200;

// ---------------------------------------------------------------------------
// Outcome plumbing
// ---------------------------------------------------------------------------

/// What became of a child that made one bounded scan.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Returned the expected outcome code without dying.
    Code(u8),
    /// Died on a signal — for a guard-page over-read, `SIGSEGV`.
    Signal(c_int),
    /// The mapping could not be built, so the arm proves nothing either way.
    FixtureFailed(c_int),
    /// Neither, within the deadline.
    Hung,
}

/// Reap `pid` with a deadline, killing it rather than blocking forever.
///
/// # Safety
/// `pid` must be an unreaped child of this process.
unsafe fn bounded_wait(pid: libc::pid_t) -> Outcome {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let mut status: c_int = 0;
        // SAFETY: `pid` is this process's child and `status` is a live local.
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            if libc::WIFSIGNALED(status) {
                return Outcome::Signal(libc::WTERMSIG(status));
            }
            let code = libc::WEXITSTATUS(status);
            if code >= FIXTURE_BASE {
                return Outcome::FixtureFailed(code);
            }
            return Outcome::Code(code as u8);
        }
        if std::time::Instant::now() >= deadline {
            // SAFETY: killing a child this process owns.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                let mut sink: c_int = 0;
                libc::waitpid(pid, &mut sink, 0);
            }
            return Outcome::Hung;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// Place an `AVAIL`-element string so it ENDS flush against a guard page, then
/// run `body` on it in a child and report what happened.
///
/// `elem` is the element width in bytes (1 narrow, 4 wide). Everything at or
/// beyond the page boundary is `PROT_NONE`, so with `n > AVAIL` a
/// window-loading implementation faults and a terminator-respecting one does
/// not. `body` returns the arm's outcome code, which must stay below
/// [`FIXTURE_BASE`].
fn probe(elem: usize, body: impl FnOnce(*const u8) -> u8) -> Outcome {
    // SAFETY: fork; the child only touches the mapping it just made, runs one
    // arm and `_exit`s. Nothing on the child path allocates, so it cannot block
    // on an allocator lock this process's other threads may hold across `fork`.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // SAFETY: the child owns this mapping exclusively and writes only inside
        // the readable page.
        unsafe {
            let base = libc::mmap(
                std::ptr::null_mut(),
                2 * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if base == libc::MAP_FAILED {
                libc::_exit(FIXTURE_BASE);
            }
            if libc::mprotect(base.add(PAGE), PAGE, libc::PROT_NONE) != 0 {
                libc::_exit(FIXTURE_BASE + 1);
            }

            // End the readable elements exactly at the page boundary.
            let p = base.cast::<u8>().add(PAGE - AVAIL * elem);
            std::ptr::write_bytes(p, 0, AVAIL * elem);
            for i in 0..AVAIL {
                if i != NUL_AT {
                    // Little-endian: writing the low byte suffices for both widths.
                    p.add(i * elem).write(b'a');
                }
            }

            let code = body(p);
            libc::_exit(c_int::from(code));
        }
    }
    // SAFETY: `pid` is the child just forked.
    unsafe { bounded_wait(pid) }
}

// ---------------------------------------------------------------------------
// Arm shapes
// ---------------------------------------------------------------------------

type NarrowLen = unsafe extern "C" fn(*const c_char, usize) -> usize;
type NarrowCmp = unsafe extern "C" fn(*const c_char, *const c_char, usize) -> c_int;
type NarrowCpy = unsafe extern "C" fn(*mut c_char, *const c_char, usize) -> *mut c_char;
type WideLen = unsafe extern "C" fn(*const u32, usize) -> usize;
type WideCmp = unsafe extern "C" fn(*const u32, *const u32, usize) -> c_int;
type WideCpy = unsafe extern "C" fn(*mut u32, *const u32, usize) -> *mut u32;

/// Every bound each arm is probed with.
const BOUNDS: [usize; 8] = [4, 8, 16, 31, 32, 63, 128, 4096];

/// Largest `n` any arm is probed with, and so the size of every scratch buffer:
/// `strncpy` zero-fills its whole `n`, so the destination must hold it.
const MAX_N: usize = 4096;

/// Scratch for the arms that need a second, fully-mapped operand or a
/// destination. Stack-resident: the child must not allocate.
struct Scratch {
    narrow: [c_char; MAX_N * 2],
    wide: [u32; MAX_N * 2],
}

impl Scratch {
    /// A mapped copy of the guard-flush string, for the compare arms.
    fn peer(&mut self) -> *mut c_char {
        self.narrow.fill(0);
        self.narrow[0] = b'a' as c_char;
        self.narrow.as_mut_ptr()
    }

    fn wide_peer(&mut self) -> *mut u32 {
        self.wide.fill(0);
        self.wide[0] = u32::from(b'a');
        self.wide.as_mut_ptr()
    }

    /// A zeroed destination, for the copy arms.
    fn dst(&mut self) -> *mut c_char {
        self.narrow.fill(0);
        self.narrow.as_mut_ptr()
    }

    fn wide_dst(&mut self) -> *mut u32 {
        self.wide.fill(0);
        self.wide.as_mut_ptr()
    }

    /// Count of non-NUL elements the arm left in `narrow`, which for every copy
    /// arm here is the source length (`NUL_AT`).
    fn narrow_written(&self) -> u8 {
        self.narrow.iter().filter(|&&c| c != 0).count() as u8
    }

    fn wide_written(&self) -> u8 {
        self.wide.iter().filter(|&&c| c != 0).count() as u8
    }
}

/// One function under test, paired with the same call against the host.
struct Arm {
    name: &'static str,
    /// Run fl's definition on a guard-flush string bounded by `n`.
    fl: Box<dyn Fn(*const u8, usize) -> u8>,
    /// The identical call against glibc.
    host: Box<dyn Fn(*const u8, usize) -> u8>,
    /// Element width in bytes: what makes the string end flush at the page.
    elem: usize,
}

/// Normalize a comparison result to a small code: 0 equal, 1 negative, 2 positive.
fn cmp_code(r: c_int) -> u8 {
    match r.signum() {
        0 => 0,
        -1 => 1,
        _ => 2,
    }
}

/// Build the arm table, resolving each host entry point through `dlsym`.
///
/// Every `host_fn` call passes fl's own definition so a collapsed oracle fails
/// loudly instead of comparing fl against itself.
fn arms() -> Vec<Arm> {
    use frankenlibc_abi::{string_abi as s, wchar_abi as w};

    // Narrow length.
    let fl_strnlen: NarrowLen = s::strnlen;
    let host_strnlen: NarrowLen = unsafe { host_fn(c"strnlen", s::strnlen as *const ()) };
    // Narrow compare.
    let fl_strncmp: NarrowCmp = s::strncmp;
    let host_strncmp: NarrowCmp = unsafe { host_fn(c"strncmp", s::strncmp as *const ()) };
    let fl_strncasecmp: NarrowCmp = s::strncasecmp;
    let host_strncasecmp: NarrowCmp =
        unsafe { host_fn(c"strncasecmp", s::strncasecmp as *const ()) };
    // Narrow copy.
    let fl_strncpy: NarrowCpy = s::strncpy;
    let host_strncpy: NarrowCpy = unsafe { host_fn(c"strncpy", s::strncpy as *const ()) };
    let fl_stpncpy: NarrowCpy = s::stpncpy;
    let host_stpncpy: NarrowCpy = unsafe { host_fn(c"stpncpy", s::stpncpy as *const ()) };
    let fl_strncat: NarrowCpy = s::strncat;
    let host_strncat: NarrowCpy = unsafe { host_fn(c"strncat", s::strncat as *const ()) };
    // Wide.
    let fl_wcsnlen: WideLen = wide_len_shim;
    let host_wcsnlen: WideLen = unsafe { host_fn(c"wcsnlen", wide_len_shim as *const ()) };
    let fl_wcsncmp: WideCmp = w::wcsncmp;
    let host_wcsncmp: WideCmp = unsafe { host_fn(c"wcsncmp", w::wcsncmp as *const ()) };
    let fl_wcsncasecmp: WideCmp = w::wcsncasecmp;
    let host_wcsncasecmp: WideCmp =
        unsafe { host_fn(c"wcsncasecmp", w::wcsncasecmp as *const ()) };
    let fl_wcsncpy: WideCpy = w::wcsncpy;
    let host_wcsncpy: WideCpy = unsafe { host_fn(c"wcsncpy", w::wcsncpy as *const ()) };

    let len_arm = |name, f: NarrowLen| -> Box<dyn Fn(*const u8, usize) -> u8> {
        let _ = name;
        // SAFETY: `p` is the guard-flush string and `n` its caller-chosen bound.
        Box::new(move |p, n| unsafe { f(p.cast::<c_char>(), n) as u8 })
    };
    let wlen_arm = |f: WideLen| -> Box<dyn Fn(*const u8, usize) -> u8> {
        // SAFETY: as above, at wide element width.
        Box::new(move |p, n| unsafe { f(p.cast::<u32>(), n) as u8 })
    };
    let cmp_arm = |f: NarrowCmp| -> Box<dyn Fn(*const u8, usize) -> u8> {
        Box::new(move |p, n| {
            let mut sc = fresh_scratch();
            let peer = sc.peer();
            // SAFETY: `p` is guard-flush, `peer` is a fully-mapped equal copy.
            cmp_code(unsafe { f(p.cast::<c_char>(), peer, n) })
        })
    };
    let wcmp_arm = |f: WideCmp| -> Box<dyn Fn(*const u8, usize) -> u8> {
        Box::new(move |p, n| {
            let mut sc = fresh_scratch();
            let peer = sc.wide_peer();
            // SAFETY: as above, at wide element width.
            cmp_code(unsafe { f(p.cast::<u32>(), peer, n) })
        })
    };
    let cpy_arm = |f: NarrowCpy| -> Box<dyn Fn(*const u8, usize) -> u8> {
        Box::new(move |p, n| {
            let mut sc = fresh_scratch();
            let dst = sc.dst();
            // SAFETY: `dst` holds MAX_N*2 elements and `n <= MAX_N`, which covers
            // strncpy's zero-fill and strncat's append plus terminator.
            unsafe { f(dst, p.cast::<c_char>(), n) };
            sc.narrow_written()
        })
    };
    let wcpy_arm = |f: WideCpy| -> Box<dyn Fn(*const u8, usize) -> u8> {
        Box::new(move |p, n| {
            let mut sc = fresh_scratch();
            let dst = sc.wide_dst();
            // SAFETY: as above, at wide element width.
            unsafe { f(dst, p.cast::<u32>(), n) };
            sc.wide_written()
        })
    };

    vec![
        Arm {
            name: "strnlen",
            fl: len_arm("strnlen", fl_strnlen),
            host: len_arm("strnlen", host_strnlen),
            elem: 1,
        },
        Arm {
            name: "strncmp",
            fl: cmp_arm(fl_strncmp),
            host: cmp_arm(host_strncmp),
            elem: 1,
        },
        Arm {
            name: "strncasecmp",
            fl: cmp_arm(fl_strncasecmp),
            host: cmp_arm(host_strncasecmp),
            elem: 1,
        },
        Arm {
            name: "strncpy",
            fl: cpy_arm(fl_strncpy),
            host: cpy_arm(host_strncpy),
            elem: 1,
        },
        Arm {
            name: "stpncpy",
            fl: cpy_arm(fl_stpncpy),
            host: cpy_arm(host_stpncpy),
            elem: 1,
        },
        Arm {
            name: "strncat",
            fl: cpy_arm(fl_strncat),
            host: cpy_arm(host_strncat),
            elem: 1,
        },
        Arm {
            name: "wcsnlen",
            fl: wlen_arm(fl_wcsnlen),
            host: wlen_arm(host_wcsnlen),
            elem: 4,
        },
        Arm {
            name: "wcsncmp",
            fl: wcmp_arm(fl_wcsncmp),
            host: wcmp_arm(host_wcsncmp),
            elem: 4,
        },
        Arm {
            name: "wcsncasecmp",
            fl: wcmp_arm(fl_wcsncasecmp),
            host: wcmp_arm(host_wcsncasecmp),
            elem: 4,
        },
        Arm {
            name: "wcsncpy",
            fl: wcpy_arm(fl_wcsncpy),
            host: wcpy_arm(host_wcsncpy),
            elem: 4,
        },
    ]
}

/// fl's `wcsnlen`, re-declared at the `*const u32` width this file uses.
///
/// `wchar_abi::wcsnlen` takes `*const libc::wchar_t` (`i32`); the cast is only a
/// signedness change on the pointee, not a layout one.
unsafe extern "C" fn wide_len_shim(s: *const u32, maxlen: usize) -> usize {
    // SAFETY: forwarding the caller's pointer and bound unchanged.
    unsafe { frankenlibc_abi::wchar_abi::wcsnlen(s.cast::<libc::wchar_t>(), maxlen) }
}

/// Zeroed scratch on the child's stack. Boxed would allocate; this must not.
fn fresh_scratch() -> Scratch {
    Scratch {
        narrow: [0; MAX_N * 2],
        wide: [0; MAX_N * 2],
    }
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// No bounded scan may read past the terminator where glibc does not.
///
/// The `n` values straddle every window width in play: 4, 8, 16 and 32 are the
/// wide fast-path tiers and the narrow SWAR/SIMD widths, and 31 and 63 land
/// mid-window so a tier that rounds its bound up is caught too. 128 and 4096
/// reach the folded 128-byte narrow tier and the 256-element wide block, which
/// the small bounds never enter — a bound is not a small number just because the
/// string is short, and `strnlen(p, PATH_MAX)` on a 2-byte name is the shape
/// several callers inside this crate actually pass.
#[test]
fn bounded_scans_never_read_into_guard_page() {
    let mut divergences = Vec::new();
    let mut checked = 0usize;

    for arm in arms() {
        for &n in &BOUNDS {
            let host = probe(arm.elem, |p| (arm.host)(p, n));
            let fl = probe(arm.elem, |p| (arm.fl)(p, n));
            println!(
                "BOUNDED_GUARD {:<12} n={n:<3} avail={AVAIL} nul_at={NUL_AT} host={host:?} fl={fl:?}",
                arm.name
            );

            // The host arm is the fixture's own proof: glibc performs this exact
            // call on this exact mapping without faulting. If it ever does fault,
            // the mapping is wrong and nothing may be concluded about fl.
            assert!(
                matches!(host, Outcome::Code(_)),
                "host glibc must survive {}(.., {n}) on a {AVAIL}-element string; \
                 got {host:?} — the fixture is wrong, not fl",
                arm.name
            );
            checked += 1;

            if fl != host {
                divergences.push(format!("{} n={n}: fl={fl:?} host={host:?}", arm.name));
            }
        }
    }

    // A silent zero here would be indistinguishable from a pass, so assert the
    // positive fact: every arm times every bound actually ran.
    assert_eq!(checked, 10 * BOUNDS.len(), "not every arm ran");
    assert!(
        divergences.is_empty(),
        "bounded scans read past the terminator where glibc did not: {divergences:#?}"
    );
}

/// `strnlen(p, SIZE_MAX)` and `wcsnlen(p, SIZE_MAX)` are legal calls, and the
/// page clamp must not overflow into admitting them wholesale.
///
/// Only the LENGTH arms are asked. A copy arm at this bound would be asked to
/// zero-fill the address space, which says nothing about read footprint.
///
/// The distinction this pins is invisible at any smaller bound: a clamp written
/// as `page_offset + bound <= PAGE` wraps here, reports the whole remaining
/// address space as one page, and hands the unclamped bound to a scan that then
/// walks into the guard page — the exact fault the small-bound cases catch, back
/// again through arithmetic rather than through the window width.
#[test]
fn saturating_bound_is_still_page_clamped() {
    use frankenlibc_abi::string_abi as s;

    let fl_strnlen: NarrowLen = s::strnlen;
    let host_strnlen: NarrowLen = unsafe { host_fn(c"strnlen", s::strnlen as *const ()) };
    let fl_wcsnlen: WideLen = wide_len_shim;
    let host_wcsnlen: WideLen = unsafe { host_fn(c"wcsnlen", wide_len_shim as *const ()) };

    // SAFETY (all four): the guard-flush string terminates at NUL_AT, so a
    // conforming scan stops there no matter how large the bound.
    let narrow_host = probe(1, |p| unsafe {
        host_strnlen(p.cast::<c_char>(), usize::MAX) as u8
    });
    let narrow_fl = probe(1, |p| unsafe {
        fl_strnlen(p.cast::<c_char>(), usize::MAX) as u8
    });
    let wide_host = probe(4, |p| unsafe { host_wcsnlen(p.cast::<u32>(), usize::MAX) as u8 });
    let wide_fl = probe(4, |p| unsafe { fl_wcsnlen(p.cast::<u32>(), usize::MAX) as u8 });

    println!("BOUNDED_GUARD strnlen      n=SIZE_MAX host={narrow_host:?} fl={narrow_fl:?}");
    println!("BOUNDED_GUARD wcsnlen      n=SIZE_MAX host={wide_host:?} fl={wide_fl:?}");

    let want = Outcome::Code(NUL_AT as u8);
    assert_eq!(narrow_host, want, "fixture: host strnlen must survive SIZE_MAX");
    assert_eq!(wide_host, want, "fixture: host wcsnlen must survive SIZE_MAX");
    assert_eq!(narrow_fl, want, "fl strnlen at SIZE_MAX");
    assert_eq!(wide_fl, want, "fl wcsnlen at SIZE_MAX");
}
