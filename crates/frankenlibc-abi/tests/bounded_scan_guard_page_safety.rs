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
    probe_in_child(|guard_page| {
        // End the readable elements exactly at the page boundary.
        // SAFETY: `guard_page` is the boundary of a mapped page and the whole
        // `AVAIL * elem` region below it is writable.
        let p = unsafe { guard_page.sub(AVAIL * elem) };
        // SAFETY: as above.
        unsafe {
            std::ptr::write_bytes(p, 0, AVAIL * elem);
            for i in 0..AVAIL {
                if i != NUL_AT {
                    // Little-endian: writing the low byte suffices for both widths.
                    p.add(i * elem).write(b'a');
                }
            }
        }
        (p, body)
    })
}

/// Place `payload` followed by a NUL so the terminator is the LAST readable byte,
/// then run `body` on it in a child.
///
/// The narrow-only sibling of [`probe`], for the functions whose behaviour
/// depends on what the string SAYS rather than only on its length. `strtod`
/// guards its capped scan behind a byte-at-a-time fast path that handles plain
/// decimals, so a probe that can only place `"a"` cannot reach the capped scan at
/// all; a payload of `"0x10"` or `"nan"` is rejected by that fast path and falls
/// through to it.
fn probe_payload(payload: &[u8], body: impl FnOnce(*const u8) -> u8) -> Outcome {
    let total = payload.len() + 1;
    probe_in_child(move |guard_page| {
        // SAFETY: `total` bytes below the guard page are mapped and writable.
        let p = unsafe { guard_page.sub(total) };
        // SAFETY: as above; the NUL lands on the last readable byte.
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), p, payload.len());
            p.add(payload.len()).write(0);
        }
        (p, body)
    })
}

/// Shared fixture: two pages with the second one `PROT_NONE`, in a fresh child.
///
/// `place` receives the address of the guard-page boundary, writes the fixture
/// below it, and returns the pointer to hand the arm together with the arm
/// itself. Forked because the failure mode is a SIGSEGV, which would otherwise
/// take the whole test binary with it.
fn probe_in_child<F>(place: impl FnOnce(*mut u8) -> (*mut u8, F)) -> Outcome
where
    F: FnOnce(*const u8) -> u8,
{
    // SAFETY: fork; the child only touches the mapping it just made, runs one
    // arm and `_exit`s.
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

            let (p, body) = place(base.cast::<u8>().add(PAGE));
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
type NarrowDup = unsafe extern "C" fn(*const c_char, usize) -> *mut c_char;
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
    // Bounded duplicate: `n` is a ceiling on the READ, and the allocation is
    // sized from whatever the scan found, so an over-read is the whole risk.
    let fl_strndup: NarrowDup = s::strndup;
    let host_strndup: NarrowDup = unsafe { host_fn(c"strndup", s::strndup as *const ()) };
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
    // `strndup` is the one arm whose child allocates, which after `fork` is only
    // safe because these test binaries build in the debug profile, where fl's
    // `malloc` export is not `no_mangle` and so does not interpose: the child
    // reaches glibc's allocator, which reinitializes its locks through the
    // registered atfork handler. The bounded wait is the backstop if that ever
    // stops holding — a deadlocked child reports `Hung`, not a hang.
    let dup_arm = |f: NarrowDup| -> Box<dyn Fn(*const u8, usize) -> u8> {
        Box::new(move |p, n| {
            // SAFETY: `p` is the guard-flush string; `n` is strndup's ceiling.
            let got = unsafe { f(p.cast::<c_char>(), n) };
            if got.is_null() {
                return FIXTURE_BASE as u8 - 1;
            }
            // Walk the result with a plain loop rather than calling fl's `strlen`,
            // so the arm measures only the function under test.
            let mut len = 0u8;
            // SAFETY: strndup guarantees a NUL-terminated result.
            while unsafe { *got.add(len as usize) } != 0 {
                len += 1;
            }
            len
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
            name: "strndup",
            fl: dup_arm(fl_strndup),
            host: dup_arm(host_strndup),
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
    assert_eq!(checked, 11 * BOUNDS.len(), "not every arm ran");
    assert!(
        divergences.is_empty(),
        "bounded scans read past the terminator where glibc did not: {divergences:#?}"
    );
}

/// POSITIVE CONTROL: prove this fixture can actually observe an over-read.
///
/// `capped_parsers_never_read_into_guard_page` came back green on the first run,
/// and a green guard-page arm is indistinguishable from an arm that never touched
/// the mapping — the same failure mode as any silently-passing gate. So one arm
/// is asked to over-read ON PURPOSE.
///
/// `memchr(p, c, n)` is the right instrument because `n` really is a promise of
/// `n` readable bytes, so handing it 4096 over a 5-byte buffer is a deliberate
/// contract violation rather than a defect being hunted; both implementations are
/// entitled to read all 4096 and both should die. If EITHER survives, the fixture
/// is not placing the string where it claims and no green result from this file
/// means anything.
#[test]
fn fixture_can_observe_an_over_read() {
    use frankenlibc_abi::string_abi as s;

    type MemchrFn = unsafe extern "C" fn(*const std::ffi::c_void, c_int, usize) -> *mut std::ffi::c_void;
    let fl: MemchrFn = s::memchr;
    let host: MemchrFn = unsafe { host_fn(c"memchr", s::memchr as *const ()) };

    let arm = |f: MemchrFn| {
        // SAFETY: intentionally out of contract — see the doc comment. The child
        // is expected to die here, which is the point.
        move |p: *const u8| {
            let found = unsafe { f(p.cast::<std::ffi::c_void>(), 0xFF, 4096) };
            u8::from(!found.is_null())
        }
    };
    let host_outcome = probe_payload(b"0x10", arm(host));
    let fl_outcome = probe_payload(b"0x10", arm(fl));
    println!(
        "CAPPED_GUARD control      memchr(p,0xFF,4096) over a 5-byte buffer: \
         host={host_outcome:?} fl={fl_outcome:?}"
    );

    assert_eq!(
        host_outcome,
        Outcome::Signal(libc::SIGSEGV),
        "the fixture did not make glibc's memchr fault on a deliberate 4096-byte \
         over-read of a 5-byte buffer, so the string is not flush against the \
         guard page and every other result in this file is vacuous"
    );
    assert_eq!(
        fl_outcome,
        Outcome::Signal(libc::SIGSEGV),
        "fl's memchr survived a deliberate 4096-byte over-read; either the \
         fixture is wrong or memchr is not reading what it was told to"
    );

    // WHY THE CAPPED PARSERS SURVIVE, measured rather than argued. Their bound is
    // `known_remaining(p).unwrap_or(BIG_CAP)`, so everything turns on what the
    // allocator's bookkeeping says about a pointer it never handed out. If that
    // is `None` the cap applies and the 128-byte folded tier in `scan_c_string`
    // would run off the page; if it is `Some(small)` the scan is already bounded
    // by the real extent and no cap is ever consulted. Asking the allocator
    // directly settles which, and it is the one fact the timings cannot show.
    let reported = probe_payload(b"0x10", |p| {
        match frankenlibc_abi::malloc_abi::known_remaining_for_tests(p as usize) {
            None => 0,
            // Bucketed so the exit status can carry it: 1 means "smaller than the
            // distance to the guard page", 2 means "at least that far", which is
            // the only distinction that decides whether a scan can fault.
            Some(remaining) if remaining <= 5 => 1,
            Some(_) => 2,
        }
    });
    println!("CAPPED_GUARD known_remaining over a foreign mmap: {reported:?} (0=None 1=<=5 2=>5)");
}

type StrtodFn = unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> f64;
type StrtofFn = unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> f32;
type InetNetworkFn = unsafe extern "C" fn(*const c_char) -> libc::c_uint;

/// Payloads that reach the CAPPED scan rather than a byte-at-a-time fast path.
///
/// `strtod`/`strtof` try `parse_strtod_short_decimal_c_string_fast` first, which
/// walks byte by byte and is page-safe. It bails on a hex prefix and on `inf`/
/// `nan`, and only then does the capped scan run — so a plain `"1"` would prove
/// nothing about the scan. Each payload here is a VALID input that the fast path
/// refuses, paired with the character count both implementations must consume.
const PARSER_PAYLOADS: &[(&[u8], u8, &str)] = &[
    (b"0x10", 4, "hex_integer"),
    (b"0x1p4", 5, "hex_float_with_exponent"),
    (b"nan", 3, "nan"),
    (b"inf", 3, "infinity"),
    // 20 significant digits, over the fast path's MAX_FIXED_SIGNIFICANT_DIGITS of
    // 15. Included because the four payloads above all came back GREEN, and a
    // green arm here is only meaningful if the capped scan was actually reached:
    // this one cannot be served by a 15-digit fixed-decimal path whatever its
    // prefix handling does, so if the capped scan is reachable at all, it is
    // reachable from here.
    (b"12345678901234567890", 20, "twenty_significant_digits"),
    // Inputs with NOTHING for a numeric fast path to consume. `strtod("")` and
    // `strtod("zzz")` are legal calls that must return 0 and leave endptr at the
    // start, and they are the shapes most likely to fall through every fast path
    // to the capped scan — which `known_remaining` was measured to leave
    // unbounded (it reports None for a foreign mmap, so the 131072 cap applies).
    (b"zzz", 0, "non_numeric"),
    (b"", 0, "empty_string"),
    (b"   ", 0, "whitespace_only"),
    (b"+", 0, "lone_sign"),
    (b".", 0, "lone_point"),
    (b"0x", 1, "truncated_hex_prefix"),
];

/// The functions whose defensive cap is applied to a caller string on the
/// DEPLOYED path must not read past the terminator either.
///
/// Filed as bd-strtod-capped-scan-overread-iyj9oc from code reading alone. Unlike
/// the bounded family above, these take no `n` at all: the bound is a cap the
/// implementation invents (131072 for the numeric scan), so every one of them
/// admits the 128-byte folded window regardless of what the caller passed. glibc
/// parses these byte by byte and completes.
#[test]
fn capped_parsers_never_read_into_guard_page() {
    use frankenlibc_abi::{glibc_internal_abi as gi, stdlib_abi as s};

    let fl_strtod: StrtodFn = s::strtod;
    let host_strtod: StrtodFn = unsafe { host_fn(c"strtod", s::strtod as *const ()) };
    let fl_strtof: StrtofFn = s::strtof;
    let host_strtof: StrtofFn = unsafe { host_fn(c"strtof", s::strtof as *const ()) };
    let fl_inet_network: InetNetworkFn = gi::inet_network;
    let host_inet_network: InetNetworkFn =
        unsafe { host_fn(c"inet_network", gi::inet_network as *const ()) };

    // Each arm reports how many characters it consumed, which tests behaviour as
    // well as survival: a scan that dies reports Signal, and one that quietly
    // stops early reports a different count.
    let strtod_arm = |f: StrtodFn| {
        move |p: *const u8| {
            let mut end: *mut c_char = std::ptr::null_mut();
            // SAFETY: `p` is a NUL-terminated string flush against a guard page.
            unsafe { f(p.cast::<c_char>(), &mut end) };
            (end as usize - p as usize) as u8
        }
    };
    let strtof_arm = |f: StrtofFn| {
        move |p: *const u8| {
            let mut end: *mut c_char = std::ptr::null_mut();
            // SAFETY: as above.
            unsafe { f(p.cast::<c_char>(), &mut end) };
            (end as usize - p as usize) as u8
        }
    };

    let mut divergences = Vec::new();
    let mut checked = 0usize;

    for (payload, consumed, name) in PARSER_PAYLOADS {
        let text = String::from_utf8_lossy(payload).into_owned();
        for (symbol, host_outcome, fl_outcome) in [
            (
                "strtod",
                probe_payload(payload, strtod_arm(host_strtod)),
                probe_payload(payload, strtod_arm(fl_strtod)),
            ),
            (
                "strtof",
                probe_payload(payload, strtof_arm(host_strtof)),
                probe_payload(payload, strtof_arm(fl_strtof)),
            ),
        ] {
            println!(
                "CAPPED_GUARD {symbol:<12} payload={text:<6} case={name:<24} \
                 host={host_outcome:?} fl={fl_outcome:?}"
            );
            assert_eq!(
                host_outcome,
                Outcome::Code(*consumed),
                "host glibc must parse {symbol}({text:?}) flush against a guard page \
                 and consume {consumed}; the fixture is wrong, not fl"
            );
            checked += 1;
            if fl_outcome != host_outcome {
                divergences.push(format!(
                    "{symbol} payload={text:?}: fl={fl_outcome:?} host={host_outcome:?}"
                ));
            }
        }
    }

    // inet_network takes a dotted quad and no bound at all; its cap is
    // INET_TEXT_SCAN_LIMIT. The outcome code is the low byte of the result, which
    // both sides must agree on.
    for payload in [b"1.2.3.4".as_slice(), b"10.0".as_slice()] {
        let text = String::from_utf8_lossy(payload).into_owned();
        let arm = |f: InetNetworkFn| {
            // SAFETY: `p` is a NUL-terminated string flush against a guard page.
            move |p: *const u8| (unsafe { f(p.cast::<c_char>()) } & 0x3f) as u8
        };
        let host_outcome = probe_payload(payload, arm(host_inet_network));
        let fl_outcome = probe_payload(payload, arm(fl_inet_network));
        println!(
            "CAPPED_GUARD {:<12} payload={text:<8} host={host_outcome:?} fl={fl_outcome:?}",
            "inet_network"
        );
        assert!(
            matches!(host_outcome, Outcome::Code(_)),
            "host glibc must survive inet_network({text:?}) flush against a guard page; \
             got {host_outcome:?} — the fixture is wrong, not fl"
        );
        checked += 1;
        if fl_outcome != host_outcome {
            divergences.push(format!(
                "inet_network payload={text:?}: fl={fl_outcome:?} host={host_outcome:?}"
            ));
        }
    }

    assert_eq!(
        checked,
        PARSER_PAYLOADS.len() * 2 + 2,
        "not every arm ran"
    );
    assert!(
        divergences.is_empty(),
        "capped parsers read past the terminator where glibc did not: {divergences:#?}"
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
