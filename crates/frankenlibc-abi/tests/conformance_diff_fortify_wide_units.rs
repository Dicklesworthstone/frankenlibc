#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // fork-isolated abort probing against a live host oracle

//! Every wide fortify wrapper counts its size in WIDE CHARACTERS, not bytes.
//!
//! ## The defect
//!
//! fl scaled the requested length to bytes (`checked_wide_bytes`) and compared
//! that against the destination size, at eleven call sites. glibc's fortify
//! headers pass `__glibc_objsize (dst) / sizeof (wchar_t)`, so the size is
//! already in wide characters and glibc compares the two directly. fl therefore
//! aborted at a QUARTER of the real capacity — the same "stricter than glibc"
//! shape as `__fgets_chk`'s negative count (bd-ig4hzw) and `__fgetws_chk`'s
//! static rule (bd-917hzv), and the third instance of it in this family.
//!
//! Probed fork-isolated on host glibc 2.42 before any code changed:
//!
//! ```text
//! __wmemset_chk  n=100 destlen=256 -> ok       (byte view would abort: 400 > 256)
//! __wmemcpy_chk  n=100 destlen=256 -> ok
//! __mbstowcs_chk len=100 dstlen=256 -> ok
//! __wmemset_chk  n=300 destlen=256 -> ABORT    (wide view: 300 > 256)
//! __mbstowcs_chk len=257 dstlen=256 -> ABORT
//! __wcscpy_chk   destlen=3, 5-char src -> ABORT
//! ```
//!
//! ## Why every case here is a discriminating one
//!
//! A case where both unit conventions agree cannot catch this and cannot catch a
//! regression of it. Each function below is called once where the views DISAGREE
//! (must not abort) and once where they AGREE that it overflows (must abort), so
//! the gate fails if fl is too strict OR too lax.

use std::ffi::{c_void, c_char};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Outcome {
    Ok,
    Aborted,
}

/// Run `body` in a forked child, with a bounded wait so a wedged child fails the
/// test rather than hanging the run.
fn run(body: impl FnOnce()) -> Outcome {
    // SAFETY: fork; the child only runs `body` and `_exit`s.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        body();
        // SAFETY: child terminating without running atexit handlers.
        unsafe { libc::_exit(0) };
    }
    let mut status = 0i32;
    let started = std::time::Instant::now();
    loop {
        // SAFETY: `pid` is this process's child.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r != 0 {
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "child {pid} did not exit within 20s"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    if libc::WIFSIGNALED(status) {
        Outcome::Aborted
    } else {
        Outcome::Ok
    }
}

fn host(name: &std::ffi::CStr) -> *mut c_void {
    // SAFETY: the process's own libc.
    let h = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!h.is_null(), "dlopen libc.so.6");
    // SAFETY: handle from dlopen; NUL-terminated name.
    let p = unsafe { libc::dlsym(h, name.as_ptr()) };
    assert!(!p.is_null(), "host glibc does not export {name:?}");
    p
}

/// A destination far larger than any `destlen` claimed below, so a CORRECT
/// implementation never runs off it and only the check's arithmetic is under
/// test.
fn wide_dst() -> Vec<u32> {
    vec![0u32; 4096]
}

fn wide_src(len: usize) -> Vec<u32> {
    let mut v = vec![b'x' as u32; len];
    v.push(0);
    v
}

macro_rules! both {
    ($name:literal, $ty:ty, $fl:expr, $call:expr) => {{
        let cname = concat!($name, "\0").as_bytes();
        let cstr = std::ffi::CStr::from_bytes_with_nul(cname).expect("NUL-terminated");
        // SAFETY: the resolved symbol has the signature named by `$ty`.
        let host_f: $ty = unsafe { std::mem::transmute(host(cstr)) };
        // SAFETY: fl's own definition, same signature.
        let fl_f: $ty = unsafe { std::mem::transmute($fl as *const ()) };
        ($name, host_f, fl_f, $call)
    }};
}

type Cpy = unsafe extern "C" fn(*mut u32, *const u32, usize) -> *mut u32;
type NCpy = unsafe extern "C" fn(*mut u32, *const u32, usize, usize) -> *mut u32;
type Set = unsafe extern "C" fn(*mut u32, u32, usize, usize) -> *mut u32;
type Mbs = unsafe extern "C" fn(*mut u32, *const c_char, usize, usize) -> usize;

#[test]
fn wide_fortify_wrappers_count_wide_characters_not_bytes() {
    let mut compared = 0usize;
    let mut aborts = 0usize;
    let mut bad: Vec<String> = Vec::new();

    macro_rules! check {
        ($label:expr, $expect_abort:expr, $host:expr, $fl:expr) => {{
            let h = run($host);
            let m = run($fl);
            if h == Outcome::Aborted {
                aborts += 1;
            }
            if m != h {
                bad.push(format!("{}: fl {m:?}, host {h:?}", $label));
            }
            let expected = if $expect_abort {
                Outcome::Aborted
            } else {
                Outcome::Ok
            };
            if h != expected {
                bad.push(format!(
                    "{}: the HOST gave {h:?} where the probe expected {expected:?}; the \
                     case no longer discriminates",
                    $label
                ));
            }
            compared += 1;
        }};
    }

    // --- __wcscpy_chk: needs strlen(src)+1 wide chars ---
    {
        let (_, hf, mf, _) = both!(
            "__wcscpy_chk",
            Cpy,
            frankenlibc_abi::fortify_abi::__wcscpy_chk,
            ()
        );
        check!("__wcscpy_chk destlen=8 src=5", false,
            || { let mut d = wide_dst(); let s = wide_src(5);
                 // SAFETY: destination is 4096 wide chars; 8 is the CLAIMED size.
                 unsafe { hf(d.as_mut_ptr(), s.as_ptr(), 8) }; },
            || { let mut d = wide_dst(); let s = wide_src(5);
                 // SAFETY: as above, against fl.
                 unsafe { mf(d.as_mut_ptr(), s.as_ptr(), 8) }; });
        check!("__wcscpy_chk destlen=3 src=5", true,
            || { let mut d = wide_dst(); let s = wide_src(5);
                 // SAFETY: as above; 3 < 6 required, so it must abort.
                 unsafe { hf(d.as_mut_ptr(), s.as_ptr(), 3) }; },
            || { let mut d = wide_dst(); let s = wide_src(5);
                 // SAFETY: as above, against fl.
                 unsafe { mf(d.as_mut_ptr(), s.as_ptr(), 3) }; });
    }

    // --- __wmemset_chk / __wmemcpy_chk / __wmemmove_chk: n wide chars ---
    macro_rules! wmem3 {
        ($name:literal, $fl:expr) => {{
            let (_, hf, mf, _) = both!($name, Set, $fl, ());
            check!(concat!($name, " n=100 destlen=256"), false,
                || { let mut d = wide_dst();
                     // SAFETY: 100 wide chars into a 4096-wide buffer.
                     unsafe { hf(d.as_mut_ptr(), b'x' as u32, 100, 256) }; },
                || { let mut d = wide_dst();
                     // SAFETY: as above, against fl.
                     unsafe { mf(d.as_mut_ptr(), b'x' as u32, 100, 256) }; });
            check!(concat!($name, " n=300 destlen=256"), true,
                || { let mut d = wide_dst();
                     // SAFETY: 300 > 256 claimed, so it must abort before writing.
                     unsafe { hf(d.as_mut_ptr(), b'x' as u32, 300, 256) }; },
                || { let mut d = wide_dst();
                     // SAFETY: as above, against fl.
                     unsafe { mf(d.as_mut_ptr(), b'x' as u32, 300, 256) }; });
        }};
    }
    wmem3!("__wmemset_chk", frankenlibc_abi::fortify_abi::__wmemset_chk);

    macro_rules! wcopy {
        ($name:literal, $fl:expr) => {{
            let (_, hf, mf, _) = both!($name, NCpy, $fl, ());
            check!(concat!($name, " n=100 destlen=256"), false,
                || { let mut d = wide_dst(); let s = wide_src(200);
                     // SAFETY: copying 100 wide chars from a 200-char source.
                     unsafe { hf(d.as_mut_ptr(), s.as_ptr(), 100, 256) }; },
                || { let mut d = wide_dst(); let s = wide_src(200);
                     // SAFETY: as above, against fl.
                     unsafe { mf(d.as_mut_ptr(), s.as_ptr(), 100, 256) }; });
            check!(concat!($name, " n=300 destlen=256"), true,
                || { let mut d = wide_dst(); let s = wide_src(400);
                     // SAFETY: 300 > 256 claimed; must abort before writing.
                     unsafe { hf(d.as_mut_ptr(), s.as_ptr(), 300, 256) }; },
                || { let mut d = wide_dst(); let s = wide_src(400);
                     // SAFETY: as above, against fl.
                     unsafe { mf(d.as_mut_ptr(), s.as_ptr(), 300, 256) }; });
        }};
    }
    wcopy!("__wmemcpy_chk", frankenlibc_abi::fortify_abi::__wmemcpy_chk);
    wcopy!("__wmemmove_chk", frankenlibc_abi::fortify_abi::__wmemmove_chk);
    wcopy!("__wcsncpy_chk", frankenlibc_abi::fortify_abi::__wcsncpy_chk);

    // --- __mbstowcs_chk: len wide chars into dstlen wide chars ---
    {
        let (_, hf, mf, _) = both!(
            "__mbstowcs_chk",
            Mbs,
            frankenlibc_abi::fortify_abi::__mbstowcs_chk,
            ()
        );
        check!("__mbstowcs_chk len=100 dstlen=256", false,
            || { let mut d = wide_dst();
                 // SAFETY: converting at most 100 wide chars from a 5-byte string.
                 unsafe { hf(d.as_mut_ptr(), c"hello".as_ptr(), 100, 256) }; },
            || { let mut d = wide_dst();
                 // SAFETY: as above, against fl.
                 unsafe { mf(d.as_mut_ptr(), c"hello".as_ptr(), 100, 256) }; });
        check!("__mbstowcs_chk len=300 dstlen=256", true,
            || { let mut d = wide_dst();
                 // SAFETY: 300 > 256 claimed; must abort.
                 unsafe { hf(d.as_mut_ptr(), c"hello".as_ptr(), 300, 256) }; },
            || { let mut d = wide_dst();
                 // SAFETY: as above, against fl.
                 unsafe { mf(d.as_mut_ptr(), c"hello".as_ptr(), 300, 256) }; });
    }

    println!("compared {compared} wide-fortify cells, {aborts} host aborts");
    for b in &bad {
        println!("  {b}");
    }
    // Non-vacuity: if nothing aborted, the gate would pass against a build with
    // every check deleted.
    assert!(
        aborts >= 4,
        "only {aborts} host aborts observed; this gate cannot see an over-strict \
         OR an absent check without them"
    );
    assert!(bad.is_empty(), "{} divergent cells:\n  {}", bad.len(), bad.join("\n  "));
}
