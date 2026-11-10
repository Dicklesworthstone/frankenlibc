#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // real FILE* streams over a temp file; live host-glibc oracle

//! fgetpos/fsetpos gate (bd-678e8f) — roundtrip arms PLUS a host-glibc
//! differential over the same observable script.
//!
//! WHY THE HOST ARM EXISTS. bd-c4z8fx recorded this gate as unaudited for a
//! single reason: it had no glibc arm to audit. It drove fl's own streams and
//! checked them against fl's own reported offsets, so the claim in the header
//! above — "matches host glibc's observable behaviour" — was an intent rather
//! than a measurement; the file never called glibc. That is the
//! golden-values-wearing-a-differential-name class that
//! `scripts/audit_oracle_arms.py --no-host-arm` reports, and the coverage it
//! appears to contribute is not coverage (bd-reality-202609-lx578q.7).
//!
//! `fgetpos`, `fsetpos`, `ftell`, `ftello64`, `fgetpos64` and `fsetpos64` all
//! exist in host libc, so a real oracle is available. Resolution goes through
//! `common/dlsym_oracle`, which asserts the resolved address is NOT fl's own
//! export: fl exports every one of these symbols into this same test binary, so
//! a link-time declaration is only an oracle as long as the linker happens to
//! choose libc.so.6 instead. In a release-profile run it never does.
//!
//! WHAT IS COMPARED, AND WHY NOT THE BYTES OF `fpos_t`. `fpos_t` is opaque and
//! its layout is implementation-defined; POSIX only requires that a value
//! written by `fgetpos` and handed back to `fsetpos` on the same stream restore
//! the position. Comparing the struct would be asserting a layout, so the script
//! compares what a caller observes: return codes, the offsets `ftell`/`ftello64`
//! report, and the bytes a re-read returns. The `*64` scratch buffer is zeroed
//! and never inspected for the same reason.
//!
//! NULL-POINTER ARMS ARE NOT DIFFERENTIAL, DELIBERATELY. glibc dereferences a
//! null stream; fl returns -1/EINVAL. That divergence is FrankenLibC's specified
//! contract, so it is asserted against fl's documented behaviour rather than
//! compared against a call glibc does not survive.

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::stdio_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::{host_addr, host_fn};

static CNT: AtomicU64 = AtomicU64::new(0);
fn tmp_with(content: &[u8]) -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fgetpos-{}-{}", std::process::id(), n));
    std::fs::write(&p, content).unwrap();
    let c = CString::new(p.to_string_lossy().as_bytes()).unwrap();
    (p, c)
}

// ---------------------------------------------------------------------------
// The differential script: one sequence of observable calls, run against fl and
// against host glibc, compared line for line.
// ---------------------------------------------------------------------------

type Fopen = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type Fclose = unsafe extern "C-unwind" fn(*mut c_void) -> c_int;
type Fread = unsafe extern "C-unwind" fn(*mut c_void, usize, usize, *mut c_void) -> usize;
type Ftell = unsafe extern "C-unwind" fn(*mut c_void) -> c_long;
type Fgetpos = unsafe extern "C-unwind" fn(*mut c_void, *mut libc::fpos_t) -> c_int;
type Fsetpos = unsafe extern "C-unwind" fn(*mut c_void, *const libc::fpos_t) -> c_int;
type Fgetpos64 = unsafe extern "C-unwind" fn(*mut c_void, *mut c_void) -> c_int;
type Fsetpos64 = unsafe extern "C-unwind" fn(*mut c_void, *const c_void) -> c_int;
type Ftello64 = unsafe extern "C-unwind" fn(*mut c_void) -> i64;
type Fdopen = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_void;
type Fgetc = unsafe extern "C-unwind" fn(*mut c_void) -> c_int;
type Ungetc = unsafe extern "C-unwind" fn(c_int, *mut c_void) -> c_int;
type Fwrite = unsafe extern "C-unwind" fn(*const c_void, usize, usize, *mut c_void) -> usize;
type Fseek = unsafe extern "C-unwind" fn(*mut c_void, c_long, c_int) -> c_int;
type Fopencookie =
    unsafe extern "C" fn(*mut c_void, *const c_char, fl::CookieIoFuncs) -> *mut c_void;

/// One implementation's entry points, all resolved to the same provider.
struct Streams {
    fopen: Fopen,
    fclose: Fclose,
    fread: Fread,
    ftell: Ftell,
    fgetpos: Fgetpos,
    fsetpos: Fsetpos,
    fgetpos64: Fgetpos64,
    fsetpos64: Fsetpos64,
    ftello64: Ftello64,
    fdopen: Fdopen,
    fgetc: Fgetc,
    ungetc: Ungetc,
    fwrite: Fwrite,
    fseek: Fseek,
    ferror: Fgetc,
    fopencookie: Fopencookie,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Run the full script and return every observable result, in order.
///
/// The two arms must produce IDENTICAL vectors: any difference is a real
/// divergence in position reporting or in the bytes a restore re-reads.
unsafe fn run_script(s: &Streams, path: &CStr) -> Vec<String> {
    let mut t: Vec<String> = Vec::new();
    // SAFETY: every pointer passed here is either freshly created by this
    // function (the stream), a stack buffer of the stated length, or the
    // caller-owned path. Signature types are declared above and match the C
    // prototypes of the resolved symbols.
    unsafe {
        let f = (s.fopen)(path.as_ptr(), c"r".as_ptr());
        t.push(format!("fopen_is_null={}", f.is_null()));
        if f.is_null() {
            return t;
        }

        let mut buf = [0u8; 3];
        let n = (s.fread)(buf.as_mut_ptr().cast(), 1, 3, f);
        t.push(format!("read3={n}:{}", hex(&buf[..n.min(3)])));
        t.push(format!("ftell_at_3={}", (s.ftell)(f)));

        // Save position 3, read past it, restore, and re-read.
        let mut pos: libc::fpos_t = std::mem::zeroed();
        t.push(format!("fgetpos={}", (s.fgetpos)(f, &mut pos)));
        let n = (s.fread)(buf.as_mut_ptr().cast(), 1, 3, f);
        t.push(format!("read3b={n}:{}", hex(&buf[..n.min(3)])));
        t.push(format!("ftell_at_6={}", (s.ftell)(f)));

        t.push(format!("fsetpos={}", (s.fsetpos)(f, &pos)));
        t.push(format!("ftell_restored={}", (s.ftell)(f)));
        let n = (s.fread)(buf.as_mut_ptr().cast(), 1, 3, f);
        t.push(format!("reread3={n}:{}", hex(&buf[..n.min(3)])));

        // The 64-bit pair at offset 6, through a zeroed 16-byte opaque slot.
        let mut pos64 = [0u8; 16];
        t.push(format!(
            "fgetpos64={}",
            (s.fgetpos64)(f, pos64.as_mut_ptr().cast())
        ));
        t.push(format!("ftello64_at_6={}", (s.ftello64)(f)));
        let mut rest = [0u8; 4];
        let n = (s.fread)(rest.as_mut_ptr().cast(), 1, 4, f);
        t.push(format!("read4={n}:{}", hex(&rest[..n.min(4)])));
        t.push(format!(
            "fsetpos64={}",
            (s.fsetpos64)(f, pos64.as_ptr().cast())
        ));
        t.push(format!("ftello64_restored={}", (s.ftello64)(f)));
        let n = (s.fread)(rest.as_mut_ptr().cast(), 1, 4, f);
        t.push(format!("reread4={n}:{}", hex(&rest[..n.min(4)])));

        // Read the remainder to EOF: the offset at EOF must agree too.
        let mut tail = [0u8; 32];
        let n = (s.fread)(tail.as_mut_ptr().cast(), 1, 32, f);
        t.push(format!("read_tail={n}:{}", hex(&tail[..n.min(32)])));
        t.push(format!("ftell_at_eof={}", (s.ftell)(f)));

        t.push(format!("fclose={}", (s.fclose)(f)));
    }
    t
}

fn fl_streams() -> Streams {
    Streams {
        fopen: fl::fopen,
        fclose: fl::fclose,
        fread: fl::fread,
        ftell: fl::ftell,
        fgetpos: fl::fgetpos,
        fsetpos: fl::fsetpos,
        fgetpos64: fl::fgetpos64,
        fsetpos64: fl::fsetpos64,
        ftello64: fl::ftello64,
        fdopen: fl::fdopen,
        fgetc: fl::fgetc,
        ungetc: fl::ungetc,
        fwrite: fl::fwrite,
        fseek: fl::fseek,
        ferror: fl::ferror,
        fopencookie: fl::fopencookie,
    }
}

/// Host glibc, resolved explicitly and rejected if it aliases fl's own export.
///
/// # Safety
///
/// The `F` type parameters must match each symbol's C prototype; the declared
/// type aliases above do.
fn host_streams() -> Streams {
    // SAFETY: each resolved address is given the declared type of the C
    // prototype and is checked against fl's own definition inside `host_fn`,
    // which panics rather than handing back an arm that IS fl.
    unsafe {
        Streams {
            fopen: host_fn(c"fopen", fl::fopen as *const ()),
            fclose: host_fn(c"fclose", fl::fclose as *const ()),
            fread: host_fn(c"fread", fl::fread as *const ()),
            ftell: host_fn(c"ftell", fl::ftell as *const ()),
            fgetpos: host_fn(c"fgetpos", fl::fgetpos as *const ()),
            fsetpos: host_fn(c"fsetpos", fl::fsetpos as *const ()),
            fgetpos64: host_fn(c"fgetpos64", fl::fgetpos64 as *const ()),
            fsetpos64: host_fn(c"fsetpos64", fl::fsetpos64 as *const ()),
            ftello64: host_fn(c"ftello64", fl::ftello64 as *const ()),
            fdopen: host_fn(c"fdopen", fl::fdopen as *const ()),
            fgetc: host_fn(c"fgetc", fl::fgetc as *const ()),
            ungetc: host_fn(c"ungetc", fl::ungetc as *const ()),
            fwrite: host_fn(c"fwrite", fl::fwrite as *const ()),
            fseek: host_fn(c"fseek", fl::fseek as *const ()),
            ferror: host_fn(c"ferror", fl::ferror as *const ()),
            fopencookie: host_fn(c"fopencookie", fl::fopencookie as *const ()),
        }
    }
}

#[test]
fn fgetpos_fsetpos_match_host_glibc_trace() {
    let (path, c) = tmp_with(b"ABCDEFGHIJ");
    let fl_trace = unsafe { run_script(&fl_streams(), &c) };
    let host_trace = unsafe { run_script(&host_streams(), &c) };
    let _ = std::fs::remove_file(&path);

    // Pinned glibc reference values, so a host glibc change is visible rather
    // than silently absorbed into a passing comparison. This also makes the
    // comparison non-vacuous: a script that bailed out at the first call (for
    // example `fopen_is_null=true`, or an arm that returned early) would
    // otherwise compare equal to a similarly truncated run.
    let expected = vec![
        "fopen_is_null=false",
        "read3=3:414243",
        "ftell_at_3=3",
        "fgetpos=0",
        "read3b=3:444546",
        "ftell_at_6=6",
        "fsetpos=0",
        "ftell_restored=3",
        "reread3=3:444546",
        "fgetpos64=0",
        "ftello64_at_6=6",
        "read4=4:4748494a",
        "fsetpos64=0",
        "ftello64_restored=6",
        "reread4=4:4748494a",
        "read_tail=0:",
        "ftell_at_eof=10",
        "fclose=0",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    assert_eq!(
        host_trace, expected,
        "host glibc reference trace changed; re-derive the pinned values"
    );
    assert_eq!(
        fl_trace, host_trace,
        "fgetpos/fsetpos observable trace diverged from host glibc"
    );
}

/// The provider-identity control. A gate whose "glibc" arm resolves to fl's own
/// export would compare fl against itself and pass unconditionally; this asserts
/// that the resolver refuses that case rather than returning it.
#[test]
fn fgetpos_oracle_rejects_identical_candidate_provider() {
    // SAFETY: only resolves and compares code addresses; no mismatched call.
    let host = unsafe { host_addr(c"fgetpos", fl::fgetpos as *const ()) };
    let rejected = std::panic::catch_unwind(|| unsafe {
        host_addr(c"fgetpos", host.cast());
    });
    let error = rejected.expect_err("an identical candidate/oracle provider must be rejected");
    let message = error
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied())
        .expect("provider rejection must report a diagnostic");
    assert!(
        message.contains("IS fl's own definition"),
        "expected the provider-identity rejection, got: {message}"
    );
}

/// FrankenLibC's specified null-argument contract, which glibc does not share
/// (it dereferences) and which therefore cannot be a differential arm.
#[test]
fn fgetpos_null_arguments_follow_the_specified_fl_contract() {
    // SAFETY: the whole point is that these calls do not touch the pointers.
    unsafe {
        let errno_loc = frankenlibc_abi::errno_abi::__errno_location;
        assert_eq!(fl::fgetpos(std::ptr::null_mut(), std::ptr::null_mut()), -1);
        assert_eq!(*errno_loc(), libc::EINVAL);

        let (path, c) = tmp_with(b"xy");
        let f = fl::fopen(c.as_ptr().cast::<c_char>(), c"r".as_ptr().cast::<c_char>());
        assert!(!f.is_null());
        assert_eq!(fl::fgetpos(f, std::ptr::null_mut()), -1);
        assert_eq!(fl::fsetpos(f, std::ptr::null()), -1);
        assert_eq!(fl::fclose(f), 0);
        let _ = std::fs::remove_file(&path);
    }
}

// ---------------------------------------------------------------------------
// Roundtrip arms, unchanged from bd-678e8f: these pin fl's own stream
// behaviour independently of the oracle above (a divergence in BOTH arms
// would cancel out of the comparison but must not pass here).
// ---------------------------------------------------------------------------

#[test]
fn fgetpos_fsetpos_roundtrip() {
    let (path, c) = tmp_with(b"ABCDEFGHIJ");
    let f = unsafe { fl::fopen(c.as_ptr().cast::<c_char>(), c"r".as_ptr().cast::<c_char>()) };
    assert!(!f.is_null());

    let mut buf = [0u8; 3];
    // Read "ABC".
    assert_eq!(unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, 3, f) }, 3);
    assert_eq!(&buf, b"ABC");

    // Save position (offset 3).
    let mut pos: libc::fpos_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { fl::fgetpos(f, &mut pos) },
        0,
        "fgetpos should succeed"
    );
    assert_eq!(
        unsafe { fl::ftell(f) },
        3,
        "position should be 3 after reading ABC"
    );

    // Read "DEF".
    assert_eq!(unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, 3, f) }, 3);
    assert_eq!(&buf, b"DEF");

    // Restore to offset 3, re-read -> "DEF" again.
    assert_eq!(unsafe { fl::fsetpos(f, &pos) }, 0, "fsetpos should succeed");
    assert_eq!(unsafe { fl::ftell(f) }, 3, "fsetpos must restore offset 3");
    buf = [0u8; 3];
    assert_eq!(unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, 3, f) }, 3);
    assert_eq!(&buf, b"DEF", "re-read after fsetpos must match");

    unsafe { fl::fclose(f) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fsetpos_to_start_rereads_whole_file() {
    let (path, c) = tmp_with(b"hello world");
    let f = unsafe { fl::fopen(c.as_ptr().cast::<c_char>(), c"r".as_ptr().cast::<c_char>()) };
    assert!(!f.is_null());

    // Save start, read everything, restore start, read first 5.
    let mut start: libc::fpos_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { fl::fgetpos(f, &mut start) }, 0);
    let mut all = [0u8; 11];
    assert_eq!(unsafe { fl::fread(all.as_mut_ptr().cast(), 1, 11, f) }, 11);
    assert_eq!(&all, b"hello world");

    assert_eq!(unsafe { fl::fsetpos(f, &start) }, 0);
    let mut five = [0u8; 5];
    assert_eq!(unsafe { fl::fread(five.as_mut_ptr().cast(), 1, 5, f) }, 5);
    assert_eq!(
        &five, b"hello",
        "fsetpos to start must re-read from the beginning"
    );

    unsafe { fl::fclose(f) };
    let _ = std::fs::remove_file(&path);
}

/// Failure must not partially publish an opaque position, nor turn a seek
/// failure into a read/write error on the stream.
unsafe fn failed_position(s: &Streams, f: *mut c_void, large: bool) -> (c_int, c_int, bool, c_int) {
    let mut pos = std::mem::MaybeUninit::<libc::fpos_t>::uninit();
    // SAFETY: all bytes of this aligned local object are writable; only a
    // failure is inspected, so no opaque position value is interpreted.
    unsafe {
        std::ptr::write_bytes(
            pos.as_mut_ptr().cast::<u8>(),
            0xa5,
            size_of::<libc::fpos_t>(),
        );
        *libc::__errno_location() = 0;
        let result = if large {
            (s.fgetpos64)(f, pos.as_mut_ptr().cast())
        } else {
            (s.fgetpos)(f, pos.as_mut_ptr())
        };
        let error = *libc::__errno_location();
        let untouched =
            std::slice::from_raw_parts(pos.as_ptr().cast::<u8>(), size_of::<libc::fpos_t>())
                .iter()
                .all(|&byte| byte == 0xa5);
        (result, error, untouched, (s.ferror)(f))
    }
}

#[test]
fn nonseekable_positions_match_host_before_and_after_cached_reads() {
    for socket in [false, true] {
        for s in [host_streams(), fl_streams()] {
            // SAFETY: the pipe/socket pair is local; fdopen owns the read end,
            // and one available byte prevents the cache-priming read blocking.
            unsafe {
                let mut fds = [-1; 2];
                assert_eq!(
                    if socket {
                        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
                    } else {
                        libc::pipe(fds.as_mut_ptr())
                    },
                    0
                );
                assert_eq!(libc::write(fds[1], b"Q".as_ptr().cast(), 1), 1);
                let f = (s.fdopen)(fds[0], c"r".as_ptr());
                assert!(!f.is_null());
                for warm in [false, true] {
                    if warm {
                        assert_eq!((s.fgetc)(f), b'Q' as c_int);
                    }
                    for large in [false, true] {
                        assert_eq!(
                            failed_position(&s, f, large),
                            (-1, libc::ESPIPE, true, 0),
                            "socket={socket} warm={warm} large={large}"
                        );
                    }
                }
                assert_eq!((s.fclose)(f), 0);
                assert_eq!(libc::close(fds[1]), 0);
            }
        }
    }
}

#[test]
fn append_positions_do_not_flush_and_restore_the_pending_end() {
    for s in [host_streams(), fl_streams()] {
        let (path, name) = tmp_with(b"ABCDEF");
        // SAFETY: each provider owns its stream; saved positions are used
        // only with the stream that produced them, and every buffer is live.
        unsafe {
            let f = (s.fopen)(name.as_ptr(), c"a+".as_ptr());
            assert!(!f.is_null());
            assert_eq!((s.fwrite)(b"XY".as_ptr().cast(), 1, 2, f), 2);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 6);
            let mut pos = std::mem::MaybeUninit::<libc::fpos_t>::zeroed();
            let mut pos64 = std::mem::MaybeUninit::<libc::fpos_t>::zeroed();
            assert_eq!((s.fgetpos)(f, pos.as_mut_ptr()), 0);
            assert_eq!((s.ftell)(f), 8);
            assert_eq!((s.fgetpos64)(f, pos64.as_mut_ptr().cast()), 0);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 6);
            assert_eq!((s.fwrite)(b"Z".as_ptr().cast(), 1, 1, f), 1);
            assert_eq!((s.fsetpos)(f, pos.as_ptr()), 0);
            assert_eq!((s.fgetc)(f), b'Z' as c_int);
            assert_eq!((s.fsetpos64)(f, pos64.as_ptr().cast()), 0);
            assert_eq!((s.fgetc)(f), b'Z' as c_int);
            assert_eq!((s.fclose)(f), 0);
        }
    }
}

struct PositionCookie {
    position: i64,
    end: usize,
    data: [u8; 32],
    writes: usize,
    seek_error: c_int,
    panic_on_seek: std::cell::Cell<bool>,
}

impl PositionCookie {
    fn new() -> Self {
        let mut data = [0; 32];
        data[..10].copy_from_slice(b"ABCDEFGHIJ");
        Self {
            position: 4,
            end: 10,
            data,
            writes: 0,
            seek_error: 0,
            panic_on_seek: std::cell::Cell::new(false),
        }
    }
}

unsafe extern "C-unwind" fn position_read(
    cookie: *mut c_void,
    dst: *mut c_char,
    n: usize,
) -> isize {
    // SAFETY: the test keeps its cookie and the provider's output buffer live.
    let cookie = unsafe { &mut *cookie.cast::<PositionCookie>() };
    let start = cookie.position as usize;
    let count = n.min(cookie.end.saturating_sub(start));
    if count != 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(cookie.data.as_ptr().add(start), dst.cast(), count)
        };
        cookie.position += count as i64;
    }
    count as isize
}

unsafe extern "C-unwind" fn position_write(
    cookie: *mut c_void,
    src: *const c_char,
    n: usize,
) -> isize {
    // SAFETY: callback storage and the provider's input buffer remain live.
    let cookie = unsafe { &mut *cookie.cast::<PositionCookie>() };
    let start = cookie.position as usize;
    let count = n.min(cookie.data.len().saturating_sub(start));
    if count != 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(src.cast(), cookie.data.as_mut_ptr().add(start), count)
        };
        cookie.position += count as i64;
        cookie.end = cookie.end.max(start + count);
    }
    cookie.writes += 1;
    count as isize
}

unsafe extern "C-unwind" fn position_seek(
    cookie: *mut c_void,
    offset: *mut i64,
    whence: c_int,
) -> c_int {
    // SAFETY: the test supplies its live cookie and stdio supplies an offset.
    let cookie = unsafe { &mut *cookie.cast::<PositionCookie>() };
    assert!(!cookie.panic_on_seek.get(), "position callback unwind");
    if cookie.seek_error != 0 {
        unsafe { *libc::__errno_location() = cookie.seek_error };
        return -1;
    }
    let base = match whence {
        libc::SEEK_SET => 0,
        libc::SEEK_CUR => cookie.position,
        libc::SEEK_END => cookie.end as i64,
        _ => unreachable!("stdio must validate the seek origin"),
    };
    let Some(position) = base.checked_add(unsafe { *offset }).filter(|&p| p >= 0) else {
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return -1;
    };
    cookie.position = position;
    unsafe { *offset = position };
    0
}

fn position_callbacks() -> fl::CookieIoFuncs {
    fl::CookieIoFuncs {
        read: Some(position_read),
        write: Some(position_write),
        seek: Some(position_seek),
        close: None,
    }
}

#[test]
fn cookie_positions_use_callbacks_and_preserve_input_on_failed_queries() {
    for s in [host_streams(), fl_streams()] {
        let mut cookie = PositionCookie::new();
        // SAFETY: the stack cookie outlives the stream and all callbacks.
        unsafe {
            let f = (s.fopencookie)(
                std::ptr::from_mut(&mut cookie).cast(),
                c"r+".as_ptr(),
                position_callbacks(),
            );
            assert!(!f.is_null());
            let mut saved = std::mem::MaybeUninit::<libc::fpos_t>::zeroed();
            assert_eq!((s.fgetpos)(f, saved.as_mut_ptr()), 0);
            assert_eq!((s.ftell)(f), 4);
            assert_eq!((s.fgetc)(f), b'E' as c_int);
            assert_eq!((s.ungetc)(b'X' as c_int, f), b'X' as c_int);
            assert_eq!((s.ftello64)(f), 4);
            assert_eq!((s.fseek)(f, 0, libc::SEEK_CUR), 0);
            assert_eq!((s.fgetc)(f), b'E' as c_int);
            assert_eq!((s.fsetpos)(f, saved.as_ptr()), 0);
            assert_eq!((s.fgetc)(f), b'E' as c_int);
            assert_eq!((s.ungetc)(b'Y' as c_int, f), b'Y' as c_int);
            cookie.seek_error = libc::EACCES;
            for large in [false, true] {
                assert_eq!(failed_position(&s, f, large), (-1, libc::EACCES, true, 0));
            }
            assert_eq!((s.fgetc)(f), b'Y' as c_int);
            *libc::__errno_location() = 0;
            assert_eq!((s.fsetpos)(f, saved.as_ptr()), -1);
            assert_eq!(*libc::__errno_location(), libc::EACCES);
            assert_eq!((s.ferror)(f), 0);
            cookie.seek_error = 0;
            assert_eq!((s.fsetpos)(f, saved.as_ptr()), 0);
            assert_eq!((s.fgetc)(f), b'E' as c_int);
            assert_eq!((s.fclose)(f), 0);
        }
    }
}

#[test]
fn cookie_positions_count_pending_output_without_writing_it() {
    for s in [host_streams(), fl_streams()] {
        for (mode, expected) in [(c"w", 6), (c"a", 12)] {
            let mut cookie = PositionCookie::new();
            // SAFETY: each cookie stays live until its stream is closed.
            unsafe {
                let f = (s.fopencookie)(
                    std::ptr::from_mut(&mut cookie).cast(),
                    mode.as_ptr(),
                    position_callbacks(),
                );
                assert!(!f.is_null());
                assert_eq!((s.fwrite)(b"XY".as_ptr().cast(), 1, 2, f), 2);
                let mut saved = std::mem::MaybeUninit::<libc::fpos_t>::zeroed();
                assert_eq!((s.fgetpos64)(f, saved.as_mut_ptr().cast()), 0);
                assert_eq!((s.ftell)(f), expected);
                assert_eq!(cookie.writes, 0, "position queries must not write output");
                assert_eq!(&cookie.data[..10], b"ABCDEFGHIJ");
                assert_eq!((s.fsetpos64)(f, saved.as_ptr().cast()), 0);
                assert_eq!(cookie.position, expected);
                assert_eq!(cookie.writes, 1);
                assert_eq!((s.fclose)(f), 0);
            }
        }
    }
}

#[test]
fn missing_cookie_seek_reports_position_failure_without_inventing_an_offset() {
    for s in [host_streams(), fl_streams()] {
        // SAFETY: no callbacks dereference the null cookie.
        unsafe {
            let f = (s.fopencookie)(
                std::ptr::null_mut(),
                c"r".as_ptr(),
                fl::CookieIoFuncs::default(),
            );
            assert!(!f.is_null());
            for large in [false, true] {
                assert_eq!(failed_position(&s, f, large), (-1, libc::EIO, true, 0));
            }
            *libc::__errno_location() = libc::EDOM;
            assert_eq!((s.ftell)(f), -1);
            assert_eq!(*libc::__errno_location(), libc::EDOM);
            assert_eq!((s.fclose)(f), 0);
        }
    }
}

#[test]
fn host_owned_wide_stream_positions_preserve_multibyte_boundaries() {
    use frankenlibc_abi::{locale_abi, wchar_abi};

    type NewLocale = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_void;
    type UseLocale = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
    type FreeLocale = unsafe extern "C" fn(*mut c_void);
    type GetWide = unsafe extern "C-unwind" fn(*mut c_void) -> u32;
    struct HostLocale {
        current: *mut c_void,
        previous: *mut c_void,
        select: UseLocale,
        free: FreeLocale,
    }
    impl Drop for HostLocale {
        fn drop(&mut self) {
            // SAFETY: restore the thread's previous selection before freeing
            // this test's host-owned locale.
            unsafe {
                (self.select)(self.previous);
                (self.free)(self.current);
            }
        }
    }

    // SAFETY: every oracle is resolved against the host provider with its ABI
    // signature checked here, and the locale selection affects only this thread.
    unsafe {
        let new_locale: NewLocale = host_fn(c"newlocale", locale_abi::newlocale as *const ());
        let select: UseLocale = host_fn(c"uselocale", locale_abi::uselocale as *const ());
        let free: FreeLocale = host_fn(c"freelocale", locale_abi::freelocale as *const ());
        let current = new_locale(
            libc::LC_CTYPE_MASK,
            c"C.UTF-8".as_ptr(),
            std::ptr::null_mut(),
        );
        assert!(
            !current.is_null(),
            "C.UTF-8 locale is required by this gate"
        );
        let previous = select(current);
        assert!(!previous.is_null());
        let _locale = HostLocale {
            current,
            previous,
            select,
            free,
        };
        let get_wide: GetWide = host_fn(c"fgetwc", wchar_abi::fgetwc as *const ());
        let end_of_file: Fgetc = host_fn(c"feof", fl::feof as *const ());
        let host = host_streams();
        let (_path, name) = tmp_with("Aé😀Z".as_bytes());
        // Both arms use an actual host-owned wide FILE. The native arm must
        // forward the opaque positions to that owner, including conversion
        // state, rather than reinterpret them as a native byte-only position.
        for native_positions in [false, true] {
            let s = if native_positions {
                fl_streams()
            } else {
                host_streams()
            };
            let f = (host.fopen)(name.as_ptr(), c"r".as_ptr());
            assert!(!f.is_null());
            assert_eq!(get_wide(f), 'A' as u32);
            let mut saved = std::mem::MaybeUninit::<libc::fpos_t>::zeroed();
            let mut saved64 = std::mem::MaybeUninit::<libc::fpos_t>::zeroed();
            assert_eq!((s.fgetpos)(f, saved.as_mut_ptr()), 0);
            assert_eq!(get_wide(f), 'é' as u32);
            assert_eq!((s.fgetpos64)(f, saved64.as_mut_ptr().cast()), 0);
            assert_eq!(get_wide(f), '😀' as u32);
            assert_eq!(get_wide(f), 'Z' as u32);
            assert_eq!(get_wide(f), u32::MAX);
            assert_ne!(end_of_file(f), 0);
            assert_eq!((s.fsetpos)(f, saved.as_ptr()), 0);
            assert_eq!(end_of_file(f), 0);
            assert_eq!(get_wide(f), 'é' as u32);
            assert_eq!((s.fsetpos64)(f, saved64.as_ptr().cast()), 0);
            assert_eq!(get_wide(f), '😀' as u32);
            assert_eq!((host.fclose)(f), 0);
        }
    }
}

#[test]
fn cookie_position_overflow_matches_host_without_publishing_or_flushing() {
    for s in [host_streams(), fl_streams()] {
        let mut cookie = PositionCookie::new();
        cookie.position = i64::MAX - 1;
        // SAFETY: the backend cursor is queried without indexing storage;
        // restore it to the buffer before any pending output is flushed.
        unsafe {
            let f = (s.fopencookie)(
                std::ptr::from_mut(&mut cookie).cast(),
                c"w".as_ptr(),
                position_callbacks(),
            );
            assert!(!f.is_null());
            assert_eq!((s.fwrite)(b"XY".as_ptr().cast(), 1, 2, f), 2);
            for large in [false, true] {
                assert_eq!(failed_position(&s, f, large), (-1, libc::EINVAL, true, 0));
            }
            assert_eq!(cookie.writes, 0);
            assert_eq!(&cookie.data[..10], b"ABCDEFGHIJ");
            cookie.position = 4;
            assert_eq!((s.fclose)(f), 0);
        }
    }
}

#[test]
fn native_cookie_position_unwind_releases_locks_and_preserves_the_stream() {
    use frankenlibc_abi::{glibc_internal_abi, io_internal_abi};

    let mut cookie = PositionCookie::new();
    // SAFETY: the native stream and cookie remain live across caught Rust
    // unwinds; all public/alias boundaries are explicitly C-unwind.
    unsafe {
        let f = fl::fopencookie(
            std::ptr::from_mut(&mut cookie).cast(),
            c"r+".as_ptr(),
            position_callbacks(),
        );
        assert!(!f.is_null());
        let mut saved = std::mem::MaybeUninit::<libc::fpos_t>::zeroed();
        assert_eq!(fl::fgetpos(f, saved.as_mut_ptr()), 0);
        for operation in 0..15 {
            cookie.panic_on_seek.set(true);
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match operation {
                    0 => {
                        fl::ftell(f);
                    }
                    1 => {
                        fl::fgetpos(f, saved.as_mut_ptr());
                    }
                    2 => {
                        fl::fgetpos64(f, saved.as_mut_ptr().cast());
                    }
                    3 => {
                        fl::fsetpos(f, saved.as_ptr());
                    }
                    4 => {
                        io_internal_abi::_IO_ftell(f);
                    }
                    5 => {
                        io_internal_abi::_IO_fgetpos(f, saved.as_mut_ptr().cast());
                    }
                    6 => {
                        io_internal_abi::_IO_fgetpos64(f, saved.as_mut_ptr().cast());
                    }
                    7 => {
                        io_internal_abi::_IO_fsetpos64(f, saved.as_ptr().cast());
                    }
                    8 => {
                        io_internal_abi::_IO_fsetpos(f, saved.as_ptr().cast());
                    }
                    9 => {
                        glibc_internal_abi::__fseeko64(f, 0, libc::SEEK_CUR);
                    }
                    10 => {
                        glibc_internal_abi::__ftello64(f);
                    }
                    11 => {
                        fl::ftello64(f);
                    }
                    12 => {
                        fl::fseek(f, 0, libc::SEEK_CUR);
                    }
                    13 => {
                        fl::fseeko64(f, 0, libc::SEEK_CUR);
                    }
                    _ => {
                        fl::fsetpos64(f, saved.as_ptr().cast());
                    }
                }));
            assert!(
                result.is_err(),
                "operation {operation} did not invoke its seek callback"
            );
            cookie.panic_on_seek.set(false);
            assert_eq!(fl::ftell(f), 4);
            assert_eq!(fl::ferror(f), 0);
        }
        assert_eq!(fl::fclose(f), 0);
    }
}
