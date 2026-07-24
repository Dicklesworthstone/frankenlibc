//! In-process fread-fmemopen A/B under thread contention (cc_fl/MagentaCondor,
//! cc-fread-mem-2026-07-11 retry round 2).
//!
//! WHY THIS EXISTS. The parked fread-fmemopen pointer-cursor lever cannot be resolved by
//! `stdio_mt_contention_bench`: that harness spawns N threads, allocates the source Vec,
//! and opens/closes N `fmemopen` streams inside EVERY measured iteration, so spawn +
//! allocator noise dominate. Its 2026-07-22 12-round two-binary A/B FAILED ITS NULL
//! CONTROL (the identical-code fgetc arm "moved" 8.4% at 8 threads, per-arm CVs 33-43%)
//! and 7/12 base runs died in the fl-malloc NULL-return abort (bd-ummyux) triggered by
//! that same churn. This harness follows `stdio_mapper_mt_ab.rs`: threads spawned ONCE,
//! barrier-synced rounds, per-thread timing, source buffers allocated ONCE — the drain
//! workload (fmemopen + 64 freads + fclose) stays intact because stream lifecycle IS the
//! workload the lever targets, but nothing else churns.
//!
//! WHAT IS MEASURED. Per round, each thread performs `K` cycles of: open its OWN
//! `fmemopen(_, N, "r")` stream over a pre-allocated buffer, drain it with `N/CHUNK`
//! calls to `fread(buf, 1, CHUNK, fp)`, close it. Arms:
//!   * `fl`    - the deployed FrankenLibC `fread` path (whatever is linked in this binary;
//!               old-vs-new is compared ACROSS two binaries built with/without the lever,
//!               alternated at the process level by the runner).
//!   * `glibc` - host glibc via `dlmopen(LM_ID_NEWLM)` (immune to symbol interposition),
//!               the within-binary substrate canary: the cross-binary comparator is the
//!               fl/glibc RATIO, which cancels worker drift and code-layout luck.
//!
//! `verify()` runs first: one fl drain and one glibc drain over the same content must
//! agree on every returned byte and every per-call return count — a dead-code arm or a
//! divergent fast path aborts before any timing.
//!
//! Run: `cargo run --release -p frankenlibc-bench --features abi-bench --example stdio_fread_mem_mt_ab`

use std::ffi::{c_char, c_int, c_void};
use std::hint::black_box;
use std::sync::{Barrier, OnceLock};
use std::time::Instant;

use frankenlibc_abi::stdio_abi as fl;

/// Stream size in bytes; matches the parked lever's original bench arm.
const N: usize = 4096;
/// fread element count per call ⇒ N/CHUNK = 64 fread calls per drain.
const CHUNK: usize = 64;
/// Open-drain-close cycles per thread per round (amortizes barrier + timer overhead).
const K: usize = 25;
/// Timed rounds per arm (first `WARMUP` discarded).
const ROUNDS: usize = 60;
const WARMUP: usize = 5;

type FmemopenFn = unsafe extern "C" fn(*mut c_void, usize, *const c_char) -> *mut c_void;
type FopenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type FreadFn = unsafe extern "C" fn(*mut c_void, usize, usize, *mut c_void) -> usize;
type FgetsFn = unsafe extern "C" fn(*mut c_char, c_int, *mut c_void) -> *mut c_char;
type FgetcFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type FeofFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type FtellFn = unsafe extern "C" fn(*mut c_void) -> libc::c_long;
type UngetcFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
type FflushFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type FgetposFn = unsafe extern "C" fn(*mut c_void, *mut libc::fpos_t) -> c_int;
type GetlineFn = unsafe extern "C" fn(*mut *mut c_char, *mut usize, *mut c_void) -> isize;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type MallocFn = unsafe extern "C" fn(usize) -> *mut c_void;
type FputsFn = unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int;
type FputcFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
type FseekFn = unsafe extern "C" fn(*mut c_void, libc::c_long, c_int) -> c_int;
type FcloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;

struct HostStdio {
    fmemopen: FmemopenFn,
    fopen: FopenFn,
    fread: FreadFn,
    fgets: FgetsFn,
    fgetc: FgetcFn,
    feof: FeofFn,
    ftell: FtellFn,
    ungetc: UngetcFn,
    fflush: FflushFn,
    fgetpos: FgetposFn,
    getline: GetlineFn,
    free: FreeFn,
    malloc: MallocFn,
    fputs: FputsFn,
    fputc: FputcFn,
    fseek: FseekFn,
    fclose: FcloseFn,
}

fn host() -> &'static HostStdio {
    static H: OnceLock<HostStdio> = OnceLock::new();
    H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc.so.6 failed");
        let sym = |n: &[u8]| {
            let p = libc::dlsym(h, n.as_ptr().cast());
            assert!(!p.is_null(), "dlsym {:?} failed", std::str::from_utf8(n));
            p
        };
        HostStdio {
            fmemopen: std::mem::transmute::<*mut c_void, FmemopenFn>(sym(b"fmemopen\0")),
            fopen: std::mem::transmute::<*mut c_void, FopenFn>(sym(b"fopen\0")),
            fread: std::mem::transmute::<*mut c_void, FreadFn>(sym(b"fread\0")),
            fgets: std::mem::transmute::<*mut c_void, FgetsFn>(sym(b"fgets\0")),
            fgetc: std::mem::transmute::<*mut c_void, FgetcFn>(sym(b"fgetc\0")),
            feof: std::mem::transmute::<*mut c_void, FeofFn>(sym(b"feof\0")),
            ftell: std::mem::transmute::<*mut c_void, FtellFn>(sym(b"ftell\0")),
            ungetc: std::mem::transmute::<*mut c_void, UngetcFn>(sym(b"ungetc\0")),
            fflush: std::mem::transmute::<*mut c_void, FflushFn>(sym(b"fflush\0")),
            fgetpos: std::mem::transmute::<*mut c_void, FgetposFn>(sym(b"fgetpos\0")),
            getline: std::mem::transmute::<*mut c_void, GetlineFn>(sym(b"getline\0")),
            free: std::mem::transmute::<*mut c_void, FreeFn>(sym(b"free\0")),
            malloc: std::mem::transmute::<*mut c_void, MallocFn>(sym(b"malloc\0")),
            fputs: std::mem::transmute::<*mut c_void, FputsFn>(sym(b"fputs\0")),
            fputc: std::mem::transmute::<*mut c_void, FputcFn>(sym(b"fputc\0")),
            fseek: std::mem::transmute::<*mut c_void, FseekFn>(sym(b"fseek\0")),
            fclose: std::mem::transmute::<*mut c_void, FcloseFn>(sym(b"fclose\0")),
        }
    })
}

/// One full drain cycle on the given arm. Returns total bytes read (must equal N).
fn drain_fl(data: &mut [u8]) -> usize {
    let fp = unsafe { fl::fmemopen(data.as_mut_ptr().cast(), N, c"r".as_ptr()) };
    assert!(!fp.is_null(), "fl fmemopen failed");
    let mut buf = [0u8; CHUNK];
    let mut got = 0usize;
    for _ in 0..(N / CHUNK) {
        // size=1 ⇒ the return value is the byte count for this call.
        got += unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, CHUNK, fp) };
        black_box(&buf);
    }
    unsafe { fl::fclose(fp) };
    got
}

fn drain_glibc(data: &mut [u8], h: &'static HostStdio) -> usize {
    let fp = unsafe { (h.fmemopen)(data.as_mut_ptr().cast(), N, c"r".as_ptr()) };
    assert!(!fp.is_null(), "glibc fmemopen failed");
    let mut buf = [0u8; CHUNK];
    let mut got = 0usize;
    for _ in 0..(N / CHUNK) {
        got += unsafe { (h.fread)(buf.as_mut_ptr().cast(), 1, CHUNK, fp) };
        black_box(&buf);
    }
    unsafe { (h.fclose)(fp) };
    got
}

/// Fill `data` with 64-byte lines: 63 payload bytes + '\n', so an fgets drain with a
/// 128-byte dst consumes exactly one line per call.
fn make_lines(data: &mut [u8]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b = if i % 64 == 63 { b'\n' } else { b'x' };
    }
}

/// fgets drain cycle: open, read lines until NULL, close. Returns lines read (must be N/64).
fn drain_fl_gets(data: &mut [u8]) -> usize {
    let fp = unsafe { fl::fmemopen(data.as_mut_ptr().cast(), N, c"r".as_ptr()) };
    assert!(!fp.is_null(), "fl fmemopen failed");
    let mut buf = [0u8; 128];
    let mut lines = 0usize;
    while !unsafe { fl::fgets(buf.as_mut_ptr().cast(), 128, fp) }.is_null() {
        lines += 1;
        black_box(&buf);
    }
    unsafe { fl::fclose(fp) };
    lines
}

fn drain_glibc_gets(data: &mut [u8], h: &'static HostStdio) -> usize {
    let fp = unsafe { (h.fmemopen)(data.as_mut_ptr().cast(), N, c"r".as_ptr()) };
    assert!(!fp.is_null(), "glibc fmemopen failed");
    let mut buf = [0u8; 128];
    let mut lines = 0usize;
    while !unsafe { (h.fgets)(buf.as_mut_ptr().cast(), 128, fp) }.is_null() {
        lines += 1;
        black_box(&buf);
    }
    unsafe { (h.fclose)(fp) };
    lines
}

/// fgets differential before timing: over lined data AND a no-trailing-newline tail, fl and
/// glibc must agree on every return disposition and every buffer prefix, at n=128 and the
/// awkward n=7 (mid-line capacity stops).
fn verify_gets(h: &'static HostStdio) {
    for tail_newline in [true, false] {
        let mut data = vec![0u8; 300];
        make_lines(&mut data);
        if !tail_newline {
            let last = data.len() - 1;
            data[last] = b'y';
        }
        let mut d1 = data.clone();
        let mut d2 = data.clone();
        let ns: [c_int; 2] = [128, 7];
        for n in ns {
            let fp_f = unsafe { fl::fmemopen(d1.as_mut_ptr().cast(), d1.len(), c"r".as_ptr()) };
            let fp_g =
                unsafe { (h.fmemopen)(d2.as_mut_ptr().cast(), d2.len(), c"r".as_ptr()) };
            assert!(!fp_f.is_null() && !fp_g.is_null());
            loop {
                let mut bf = [0x5au8; 130];
                let mut bg = [0x5au8; 130];
                let rf = unsafe { fl::fgets(bf.as_mut_ptr().cast(), n, fp_f) };
                let rg = unsafe { (h.fgets)(bg.as_mut_ptr().cast(), n, fp_g) };
                assert_eq!(
                    rf.is_null(),
                    rg.is_null(),
                    "fgets disposition diverged (n={n} tail_newline={tail_newline})"
                );
                assert_eq!(
                    &bf[..n as usize],
                    &bg[..n as usize],
                    "fgets bytes diverged (n={n} tail_newline={tail_newline})"
                );
                if rf.is_null() {
                    break;
                }
            }
            unsafe { fl::fclose(fp_f) };
            unsafe { (h.fclose)(fp_g) };
        }
    }
    println!("verify_gets: OK (fl fgets == glibc fgets, dispositions + bytes, n=128 and n=7)");
}

/// FD-stream drain: rewind, then N fgetc through the buffered fd path. Returns bytes read
/// (must equal N). This is the path that loses ALL `__libc_single_threaded`-gated fast
/// paths once a second thread exists: every fgetc pays canonical_stream_id + the ONE global
/// registry mutex + HashMap get_mut. The FILE* is opened once per thread (no open/close
/// churn); each drain costs one fseek + one buffer refill + N userspace byte reads.
fn drain_fl_fd(fp: *mut c_void) -> usize {
    assert_eq!(unsafe { fl::fseek(fp, 0, 0) }, 0, "fl fseek failed");
    let mut got = 0usize;
    for _ in 0..N {
        if unsafe { fl::fgetc(fp) } >= 0 {
            got += 1;
        }
    }
    got
}

/// FEOF loop drain: the realistic `while(!feof(fp)) fgetc(fp)` pattern. fgetc is cell-cached in
/// both arms, so the base-vs-cand delta isolates feof's MT cost (map lock per call vs cell cache).
fn drain_fl_feof(fp: *mut c_void) -> usize {
    assert_eq!(unsafe { fl::fseek(fp, 0, 0) }, 0, "fl fseek failed");
    let mut got = 0usize;
    while unsafe { fl::feof(fp) } == 0 {
        if unsafe { fl::fgetc(fp) } < 0 {
            break;
        }
        got += 1;
    }
    got
}

fn drain_glibc_feof(fp: *mut c_void, h: &'static HostStdio) -> usize {
    assert_eq!(unsafe { (h.fseek)(fp, 0, 0) }, 0, "glibc fseek failed");
    let mut got = 0usize;
    while unsafe { (h.feof)(fp) } == 0 {
        if unsafe { (h.fgetc)(fp) } < 0 {
            break;
        }
        got += 1;
    }
    got
}

fn drain_glibc_fd(fp: *mut c_void, h: &'static HostStdio) -> usize {
    assert_eq!(unsafe { (h.fseek)(fp, 0, 0) }, 0, "glibc fseek failed");
    let mut got = 0usize;
    for _ in 0..N {
        if unsafe { (h.fgetc)(fp) } >= 0 {
            got += 1;
        }
    }
    got
}

/// FTELL loop drain: the realistic position-tracking `for { c=fgetc(fp); off=ftell(fp); }` read
/// loop (tokenizers recording token offsets). fgetc is cell-cached in both arms, so the base-vs-
/// cand delta isolates ftell's MT cost (registry map lock per call vs cell cache). The FGETC_FD
/// arm (fgetc-only) is the null control — ftell adds work but fgetc is unchanged between arms.
fn drain_fl_ftell(fp: *mut c_void) -> usize {
    assert_eq!(unsafe { fl::fseek(fp, 0, 0) }, 0, "fl fseek failed");
    let mut got = 0usize;
    for _ in 0..N {
        if unsafe { fl::fgetc(fp) } >= 0 {
            got += 1;
        }
        black_box(unsafe { fl::ftell(fp) });
    }
    got
}

fn drain_glibc_ftell(fp: *mut c_void, h: &'static HostStdio) -> usize {
    assert_eq!(unsafe { (h.fseek)(fp, 0, 0) }, 0, "glibc fseek failed");
    let mut got = 0usize;
    for _ in 0..N {
        if unsafe { (h.fgetc)(fp) } >= 0 {
            got += 1;
        }
        black_box(unsafe { (h.ftell)(fp) });
    }
    got
}

/// FSEEK loop drain (PROFILE-ONLY): `for i { fseek(fp, (i&1)*64, SEEK_SET); }` — alternate two
/// offsets to force a real position change each call in both arms. Measures fseek's per-call cost;
/// compare fl 1t-vs-8t scaling (map-lock convoy signal) against glibc. No cell-cache exists yet.
fn drain_fl_fseek(fp: *mut c_void) -> usize {
    let mut got = 0usize;
    for i in 0..N {
        let off = ((i & 1) * 64) as libc::c_long;
        if unsafe { fl::fseek(fp, off, 0) } == 0 {
            got += 1;
        }
    }
    got
}

fn drain_glibc_fseek(fp: *mut c_void, h: &'static HostStdio) -> usize {
    let mut got = 0usize;
    for i in 0..N {
        let off = ((i & 1) * 64) as libc::c_long;
        if unsafe { (h.fseek)(fp, off, 0) } == 0 {
            got += 1;
        }
    }
    got
}

/// FGETPOS loop drain: the backtracking-parser save pattern `for { fgetc; fgetpos(fp,&pos); }`.
/// fgetc is cell-cached in both arms; the delta isolates fgetpos's MT cost (map lock vs cell cache;
/// fgetpos is ftell with an out-param). FGETC_FD is the null control. Returns bytes read (== N).
fn drain_fl_fgetpos(fp: *mut c_void) -> usize {
    assert_eq!(unsafe { fl::fseek(fp, 0, 0) }, 0, "fl fseek failed");
    let mut pos: libc::fpos_t = unsafe { std::mem::zeroed() };
    let mut got = 0usize;
    for _ in 0..N {
        if unsafe { fl::fgetc(fp) } >= 0 {
            got += 1;
        }
        unsafe { fl::fgetpos(fp, &mut pos) };
        black_box(&pos);
    }
    got
}

fn drain_glibc_fgetpos(fp: *mut c_void, h: &'static HostStdio) -> usize {
    assert_eq!(unsafe { (h.fseek)(fp, 0, 0) }, 0, "glibc fseek failed");
    let mut pos: libc::fpos_t = unsafe { std::mem::zeroed() };
    let mut got = 0usize;
    for _ in 0..N {
        if unsafe { (h.fgetc)(fp) } >= 0 {
            got += 1;
        }
        unsafe { (h.fgetpos)(fp, &mut pos) };
        black_box(&pos);
    }
    got
}

/// UNGETC loop drain: the parser lookahead `for { c=fgetc(fp); ungetc(c,fp); }` oscillation. fgetc
/// is cell-cached in both arms (and reads the pushed-back byte via buffered_read_into), so the
/// base-vs-cand delta isolates ungetc's MT cost (registry map lock per call vs cell cache). The
/// FGETC_FD arm is the null control. Position oscillates (never EOF); returns bytes read (== N).
fn drain_fl_ungetc(fp: *mut c_void) -> usize {
    assert_eq!(unsafe { fl::fseek(fp, 0, 0) }, 0, "fl fseek failed");
    let mut got = 0usize;
    for _ in 0..N {
        let c = unsafe { fl::fgetc(fp) };
        if c < 0 {
            break;
        }
        got += 1;
        unsafe { fl::ungetc(c, fp) };
    }
    got
}

fn drain_glibc_ungetc(fp: *mut c_void, h: &'static HostStdio) -> usize {
    assert_eq!(unsafe { (h.fseek)(fp, 0, 0) }, 0, "glibc fseek failed");
    let mut got = 0usize;
    for _ in 0..N {
        let c = unsafe { (h.fgetc)(fp) };
        if c < 0 {
            break;
        }
        got += 1;
        unsafe { (h.ungetc)(c, fp) };
    }
    got
}

/// GETLINE loop drain: the idiomatic `while (getline(&line,&n,fp) != -1)` file-line reader. The
/// `line`/`n` buffer is allocated ONCE per thread (with the arm's matching allocator) and reused
/// across every drain — sized (256B) so getline never reallocs a 64B line, so getline never
/// touches the allocator and the buffer's ownership is unambiguous (freed once at thread end with
/// the same allocator). base pays the registry map lock + decide/observe PER LINE; cand hits the
/// cell cache (primed by the slow path). Returns bytes read (must == N).
fn drain_fl_getline(fp: *mut c_void, line: &mut *mut c_char, n: &mut usize) -> usize {
    assert_eq!(unsafe { fl::fseek(fp, 0, 0) }, 0, "fl fseek failed");
    let mut got = 0usize;
    loop {
        let rc = unsafe { fl::getline(line, n, fp) };
        if rc < 0 {
            break;
        }
        got += rc as usize;
    }
    got
}

fn drain_glibc_getline(
    fp: *mut c_void,
    h: &'static HostStdio,
    line: &mut *mut c_char,
    n: &mut usize,
) -> usize {
    assert_eq!(unsafe { (h.fseek)(fp, 0, 0) }, 0, "glibc fseek failed");
    let mut got = 0usize;
    loop {
        let rc = unsafe { (h.getline)(line, n, fp) };
        if rc < 0 {
            break;
        }
        got += rc as usize;
    }
    got
}

/// FD fgets drain: rewind, then fgets(buf, 128) until NULL → N/64 lines. Returns bytes read.
fn drain_fl_fgets_fd(fp: *mut c_void) -> usize {
    assert_eq!(unsafe { fl::fseek(fp, 0, 0) }, 0, "fl fseek failed");
    let mut buf = [0u8; 128];
    let mut got = 0usize;
    while !unsafe { fl::fgets(buf.as_mut_ptr().cast(), 128, fp) }.is_null() {
        got += 64;
        black_box(&buf);
    }
    got
}

fn drain_glibc_fgets_fd(fp: *mut c_void, h: &'static HostStdio) -> usize {
    assert_eq!(unsafe { (h.fseek)(fp, 0, 0) }, 0, "glibc fseek failed");
    let mut buf = [0u8; 128];
    let mut got = 0usize;
    while !unsafe { (h.fgets)(buf.as_mut_ptr().cast(), 128, fp) }.is_null() {
        got += 64;
        black_box(&buf);
    }
    got
}

/// FD fread drain: rewind, then fread(buf, 1, 64) × N/64. Returns bytes read (must == N).
fn drain_fl_fread_fd(fp: *mut c_void) -> usize {
    assert_eq!(unsafe { fl::fseek(fp, 0, 0) }, 0, "fl fseek failed");
    let mut buf = [0u8; 64];
    let mut got = 0usize;
    for _ in 0..(N / 64) {
        got += unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, 64, fp) };
        black_box(&buf);
    }
    got
}

fn drain_glibc_fread_fd(fp: *mut c_void, h: &'static HostStdio) -> usize {
    assert_eq!(unsafe { (h.fseek)(fp, 0, 0) }, 0, "glibc fseek failed");
    let mut buf = [0u8; 64];
    let mut got = 0usize;
    for _ in 0..(N / 64) {
        got += unsafe { (h.fread)(buf.as_mut_ptr().cast(), 1, 64, fp) };
        black_box(&buf);
    }
    got
}

/// A single 64-byte line (63 'x' + '\n') as a NUL-terminated C string for fputs.
const FPUTS_LINE: &[u8] = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n\0";

/// FD write drain: fputs N/64 lines to a write stream. Returns bytes written (must == N).
fn drain_fl_fputs(fp: *mut c_void) -> usize {
    let mut n = 0usize;
    for _ in 0..(N / 64) {
        if unsafe { fl::fputs(FPUTS_LINE.as_ptr().cast(), fp) } >= 0 {
            n += 64;
        }
    }
    n
}

fn drain_glibc_fputs(fp: *mut c_void, h: &'static HostStdio) -> usize {
    let mut n = 0usize;
    for _ in 0..(N / 64) {
        if unsafe { (h.fputs)(FPUTS_LINE.as_ptr().cast(), fp) } >= 0 {
            n += 64;
        }
    }
    n
}

/// FD fputc drain: fputc N single bytes. Returns bytes written (must == N).
fn drain_fl_fputc(fp: *mut c_void) -> usize {
    let mut n = 0usize;
    for _ in 0..N {
        if unsafe { fl::fputc(b'x' as c_int, fp) } >= 0 {
            n += 1;
        }
    }
    n
}

/// FFLUSH loop drain (PROFILE-ONLY): the durability-logging `for { fputc; fflush(fp); }` pattern
/// on a /dev/null "w" stream. fputc is cell-cached in both arms (buffers 1 byte); fflush writes it
/// + exercises fflush's map locks. Compare fl 1t-vs-8t scaling (map-lock convoy) against glibc.
fn drain_fl_fflush(fp: *mut c_void) -> usize {
    let mut n = 0usize;
    for _ in 0..N {
        unsafe { fl::fputc(b'x' as c_int, fp) };
        if unsafe { fl::fflush(fp) } == 0 {
            n += 1;
        }
    }
    n
}

fn drain_glibc_fflush(fp: *mut c_void, h: &'static HostStdio) -> usize {
    let mut n = 0usize;
    for _ in 0..N {
        unsafe { (h.fputc)(b'x' as c_int, fp) };
        if unsafe { (h.fflush)(fp) } == 0 {
            n += 1;
        }
    }
    n
}

fn drain_glibc_fputc(fp: *mut c_void, h: &'static HostStdio) -> usize {
    let mut n = 0usize;
    for _ in 0..N {
        if unsafe { (h.fputc)(b'x' as c_int, fp) } >= 0 {
            n += 1;
        }
    }
    n
}

/// Write the per-thread backing file and return its NUL-terminated path.
fn make_fd_file(tag: &str) -> std::ffi::CString {
    use std::sync::atomic::{AtomicUsize, Ordering as AOrd};
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let mut data = vec![0u8; N];
    make_lines(&mut data);
    let path = format!(
        "/dev/shm/fl_stdio_fd_ab_{}_{}_{}",
        std::process::id(),
        tag,
        SEQ.fetch_add(1, AOrd::Relaxed)
    );
    std::fs::write(&path, &data).expect("write backing file");
    std::ffi::CString::new(path).expect("path nul")
}

/// FD differential before timing: fl and glibc fgetc over the same file must agree on every
/// byte, the EOF transition, and a mid-stream rewind.
fn verify_fd(h: &'static HostStdio) {
    let path = make_fd_file("verify");
    let fp_f = unsafe { fl::fopen(path.as_ptr(), c"r".as_ptr()) };
    let fp_g = unsafe { (h.fopen)(path.as_ptr(), c"r".as_ptr()) };
    assert!(!fp_f.is_null() && !fp_g.is_null(), "fopen failed");
    for pass in 0..2 {
        assert_eq!(unsafe { fl::fseek(fp_f, 0, 0) }, 0);
        assert_eq!(unsafe { (h.fseek)(fp_g, 0, 0) }, 0);
        for i in 0..=N {
            let cf = unsafe { fl::fgetc(fp_f) };
            let cg = unsafe { (h.fgetc)(fp_g) };
            assert_eq!(cf, cg, "fgetc diverged at byte {i} pass {pass}");
        }
    }
    unsafe { fl::fclose(fp_f) };
    unsafe { (h.fclose)(fp_g) };
    let _ = std::fs::remove_file(path.to_str().expect("utf8 path"));
    println!("verify_fd: OK (fl fgetc == glibc fgetc over fd stream, bytes + EOF + rewind)");
}

/// Byte-identity proof before any timing: fl and glibc drains over identical content must
/// return the same bytes with the same per-call counts (incl. a partial tail read).
fn verify(h: &'static HostStdio) {
    let mut data: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();
    let fp_f = unsafe { fl::fmemopen(data.as_mut_ptr().cast(), N, c"r".as_ptr()) };
    let fp_g = unsafe { (h.fmemopen)(data.as_mut_ptr().cast(), N, c"r".as_ptr()) };
    assert!(!fp_f.is_null() && !fp_g.is_null());
    let mut bf = [0u8; CHUNK];
    let mut bg = [0u8; CHUNK];
    // Full drain plus one extra call at EOF (ret must be 0 on both).
    for call in 0..=(N / CHUNK) {
        let rf = unsafe { fl::fread(bf.as_mut_ptr().cast(), 1, CHUNK, fp_f) };
        let rg = unsafe { (h.fread)(bg.as_mut_ptr().cast(), 1, CHUNK, fp_g) };
        assert_eq!(rf, rg, "fread return diverged at call {call}");
        assert_eq!(&bf[..rf], &bg[..rg], "fread bytes diverged at call {call}");
    }
    unsafe { fl::fclose(fp_f) };
    unsafe { (h.fclose)(fp_g) };
    println!("verify: OK (fl fread == glibc fread, bytes + counts, incl. EOF call)");
}

fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
    let n = v.len();
    if n % 2 == 0 { (v[n / 2 - 1] + v[n / 2]) / 2.0 } else { v[n / 2] }
}

fn cv_pct(xs: &[f64]) -> f64 {
    let m = xs.iter().sum::<f64>() / xs.len() as f64;
    if m == 0.0 {
        return 0.0;
    }
    let var = xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / xs.len() as f64;
    100.0 * var.sqrt() / m
}

/// Run one arm at `threads`: workers spawned once, `ROUNDS` barrier-synced rounds, each
/// thread times its own K drains per round. Returns per-round ns/drain, averaged across
/// threads, warmup discarded.
#[derive(Clone, Copy, PartialEq)]
enum Work {
    FreadMem,
    FgetsMem,
    FgetcFd,
    FeofFd,
    FtellFd,
    FgetposFd,
    UngetcFd,
    FseekFd,
    FflushFd,
    GetlineFd,
    FputsFd,
    FgetsFd,
    FreadFd,
    FputcFd,
}

fn run_arm(threads: usize, use_glibc: bool, work: Work, h: &'static HostStdio) -> Vec<f64> {
    let barrier = Barrier::new(threads);
    let mut per_thread: Vec<Vec<f64>> = Vec::new();

    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let barrier = &barrier;
            handles.push(s.spawn(move || {
                let mut data = vec![b'x'; N]; // allocated ONCE per thread
                if work == Work::FgetsMem {
                    make_lines(&mut data);
                }
                // FD workload: FILE* opened ONCE per thread (no churn). Reads open the
                // pre-written backing file "r"; writes open /dev/null "w" (isolates the
                // registry-lock cost from real fd-write cost — Full-buffered, rare flush).
                let (fd_path, fd_fp) = match work {
                    Work::FgetcFd
                    | Work::FgetsFd
                    | Work::FreadFd
                    | Work::FeofFd
                    | Work::FtellFd
                    | Work::FgetposFd
                    | Work::UngetcFd
                    | Work::FseekFd
                    | Work::GetlineFd => {
                        let path = make_fd_file(if use_glibc { "glibc" } else { "fl" });
                        let fp = if use_glibc {
                            unsafe { (h.fopen)(path.as_ptr(), c"r".as_ptr()) }
                        } else {
                            unsafe { fl::fopen(path.as_ptr(), c"r".as_ptr()) }
                        };
                        assert!(!fp.is_null(), "fopen r failed for fd workload");
                        (Some(path), fp)
                    }
                    Work::FputsFd | Work::FputcFd | Work::FflushFd => {
                        let fp = if use_glibc {
                            unsafe { (h.fopen)(c"/dev/null".as_ptr(), c"w".as_ptr()) }
                        } else {
                            unsafe { fl::fopen(c"/dev/null".as_ptr(), c"w".as_ptr()) }
                        };
                        assert!(!fp.is_null(), "fopen w failed for fd workload");
                        (None, fp)
                    }
                    _ => (None, std::ptr::null_mut()),
                };
                // getline buffer: one per thread, allocated with the arm's matching allocator,
                // sized (256B) so getline never reallocs a 64B line — getline never touches the
                // allocator, so ownership is unambiguous and the free below always matches.
                let (mut gl_line, mut gl_n): (*mut c_char, usize) = if work == Work::GetlineFd {
                    const GL_BUF: usize = 256;
                    let p = if use_glibc {
                        unsafe { (h.malloc)(GL_BUF) }
                    } else {
                        unsafe { frankenlibc_abi::malloc_abi::malloc(GL_BUF) }
                    };
                    assert!(!p.is_null(), "getline buffer alloc failed");
                    (p.cast(), GL_BUF)
                } else {
                    (std::ptr::null_mut(), 0)
                };
                let mut rounds = Vec::with_capacity(ROUNDS);
                let mut got_total = 0usize;
                for _ in 0..ROUNDS {
                    barrier.wait();
                    let start = Instant::now();
                    for _ in 0..K {
                        got_total += match (use_glibc, work) {
                            (false, Work::FreadMem) => drain_fl(&mut data),
                            (true, Work::FreadMem) => drain_glibc(&mut data, h),
                            (false, Work::FgetsMem) => drain_fl_gets(&mut data),
                            (true, Work::FgetsMem) => drain_glibc_gets(&mut data, h),
                            (false, Work::FeofFd) => drain_fl_feof(fd_fp),
                            (true, Work::FeofFd) => drain_glibc_feof(fd_fp, h),
                            (false, Work::FtellFd) => drain_fl_ftell(fd_fp),
                            (true, Work::FtellFd) => drain_glibc_ftell(fd_fp, h),
                            (false, Work::FgetposFd) => drain_fl_fgetpos(fd_fp),
                            (true, Work::FgetposFd) => drain_glibc_fgetpos(fd_fp, h),
                            (false, Work::UngetcFd) => drain_fl_ungetc(fd_fp),
                            (true, Work::UngetcFd) => drain_glibc_ungetc(fd_fp, h),
                            (false, Work::FseekFd) => drain_fl_fseek(fd_fp),
                            (true, Work::FseekFd) => drain_glibc_fseek(fd_fp, h),
                            (false, Work::GetlineFd) => {
                                drain_fl_getline(fd_fp, &mut gl_line, &mut gl_n)
                            }
                            (true, Work::GetlineFd) => {
                                drain_glibc_getline(fd_fp, h, &mut gl_line, &mut gl_n)
                            }
                            (false, Work::FgetcFd) => drain_fl_fd(fd_fp),
                            (true, Work::FgetcFd) => drain_glibc_fd(fd_fp, h),
                            (false, Work::FputsFd) => drain_fl_fputs(fd_fp),
                            (true, Work::FputsFd) => drain_glibc_fputs(fd_fp, h),
                            (false, Work::FgetsFd) => drain_fl_fgets_fd(fd_fp),
                            (true, Work::FgetsFd) => drain_glibc_fgets_fd(fd_fp, h),
                            (false, Work::FreadFd) => drain_fl_fread_fd(fd_fp),
                            (true, Work::FreadFd) => drain_glibc_fread_fd(fd_fp, h),
                            (false, Work::FputcFd) => drain_fl_fputc(fd_fp),
                            (true, Work::FputcFd) => drain_glibc_fputc(fd_fp, h),
                            (false, Work::FflushFd) => drain_fl_fflush(fd_fp),
                            (true, Work::FflushFd) => drain_glibc_fflush(fd_fp, h),
                        };
                    }
                    rounds.push(start.elapsed().as_nanos() as f64 / K as f64);
                }
                if !fd_fp.is_null() {
                    if use_glibc {
                        unsafe { (h.fclose)(fd_fp) };
                    } else {
                        unsafe { fl::fclose(fd_fp) };
                    }
                }
                if let Some(path) = fd_path {
                    let _ = std::fs::remove_file(path.to_str().expect("utf8 path"));
                }
                // Free the getline buffer with the SAME allocator that allocated it.
                if !gl_line.is_null() {
                    if use_glibc {
                        unsafe { (h.free)(gl_line.cast()) };
                    } else {
                        unsafe { frankenlibc_abi::malloc_abi::free(gl_line.cast()) };
                    }
                }
                // Execution proof: every drain returned all N bytes (fread/fgetc-fd) /
                // all lines (fgets).
                let expect = if work == Work::FgetsMem {
                    (N / 64) * K * ROUNDS
                } else {
                    N * K * ROUNDS
                };
                assert_eq!(got_total, expect, "short drain detected");
                rounds
            }));
        }
        for hnd in handles {
            per_thread.push(hnd.join().expect("worker panicked"));
        }
    });

    (WARMUP..ROUNDS)
        .map(|r| {
            per_thread.iter().map(|t| t[r]).sum::<f64>() / per_thread.len() as f64
        })
        .collect()
}

fn main() {
    let h = host();
    verify(h);
    verify_gets(h);
    verify_fd(h);
    let maxt: usize = std::thread::available_parallelism().map(|n| n.get().min(8)).unwrap_or(8);
    for &(work, tag) in &[
        (Work::FreadMem, "FREAD_MEM_AB"),
        (Work::FgetsMem, "FGETS_MEM_AB"),
        (Work::FgetcFd, "FGETC_FD_AB"),
        (Work::FeofFd, "FEOF_FD_AB"),
        (Work::FtellFd, "FTELL_FD_AB"),
        (Work::FgetposFd, "FGETPOS_FD_AB"),
        (Work::UngetcFd, "UNGETC_FD_AB"),
        (Work::FseekFd, "FSEEK_FD_AB"),
        (Work::FflushFd, "FFLUSH_FD_AB"),
        (Work::GetlineFd, "GETLINE_FD_AB"),
        (Work::FputsFd, "FPUTS_FD_AB"),
        (Work::FgetsFd, "FGETS_FD_AB"),
        (Work::FreadFd, "FREAD_FD_AB"),
        (Work::FputcFd, "FPUTC_FD_AB"),
    ] {
        for &threads in &[1usize, maxt] {
            // Warm both arms once (first-touch, dlmopen init, allocator warm).
            run_arm(threads, false, work, h);
            run_arm(threads, true, work, h);
            let fl_r = run_arm(threads, false, work, h);
            let gl_r = run_arm(threads, true, work, h);
            let (fm, gm) = (median(&fl_r), median(&gl_r));
            println!(
                "{tag} threads={threads} arm=fl ns_drain={fm:.1} cv={:.2}",
                cv_pct(&fl_r)
            );
            println!(
                "{tag} threads={threads} arm=glibc ns_drain={gm:.1} cv={:.2}",
                cv_pct(&gl_r)
            );
            println!("{tag} threads={threads} ratio_fl_over_glibc={:.4}", fm / gm);
        }
    }
}
