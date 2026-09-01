#![cfg(all(target_os = "linux", not(feature = "standalone")))]
#![allow(unsafe_code)] // live host-glibc stdio_ext.h oracle + real FILE* streams

//! Differential gate for the stdio_ext.h introspection family (bd-bap2cl).
//! __freadable / __fwritable / __flbf / __fbufsize / __fpending previously
//! discarded the FILE* and returned constants (readable=1, writable=1, lbf=0,
//! bufsize=BUFSIZ, pending=0), so e.g. __fwritable on a read-only stream was
//! wrong. They now read fl's actual stream state. This gate opens the SAME mode
//! with fl and with host glibc and asserts the introspection agrees. No mocks.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

type File = c_void;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(path: *const c_char, mode: *const c_char) -> *mut File;
        pub fn fclose(f: *mut File) -> c_int;
        pub fn setvbuf(f: *mut File, buf: *mut c_char, mode: c_int, size: usize) -> c_int;
        pub fn fwrite(p: *const c_void, sz: usize, n: usize, f: *mut File) -> usize;
        pub fn fflush(f: *mut File) -> c_int;
        pub fn __freadable(f: *mut File) -> c_int;
        pub fn __fwritable(f: *mut File) -> c_int;
        pub fn __flbf(f: *mut File) -> c_int;
        pub fn __fpending(f: *mut File) -> usize;
    }
}

use frankenlibc_abi::glibc_internal_abi as fle; // fl's __f* entry points
use frankenlibc_abi::stdio_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);
fn temp_path(tag: &str) -> std::ffi::CString {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-stdioext-{}-{}-{}", std::process::id(), tag, n));
    // ensure the file exists (needed for "r"/"r+")
    std::fs::write(&p, b"seed-data\n").unwrap();
    std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap()
}

#[test]
fn freadable_fwritable_match_glibc_per_mode() {
    for mode in ["r", "w", "a", "r+", "w+", "a+"] {
        let cm = std::ffi::CString::new(mode).unwrap();
        let gp = temp_path(&format!("g{mode}"));
        let fp = temp_path(&format!("f{mode}"));

        let gs = unsafe { g::fopen(gp.as_ptr(), cm.as_ptr()) };
        let fs = unsafe { fl::fopen(fp.as_ptr().cast::<c_char>(), cm.as_ptr().cast::<c_char>()) };
        assert!(!gs.is_null() && !fs.is_null(), "fopen({mode}) failed");

        let gr = unsafe { g::__freadable(gs) } != 0;
        let fr = unsafe { fle::__freadable(fs) } != 0;
        assert_eq!(fr, gr, "__freadable mode={mode}: fl={fr} glibc={gr}");

        let gw = unsafe { g::__fwritable(gs) } != 0;
        let fw = unsafe { fle::__fwritable(fs) } != 0;
        assert_eq!(fw, gw, "__fwritable mode={mode}: fl={fw} glibc={gw}");

        // Sanity vs the spec: "r" is read-only, "w"/"a" write-only.
        match mode {
            "r" => assert!(fr && !fw, "r must be read-only"),
            "w" | "a" => assert!(!fr && fw, "{mode} must be write-only"),
            _ => assert!(fr && fw, "{mode} must be read+write"),
        }

        unsafe {
            g::fclose(gs);
            fl::fclose(fs);
        }
    }
}

#[test]
fn flbf_matches_glibc_after_setvbuf() {
    // _IOLBF -> line-buffered (nonzero); _IOFBF/_IONBF -> not line-buffered.
    for (vmode, want_lbf) in [
        (libc::_IOLBF, true),
        (libc::_IOFBF, false),
        (libc::_IONBF, false),
    ] {
        let cm = c"w";
        let gp = temp_path("glbf");
        let fp = temp_path("flbf");
        let gs = unsafe { g::fopen(gp.as_ptr(), cm.as_ptr()) };
        let fs = unsafe { fl::fopen(fp.as_ptr().cast::<c_char>(), cm.as_ptr().cast::<c_char>()) };
        unsafe {
            g::setvbuf(gs, std::ptr::null_mut(), vmode, 0);
            fl::setvbuf(fs, std::ptr::null_mut(), vmode, 0);
        }
        let glbf = unsafe { g::__flbf(gs) } != 0;
        let flbf = unsafe { fle::__flbf(fs) } != 0;
        assert_eq!(flbf, glbf, "__flbf vmode={vmode}: fl={flbf} glibc={glbf}");
        assert_eq!(flbf, want_lbf, "__flbf vmode={vmode} expected {want_lbf}");
        unsafe {
            g::fclose(gs);
            fl::fclose(fs);
        }
    }
}

#[test]
fn fpending_matches_glibc_for_buffered_writes() {
    // Full-buffered stream: a small write stays pending until flush.
    let cm = c"w";
    let gp = temp_path("gpend");
    let fp = temp_path("fpend");
    let gs = unsafe { g::fopen(gp.as_ptr(), cm.as_ptr()) };
    let fs = unsafe { fl::fopen(fp.as_ptr().cast::<c_char>(), cm.as_ptr().cast::<c_char>()) };
    // Force full buffering on both so the bytes are retained.
    let gbuf = vec![0u8; 4096];
    let fbuf = vec![0u8; 4096];
    unsafe {
        g::setvbuf(gs, gbuf.as_ptr() as *mut c_char, libc::_IOFBF, 4096);
        fl::setvbuf(fs, fbuf.as_ptr() as *mut c_char, libc::_IOFBF, 4096);
    }

    let data = b"hello stdio_ext";
    unsafe {
        g::fwrite(data.as_ptr().cast(), 1, data.len(), gs);
        fl::fwrite(data.as_ptr().cast(), 1, data.len(), fs);
    }
    let gp_n = unsafe { g::__fpending(gs) };
    let fp_n = unsafe { fle::__fpending(fs) };
    assert_eq!(fp_n, gp_n, "__fpending after write: fl={fp_n} glibc={gp_n}");
    assert_eq!(
        fp_n,
        data.len(),
        "__fpending must equal buffered byte count"
    );

    // After flush, nothing pending.
    unsafe {
        g::fflush(gs);
        fl::fflush(fs);
    }
    let gp0 = unsafe { g::__fpending(gs) };
    let fp0 = unsafe { fle::__fpending(fs) };
    assert_eq!(fp0, gp0, "__fpending after flush: fl={fp0} glibc={gp0}");
    assert_eq!(fp0, 0, "__fpending must be 0 after flush");

    // keep the static buffers alive until both streams are closed
    unsafe {
        g::fclose(gs);
        fl::fclose(fs);
    }
    drop(gbuf);
    drop(fbuf);
}

// ---------------------------------------------------------------------------
// `fprintf("%s\n", ..)` vs the buffering mode (bd-xh08pf)
//
// fl has a fast path, `try_write_direct_s_newline_stream`, that absorbs a whole
// `%s\n` conversion straight into the stream buffer without going through the
// formatter. It is only allowed to do that on a FULLY buffered stream: on a
// line-buffered one the newline must still force a flush, and on an unbuffered
// one the bytes must reach the fd immediately. A fast path that took the
// line-buffered case too would swallow the flush, and the program's output would
// appear late — or, at exit, in the wrong order relative to stderr.
//
// This replaces a dead inline `#[cfg(test)]` test in stdio_abi.rs that called
// that private helper directly and read `pending_flush()` off the private
// stream. `__fpending` reports the same byte count through the public ABI, and
// glibc implements the same contract, so the rewrite is differential where the
// original could only compare fl to fl's own expectations.
//
// The host arm here is resolved with `dlsym`, unlike `mod g` above. fl exports
// `fopen`/`setvbuf`/`fprintf`/`__fpending` under `#[no_mangle]` in release
// builds, so a link-time declaration in a release test binary binds to FL and
// the comparison collapses (bd-0q7ba9 tracks that across the suite; the older
// arms in this file are left as they are rather than quietly rewritten here).
// ---------------------------------------------------------------------------

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

use frankenlibc_abi::stdio_abi::stdio_may_delegate_to_host_for_tests;

type FopenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut File;
type FcloseFn = unsafe extern "C" fn(*mut File) -> c_int;
type SetvbufFn = unsafe extern "C" fn(*mut File, *mut c_char, c_int, usize) -> c_int;
type FflushFn = unsafe extern "C" fn(*mut File) -> c_int;
type FpendingFn = unsafe extern "C" fn(*mut File) -> usize;
/// Declared VARIADIC on purpose. Calling a variadic C function through a
/// fixed-arity pointer leaves `al` (the SysV vector-register count) unset, which
/// glibc's `fprintf` prologue reads to decide whether to spill the XMM save
/// area. Keeping the type variadic makes the call ABI-correct instead of
/// happening to work.
type FprintfFn = unsafe extern "C" fn(*mut File, *const c_char, ...) -> c_int;

/// The buffer size glibc gives a fully buffered stream when `setvbuf` is called
/// with a NULL `buf`. Measured, not assumed: `__fbufsize` reports 4096 for
/// `_IOFBF` regardless of the `size` argument passed (bd-kzceks).
const GLIBC_DEFAULT_BUFSIZ: usize = 4096;

struct StdioArm {
    name: &'static str,
    fopen: FopenFn,
    fclose: FcloseFn,
    setvbuf: SetvbufFn,
    fflush: FflushFn,
    fpending: FpendingFn,
    fprintf: FprintfFn,
}

fn fl_arm() -> StdioArm {
    StdioArm {
        name: "fl",
        fopen: fl::fopen,
        fclose: fl::fclose,
        setvbuf: fl::setvbuf,
        fflush: fl::fflush,
        fpending: fle::__fpending,
        fprintf: fl::fprintf,
    }
}

fn host_arm() -> StdioArm {
    // SAFETY: every signature matches the C declaration of the named symbol.
    unsafe {
        StdioArm {
            name: "glibc",
            fopen: dlsym_oracle::host_fn(c"fopen", fl::fopen as *const ()),
            fclose: dlsym_oracle::host_fn(c"fclose", fl::fclose as *const ()),
            setvbuf: dlsym_oracle::host_fn(c"setvbuf", fl::setvbuf as *const ()),
            fflush: dlsym_oracle::host_fn(c"fflush", fl::fflush as *const ()),
            fpending: dlsym_oracle::host_fn(c"__fpending", fle::__fpending as *const ()),
            fprintf: dlsym_oracle::host_fn(c"fprintf", fl::fprintf as *const ()),
        }
    }
}

/// What one `fprintf(f, "%s\n", "status=ok")` did to a stream in `vmode`.
#[derive(PartialEq, Eq, Debug)]
struct NewlineWriteOutcome {
    /// `fprintf`'s return value — 10 for "status=ok\n".
    rc: c_int,
    /// Bytes still sitting in the stream buffer afterwards.
    pending: usize,
    /// Bytes visible in the file BEFORE any explicit flush. This is the field
    /// that separates line- from fully-buffered.
    on_disk_before_flush: u64,
    /// Bytes visible after `fflush`, i.e. the total that was written at all.
    on_disk_after_flush: u64,
}

fn newline_write(arm: &StdioArm, vmode: c_int) -> NewlineWriteOutcome {
    let path = temp_path(&format!("{}-nl-{vmode}", arm.name));
    let os_path = std::path::PathBuf::from(path.to_str().unwrap());

    // SAFETY: `path` is NUL-terminated; the stream is used only through `arm`,
    // which is one implementation throughout, and closed exactly once.
    unsafe {
        let f = (arm.fopen)(path.as_ptr(), c"w".as_ptr());
        assert!(!f.is_null(), "{}: fopen failed", arm.name);
        if arm.name == "fl" {
            assert!(
                !stdio_may_delegate_to_host_for_tests(f),
                "the fl stream is delegating to host glibc, so this gate would be \
                 comparing glibc against glibc"
            );
        }
        // 4096, not 0, and the number matters. glibc IGNORES `size` when `buf`
        // is NULL and always allocates 4096 for a fully buffered stream, while
        // fl honours it (`size.max(1)`), so `size = 0` gives fl a ONE-BYTE
        // buffer and an effectively unbuffered stream. That is a real
        // divergence — measured and filed as bd-kzceks — but a DIFFERENT one
        // from the newline contract under test here, so this gate pins the size
        // to glibc's own default and leaves that bug to its own bead.
        assert_eq!(
            (arm.setvbuf)(f, std::ptr::null_mut(), vmode, GLIBC_DEFAULT_BUFSIZ),
            0,
            "{}: setvbuf({vmode}) failed",
            arm.name
        );

        let rc = (arm.fprintf)(f, c"%s\n".as_ptr(), c"status=ok".as_ptr());
        let pending = (arm.fpending)(f);
        let on_disk_before_flush = std::fs::metadata(&os_path).map(|m| m.len()).unwrap_or(0);

        assert_eq!((arm.fflush)(f), 0, "{}: fflush failed", arm.name);
        let on_disk_after_flush = std::fs::metadata(&os_path).map(|m| m.len()).unwrap_or(0);
        assert_eq!((arm.fclose)(f), 0, "{}: fclose failed", arm.name);

        NewlineWriteOutcome {
            rc,
            pending,
            on_disk_before_flush,
            on_disk_after_flush,
        }
    }
}

#[test]
fn fpending_after_printf_newline_matches_glibc_across_buffering_modes() {
    let fl = fl_arm();
    let host = host_arm();
    let mut divergences = Vec::new();

    for (vmode, label) in [
        (libc::_IOFBF, "_IOFBF"),
        (libc::_IOLBF, "_IOLBF"),
        (libc::_IONBF, "_IONBF"),
    ] {
        let f = newline_write(&fl, vmode);
        let h = newline_write(&host, vmode);
        if f != h {
            divergences.push(format!("{label}\n    fl:    {f:?}\n    glibc: {h:?}"));
        }
    }
    assert!(
        divergences.is_empty(),
        "fprintf(\"%s\\n\") diverges from live glibc:\n  {}",
        divergences.join("\n  ")
    );
}

/// The gate above compares fl to glibc; this one states what they must AGREE
/// ON, so a future where both drift the same way still fails.
///
/// Without it, a fast path that absorbed the line-buffered case in fl AND a
/// glibc that did the same would pass the differential test while breaking every
/// program that relies on line buffering to interleave its output.
#[test]
fn line_buffering_flushes_at_the_newline_and_full_buffering_does_not() {
    let fl = fl_arm();

    let full = newline_write(&fl, libc::_IOFBF);
    assert_eq!(full.rc, 10, "fprintf must report the 10 bytes it formatted");
    assert_eq!(
        full.pending, 10,
        "a fully buffered stream must hold \"status=ok\\n\" in its buffer"
    );
    assert_eq!(
        full.on_disk_before_flush, 0,
        "a fully buffered stream must not have reached the fd yet"
    );
    assert_eq!(full.on_disk_after_flush, 10);

    for (vmode, label) in [(libc::_IOLBF, "_IOLBF"), (libc::_IONBF, "_IONBF")] {
        let out = newline_write(&fl, vmode);
        assert_eq!(out.rc, 10, "{label}: fprintf return value");
        assert_eq!(
            out.pending, 0,
            "{label}: the newline must have flushed the buffer, not been absorbed \
             by the direct %s\\n fast path"
        );
        assert_eq!(
            out.on_disk_before_flush, 10,
            "{label}: the bytes must be at the fd before any explicit fflush"
        );
    }
}
