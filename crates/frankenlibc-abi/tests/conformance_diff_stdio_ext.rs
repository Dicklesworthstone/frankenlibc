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
        pub fn __freadable(f: *mut File) -> c_int;
        pub fn __fwritable(f: *mut File) -> c_int;
        pub fn __flbf(f: *mut File) -> c_int;
        pub fn __fpending(f: *mut File) -> usize;
    }
    // Declared C-unwind to match fl's stdio entry points, which let a
    // fopencookie callback unwind through them (as glibc's do).
    unsafe extern "C-unwind" {
        pub fn fclose(f: *mut File) -> c_int;
        pub fn setvbuf(f: *mut File, buf: *mut c_char, mode: c_int, size: usize) -> c_int;
        pub fn fwrite(p: *const c_void, sz: usize, n: usize, f: *mut File) -> usize;
        pub fn fflush(f: *mut File) -> c_int;
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
type FcloseFn = unsafe extern "C-unwind" fn(*mut File) -> c_int;
type SetvbufFn = unsafe extern "C-unwind" fn(*mut File, *mut c_char, c_int, usize) -> c_int;
type FflushFn = unsafe extern "C-unwind" fn(*mut File) -> c_int;
type FpendingFn = unsafe extern "C" fn(*mut File) -> usize;
type FwriteFn = unsafe extern "C-unwind" fn(*const c_void, usize, usize, *mut File) -> usize;
/// Declared VARIADIC on purpose. Calling a variadic C function through a
/// fixed-arity pointer leaves `al` (the SysV vector-register count) unset, which
/// glibc's `fprintf` prologue reads to decide whether to spill the XMM save
/// area. Keeping the type variadic makes the call ABI-correct instead of
/// happening to work.
type FprintfFn = unsafe extern "C-unwind" fn(*mut File, *const c_char, ...) -> c_int;

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
    fwrite: FwriteFn,
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
        fwrite: fl::fwrite,
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
            fwrite: dlsym_oracle::host_fn(c"fwrite", fl::fwrite as *const ()),
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

// ---------------------------------------------------------------------------
// setvbuf's size argument when `buf` is NULL (bd-kzceks)
//
// glibc IGNORES `size` when the caller passes a NULL buffer and hands the stream
// its own default — measured at 4096 across sizes 0, 64, 4096 and 65536. fl used
// to pass the caller's size through to a buffer whose capacity is `size.max(1)`,
// so `setvbuf(f, NULL, _IOFBF, 0)` — "buffer this fully, you pick the size" —
// produced a ONE-BYTE buffer and turned every write into its own write(2).
//
// `fpending_matches_glibc_for_buffered_writes` above cannot see this: it passes
// 4096, which happens to equal glibc's default, so the two agree by coincidence.
// This matrix varies the size on purpose.
// ---------------------------------------------------------------------------

/// Payload lengths to write. 5 is smaller than every `size` under test, so it
/// only discriminates when the size clamps below 5; 200 is larger than the 1-
/// and 64-byte sizes, which is what makes those rows tell fl's honoured-`size`
/// buffer apart from glibc's 4096-byte one. With only the 5-byte payload, the
/// size=64 rows agree even on the unfixed build.
const PAYLOAD_LENS: &[usize] = &[5, 200];

/// What a small write did to a stream configured with a NULL buffer.
#[derive(PartialEq, Eq, Debug)]
struct NullBufOutcome {
    pending: usize,
    on_disk_before_flush: u64,
    on_disk_after_flush: u64,
}

fn null_buf_write(arm: &StdioArm, vmode: c_int, size: usize, payload_len: usize) -> NullBufOutcome {
    let path = temp_path(&format!("{}-nb-{vmode}-{size}-{payload_len}", arm.name));
    let os_path = std::path::PathBuf::from(path.to_str().unwrap());
    // No newline anywhere in it, so line buffering has nothing to flush on.
    let payload = vec![b'a'; payload_len];

    // SAFETY: `path` is NUL-terminated; the stream is used only through `arm`
    // and closed exactly once.
    unsafe {
        let f = (arm.fopen)(path.as_ptr(), c"w".as_ptr());
        assert!(!f.is_null(), "{}: fopen failed", arm.name);
        assert_eq!(
            (arm.setvbuf)(f, std::ptr::null_mut(), vmode, size),
            0,
            "{}: setvbuf(NULL, {vmode}, {size}) failed",
            arm.name
        );
        (arm.fwrite)(payload.as_ptr().cast(), 1, payload.len(), f);
        let pending = (arm.fpending)(f);
        let on_disk_before_flush = std::fs::metadata(&os_path).map(|m| m.len()).unwrap_or(0);
        assert_eq!((arm.fflush)(f), 0, "{}: fflush failed", arm.name);
        let on_disk_after_flush = std::fs::metadata(&os_path).map(|m| m.len()).unwrap_or(0);
        assert_eq!((arm.fclose)(f), 0, "{}: fclose failed", arm.name);
        NullBufOutcome {
            pending,
            on_disk_before_flush,
            on_disk_after_flush,
        }
    }
}

#[test]
fn setvbuf_with_a_null_buffer_ignores_the_size_like_glibc() {
    let fl = fl_arm();
    let host = host_arm();
    let mut divergences = Vec::new();

    for (vmode, label) in [
        (libc::_IOFBF, "_IOFBF"),
        (libc::_IOLBF, "_IOLBF"),
        (libc::_IONBF, "_IONBF"),
    ] {
        for size in [0usize, 1, 64, 4096, 65536] {
            for &len in PAYLOAD_LENS {
                let f = null_buf_write(&fl, vmode, size, len);
                let h = null_buf_write(&host, vmode, size, len);
                if f != h {
                    divergences.push(format!(
                        "{label} size={size} payload={len}\n    fl:    {f:?}\n    glibc: {h:?}"
                    ));
                }
            }
        }
    }
    assert!(
        divergences.is_empty(),
        "setvbuf(NULL, ..) behaviour diverges from live glibc:\n  {}",
        divergences.join("\n  ")
    );
}

/// And state the contract the differential test is checking, so a future where
/// BOTH implementations changed still fails: a 5-byte write into a
/// self-allocated buffer is retained by _IOFBF and _IOLBF (no newline in it) and
/// goes straight to the fd when unbuffered — whatever `size` said.
#[test]
fn a_null_buffer_never_yields_an_effectively_unbuffered_stream() {
    let fl = fl_arm();
    for size in [0usize, 1, 64, 4096, 65536] {
        for &len in PAYLOAD_LENS {
            let n = len as u64;
            for (vmode, label) in [(libc::_IOFBF, "_IOFBF"), (libc::_IOLBF, "_IOLBF")] {
                let out = null_buf_write(&fl, vmode, size, len);
                assert_eq!(
                    out,
                    NullBufOutcome {
                        pending: len,
                        on_disk_before_flush: 0,
                        on_disk_after_flush: n,
                    },
                    "{label} size={size} payload={len}: a NULL buffer must give a real \
                     buffer, not a write-through stream"
                );
            }
            let unbuffered = null_buf_write(&fl, libc::_IONBF, size, len);
            assert_eq!(
                unbuffered,
                NullBufOutcome {
                    pending: 0,
                    on_disk_before_flush: n,
                    on_disk_after_flush: n,
                },
                "_IONBF size={size} payload={len}"
            );
        }
    }
}

// Global stream flushing and stdout reassignment must run in subprocesses:
// libtest's parallel tests and capture streams are otherwise part of the input.
// The parent deadline also makes a FILE/cell lock-order regression fail boundedly.
fn run_linebuffer_case(case: &str, provider: &str, mode: &str) {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "linebuffer_subprocess",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("FL_STDIO_LINEBUFFER_CASE", case)
        .env("FL_STDIO_LINEBUFFER_PROVIDER", provider)
        .env("FRANKENLIBC_MODE", mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    if case == "blocked-input" {
        let mut output = child.stdout.take().unwrap();
        // SAFETY: the child stdout descriptor remains owned by output.
        assert_eq!(
            unsafe { libc::fcntl(output.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let mut observed = Vec::new();
        loop {
            let mut bytes = [0u8; 256];
            match output.read(&mut bytes) {
                Ok(n) => observed.extend_from_slice(&bytes[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("{case}/{provider}/{mode}: {e}"),
            }
            if observed
                .windows(b"FL_PROMPT_BEFORE_INPUT".len())
                .any(|window| window == b"FL_PROMPT_BEFORE_INPUT")
            {
                break;
            }
            if Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "{case}/{provider}/{mode}: prompt never reached the pipe before input: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.stdin.take().unwrap().write_all(b"x").unwrap();
        // Keep the child's stdout pipe open until its test harness finishes.
        child.stdout = Some(output);
    }
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().unwrap();
            assert!(
                status.success(),
                "{case}/{provider}/{mode}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "{case}/{provider}/{mode}: stream operation exceeded 10s: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn flush_linebuffered_preserves_full_buffers_and_mixed_providers() {
    for case in ["flushlbf", "io_flush_linebuffered"] {
        run_linebuffer_case(case, "glibc", "strict");
        for mode in ["strict", "hardened"] {
            run_linebuffer_case(case, "fl", mode);
        }
    }
}

#[test]
fn input_underflow_flushes_only_linebuffered_stdout() {
    for case in [
        "getc-line",
        "getc-unbuffered",
        "gets-line",
        "gets-unbuffered",
        "getline-line",
        "getline-unbuffered",
        "fscanf-line",
        "fread-refill",
        "getc-full-input",
        "getc-full-output",
        "getc-cached",
        "getc-sticky-eof",
        "fread-direct",
        "fread-unbuffered",
        "getc-self-stdout",
    ] {
        run_linebuffer_case(case, "glibc", "strict");
        for mode in ["strict", "hardened"] {
            run_linebuffer_case(case, "fl", mode);
        }
    }
}

#[test]
fn input_flushes_prompt_before_waiting_for_pipe_data() {
    run_linebuffer_case("blocked-input", "glibc", "strict");
    for mode in ["strict", "hardened"] {
        run_linebuffer_case("blocked-input", "fl", mode);
    }
}

#[test]
#[ignore = "invoked in an isolated subprocess by the line-buffering gates"]
fn linebuffer_subprocess() {
    let case = std::env::var("FL_STDIO_LINEBUFFER_CASE").unwrap();
    let provider = std::env::var("FL_STDIO_LINEBUFFER_PROVIDER").unwrap();
    let arm = if provider == "fl" {
        fl_arm()
    } else {
        host_arm()
    };
    if case == "flushlbf" || case == "io_flush_linebuffered" {
        linebuffer_global_flush(&arm, &case);
    } else {
        linebuffer_input(&arm, &case);
    }
}

fn linebuffer_global_flush(arm: &StdioArm, case: &str) {
    use frankenlibc_abi::io_internal_abi;
    type FlushLineFn = unsafe extern "C" fn();
    // SAFETY: both exported aliases have the void(void) C ABI. The host
    // resolver rejects a symbol that accidentally binds back to the candidate.
    unsafe {
        let candidate: FlushLineFn = if case == "flushlbf" {
            fle::_flushlbf
        } else {
            io_internal_abi::_IO_flush_all_linebuffered
        };
        let name = if case == "flushlbf" {
            c"_flushlbf"
        } else {
            c"_IO_flush_all_linebuffered"
        };
        let flush: FlushLineFn = if arm.name == "fl" {
            candidate
        } else {
            dlsym_oracle::host_fn(name, candidate as *const ())
        };
        let host = host_arm();
        let providers = if arm.name == "fl" {
            vec![arm, &host]
        } else {
            vec![arm]
        };
        let mut streams = Vec::new();
        for provider in providers {
            for mode in [libc::_IOLBF, libc::_IOFBF] {
                let path = temp_path(&format!("lbf-{}-{mode}", provider.name));
                let stream = (provider.fopen)(path.as_ptr(), c"w".as_ptr());
                assert!(!stream.is_null());
                if provider.name == "fl" {
                    assert!(!stdio_may_delegate_to_host_for_tests(stream));
                }
                assert_eq!((provider.setvbuf)(stream, std::ptr::null_mut(), mode, 0), 0);
                assert_eq!(
                    (provider.fprintf)(stream, c"%s".as_ptr(), c"queued".as_ptr()),
                    6
                );
                assert_eq!((provider.fpending)(stream), 6);
                streams.push((provider, stream, path, mode));
            }
        }
        flush();
        for (provider, stream, path, mode) in streams {
            let line = mode == libc::_IOLBF;
            assert_eq!(
                (provider.fpending)(stream),
                if line { 0 } else { 6 },
                "{case}: {} mode={mode}",
                provider.name
            );
            assert_eq!(
                std::fs::metadata(path.to_str().unwrap()).unwrap().len(),
                if line { 6 } else { 0 },
                "{case}: fully buffered output must remain private"
            );
            assert_eq!((provider.fclose)(stream), 0);
        }
    }
}

fn linebuffer_input(arm: &StdioArm, case: &str) {
    type FdopenFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut File;
    type FgetcFn = unsafe extern "C-unwind" fn(*mut File) -> c_int;
    type FgetsFn = unsafe extern "C-unwind" fn(*mut c_char, c_int, *mut File) -> *mut c_char;
    type FreadFn = unsafe extern "C-unwind" fn(*mut c_void, usize, usize, *mut File) -> usize;
    type GetlineFn = unsafe extern "C-unwind" fn(*mut *mut c_char, *mut usize, *mut File) -> isize;
    type FscanfFn = unsafe extern "C-unwind" fn(*mut File, *const c_char, ...) -> c_int;
    // SAFETY: each pointer below has its named C ABI. The process owns all
    // descriptors and streams, and the prefilled input pipe cannot block.
    unsafe {
        let (fdopen, getc, gets, read, getline, scan, stdout_cell): (
            FdopenFn,
            FgetcFn,
            FgetsFn,
            FreadFn,
            GetlineFn,
            FscanfFn,
            *mut *mut File,
        ) = if arm.name == "fl" {
            (
                fl::fdopen,
                fl::fgetc,
                fl::fgets,
                fl::fread,
                fl::getline,
                fl::fscanf,
                &raw mut fl::stdout,
            )
        } else {
            (
                dlsym_oracle::host_fn(c"fdopen", fl::fdopen as *const ()),
                dlsym_oracle::host_fn(c"fgetc", fl::fgetc as *const ()),
                dlsym_oracle::host_fn(c"fgets", fl::fgets as *const ()),
                dlsym_oracle::host_fn(c"fread", fl::fread as *const ()),
                dlsym_oracle::host_fn(c"getline", fl::getline as *const ()),
                dlsym_oracle::host_fn(c"fscanf", fl::fscanf as *const ()),
                dlsym_oracle::host_addr(c"stdout", (&raw mut fl::stdout).cast()).cast(),
            )
        };
        if case == "blocked-input" {
            let source = fdopen(libc::STDIN_FILENO, c"r".as_ptr());
            let sink = *stdout_cell;
            assert!(!source.is_null());
            assert_eq!(
                (arm.setvbuf)(source, std::ptr::null_mut(), libc::_IOLBF, 0),
                0
            );
            assert_eq!(
                (arm.setvbuf)(sink, std::ptr::null_mut(), libc::_IOLBF, 0),
                0
            );
            assert_eq!(
                (arm.fprintf)(sink, c"%s".as_ptr(), c"FL_PROMPT_BEFORE_INPUT".as_ptr()),
                22
            );
            assert_eq!((arm.fpending)(sink), 22);
            // The parent sends this byte only after observing the prompt.
            assert_eq!(getc(source), c_int::from(b'x'));
            assert_eq!((arm.fpending)(sink), 0);
            assert_eq!((arm.fclose)(source), 0);
            return;
        }
        let mut output = [-1; 2];
        let mut input = [-1; 2];
        let saved_stdout = libc::dup(libc::STDOUT_FILENO);
        assert!(saved_stdout >= 0);
        assert_eq!(
            libc::pipe2(output.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK),
            0
        );
        assert_eq!(libc::pipe2(input.as_mut_ptr(), libc::O_CLOEXEC), 0);
        assert_eq!(
            libc::dup2(output[1], libc::STDOUT_FILENO),
            libc::STDOUT_FILENO
        );
        assert_eq!(libc::close(output[1]), 0);
        assert_eq!(libc::write(input[1], b"xyz\n".as_ptr().cast(), 4), 4);
        assert_eq!(libc::close(input[1]), 0);
        let source = fdopen(input[0], c"r".as_ptr());
        assert!(!source.is_null());
        if arm.name == "fl" {
            assert!(!stdio_may_delegate_to_host_for_tests(source));
        }
        let input_mode = if case == "getc-full-input" {
            libc::_IOFBF
        } else if case.ends_with("unbuffered") {
            libc::_IONBF
        } else {
            libc::_IOLBF
        };
        let output_mode = if case == "getc-full-output" {
            libc::_IOFBF
        } else {
            libc::_IOLBF
        };
        let sink = *stdout_cell;
        assert_eq!(
            (arm.setvbuf)(source, std::ptr::null_mut(), input_mode, 0),
            0
        );
        assert_eq!((arm.setvbuf)(sink, std::ptr::null_mut(), output_mode, 0), 0);
        if case == "getc-cached" {
            assert_eq!(getc(source), c_int::from(b'x'));
        } else if case == "getc-sticky-eof" {
            while getc(source) != libc::EOF {}
        }
        let other_path = temp_path("other-line-output");
        let other = (arm.fopen)(other_path.as_ptr(), c"w".as_ptr());
        assert!(!other.is_null());
        assert_eq!(
            (arm.setvbuf)(other, std::ptr::null_mut(), libc::_IOLBF, 0),
            0
        );
        assert_eq!((arm.fprintf)(other, c"%s".as_ptr(), c"other".as_ptr()), 5);
        assert_eq!((arm.fprintf)(sink, c"%s".as_ptr(), c"prompt".as_ptr()), 6);
        assert_eq!((arm.fpending)(sink), 6, "the prompt must start buffered");
        if case == "getc-self-stdout" {
            *stdout_cell = source;
        }

        let mut bytes = [0u8; 8192];
        if case.starts_with("gets-") {
            assert!(!gets(bytes.as_mut_ptr().cast(), bytes.len() as c_int, source).is_null());
        } else if case.starts_with("getline-") {
            let mut line = std::ptr::null_mut();
            let mut capacity = 0;
            assert_eq!(getline(&mut line, &mut capacity, source), 4);
            // A short-lived subprocess retains this one allocation until exit;
            // freeing through the wrong provider would obscure the I/O contract.
        } else if case == "fscanf-line" {
            assert_eq!(scan(source, c"%c".as_ptr(), bytes.as_mut_ptr()), 1);
        } else if case.starts_with("fread-") {
            let n = if case == "fread-direct" {
                bytes.len()
            } else {
                1
            };
            assert_eq!(read(bytes.as_mut_ptr().cast(), 1, n, source), n.min(4));
        } else {
            let expected = match case {
                "getc-cached" => c_int::from(b'y'),
                "getc-sticky-eof" => libc::EOF,
                _ => c_int::from(b'x'),
            };
            assert_eq!(getc(source), expected);
        }
        *stdout_cell = sink;
        let should_flush = !matches!(
            case,
            "getc-full-input"
                | "getc-full-output"
                | "getc-cached"
                | "getc-sticky-eof"
                | "fread-direct"
                | "fread-unbuffered"
                | "getc-self-stdout"
        );
        let count = libc::read(output[0], bytes.as_mut_ptr().cast(), bytes.len());
        assert_eq!(
            count,
            if should_flush { 6 } else { -1 },
            "{case}: prompt visibility"
        );
        if should_flush {
            assert_eq!(&bytes[..6], b"prompt");
        } else {
            assert_eq!(*libc::__errno_location(), libc::EAGAIN);
        }
        assert_eq!((arm.fpending)(sink), if should_flush { 0 } else { 6 });
        assert_eq!(
            (arm.fpending)(other),
            5,
            "input flush is specific to stdout"
        );
        assert_eq!((arm.fclose)(other), 0);
        assert_eq!((arm.fclose)(source), 0);
        assert_eq!((arm.fflush)(sink), 0);
        assert_eq!(
            libc::dup2(saved_stdout, libc::STDOUT_FILENO),
            libc::STDOUT_FILENO
        );
        assert_eq!(libc::close(saved_stdout), 0);
        assert_eq!(libc::close(output[0]), 0);
    }
}
