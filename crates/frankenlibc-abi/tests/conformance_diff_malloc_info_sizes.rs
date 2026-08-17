#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // drives malloc_info against a live host-glibc oracle
//! Gate for the `<sizes>` block of `malloc_info` (bd-dcrhgl).
//!
//! WHAT THIS FIXES. fl emitted `<sizes>` EMPTY while host glibc publishes one
//! `<size .../>` element per occupied bin — a live probe of this host's glibc
//! 2.42 returned 24 of them. fl was already maintaining exactly the data needed,
//! in the `per_size_class` histogram it updated on every alloc and every free and
//! then never read: the array reached neither `MallocStatsSnapshot` nor
//! `malloc_stats` nor `malloc_info`. So the allocator paid for that bookkeeping on
//! every call and no caller could observe it.
//!
//! WHAT THIS GATE CAN AND CANNOT ASSERT. It cannot demand byte equality with
//! glibc: fl's size classes are not glibc's bins, so the two will legitimately
//! report different boundaries and counts for the same workload. Demanding
//! equality would be demanding fl reimplement glibc's internal binning, which is
//! not the contract. What IS checkable, and is checked here:
//!
//!   * the host arm genuinely populates `<sizes>`, so the divergence being closed
//!     is real and not an assumption about glibc;
//!   * fl populates it too after a workload that must occupy several classes;
//!   * every entry fl emits is INTERNALLY CONSISTENT — `total` equals `from`
//!     times `count`, and `from` equals `to`, which is the convention glibc uses
//!     for its own exact-size bins;
//!   * the counts track reality: freeing everything must not leave the same
//!     population behind.
//!
//! The last point is the one that would catch the likely defect. An emitter wired
//! to a stale or never-decremented array would still produce well-formed XML with
//! plausible numbers, and only a before/after comparison across frees can tell
//! that the histogram is live rather than monotonic.

use std::ffi::c_void;

/// Render `malloc_info` from an implementation into a String via a pipe.
///
/// # Safety
/// `malloc_info` must be a real `malloc_info` and `fdopen`/`fflush` must come from
/// the SAME libc as it, or the `FILE*` is foreign to the writer.
unsafe fn capture(
    malloc_info: unsafe extern "C" fn(i32, *mut c_void) -> i32,
    fdopen: unsafe extern "C" fn(i32, *const i8) -> *mut c_void,
    fflush: unsafe extern "C" fn(*mut c_void) -> i32,
) -> String {
    let mut fds = [0i32; 2];
    // SAFETY: a fresh pipe pair.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");

    // SAFETY: fds[1] is a live writable fd; mode is a NUL-terminated constant.
    let stream = unsafe { fdopen(fds[1], c"w".as_ptr()) };
    assert!(!stream.is_null(), "fdopen failed");

    // SAFETY: options 0 with a live stream is the documented query form.
    let rc = unsafe { malloc_info(0, stream) };
    assert_eq!(rc, 0, "malloc_info returned {rc}");
    // SAFETY: flushing the stream this arm opened.
    unsafe { fflush(stream) };
    // SAFETY: closing the write end so the read below terminates at EOF.
    unsafe { libc::close(fds[1]) };

    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: reading into a local buffer from the pipe's read end.
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast::<c_void>(), buf.len()) };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    // SAFETY: closing the read end we own.
    unsafe { libc::close(fds[0]) };
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `<size .../>` entries out of the first `<sizes>` block.
fn size_entries(xml: &str) -> Vec<(usize, usize, usize, usize)> {
    let Some(start) = xml.find("<sizes>") else {
        return Vec::new();
    };
    let Some(end) = xml[start..].find("</sizes>") else {
        return Vec::new();
    };
    let block = &xml[start..start + end];
    let attr = |tag: &str, s: &str| -> Option<usize> {
        let key = format!("{tag}=\"");
        let i = s.find(&key)? + key.len();
        let j = s[i..].find('"')? + i;
        s[i..j].parse().ok()
    };
    block
        .split("<size ")
        .skip(1)
        .filter_map(|e| {
            Some((
                attr("from", e)?,
                attr("to", e)?,
                attr("total", e)?,
                attr("count", e)?,
            ))
        })
        .collect()
}

type FdopenFn = unsafe extern "C" fn(i32, *const i8) -> *mut c_void;
type FflushFn = unsafe extern "C" fn(*mut c_void) -> i32;
type MallocInfoFn = unsafe extern "C" fn(i32, *mut c_void) -> i32;

fn host_handle() -> *mut c_void {
    // SAFETY: libc.so.6 is the process host libc.
    let h = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!h.is_null(), "dlopen libc.so.6");
    h
}

fn host_sym(name: &std::ffi::CStr) -> *mut c_void {
    // SAFETY: handle from dlopen, name NUL-terminated.
    let p = unsafe { libc::dlsym(host_handle(), name.as_ptr()) };
    assert!(!p.is_null(), "dlsym {name:?}");
    p
}

fn host_stdio() -> (FdopenFn, FflushFn) {
    // SAFETY: both symbols have the C signatures transmuted to.
    unsafe {
        (
            std::mem::transmute::<_, FdopenFn>(host_sym(c"fdopen")),
            std::mem::transmute::<_, FflushFn>(host_sym(c"fflush")),
        )
    }
}

#[test]
fn host_glibc_populates_the_sizes_block() {
    // POSITIVE CONTROL for the whole premise. If the host does not populate
    // <sizes>, then fl's empty block was never a divergence and this gate is
    // asserting a convention that does not exist.
    // SAFETY: the resolved symbol has malloc_info's C signature.
    let mi = unsafe { std::mem::transmute::<_, MallocInfoFn>(host_sym(c"malloc_info")) };
    let (fo, ff) = host_stdio();

    // Occupy a spread of bins through the HOST allocator, keeping half live.
    let mut kept = Vec::new();
    for size in [16usize, 24, 32, 48, 64, 96, 128, 256, 512, 1024] {
        for i in 0..8 {
            // SAFETY: plain host allocation.
            let p = unsafe { libc::malloc(size) };
            assert!(!p.is_null());
            if i % 2 == 0 {
                // SAFETY: freed exactly once.
                unsafe { libc::free(p) };
            } else {
                kept.push(p);
            }
        }
    }

    // SAFETY: all three symbols came from the same libc.
    let xml = unsafe { capture(mi, fo, ff) };
    let entries = size_entries(&xml);
    assert!(
        !entries.is_empty(),
        "host glibc emitted an EMPTY <sizes> block, so fl's empty block would not \
         be a divergence and this gate's premise is wrong. XML: {xml}"
    );

    for p in kept {
        // SAFETY: each freed exactly once.
        unsafe { libc::free(p) };
    }
}

#[test]
fn fl_populates_sizes_consistently_and_the_counts_are_live() {
    // THE STATS MUST BE INITIALISED FIRST, and finding that out was half the
    // exercise. `global_alloc_stats()` deliberately uses `OnceLock::get()` rather
    // than `get_or_init` — initialising it lazily from the allocator would deadlock
    // during early startup — so before prewarm it returns `None` and `record_stats`
    // returns immediately. In a plain test process nothing had ever prewarmed it,
    // so `per_size_class` was not merely write-only, it was never WRITTEN, and this
    // gate's first run reported an empty block for a workload of 36 live objects.
    // That is the correct behaviour of an uninitialised accumulator, not a defect
    // in the emitter.
    frankenlibc_abi::malloc_abi::prewarm_host_allocator_symbols_for_test();
    assert!(
        frankenlibc_abi::malloc_abi::host_allocator_symbols_prewarmed_for_test(),
        "prewarm did not take, so the histogram cannot fill and this gate would \
         pass or fail for reasons unrelated to the emitter"
    );

    // Occupy several classes and keep them live.
    let mut live = Vec::new();
    for size in [16usize, 32, 64, 128, 256, 512] {
        for _ in 0..6 {
            // SAFETY: plain allocation through fl.
            let p = unsafe { frankenlibc_abi::malloc_abi::malloc(size) };
            assert!(!p.is_null(), "fl malloc({size}) returned NULL");
            live.push(p);
        }
    }

    // fl's malloc_info is driven with the HOST's fdopen/fflush, NOT fl's, and the
    // reason is a real hazard rather than a preference. `malloc_info` writes its
    // XML through an unqualified link-time `extern "C" fputs`, so which stdio
    // actually receives the stream is decided by link order rather than by the
    // caller. In this test binary that resolves to glibc, so handing it a FILE*
    // from fl's own fdopen SIGSEGVs — verified, not hypothesised. See the note at
    // the end of this file.
    let (fo, ff) = host_stdio();
    // SAFETY: fl's malloc_info with a host FILE*, which is what its internal
    // link-time fputs expects in this binary.
    let busy = unsafe { capture(frankenlibc_abi::malloc_abi::malloc_info, fo, ff) };
    let busy_entries = size_entries(&busy);
    assert!(
        !busy_entries.is_empty(),
        "fl emitted an EMPTY <sizes> block while {} allocations were live. XML: {busy}",
        live.len()
    );

    // Every entry must be internally consistent. A stale or fabricated emitter
    // produces well-formed XML, so the arithmetic is what catches it.
    for (from, to, total, count) in &busy_entries {
        assert_eq!(from, to, "fl size class must report from == to, got {from}/{to}");
        assert!(*count > 0, "an entry with count 0 should not be emitted");
        assert_eq!(
            *total,
            from.saturating_mul(*count),
            "total must be from*count for the class at {from} (count {count})"
        );
    }

    let busy_population: usize = busy_entries.iter().map(|e| e.3).sum();
    assert!(
        busy_population >= live.len(),
        "fl reported {busy_population} live objects across classes but {} are live",
        live.len()
    );

    // THE LIVENESS CHECK. Free everything and re-read: a histogram that is only
    // ever incremented would report the same population again, which is exactly
    // the defect a structural check cannot see.
    for p in live.drain(..) {
        // SAFETY: each freed exactly once.
        unsafe { frankenlibc_abi::malloc_abi::free(p) };
    }
    // SAFETY: as above, same host stdio.
    let idle = unsafe { capture(frankenlibc_abi::malloc_abi::malloc_info, fo, ff) };
    let idle_population: usize = size_entries(&idle).iter().map(|e| e.3).sum();
    assert!(
        idle_population < busy_population,
        "population did not fall after freeing every allocation ({busy_population} -> \
         {idle_population}); the histogram is not tracking frees"
    );
}
