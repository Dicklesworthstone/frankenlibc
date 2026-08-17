#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // counting global allocator + variadic sscanf calls

//! Pin how many heap allocations one `sscanf` call performs.
//!
//! ## Why a COUNT and not a timing
//!
//! The sscanf family is a measured loss against glibc (`string_token` 2.238x,
//! fl 93.765 ns against 41.880 ns). The gap decomposes: `single_int`, which
//! never reaches the parsing engine because `strict_scan_decimal_ints` serves
//! pure-decimal-int formats from a fixed-size struct, still costs 80.107 ns
//! against 50.699 ns. So roughly 29 ns is fixed overhead OUTSIDE the engine and
//! the engine path adds the rest.
//!
//! What the engine adds that glibc does not is heap traffic: `parse_scanf_format`
//! returns a `Vec<ScanDirective>` and `scan_input` builds a `Vec<ScanValue>`.
//! glibc's `sscanf` allocates nothing for these formats.
//!
//! Timing that difference needs a quiet machine. COUNTING it does not — the
//! count is exact, load-independent, and it is the property actually being
//! changed, so it is what this gate asserts. A ratio measured on a loaded box
//! would be the weaker claim.
//!
//! ## What the numbers mean
//!
//! `ALLOCS_PER_ENGINE_CALL` is a CEILING, not a target: it is asserted with `<=`
//! so removing an allocation makes the gate pass more easily and never fails
//! spuriously, while ADDING one — the regression this exists to catch — fails it.
//! The fast-path case is asserted at zero, which is the standing property that
//! makes those cases the least bad in the family.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::{CString, c_char, c_int};
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};

/// Allocation counter, armed only around the measured call.
///
/// Arming matters: a test binary allocates constantly (formatting, panics,
/// harness bookkeeping), so an unarmed counter measures the harness rather than
/// the call under test.
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);

struct Counting;

// SAFETY: every method forwards to `System` unchanged; the counter is
// observation only and never changes which pointer is returned.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: forwarding the caller's layout to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarding the caller's pointer and layout.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: forwarding the caller's pointer, layout and new size.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: forwarding the caller's layout.
        unsafe { System.alloc_zeroed(layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Run `f` with the counter armed and return how many allocations it made.
fn count_allocs(f: impl FnOnce()) -> usize {
    ALLOCS.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    f();
    ARMED.store(false, Ordering::Relaxed);
    ALLOCS.load(Ordering::Relaxed)
}

/// Allocations one `sscanf` performs, with the CString setup left outside the
/// armed window so only the call itself is counted.
fn allocs_for(input: &str, format: &str) -> usize {
    let cin = CString::new(input).unwrap();
    let cfmt = CString::new(format).unwrap();
    let mut out = [0u8; 256];
    let mut n: c_int = 0;

    // Warm any one-time lazy initialisation (locale tables, policy state) so it
    // is not billed to the measured call.
    // SAFETY: the format takes one %s-shaped pointer and one %n.
    unsafe {
        frankenlibc_abi::stdio_abi::sscanf(
            cin.as_ptr(),
            cfmt.as_ptr(),
            out.as_mut_ptr().cast::<c_char>(),
            &mut n as *mut c_int,
        );
    }

    count_allocs(|| {
        // SAFETY: same call, now inside the armed window.
        unsafe {
            frankenlibc_abi::stdio_abi::sscanf(
                std::hint::black_box(cin.as_ptr()),
                std::hint::black_box(cfmt.as_ptr()),
                out.as_mut_ptr().cast::<c_char>(),
                &mut n as *mut c_int,
            );
        }
    })
}

/// Ceiling for one engine-path call. See the module note: `<=`, so removing an
/// allocation never fails this gate and adding one does.
///
/// It is 1, not 0, for exactly one reason: `%[...]` boxes its 257-byte `ScanSet`
/// table, and only a scanset conversion pays that. `%s`, `%f` and the literal
/// directives around them allocate NOTHING, which is what glibc does. Before
/// this was measured the same three formats cost four allocations each.
const ALLOCS_PER_ENGINE_CALL: usize = 1;

#[test]
fn engine_path_allocation_count_is_bounded() {
    for (input, format) in [
        ("hello world", "%s%n"),
        ("key=value", "%[^=]%n"),
        ("3.5", "%f%n"),
    ] {
        let n = allocs_for(input, format);
        println!("sscanf({input:?}, {format:?}) allocations={n}");
        assert!(
            n <= ALLOCS_PER_ENGINE_CALL,
            "sscanf({input:?}, {format:?}) made {n} allocations, ceiling is \
             {ALLOCS_PER_ENGINE_CALL}. Every allocation here is per-CALL cost that glibc \
             does not pay, and this family is a measured loss (string_token 2.238x)."
        );
    }
}

/// The decimal-int fast path must stay allocation-free.
///
/// This is the load-bearing half of the file. `single_int` and `two_ints` are
/// the least-bad cases in the family precisely because
/// `strict_decimal_int_format_count` routes them around the engine; if that
/// routing ever breaks they would quietly acquire the engine's allocations and
/// the only symptom would be a slightly worse benchmark nobody re-ran.
#[test]
fn decimal_int_fast_path_allocates_nothing() {
    for (input, format) in [("42", "%d"), ("1 2", "%d %d"), ("7 8 9", "%d %d %d")] {
        let cin = CString::new(input).unwrap();
        let cfmt = CString::new(format).unwrap();
        let mut a: c_int = 0;
        let mut b: c_int = 0;
        let mut c: c_int = 0;

        // SAFETY: the formats take at most three int pointers.
        unsafe {
            frankenlibc_abi::stdio_abi::sscanf(
                cin.as_ptr(),
                cfmt.as_ptr(),
                &mut a as *mut c_int,
                &mut b as *mut c_int,
                &mut c as *mut c_int,
            );
        }

        let n = count_allocs(|| {
            // SAFETY: same call inside the armed window.
            unsafe {
                frankenlibc_abi::stdio_abi::sscanf(
                    std::hint::black_box(cin.as_ptr()),
                    std::hint::black_box(cfmt.as_ptr()),
                    &mut a as *mut c_int,
                    &mut b as *mut c_int,
                    &mut c as *mut c_int,
                );
            }
        });
        println!("sscanf({input:?}, {format:?}) allocations={n} (fast path)");
        assert_eq!(
            n, 0,
            "sscanf({input:?}, {format:?}) took the ENGINE path and allocated {n} times; \
             the pure-decimal-int fast path is what makes these the least-bad cases"
        );
    }
}

/// The counter itself must be able to see an allocation, or every zero above is
/// meaningless.
#[test]
fn the_counter_observes_a_known_allocation() {
    let n = count_allocs(|| {
        let v: Vec<u8> = Vec::with_capacity(4096);
        std::hint::black_box(&v);
    });
    assert!(n >= 1, "counting allocator observed {n} allocations for a 4 KiB Vec");
}

/// The STREAM family goes through the same engine but reads its input into a
/// buffer first, so it is counted separately.
///
/// `read_stream_for_scanf` used to `vec![0u8; cap]` per call — an 8 KiB
/// allocation and an 8 KiB zero-fill for bytes `read` immediately overwrote.
/// It now takes a per-thread pooled buffer and reads into its spare capacity,
/// so a warmed thread allocates nothing, which is what glibc does.
#[test]
fn stream_scanf_reuses_its_read_buffer() {
    use std::io::Write;

    let dir = std::env::temp_dir().join("fl_scanf_alloc_count");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("input.txt");
    {
        let mut f = std::fs::File::create(&path).expect("create input");
        writeln!(f, "hello 42").expect("write input");
    }
    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    let mode = CString::new("r").unwrap();
    let fmt = CString::new("%s %d").unwrap();

    let mut word = [0u8; 64];
    let mut n: c_int = 0;

    // Warm, then measure a second call on a freshly opened stream so the count
    // is one call's cost and not first-touch initialisation.
    for warm in [true, false] {
        // SAFETY: path and mode are NUL-terminated.
        let f = unsafe { frankenlibc_abi::stdio_abi::fopen(cpath.as_ptr(), mode.as_ptr()) };
        assert!(!f.is_null(), "fopen failed");
        let counted = count_allocs(|| {
            // SAFETY: the format takes one char* and one int*.
            unsafe {
                frankenlibc_abi::stdio_abi::fscanf(
                    f,
                    fmt.as_ptr(),
                    word.as_mut_ptr().cast::<c_char>(),
                    &mut n as *mut c_int,
                );
            }
        });
        // SAFETY: `f` came from fopen above.
        unsafe { frankenlibc_abi::stdio_abi::fclose(f) };
        if !warm {
            println!("fscanf(\"%s %d\") allocations={counted} (stream path)");
            assert_eq!(n, 42, "fscanf did not parse the input");
            assert_eq!(
                counted, 0,
                "stream fscanf allocated {counted} times on a warmed thread; the read \
                 buffer is pooled precisely so it does not"
            );
        }
    }
}
