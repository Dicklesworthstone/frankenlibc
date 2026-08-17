#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // variadic sscanf against the host oracle

//! The memoised scanf format cache must never answer for the wrong format.
//!
//! ## What is being guarded
//!
//! `scanf_core_impl` memoises `parse_scanf_format` per thread, because a profile
//! of the family's worst case spends 24.5% rebuilding directives for a format it
//! already parsed, plus 6.8% in the allocator for a `Box<ScanSet>` it re-boxes
//! every call. Formats are almost always string literals scanned in a loop, so
//! the hit rate is high and the saving is real.
//!
//! The cache keys on the format BYTES. Keying on the format POINTER would be
//! cheaper and would be a correctness hole: nothing stops a caller building a
//! format in a reusable buffer, so one address can hold different text call to
//! call. A pointer-keyed cache would then scan the input with the PREVIOUS
//! format and return a plausible, wrong answer — no crash, no diagnostic.
//!
//! [`the_cache_does_not_confuse_two_formats_at_one_address`] is the test that
//! would fail if anyone ever "optimises" the comparison away, and it is written
//! to fail for that reason specifically: it reuses ONE buffer, overwriting it
//! between calls, so the address is identical and only the bytes differ.
//!
//! The rest of the file checks the cache is transparent — same answers as the
//! host for repeated, alternating and first-call-cold sequences.

use std::ffi::{CString, c_char, c_int};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

type SscanfFn = unsafe extern "C" fn(*const c_char, *const c_char, ...) -> c_int;

fn glibc_sscanf() -> SscanfFn {
    // SAFETY: NUL-terminated name paired with fl's own definition, so a
    // collapsed arm is detected rather than compared against itself.
    unsafe {
        host_fn(
            c"__isoc23_sscanf",
            frankenlibc_abi::isoc_abi::__isoc23_sscanf as *const (),
        )
    }
}

/// Scan with one `char*` destination and return `(rc, text)`.
///
/// Takes the format as a raw pointer so a caller can control the ADDRESS, which
/// is the whole point of the aliasing test below.
fn scan_str(f: SscanfFn, input: &str, format: *const c_char) -> (c_int, String) {
    let cin = CString::new(input).expect("input has NUL");
    let mut buf = [0u8; 128];
    // SAFETY: every format used here takes exactly one `char *`, and the buffer
    // outsizes every token in this file.
    let rc = unsafe { f(cin.as_ptr(), format, buf.as_mut_ptr().cast::<c_char>()) };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(0);
    (rc, String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// THE load-bearing test: one address, two different formats.
///
/// The formats carry a WIDTH (`%9[^=]`, `%9[^,]`) for a reason that cost me a
/// hollow gate before I caught it. Written first as bare `%[^=]` / `%[^,]`, this
/// test passed even against a deliberately broken cache keyed on format LENGTH —
/// because a bare negated scanset is served by `strict_single_negated_scanset`
/// and never consults the cache at all. A width makes every fast path decline,
/// so these formats reach the engine and the cache is genuinely on the path.
///
/// The two stop at different delimiters, so against `"a=b,c"` they give `"a"`
/// versus `"a=b"`: a cache that reused the first parse for the second call
/// cannot produce the right answer by luck. They are also the SAME LENGTH, so a
/// cache comparing only lengths is caught too.
#[test]
fn the_cache_does_not_confuse_two_formats_at_one_address() {
    let glibc = glibc_sscanf();

    // ONE buffer, rewritten between calls: the format pointer is identical every
    // time and only the bytes change.
    let mut fmt_buf = [0u8; 8];
    let fmt_ptr = fmt_buf.as_mut_ptr().cast::<c_char>();

    let write = |buf: &mut [u8; 8], text: &str| {
        buf.fill(0);
        buf[..text.len()].copy_from_slice(text.as_bytes());
    };

    const INPUT: &str = "a=b,c";

    // Alternate the two formats through the same address several times, so a
    // stale entry has to survive only one call to be caught.
    for round in 0..4 {
        write(&mut fmt_buf, "%9[^=]");
        let want_eq = scan_str(glibc, INPUT, fmt_ptr);
        let got_eq = scan_str(
            frankenlibc_abi::isoc_abi::__isoc23_sscanf as SscanfFn,
            INPUT,
            fmt_ptr,
        );

        write(&mut fmt_buf, "%9[^,]");
        let want_comma = scan_str(glibc, INPUT, fmt_ptr);
        let got_comma = scan_str(
            frankenlibc_abi::isoc_abi::__isoc23_sscanf as SscanfFn,
            INPUT,
            fmt_ptr,
        );

        // Assert the two formats genuinely differ in outcome, or the test could
        // pass with a completely broken cache.
        assert_ne!(
            want_eq, want_comma,
            "round {round}: the two formats gave the same host answer, so this \
             test cannot detect a stale cache entry"
        );
        assert_eq!(
            want_eq,
            (1, "a".to_string()),
            "round {round}: host %9[^=] on {INPUT:?}"
        );
        assert_eq!(
            want_comma,
            (1, "a=b".to_string()),
            "round {round}: host %9[^,] on {INPUT:?}"
        );

        assert_eq!(
            got_eq, want_eq,
            "round {round}: fl %9[^=] at a reused address produced {got_eq:?}, host \
             produced {want_eq:?} — the format cache answered for the wrong format"
        );
        assert_eq!(
            got_comma, want_comma,
            "round {round}: fl %9[^,] at a reused address produced {got_comma:?}, host \
             produced {want_comma:?} — the format cache answered for the wrong format"
        );
    }
}

/// A repeated format must give the same answer cold and warm.
#[test]
fn a_repeated_format_is_stable_across_calls() {
    let glibc = glibc_sscanf();
    let fmt = CString::new("%9[^=]").expect("format has NUL");

    for (round, input) in ["key=value", "other=thing", "nodelimiter", "=leading"]
        .iter()
        .cycle()
        .take(12)
        .enumerate()
    {
        let want = scan_str(glibc, input, fmt.as_ptr());
        let got = scan_str(
            frankenlibc_abi::isoc_abi::__isoc23_sscanf as SscanfFn,
            input,
            fmt.as_ptr(),
        );
        assert_eq!(
            got, want,
            "call {round} on {input:?}: fl produced {got:?}, host produced {want:?}"
        );
    }
}

/// Interleaving distinct formats must not let one populate the other's answer.
///
/// A single-entry cache evicts on every switch, so this is the case that would
/// break if eviction were ever made lazy or the entry made shared.
#[test]
fn interleaved_formats_do_not_contaminate_each_other() {
    let glibc = glibc_sscanf();
    let formats = [
        (CString::new("%9[^=]").unwrap(), "a=b,c"),
        (CString::new("%9[^,]").unwrap(), "a=b,c"),
        (CString::new("%s").unwrap(), "  token rest"),
        (CString::new("%9[^ ]").unwrap(), "token rest"),
    ];

    let mut compared = 0usize;
    for round in 0..3 {
        for (fmt, input) in &formats {
            let want = scan_str(glibc, input, fmt.as_ptr());
            let got = scan_str(
                frankenlibc_abi::isoc_abi::__isoc23_sscanf as SscanfFn,
                input,
                fmt.as_ptr(),
            );
            assert_eq!(
                got, want,
                "round {round} {fmt:?} on {input:?}: fl produced {got:?}, host produced {want:?}"
            );
            compared += 1;
        }
    }
    assert_eq!(compared, formats.len() * 3, "the loop skipped cases");
    println!("interleaved {compared} format/input pairs against the host");
}
