//! A/B for the regex `leftmost_start` prefilter-seed prune. Patterns with a
//! determinate but NON-literal first byte (char-class led, e.g. `[0-9]+END`) take
//! the `leftmost_start` merged-sweep path (no literal_prefix memmem jump). Before
//! the prune, that sweep seeded a fresh epsilon-closure at EVERY input position;
//! after, it skips positions whose byte is not in the prefilter's first-byte set.
//!
//! Run OLD vs NEW by stashing the regex change between invocations; the win is
//! algorithmic (O(n) wasted closures -> O(n) byte checks) so it dwarfs worker
//! noise. Cases: absent match over all-letters (extreme), and a sparse-digit
//! haystack with a late match (realistic).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench regex_prefilter_ab_bench`

use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use frankenlibc_core::string::regex::{regex_compile, regex_match_bounds_bytes, REG_EXTENDED};

// Host glibc regexec (no abi-bench → resolves to libc), for the vs-glibc ratio.
fn glibc_regexec_matches(preg: &libc::regex_t, hay_cstr: &std::ffi::CStr) -> bool {
    unsafe { libc::regexec(preg, hay_cstr.as_ptr(), 0, std::ptr::null_mut(), 0) == 0 }
}

fn bench(c: &mut Criterion) {
    // (1) sparse digit first-byte, match late: `[0-9]+END` over text with sparse
    //     digit runs. Exercises the seed-prune (skip non-digit closures).
    let mut sparse: Vec<u8> = Vec::with_capacity(4096);
    let unit = b"the brown fox 7 jumps over 42 the lazy dog rests a while. ";
    while sparse.len() < 4000 {
        sparse.extend_from_slice(unit);
    }
    sparse.extend_from_slice(b"99END");

    // (2) RARE first-byte, match at the very end: `[0-9][0-9][0-9]X` over 4 KiB of
    //     letters with the only digits in "999X" at the end. The first-byte set
    //     (digits) is empty until the last 4 bytes — so the empty-region JUMP
    //     fast-forwards ~4 KiB in one scan instead of stepping every position.
    let mut rare: Vec<u8> = vec![b'a'; 4092];
    rare.extend_from_slice(b"999X");

    // (3) ICASE class matched per byte along ONE long run: `X[a-z]+9` over
    //     "X" + 4089 'a' + "9". The rare 'X' first byte means a SINGLE start (no
    //     O(n^2) multi-seed), and the surviving thread walks `[a-z]` across the
    //     whole run — so the timed work IS the per-byte class test. The OLD
    //     matches_byte ran a NESTED per-char loop (26 compares/byte under ICASE);
    //     the bitset is one lookup.
    const REG_ICASE: i32 = 2; // frankenlibc REG_ICASE bit
    let mut icase: Vec<u8> = vec![b'X'];
    icase.extend(std::iter::repeat(b'a').take(4089));
    icase.push(b'9');

    // Each case: (name, pattern, fl_cflags, glibc_cflags, haystack).
    let cases: &[(&str, &str, i32, i32, &Vec<u8>)] = &[
        ("sparse_digits_late", "[0-9]+END", REG_EXTENDED, libc::REG_EXTENDED, &sparse),
        ("rare_firstbyte_jump", "[0-9][0-9][0-9]X", REG_EXTENDED, libc::REG_EXTENDED, &rare),
        (
            "icase_class_perbyte",
            "X[a-z]+9",
            REG_EXTENDED | REG_ICASE,
            libc::REG_EXTENDED | libc::REG_ICASE,
            &icase,
        ),
    ];

    for &(name, pat_str, fl_cflags, gl_cflags, hay) in cases {
        let pat = regex_compile(pat_str.as_bytes(), fl_cflags).expect("compile");
        let mut gpreg: libc::regex_t = unsafe { std::mem::zeroed() };
        let pat_c = std::ffi::CString::new(pat_str).unwrap();
        assert_eq!(
            unsafe { libc::regcomp(&mut gpreg, pat_c.as_ptr(), gl_cflags) },
            0,
            "glibc regcomp failed"
        );
        let hay_c = std::ffi::CString::new(hay.as_slice()).unwrap();
        // correctness: fl and glibc agree on match presence.
        let fl_m = regex_match_bounds_bytes(&pat, hay, 0).is_some();
        let gl_m = glibc_regexec_matches(&gpreg, &hay_c);
        assert_eq!(fl_m, gl_m, "fl/glibc disagree on {name}");
        let mut g = c.benchmark_group(format!("regex_prefilter_{name}"));
        g.throughput(Throughput::Bytes(hay.len() as u64));
        g.bench_function("fl_core", |b| {
            b.iter(|| black_box(regex_match_bounds_bytes(&pat, black_box(hay), 0)))
        });
        g.bench_function("host_glibc", |b| {
            b.iter(|| black_box(glibc_regexec_matches(&gpreg, black_box(&hay_c))))
        });
        g.finish();
        unsafe { libc::regfree(&mut gpreg) };
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
