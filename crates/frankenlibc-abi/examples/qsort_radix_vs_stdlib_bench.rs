// Does the shipped ASCENDING integer radix lane (widths 2/4/8, num>threshold)
// beat the stdlib fixed-width fallback it preempts? The radix lane's shipped wins
// were measured vs glibc / the in-house pdqsort_recurse, NOT vs `std_sort_unstable_
// fixed_width` (a `[u8;N]` stdlib pdqsort, added later, which runs when the radix
// lane is skipped). Isolate the two on the SAME data with the SAME extern-"C"
// comparator (both pay realistic FFI: radix ~n verify calls, stdlib ~n log n).
//
//   radix  = __bench_integer_radix_attempt (the lane alone, must commit)
//   stdlib = as_chunks_mut::<N>().sort_unstable_by(extern-C cmp)  (the fallback)
//   glibc  = libc::qsort
// radix/stdlib > 1 ⇒ radix slower than the fallback ⇒ narrow/remove it.
use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

fn lcg(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *s >> 1
}

extern "C" fn gl_cmp_i16(a: *const c_void, b: *const c_void) -> i32 {
    unsafe { (*(a as *const i16)).cmp(&*(b as *const i16)) as i32 }
}
extern "C" fn gl_cmp_i32(a: *const c_void, b: *const c_void) -> i32 {
    unsafe { (*(a as *const i32)).cmp(&*(b as *const i32)) as i32 }
}
extern "C" fn gl_cmp_i64(a: *const c_void, b: *const c_void) -> i32 {
    unsafe { (*(a as *const i64)).cmp(&*(b as *const i64)) as i32 }
}

fn make(n: usize, width: usize, dist: &str) -> Vec<u8> {
    let mut s = 0x9E37_79B9_7F4A_7C15u64 ^ (n as u64) ^ ((width as u64) << 40);
    let mut out = Vec::with_capacity(n * width);
    for i in 0..n {
        let v: i64 = match dist {
            "rand" => lcg(&mut s) as i64,
            "sorted" => i as i64,
            "reverse" => (n - i) as i64,
            "dups" => (lcg(&mut s) % 16) as i64,
            _ => unreachable!(),
        };
        out.extend_from_slice(&v.to_ne_bytes()[..width]);
    }
    out
}

fn stdlib_sort(buf: &mut [u8], width: usize, cmp: fn(&[u8], &[u8]) -> i32) {
    macro_rules! s {
        ($n:literal) => {{
            let (c, _) = buf.as_chunks_mut::<$n>();
            c.sort_unstable_by(|a, b| cmp(&a[..], &b[..]).cmp(&0));
        }};
    }
    match width {
        2 => s!(2),
        4 => s!(4),
        8 => s!(8),
        _ => unreachable!(),
    }
}

fn bench(
    n: usize,
    width: usize,
    dist: &str,
    fl_cmp: fn(&[u8], &[u8]) -> i32,
    gl_cmp: extern "C" fn(*const c_void, *const c_void) -> i32,
) {
    let pristine = make(n, width, dist);
    {
        let mut r = pristine.clone();
        let committed =
            frankenlibc_core::stdlib::sort::__bench_integer_radix_attempt(&mut r, width, &fl_cmp);
        assert!(committed, "radix did not commit w{width} {dist} n={n}");
        let mut sb = pristine.clone();
        stdlib_sort(&mut sb, width, fl_cmp);
        assert_eq!(r, sb, "radix vs stdlib mismatch w{width} {dist} n={n}");
    }

    let iters = (80_000_000usize / (n * width)).max(400);
    let mut buf = pristine.clone();

    let t = Instant::now();
    for _ in 0..iters {
        buf.copy_from_slice(&pristine);
        black_box(&buf);
    }
    let reset = t.elapsed().as_nanos() as f64 / iters as f64;

    let t = Instant::now();
    for _ in 0..iters {
        buf.copy_from_slice(&pristine);
        black_box(frankenlibc_core::stdlib::sort::__bench_integer_radix_attempt(
            black_box(&mut buf),
            width,
            &fl_cmp,
        ));
    }
    let radix = (t.elapsed().as_nanos() as f64 / iters as f64 - reset).max(0.0);

    let t = Instant::now();
    for _ in 0..iters {
        buf.copy_from_slice(&pristine);
        stdlib_sort(black_box(&mut buf), width, fl_cmp);
        black_box(&buf);
    }
    let stdlib = (t.elapsed().as_nanos() as f64 / iters as f64 - reset).max(0.0);

    let t = Instant::now();
    for _ in 0..iters {
        buf.copy_from_slice(&pristine);
        unsafe {
            libc::qsort(black_box(buf.as_mut_ptr()) as *mut c_void, n, width, Some(gl_cmp))
        };
        black_box(&buf);
    }
    let gl = (t.elapsed().as_nanos() as f64 / iters as f64 - reset).max(0.0);

    println!(
        "RADIXvsSTDLIB w{width} {dist:>7} n={n:>6} radix={radix:>9.0} stdlib={stdlib:>9.0} glibc={gl:>9.0}  \
         radix/stdlib={:.2}x  glibc/stdlib={:.2}x",
        radix / stdlib,
        gl / stdlib,
    );
}

// The deployed `compare` closure is exactly this: hand the two element pointers to
// the caller's extern-"C" comparator. NO Rust-side from_ne_bytes/try_into (that
// bounds-check + panic path inflates the arm making more comparisons and does not
// exist in the real lib). Both radix-verify and stdlib pay this identical cost.
fn cmp16(a: &[u8], b: &[u8]) -> i32 {
    gl_cmp_i16(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void)
}
fn cmp32(a: &[u8], b: &[u8]) -> i32 {
    gl_cmp_i32(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void)
}
fn cmp64(a: &[u8], b: &[u8]) -> i32 {
    gl_cmp_i64(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void)
}

fn main() {
    let widths: [(usize, fn(&[u8], &[u8]) -> i32, extern "C" fn(*const c_void, *const c_void) -> i32); 3] =
        [(2, cmp16, gl_cmp_i16), (4, cmp32, gl_cmp_i32), (8, cmp64, gl_cmp_i64)];
    for (w, fl, gl) in widths {
        for &dist in &["rand", "dups", "sorted"] {
            for &n in &[16384usize, 262144] {
                bench(n, w, dist, fl, gl);
            }
        }
    }
}
