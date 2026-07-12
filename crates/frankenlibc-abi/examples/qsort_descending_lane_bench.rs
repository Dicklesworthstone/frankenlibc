// qsort descending fast-lane head-to-head. The comparison fast-lane window
// [64, 2048] previously only committed ASCENDING integer order, so a descending
// comparator (top-N / recent-first — `return b - a`) verify-failed and dropped to
// the generic stdlib byte sort driven by the caller's FFI comparator on every
// comparison. The new descending attempt is the ascending sort REVERSED (O(n)),
// no second sort, then one O(n) verify.
//
// Arms per (width, signedness): old (callback byte sort = the pre-change
// fallback), new (fl qsort, takes the descending lane), glibc. Reset baseline
// subtracted; output asserted byte-identical to a reference sort before timing.
use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_core::stdlib::qsort as fl_qsort;

fn lcg(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *s >> 1
}

fn fl_cmp_i64_desc(a: &[u8], b: &[u8]) -> i32 {
    i64::from_ne_bytes(b.try_into().unwrap()).cmp(&i64::from_ne_bytes(a.try_into().unwrap())) as i32
}
fn fl_cmp_u64_desc(a: &[u8], b: &[u8]) -> i32 {
    u64::from_ne_bytes(b.try_into().unwrap()).cmp(&u64::from_ne_bytes(a.try_into().unwrap())) as i32
}
extern "C" fn gl_cmp_i64_desc(a: *const c_void, b: *const c_void) -> i32 {
    let x = unsafe { *(a as *const i64) };
    let y = unsafe { *(b as *const i64) };
    y.cmp(&x) as i32
}
extern "C" fn gl_cmp_u64_desc(a: *const c_void, b: *const c_void) -> i32 {
    let x = unsafe { *(a as *const u64) };
    let y = unsafe { *(b as *const u64) };
    y.cmp(&x) as i32
}

// Pre-change generic fallback: the stdlib unstable sort driven by the caller's
// comparator on every comparison.
fn old_generic_sort(buf: &mut [u8], cmp: fn(&[u8], &[u8]) -> i32) {
    let (chunks, _) = buf.as_chunks_mut::<8>();
    chunks.sort_unstable_by(|a, b| cmp(&a[..], &b[..]).cmp(&0));
}

fn reference_sorted(pristine: &[u8], cmp: fn(&[u8], &[u8]) -> i32) -> Vec<u8> {
    let mut v = pristine.to_vec();
    old_generic_sort(&mut v, cmp);
    v
}

fn bench(
    label: &str,
    n: usize,
    fl_cmp: fn(&[u8], &[u8]) -> i32,
    gl_cmp: extern "C" fn(*const c_void, *const c_void) -> i32,
) {
    let mut seed = 0xDE5CE7D ^ (n as u64);
    let mut pristine = vec![0u8; n * 8];
    for chunk in pristine.chunks_exact_mut(8) {
        // Full-range keys, top bit set on ~half (so signed & unsigned diverge and
        // the descending paths of BOTH interpretations are exercised).
        let v = lcg(&mut seed);
        chunk.copy_from_slice(&(v | ((v & 1) << 63)).to_ne_bytes());
    }

    let want = reference_sorted(&pristine, fl_cmp);
    {
        let mut b = pristine.clone();
        fl_qsort(&mut b, 8, fl_cmp);
        assert_eq!(b, want, "{label}: fl new-lane output != reference sort");
        let mut g = pristine.clone();
        unsafe { libc::qsort(g.as_mut_ptr() as *mut c_void, n, 8, Some(gl_cmp)) };
        assert_eq!(g, want, "{label}: glibc output != reference sort");
    }

    let iters = (30_000_000usize / (n * 8)).max(3000);
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
        old_generic_sort(black_box(&mut buf), fl_cmp);
        black_box(&buf);
    }
    let old = (t.elapsed().as_nanos() as f64 / iters as f64 - reset).max(0.0);

    let t = Instant::now();
    for _ in 0..iters {
        buf.copy_from_slice(&pristine);
        fl_qsort(black_box(&mut buf), 8, fl_cmp);
        black_box(&buf);
    }
    let new = (t.elapsed().as_nanos() as f64 / iters as f64 - reset).max(0.0);

    let t = Instant::now();
    for _ in 0..iters {
        buf.copy_from_slice(&pristine);
        unsafe { libc::qsort(black_box(buf.as_mut_ptr()) as *mut c_void, n, 8, Some(gl_cmp)) };
        black_box(&buf);
    }
    let gl = (t.elapsed().as_nanos() as f64 / iters as f64 - reset).max(0.0);

    println!(
        "QSORT-DESC {label} n={n} old={old:.0}ns new={new:.0}ns glibc={gl:.0}ns  \
         old/new={:.2}x  glibc/new(Score)={:.2}x",
        old / new,
        gl / new,
    );
}

fn main() {
    for &n in &[128usize, 512, 1024, 2048] {
        bench("i64desc", n, fl_cmp_i64_desc, gl_cmp_i64_desc);
    }
    for &n in &[128usize, 512, 1024, 2048] {
        bench("u64desc", n, fl_cmp_u64_desc, gl_cmp_u64_desc);
    }
}
