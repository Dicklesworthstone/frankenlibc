// qsort head-to-head: fl CORE qsort (radix-lane + pdqsort) vs host glibc qsort (merge
// sort) via dlmopen, same i32 key. fl detects integer-natural comparators and radix-sorts
// in O(n) with an O(n) verify, vs glibc's O(n·log n) comparisons — an algorithmic lever.
use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

unsafe extern "C" fn cmp_i32(a: *const c_void, b: *const c_void) -> i32 {
    let x = unsafe { *(a as *const i32) };
    let y = unsafe { *(b as *const i32) };
    (x > y) as i32 - (x < y) as i32
}

fn cmp_rs(a: &[u8], b: &[u8]) -> i32 {
    let x = i32::from_ne_bytes(a[..4].try_into().unwrap());
    let y = i32::from_ne_bytes(b[..4].try_into().unwrap());
    (x > y) as i32 - (x < y) as i32
}

unsafe extern "C" fn cmp_str(a: *const c_void, b: *const c_void) -> i32 {
    let (pa, pb) = (a as *const u8, b as *const u8);
    for i in 0..16 {
        let (x, y) = (unsafe { *pa.add(i) }, unsafe { *pb.add(i) });
        if x != y {
            return x as i32 - y as i32;
        }
    }
    0
}

fn cmp_str_rs(a: &[u8], b: &[u8]) -> i32 {
    for i in 0..16 {
        if a[i] != b[i] {
            return a[i] as i32 - b[i] as i32;
        }
    }
    0
}

unsafe extern "C" fn cmp_i64(a: *const c_void, b: *const c_void) -> i32 {
    let x = unsafe { *(a as *const i64) };
    let y = unsafe { *(b as *const i64) };
    (x > y) as i32 - (x < y) as i32
}

fn cmp_i64_rs(a: &[u8], b: &[u8]) -> i32 {
    let x = i64::from_ne_bytes(a[..8].try_into().unwrap());
    let y = i64::from_ne_bytes(b[..8].try_into().unwrap());
    (x > y) as i32 - (x < y) as i32
}

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type QsortFn = unsafe extern "C" fn(
            *mut c_void,
            usize,
            usize,
            unsafe extern "C" fn(*const c_void, *const c_void) -> i32,
        );
        let gl_qsort: QsortFn =
            std::mem::transmute::<*mut c_void, QsortFn>(libc::dlsym(h, b"qsort\0".as_ptr().cast()));

        let n = 20_000usize;
        let gens: [(&str, fn(usize, usize) -> i32); 4] = [
            ("random", |i, _| (i.wrapping_mul(2_654_435_761) >> 13 & 0x3FFFF) as i32),
            ("sorted", |i, _| i as i32),
            ("reverse", |i, n| (n - i) as i32),
            ("dup10", |i, _| (i % 10) as i32),
        ];
        for (name, genf) in gens.iter() {
            let base: Vec<i32> = (0..n).map(|i| genf(i, n)).collect();

            // Correctness: fl and glibc must produce identical sorted output.
            let mut vf = base.clone();
            {
                let bytes =
                    std::slice::from_raw_parts_mut(vf.as_mut_ptr().cast::<u8>(), n * 4);
                frankenlibc_core::stdlib::sort::qsort(bytes, 4, cmp_rs);
            }
            let mut vg = base.clone();
            gl_qsort(vg.as_mut_ptr().cast(), n, 4, cmp_i32);
            assert_eq!(vf, vg, "{name}: fl qsort != glibc qsort");
            assert!(vf.windows(2).all(|w| w[0] <= w[1]), "{name}: fl not sorted");

            let iters = 1000usize;
            let t0 = Instant::now();
            for _ in 0..iters {
                let mut v = base.clone();
                let bytes =
                    std::slice::from_raw_parts_mut(v.as_mut_ptr().cast::<u8>(), n * 4);
                frankenlibc_core::stdlib::sort::qsort(bytes, 4, cmp_rs);
                black_box(v.as_ptr());
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                let mut v = base.clone();
                gl_qsort(v.as_mut_ptr().cast(), n, 4, cmp_i32);
                black_box(v.as_ptr());
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("SORT {name} n={n} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.2}x", fl / gl);
        }

        // 8-byte i64 random sort — the most common real workload (longs/pointers/keys).
        {
            let base: Vec<i64> = (0..n)
                .map(|i| (i.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 11) as i64)
                .collect();
            let mut vf = base.clone();
            {
                let b = std::slice::from_raw_parts_mut(vf.as_mut_ptr().cast::<u8>(), n * 8);
                frankenlibc_core::stdlib::sort::qsort(b, 8, cmp_i64_rs);
            }
            let mut vg = base.clone();
            gl_qsort(vg.as_mut_ptr().cast(), n, 8, cmp_i64);
            assert_eq!(vf, vg, "i64: fl qsort != glibc qsort");
            let iters = 1000usize;
            let t0 = Instant::now();
            for _ in 0..iters {
                let mut v = base.clone();
                let b = std::slice::from_raw_parts_mut(v.as_mut_ptr().cast::<u8>(), n * 8);
                frankenlibc_core::stdlib::sort::qsort(b, 8, cmp_i64_rs);
                black_box(v.as_ptr());
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                let mut v = base.clone();
                gl_qsort(v.as_mut_ptr().cast(), n, 8, cmp_i64);
                black_box(v.as_ptr());
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("SORT i64rand n={n} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.2}x", fl / gl);
        }

        // String sort: 16-byte random keys, lexicographic (memcmp) comparator.
        let m = 16usize;
        let sbase: Vec<u8> = (0..n * m)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect();
        let mut sf = sbase.clone();
        frankenlibc_core::stdlib::sort::qsort(&mut sf, m, cmp_str_rs);
        let mut sg = sbase.clone();
        gl_qsort(sg.as_mut_ptr().cast(), n, m, cmp_str);
        assert_eq!(sf, sg, "str16: fl qsort != glibc qsort");
        let iters = 1000usize;
        let t0 = Instant::now();
        for _ in 0..iters {
            let mut v = sbase.clone();
            frankenlibc_core::stdlib::sort::qsort(&mut v, m, cmp_str_rs);
            black_box(v.as_ptr());
        }
        let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
        let t1 = Instant::now();
        for _ in 0..iters {
            let mut v = sbase.clone();
            gl_qsort(v.as_mut_ptr().cast(), n, m, cmp_str);
            black_box(v.as_ptr());
        }
        let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
        println!("SORT str16 n={n} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.2}x", fl / gl);

        // Large-array integer sort: fl radix is O(n), glibc merge is O(n·log n) — the gap
        // GROWS with n (the log factor). n=1M random i32. Clone overhead is << the sort at
        // this size and equal for both, so it barely biases the ratio.
        {
            let big = 1_000_000usize;
            let base: Vec<i32> = (0..big)
                .map(|i| (i.wrapping_mul(2_654_435_761) >> 7) as i32)
                .collect();
            let mut vf = base.clone();
            {
                let b = std::slice::from_raw_parts_mut(vf.as_mut_ptr().cast::<u8>(), big * 4);
                frankenlibc_core::stdlib::sort::qsort(b, 4, cmp_rs);
            }
            let mut vg = base.clone();
            gl_qsort(vg.as_mut_ptr().cast(), big, 4, cmp_i32);
            assert_eq!(vf, vg, "i32_1M: fl qsort != glibc qsort");
            let iters = 30usize;
            let t0 = Instant::now();
            for _ in 0..iters {
                let mut v = base.clone();
                let b = std::slice::from_raw_parts_mut(v.as_mut_ptr().cast::<u8>(), big * 4);
                frankenlibc_core::stdlib::sort::qsort(b, 4, cmp_rs);
                black_box(v.as_ptr());
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                let mut v = base.clone();
                gl_qsort(v.as_mut_ptr().cast(), big, 4, cmp_i32);
                black_box(v.as_ptr());
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("SORT i32_1M n={big} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.3}x", fl / gl);
        }
    }
}
