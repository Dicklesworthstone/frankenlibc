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
    }
}
