// qsort-of-strings head-to-head: sort an array of char* pointers by strcmp. fl (radix
// bails on the string order -> pdqsort) vs glibc (merge). BOTH use the same C-ABI
// comparator (a byte-loop strcmp), so the comparator cost is identical and only the SORT
// algorithm differs. The common "sort filenames/words/log-lines" workload. Output verified.
use std::ffi::{c_void, CString};
use std::hint::black_box;
use std::time::Instant;

unsafe extern "C" fn cmp_strptr(a: *const c_void, b: *const c_void) -> i32 {
    let pa = unsafe { *(a as *const *const u8) };
    let pb = unsafe { *(b as *const *const u8) };
    let mut i = 0usize;
    loop {
        let ca = unsafe { *pa.add(i) };
        let cb = unsafe { *pb.add(i) };
        if ca != cb {
            return ca as i32 - cb as i32;
        }
        if ca == 0 {
            return 0;
        }
        i += 1;
    }
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
        // Distinct, random-order strings (8 hex chars of a hash).
        let strings: Vec<CString> = (0..n)
            .map(|i| {
                let hsh = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32;
                CString::new(format!("{:08x}", hsh)).unwrap()
            })
            .collect();
        let ptrs: Vec<*const u8> = strings.iter().map(|s| s.as_ptr().cast::<u8>()).collect();

        let fl_cmp = |a: &[u8], b: &[u8]| unsafe { cmp_strptr(a.as_ptr().cast(), b.as_ptr().cast()) };

        // Correctness: fl and glibc produce the same pointer order.
        let mut vf = ptrs.clone();
        {
            let bytes = std::slice::from_raw_parts_mut(vf.as_mut_ptr().cast::<u8>(), n * 8);
            frankenlibc_core::stdlib::sort::qsort(bytes, 8, fl_cmp);
        }
        let mut vg = ptrs.clone();
        gl_qsort(vg.as_mut_ptr().cast(), n, 8, cmp_strptr);
        assert!(vf.iter().zip(&vg).all(|(a, b)| libc::strcmp(a.cast(), b.cast()) == 0), "strsort order");

        let iters = 200usize;
        let t0 = Instant::now();
        for _ in 0..iters {
            let mut v = ptrs.clone();
            let bytes = std::slice::from_raw_parts_mut(v.as_mut_ptr().cast::<u8>(), n * 8);
            frankenlibc_core::stdlib::sort::qsort(bytes, 8, fl_cmp);
            black_box(v.as_ptr());
        }
        let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
        let t1 = Instant::now();
        for _ in 0..iters {
            let mut v = ptrs.clone();
            gl_qsort(v.as_mut_ptr().cast(), n, 8, cmp_strptr);
            black_box(v.as_ptr());
        }
        let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
        println!("STRSORT n={n} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.3}x", fl / gl);
    }
}
