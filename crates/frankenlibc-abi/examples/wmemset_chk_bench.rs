// Is __wmemset_chk's scalar `for i { *dest.add(i)=c }` loop actually slower than
// the dedicated wmemset (slice.fill) it could delegate to? Unlike explicit_bzero
// this fill is NON-volatile, so LLVM should auto-vectorize both to the same SIMD
// stores — this bench confirms whether delegation is a real win or within-noise.
// c is non-byte-repeating so no path can shortcut to a byte memset.
use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type WmemsetFn = unsafe extern "C" fn(*mut u32, u32, usize) -> *mut u32;
        let gl_wmemset: WmemsetFn = std::mem::transmute::<*mut c_void, WmemsetFn>(libc::dlsym(
            h,
            b"wmemset\0".as_ptr().cast(),
        ));

        const C: u32 = 0x1234_5678;
        for &n in &[16usize, 64, 256, 1024, 4096, 65536] {
            let mut buf = vec![0u32; n];
            let p = buf.as_mut_ptr();

            // Correctness: all three fill n words with C.
            for run in 0..3u8 {
                buf.iter_mut().for_each(|w| *w = 0);
                match run {
                    0 => {
                        frankenlibc_abi::fortify_abi::__wmemset_chk(p as *mut i32, C as i32, n, usize::MAX);
                    }
                    1 => {
                        frankenlibc_abi::wchar_abi::wmemset(p, C, n);
                    }
                    _ => {
                        gl_wmemset(p, C, n);
                    }
                }
                assert!(buf.iter().all(|&w| w == C), "run {run} n={n} not filled");
            }

            let iters = (200_000_000usize / n).max(2000);

            let t = Instant::now();
            for _ in 0..iters {
                frankenlibc_abi::fortify_abi::__wmemset_chk(black_box(p) as *mut i32, C as i32, n, usize::MAX);
                black_box(&buf);
            }
            let chk = t.elapsed().as_nanos() as f64 / iters as f64;

            let t = Instant::now();
            for _ in 0..iters {
                frankenlibc_abi::wchar_abi::wmemset(black_box(p), C, n);
                black_box(&buf);
            }
            let wm = t.elapsed().as_nanos() as f64 / iters as f64;

            let t = Instant::now();
            for _ in 0..iters {
                gl_wmemset(black_box(p), C, n);
                black_box(&buf);
            }
            let gl = t.elapsed().as_nanos() as f64 / iters as f64;

            println!(
                "WMEMSET n={n:>6} chk(scalar)={chk:>8.1}ns wmemset={wm:>8.1}ns glibc={gl:>8.1}ns  \
                 chk/wmemset={:.2}x  wmemset/glibc={:.2}x",
                chk / wm,
                wm / gl,
            );
        }
    }
}
