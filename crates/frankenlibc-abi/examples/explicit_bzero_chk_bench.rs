// __explicit_bzero_chk head-to-head: the OLD byte-by-byte write_volatile loop vs
// the NEW path (delegate to explicit_bzero → bzero → raw_memset_bytes, a
// 32B-unrolled write_volatile::<u64> wide fill) vs host glibc explicit_bzero.
// All three keep the security guarantee (volatile stores are not dead-store
// eliminated); the win is bytes-per-store. Output verified all-zero.
use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

// Replica of the pre-fix __explicit_bzero_chk inner loop.
unsafe fn old_byte_volatile_zero(dest: *mut c_void, len: usize) {
    let p = dest as *mut u8;
    for i in 0..len {
        unsafe { std::ptr::write_volatile(p.add(i), 0) };
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
        type BzeroFn = unsafe extern "C" fn(*mut c_void, usize);
        let gl_explicit_bzero: BzeroFn = std::mem::transmute::<*mut c_void, BzeroFn>(libc::dlsym(
            h,
            b"explicit_bzero\0".as_ptr().cast(),
        ));

        for &n in &[16usize, 64, 256, 1024, 4096, 65536] {
            let mut buf = vec![0xAAu8; n];
            let p = buf.as_mut_ptr() as *mut c_void;

            // Correctness: each path must leave the buffer all-zero.
            for (label, run) in [
                ("old", 0u8),
                ("new", 1),
                ("glibc", 2),
            ] {
                buf.iter_mut().for_each(|b| *b = 0xAA);
                match run {
                    0 => old_byte_volatile_zero(p, n),
                    1 => frankenlibc_abi::string_abi::explicit_bzero(p, n),
                    _ => gl_explicit_bzero(p, n),
                }
                assert!(buf.iter().all(|&b| b == 0), "{label} n={n} not fully zeroed");
            }

            // No per-iter reset: a volatile zero writes 0 to every byte regardless of
            // the buffer's current contents, so the cost is identical whether the
            // buffer is dirty or already zero — and omitting the reset keeps a fast
            // non-volatile memset out of the measured ratio.
            let iters = (200_000_000usize / n).max(2000);

            let t = Instant::now();
            for _ in 0..iters {
                old_byte_volatile_zero(black_box(p), n);
                black_box(&buf);
            }
            let old = t.elapsed().as_nanos() as f64 / iters as f64;

            let t = Instant::now();
            for _ in 0..iters {
                frankenlibc_abi::string_abi::explicit_bzero(black_box(p), n);
                black_box(&buf);
            }
            let new = t.elapsed().as_nanos() as f64 / iters as f64;

            let t = Instant::now();
            for _ in 0..iters {
                gl_explicit_bzero(black_box(p), n);
                black_box(&buf);
            }
            let gl = t.elapsed().as_nanos() as f64 / iters as f64;

            println!(
                "EBZERO n={n:>6} old={old:>8.1}ns new={new:>8.1}ns glibc={gl:>8.1}ns  \
                 old/new={:.2}x  new/glibc={:.2}x",
                old / new,
                new / gl,
            );
        }
    }
}
