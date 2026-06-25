// Large-buffer head-to-head: fl core mem/str SIMD vs host glibc (dlmopen, same process
// so worker load cancels in the ratio). Tests whether safe-Rust SIMD beats glibc at
// sizes where memory bandwidth / wide-SIMD throughput dominates (the survey only covers
// ~200-byte moderate buffers where SIMD setup overhead makes fl lose).
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
        type MemchrFn = unsafe extern "C" fn(*const c_void, i32, usize) -> *const c_void;
        type StrlenFn = unsafe extern "C" fn(*const c_void) -> usize;
        type MemcmpFn = unsafe extern "C" fn(*const c_void, *const c_void, usize) -> i32;
        let gl_memchr: MemchrFn =
            std::mem::transmute::<*mut c_void, MemchrFn>(libc::dlsym(h, b"memchr\0".as_ptr().cast()));
        let gl_strlen: StrlenFn =
            std::mem::transmute::<*mut c_void, StrlenFn>(libc::dlsym(h, b"strlen\0".as_ptr().cast()));
        let gl_memcmp: MemcmpFn =
            std::mem::transmute::<*mut c_void, MemcmpFn>(libc::dlsym(h, b"memcmp\0".as_ptr().cast()));

        for &size in &[4096usize, 65536, 1_048_576] {
            let iters = (2_000_000_000usize / size).max(200);

            // memchr: byte 'X' only at the very end → full scan.
            let mut buf = vec![b'a'; size];
            buf[size - 1] = b'X';
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_core::string::mem::memchr(black_box(&buf), b'X', size));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_memchr(black_box(buf.as_ptr().cast()), b'X' as i32, size));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("MEM memchr size={size} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.2}x", fl / gl);

            // strlen: NUL only at the end → full scan.
            let mut sbuf = vec![b'a'; size];
            sbuf[size - 1] = 0;
            let t2 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_core::string::str::strlen(black_box(&sbuf)));
            }
            let fls = t2.elapsed().as_nanos() as f64 / iters as f64;
            let t3 = Instant::now();
            for _ in 0..iters {
                black_box(gl_strlen(black_box(sbuf.as_ptr().cast())));
            }
            let gls = t3.elapsed().as_nanos() as f64 / iters as f64;
            println!("MEM strlen size={size} fl={fls:.0}ns glibc={gls:.0}ns fl/glibc={:.2}x", fls / gls);

            // memcmp: equal buffers except the last byte → full scan.
            let a = vec![b'a'; size];
            let mut b = vec![b'a'; size];
            b[size - 1] = b'b';
            let t4 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_core::string::mem::memcmp(black_box(&a), black_box(&b), size));
            }
            let flc = t4.elapsed().as_nanos() as f64 / iters as f64;
            let t5 = Instant::now();
            for _ in 0..iters {
                black_box(gl_memcmp(black_box(a.as_ptr().cast()), black_box(b.as_ptr().cast()), size));
            }
            let glc = t5.elapsed().as_nanos() as f64 / iters as f64;
            println!("MEM memcmp size={size} fl={flc:.0}ns glibc={glc:.0}ns fl/glibc={:.2}x", flc / glc);
        }

        // strstr HARD needle ("aaa…ab" never matches in "aaa…a" → full scan): does glibc's
        // strstr degrade like its weak memmem (290ns) or is it two-way-strong?
        type StrstrFn = unsafe extern "C" fn(*const c_void, *const c_void) -> *const c_void;
        let gl_strstr: StrstrFn =
            std::mem::transmute::<*mut c_void, StrstrFn>(libc::dlsym(h, b"strstr\0".as_ptr().cast()));
        for &hsz in &[4096usize, 65536] {
            let mut hay = vec![b'a'; hsz];
            *hay.last_mut().unwrap() = 0;
            let mut needle = vec![b'a'; 32];
            needle[31] = b'b';
            needle.push(0);
            let iters = (2_000_000_000usize / hsz).max(200);
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_core::string::str::strstr(black_box(&hay), black_box(&needle)));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_strstr(black_box(hay.as_ptr().cast()), black_box(needle.as_ptr().cast())));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("MEM strstr_hard hsz={hsz} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.2}x", fl / gl);
        }

        // strcasestr HARD case-mixed needle: glibc's strcasestr is famously naive O(n·m);
        // fl is dual-anchor case-fold + Two-Way. Needle "a"×31 + "B" never folds-matches
        // in "a"×N (the folded 'b' is absent) → full scan.
        type StrcasestrFn = unsafe extern "C" fn(*const c_void, *const c_void) -> *const c_void;
        let gl_scs: StrcasestrFn = std::mem::transmute::<*mut c_void, StrcasestrFn>(libc::dlsym(
            h,
            b"strcasestr\0".as_ptr().cast(),
        ));
        for &hsz in &[4096usize, 65536] {
            let mut hay = vec![b'a'; hsz];
            *hay.last_mut().unwrap() = 0;
            let mut needle = vec![b'a'; 32];
            needle[31] = b'B';
            needle.push(0);
            let iters = (2_000_000_000usize / hsz).max(200);
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_core::string::str::strcasestr(black_box(&hay), black_box(&needle)));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_scs(black_box(hay.as_ptr().cast()), black_box(needle.as_ptr().cast())));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("MEM strcasestr_hard hsz={hsz} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.2}x", fl / gl);
        }

        // wcsstr HARD wide needle: glibc's wide wcsstr is likely naive O(n·m); fl uses
        // two_way_search_wide + rarity anchor. needle (wide) "a"×31+"b" never matches "a"×N.
        type WcsstrFn = unsafe extern "C" fn(*const i32, *const i32) -> *const i32;
        let gl_wcsstr: WcsstrFn =
            std::mem::transmute::<*mut c_void, WcsstrFn>(libc::dlsym(h, b"wcsstr\0".as_ptr().cast()));
        for &hsz in &[4096usize, 65536] {
            let mut hay: Vec<u32> = vec![b'a' as u32; hsz];
            *hay.last_mut().unwrap() = 0;
            let mut needle: Vec<u32> = vec![b'a' as u32; 32];
            needle[31] = b'b' as u32;
            needle.push(0);
            let iters = (2_000_000_000usize / hsz).max(200);
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_core::string::wide::wcsstr(black_box(&hay), black_box(&needle)));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_wcsstr(black_box(hay.as_ptr().cast()), black_box(needle.as_ptr().cast())));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("MEM wcsstr_hard hsz={hsz} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.2}x", fl / gl);
        }

        // memmove non-overlapping (= memcpy, bandwidth) — 1MB.
        type MemmoveFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> *mut c_void;
        let gl_memmove: MemmoveFn =
            std::mem::transmute::<*mut c_void, MemmoveFn>(libc::dlsym(h, b"memmove\0".as_ptr().cast()));
        {
            let size = 1_048_576usize;
            let src = vec![b'a'; size];
            let mut dst = vec![0u8; size];
            let iters = 4000usize;
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_core::string::mem::memmove(black_box(&mut dst), black_box(&src), size));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_memmove(
                    black_box(dst.as_mut_ptr().cast()),
                    black_box(src.as_ptr().cast()),
                    size,
                ));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("MEM memmove_1M fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.2}x", fl / gl);
        }

        // memset across sizes: glibc uses rep stosb / AVX; fl uses a Rust fill. Small =
        // per-call overhead, large = bandwidth.
        type MemsetFn = unsafe extern "C" fn(*mut c_void, i32, usize) -> *mut c_void;
        let gl_memset: MemsetFn =
            std::mem::transmute::<*mut c_void, MemsetFn>(libc::dlsym(h, b"memset\0".as_ptr().cast()));
        for &size in &[64usize, 4096, 1_048_576] {
            let mut buf = vec![0u8; size];
            let iters = (2_000_000_000usize / size).max(500);
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_core::string::mem::memset(black_box(&mut buf), 0x5a, size));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_memset(black_box(buf.as_mut_ptr().cast()), 0x5a, size));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("MEM memset size={size} fl={fl:.1}ns glibc={gl:.1}ns fl/glibc={:.2}x", fl / gl);
        }
    }
}
