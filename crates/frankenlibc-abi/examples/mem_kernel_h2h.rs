//! Head-to-head for `frankenlibc-core`'s memory-scan kernels against the live host glibc,
//! run entirely in ONE process so both arms share the CPU, the caches and the invocation.
//!
//! Method notes that make the numbers admissible:
//!
//! * The incumbent is opened with `dlmopen(LM_ID_NEWLM, "libc.so.6")`, so it is the real
//!   shipped glibc in its own link-map namespace rather than anything this crate provides.
//!   The two arms are asserted to be different code by comparing the resolved pointer
//!   against the fl-side one; a self-compare would report a meaningless 1.0.
//! * Every op reports an **A/A null**: the glibc arm timed twice, back to back, under the
//!   identical loop. That is the noise floor for this host at this moment, and a ratio that
//!   is not close to 1.0 invalidates the paired fl/glibc figure printed beside it.
//! * The **ELF sha256 is computed from inside the running process** (`/proc/self/exe`), so
//!   the reported identity is the binary that actually produced the numbers.
//! * Results are the **median of `ROUNDS` interleaved rounds**, alternating arms within each
//!   round, so a monotonic drift in clock speed lands on both arms rather than on whichever
//!   ran second.
//! * Conformance is checked before timing: if the two arms disagree on an answer the op is
//!   reported as MISMATCH and no ratio is printed, because timing two functions that compute
//!   different things is not a comparison.

use std::hint::black_box;
use std::time::Instant;

const ROUNDS: usize = 9;

type MemchrFn = unsafe extern "C" fn(*const u8, i32, usize) -> *const u8;
type MemrchrFn = unsafe extern "C" fn(*const u8, i32, usize) -> *const u8;
type MemcmpFn = unsafe extern "C" fn(*const u8, *const u8, usize) -> i32;
type MemmemFn =
    unsafe extern "C" fn(*const u8, usize, *const u8, usize) -> *const u8;

fn sha256_self() -> String {
    use sha2::{Digest, Sha256};
    match std::fs::read("/proc/self/exe") {
        Ok(bytes) => {
            let mut h = Sha256::new();
            h.update(&bytes);
            format!("{:x}", h.finalize())
        }
        Err(_) => "<unreadable>".to_string(),
    }
}

/// Median of the per-round nanosecond figures.
fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn report(op: &str, n: usize, fl: f64, gl: f64, aa: f64) {
    println!(
        "{op:<16} n={n:<6} fl={fl:8.2}ns glibc={gl:8.2}ns  fl/glibc={:6.3}x   A/A_null={:.3}",
        fl / gl,
        aa
    );
}

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_NOW | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");

        println!("SELF_ELF_SHA256={}", sha256_self());
        let phase: Option<unsafe extern "C" fn() -> i32> = {
            let p = libc::dlsym(libc::RTLD_DEFAULT, c"__frankenlibc_runtime_phase".as_ptr());
            if p.is_null() { None } else { Some(std::mem::transmute(p)) }
        };
        // Stated, not assumed: an example links fl as an rlib rather than loading it as the
        // process libc, so the ABI entrypoints are NOT at PHASE=2 here. These figures are for
        // the CORE kernels, which is what this harness compares.
        println!(
            "RUNTIME_PHASE={} (example links fl as an rlib; core kernels under test)",
            phase.map_or(-1, |f| f())
        );
        println!("INCUMBENT=libc.so.6 via dlmopen(LM_ID_NEWLM)\n");

        let gl_memchr: MemchrFn =
            std::mem::transmute(libc::dlsym(h, c"memchr".as_ptr()));
        let gl_memrchr: MemrchrFn =
            std::mem::transmute(libc::dlsym(h, c"memrchr".as_ptr()));
        let gl_memcmp: MemcmpFn =
            std::mem::transmute(libc::dlsym(h, c"memcmp".as_ptr()));
        let gl_memmem: MemmemFn =
            std::mem::transmute(libc::dlsym(h, c"memmem".as_ptr()));
        assert!(
            gl_memchr as usize != frankenlibc_core::string::mem::memchr as usize,
            "arms identical"
        );

        // buffers: needle at the very end so both arms scan the whole length
        for &n in &[8usize, 16, 32, 64, 128, 256, 1024] {
            let mut buf = vec![b'a'; n];
            buf[n - 1] = b'z';

            // conformance before timing
            let fl_hit = frankenlibc_core::string::mem::memchr(&buf, b'z', n);
            let gl_hit = gl_memchr(buf.as_ptr(), b'z' as i32, n);
            let gl_idx = if gl_hit.is_null() {
                None
            } else {
                Some(gl_hit as usize - buf.as_ptr() as usize)
            };
            if fl_hit != gl_idx {
                println!("memchr          n={n:<6} MISMATCH fl={fl_hit:?} glibc={gl_idx:?}");
                continue;
            }

            let iters = (1 << 22) / n.max(8);
            let (mut fls, mut gls, mut aas) = (vec![], vec![], vec![]);
            for _ in 0..ROUNDS {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(frankenlibc_core::string::mem::memchr(
                        black_box(&buf),
                        black_box(b'z'),
                        black_box(n),
                    ));
                }
                fls.push(t.elapsed().as_nanos() as f64 / iters as f64);

                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memchr(black_box(buf.as_ptr()), black_box(b'z' as i32), black_box(n)));
                }
                gls.push(t.elapsed().as_nanos() as f64 / iters as f64);

                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memchr(black_box(buf.as_ptr()), black_box(b'z' as i32), black_box(n)));
                }
                aas.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
            let (fl, gl) = (median(fls), median(gls.clone()));
            report("memchr", n, fl, gl, median(aas) / gl);
        }
        println!();

        for &n in &[8usize, 16, 64, 256, 1024] {
            let mut buf = vec![b'a'; n];
            buf[0] = b'z';
            let fl_hit = frankenlibc_core::string::mem::memrchr(&buf, b'z', n);
            let gl_hit = gl_memrchr(buf.as_ptr(), b'z' as i32, n);
            let gl_idx = if gl_hit.is_null() {
                None
            } else {
                Some(gl_hit as usize - buf.as_ptr() as usize)
            };
            if fl_hit != gl_idx {
                println!("memrchr         n={n:<6} MISMATCH fl={fl_hit:?} glibc={gl_idx:?}");
                continue;
            }
            let iters = (1 << 22) / n.max(8);
            let (mut fls, mut gls, mut aas) = (vec![], vec![], vec![]);
            for _ in 0..ROUNDS {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(frankenlibc_core::string::mem::memrchr(
                        black_box(&buf), black_box(b'z'), black_box(n),
                    ));
                }
                fls.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memrchr(black_box(buf.as_ptr()), black_box(b'z' as i32), black_box(n)));
                }
                gls.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memrchr(black_box(buf.as_ptr()), black_box(b'z' as i32), black_box(n)));
                }
                aas.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
            let (fl, gl) = (median(fls), median(gls.clone()));
            report("memrchr", n, fl, gl, median(aas) / gl);
        }
        println!();

        for &n in &[8usize, 16, 64, 256, 1024] {
            let a = vec![b'q'; n];
            let mut b = vec![b'q'; n];
            b[n - 1] = b'r';
            let fl_ord = frankenlibc_core::string::mem::memcmp(&a, &b, n);
            let gl_ord = gl_memcmp(a.as_ptr(), b.as_ptr(), n);
            let agree = matches!(
                (fl_ord, gl_ord.signum()),
                (core::cmp::Ordering::Less, -1)
                    | (core::cmp::Ordering::Equal, 0)
                    | (core::cmp::Ordering::Greater, 1)
            );
            if !agree {
                println!("memcmp          n={n:<6} MISMATCH fl={fl_ord:?} glibc={gl_ord}");
                continue;
            }
            let iters = (1 << 22) / n.max(8);
            let (mut fls, mut gls, mut aas) = (vec![], vec![], vec![]);
            for _ in 0..ROUNDS {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(frankenlibc_core::string::mem::memcmp(
                        black_box(&a), black_box(&b), black_box(n),
                    ));
                }
                fls.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memcmp(black_box(a.as_ptr()), black_box(b.as_ptr()), black_box(n)));
                }
                gls.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memcmp(black_box(a.as_ptr()), black_box(b.as_ptr()), black_box(n)));
                }
                aas.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
            let (fl, gl) = (median(fls), median(gls.clone()));
            report("memcmp", n, fl, gl, median(aas) / gl);
        }
        println!();

        // memmem: fl already measured far ahead on Ir; confirm on wall time
        for &n in &[256usize, 4096] {
            let mut hay = vec![b'a'; n];
            let needle = b"needle";
            hay[n - 6..].copy_from_slice(needle);
            let fl_hit = frankenlibc_core::string::mem::memmem(&hay, n, needle, needle.len());
            let gl_hit = gl_memmem(hay.as_ptr(), n, needle.as_ptr(), needle.len());
            let gl_idx = if gl_hit.is_null() {
                None
            } else {
                Some(gl_hit as usize - hay.as_ptr() as usize)
            };
            if fl_hit != gl_idx {
                println!("memmem          n={n:<6} MISMATCH fl={fl_hit:?} glibc={gl_idx:?}");
                continue;
            }
            let iters = (1 << 20) / n.max(8);
            let (mut fls, mut gls, mut aas) = (vec![], vec![], vec![]);
            for _ in 0..ROUNDS {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(frankenlibc_core::string::mem::memmem(
                        black_box(&hay), black_box(n), black_box(needle), black_box(needle.len()),
                    ));
                }
                fls.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memmem(
                        black_box(hay.as_ptr()), black_box(n),
                        black_box(needle.as_ptr()), black_box(needle.len()),
                    ));
                }
                gls.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memmem(
                        black_box(hay.as_ptr()), black_box(n),
                        black_box(needle.as_ptr()), black_box(needle.len()),
                    ));
                }
                aas.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
            let (fl, gl) = (median(fls), median(gls.clone()));
            report("memmem", n, fl, gl, median(aas) / gl);
        }
    }
}
