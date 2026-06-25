// fnmatch head-to-head: fl iterative single-backtrack matcher vs glibc recursive
// backtracking. Adversarial pattern "*a*a*…*b" against "aaa…a" (no 'b') forces glibc to
// re-explore every '*' split (exponential); fl stays linear. Both must return NO-MATCH.
use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_core::string::fnmatch::{fnmatch_match, FnmatchFlags};

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type FnmatchFn = unsafe extern "C" fn(*const c_void, *const c_void, i32) -> i32;
        let gl_fnmatch: FnmatchFn = std::mem::transmute::<*mut c_void, FnmatchFn>(libc::dlsym(
            h,
            b"fnmatch\0".as_ptr().cast(),
        ));

        let flags = FnmatchFlags::from_bits(0);
        for &(stars, tlen) in &[(3usize, 10usize), (4, 12), (5, 14)] {
            let mut pat_b = Vec::new();
            for _ in 0..stars {
                pat_b.push(b'*');
                pat_b.push(b'a');
            }
            pat_b.push(b'*');
            pat_b.push(b'b'); // final *b never matches an all-'a' text
            let text_b = vec![b'a'; tlen];
            let mut pat_c = pat_b.clone();
            pat_c.push(0);
            let mut text_c = text_b.clone();
            text_c.push(0);

            let fl_m = fnmatch_match(&pat_b, &text_b, flags);
            let gl_m = gl_fnmatch(pat_c.as_ptr().cast(), text_c.as_ptr().cast(), 0);
            assert!(!fl_m && gl_m != 0, "fnmatch {stars}*{tlen}: fl={fl_m} glibc={gl_m}");

            let iters = 30usize;
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(fnmatch_match(black_box(&pat_b), black_box(&text_b), flags));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_fnmatch(
                    black_box(pat_c.as_ptr().cast()),
                    black_box(text_c.as_ptr().cast()),
                    0,
                ));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("FNM stars={stars} tlen={tlen} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.5}x", fl / gl);
        }
    }
}
