// a64l/l64a (SVID base-64 <-> long) are pure ~few-ns conversions that paid the
// runtime_policy decide+observe membrane tax per call (~5-10ns), roughly doubling
// their cost. This measures fl vs host glibc; run before/after the fast-path fix.
use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

#[inline(never)]
unsafe fn original_a64l(s: *const libc::c_char) -> libc::c_long {
    if s.is_null() {
        return 0;
    }
    // SAFETY: the benchmark passes a readable NUL-terminated input. This is the
    // exact bounded scan used by the pre-candidate deployed fast path.
    let (len, _) = unsafe { frankenlibc_abi::util::scan_c_string(s, Some(6)) };
    // SAFETY: the scan established that the first `len` bytes are readable.
    let slice = unsafe { std::slice::from_raw_parts(s.cast::<u8>(), len) };
    frankenlibc_core::stdlib::a64l(slice) as libc::c_long
}

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type A64l = unsafe extern "C" fn(*const libc::c_char) -> libc::c_long;
        type L64a = unsafe extern "C" fn(libc::c_long) -> *mut libc::c_char;
        let gl_a64l: A64l =
            std::mem::transmute::<*mut c_void, A64l>(libc::dlsym(h, b"a64l\0".as_ptr().cast()));
        let gl_l64a: L64a =
            std::mem::transmute::<*mut c_void, L64a>(libc::dlsym(h, b"l64a\0".as_ptr().cast()));

        let iters = 20_000_000usize;

        // a64l: fixed 5-char base-64 string.
        let s = b"Az9x0\0";
        let sp = s.as_ptr() as *const libc::c_char;
        // Correctness sanity: fl and glibc agree on the value.
        assert_eq!(
            frankenlibc_abi::stdlib_abi::a64l(sp),
            gl_a64l(sp),
            "a64l value mismatch"
        );
        assert_eq!(original_a64l(sp), gl_a64l(sp), "original a64l mismatch");

        let mut acc: i64 = 0;
        let t = Instant::now();
        for _ in 0..iters {
            acc = acc.wrapping_add(original_a64l(black_box(sp)) as i64);
        }
        let origa = t.elapsed().as_nanos() as f64 / iters as f64;
        black_box(acc);
        let t = Instant::now();
        for _ in 0..iters {
            acc = acc.wrapping_add(frankenlibc_abi::stdlib_abi::a64l(black_box(sp)) as i64);
        }
        let fla = t.elapsed().as_nanos() as f64 / iters as f64;
        black_box(acc);
        let t = Instant::now();
        for _ in 0..iters {
            acc = acc.wrapping_add(gl_a64l(black_box(sp)) as i64);
        }
        let gla = t.elapsed().as_nanos() as f64 / iters as f64;
        black_box(acc);
        println!(
            "A64L orig={origa:.2}ns cand={fla:.2}ns cand/orig={:.3}x glibc={gla:.2}ns cand/glibc={:.2}x",
            fla / origa,
            fla / gla
        );

        // l64a: fixed value.
        let v: libc::c_long = 123_456_789;
        let mut sink: usize = 0;
        let t = Instant::now();
        for _ in 0..iters {
            sink ^= frankenlibc_abi::stdlib_abi::l64a(black_box(v)) as usize;
        }
        let fll = t.elapsed().as_nanos() as f64 / iters as f64;
        black_box(sink);
        let t = Instant::now();
        for _ in 0..iters {
            sink ^= gl_l64a(black_box(v)) as usize;
        }
        let gll = t.elapsed().as_nanos() as f64 / iters as f64;
        black_box(sink);
        println!("L64A fl={fll:.2}ns glibc={gll:.2}ns  fl/glibc={:.2}x", fll / gll);
    }
}
