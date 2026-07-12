// erand48/nrand48/jrand48 (explicit-state drand48 PRNGs) pay a per-call
// runtime_policy decide+observe membrane tax that their internal-state siblings
// (drand48/lrand48/mrand48) already bypass via stdlib_membrane_fastpath. The LCG
// core is ~3-5ns, so the ~10ns tax dominates. This bench measures fl vs host glibc
// on the same explicit state; run before/after the fast-path fix (2 builds).
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
        type Erand = unsafe extern "C" fn(*mut u16) -> f64;
        type Nrand = unsafe extern "C" fn(*mut u16) -> libc::c_long;
        let gl_erand48: Erand =
            std::mem::transmute::<*mut c_void, Erand>(libc::dlsym(h, b"erand48\0".as_ptr().cast()));
        let gl_nrand48: Nrand =
            std::mem::transmute::<*mut c_void, Nrand>(libc::dlsym(h, b"nrand48\0".as_ptr().cast()));

        let iters = 20_000_000usize;

        // erand48
        let mut st: [u16; 3] = [0x1234, 0x5678, 0x9abc];
        let p = st.as_mut_ptr();
        let mut acc = 0.0f64;
        let t = Instant::now();
        for _ in 0..iters {
            acc += frankenlibc_abi::stdlib_abi::erand48(black_box(p));
        }
        let fl = t.elapsed().as_nanos() as f64 / iters as f64;
        black_box(acc);

        let mut st2: [u16; 3] = [0x1234, 0x5678, 0x9abc];
        let p2 = st2.as_mut_ptr();
        let mut acc2 = 0.0f64;
        let t = Instant::now();
        for _ in 0..iters {
            acc2 += gl_erand48(black_box(p2));
        }
        let gl = t.elapsed().as_nanos() as f64 / iters as f64;
        black_box(acc2);
        println!("ERAND48 fl={fl:.2}ns glibc={gl:.2}ns  fl/glibc={:.2}x", fl / gl);

        // nrand48
        let mut sn: [u16; 3] = [0x1111, 0x2222, 0x3333];
        let pn = sn.as_mut_ptr();
        let mut na: i64 = 0;
        let t = Instant::now();
        for _ in 0..iters {
            na = na.wrapping_add(frankenlibc_abi::stdlib_abi::nrand48(black_box(pn)));
        }
        let fln = t.elapsed().as_nanos() as f64 / iters as f64;
        black_box(na);

        let mut sn2: [u16; 3] = [0x1111, 0x2222, 0x3333];
        let pn2 = sn2.as_mut_ptr();
        let mut na2: i64 = 0;
        let t = Instant::now();
        for _ in 0..iters {
            na2 = na2.wrapping_add(gl_nrand48(black_box(pn2)) as i64);
        }
        let gln = t.elapsed().as_nanos() as f64 / iters as f64;
        black_box(na2);
        println!("NRAND48 fl={fln:.2}ns glibc={gln:.2}ns  fl/glibc={:.2}x", fln / gln);
    }
}
