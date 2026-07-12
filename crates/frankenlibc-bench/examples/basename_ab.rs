//! fl __xpg_basename vs glibc (dlmopen). Run: cargo run --release --example basename_ab --features abi-bench
use std::hint::black_box;
use std::time::Instant;
type Fn1 = unsafe extern "C" fn(*mut i8) -> *mut i8;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g: Fn1 =
        unsafe { std::mem::transmute(libc::dlsym(h, b"__xpg_basename\0".as_ptr().cast())) };
    for p in [
        "usr/local/lib/libfoo.so",
        "a/b",
        "filename.txt",
        "/deep/nested/path/to/some/resource.dat",
    ] {
        let mut fb: Vec<i8> = p.bytes().map(|b| b as i8).chain([0]).collect();
        let mut gb = fb.clone();
        let fr = unsafe {
            std::ffi::CStr::from_ptr(frankenlibc_abi::unistd_abi::__xpg_basename(fb.as_mut_ptr()))
        }
        .to_str()
        .unwrap()
        .to_string();
        let gr = unsafe { std::ffi::CStr::from_ptr(g(gb.as_mut_ptr())) }
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(fr, gr, "basename {p}");
        let lit = 100_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..80 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe {
                        frankenlibc_abi::unistd_abi::__xpg_basename(fb.as_mut_ptr())
                    });
                }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { g(gb.as_mut_ptr()) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            } else {
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { g(gb.as_mut_ptr()) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe {
                        frankenlibc_abi::unistd_abi::__xpg_basename(fb.as_mut_ptr())
                    });
                }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            }
        }
        let (f10, g10) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "BASENAME {p:<42} fl={f10:.1} glibc={g10:.1} fl/glibc={:.3}",
            f10 / g10
        );
    }
}
