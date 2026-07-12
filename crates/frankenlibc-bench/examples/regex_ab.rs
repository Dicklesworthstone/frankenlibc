//! fl regcomp/regexec vs glibc (dlmopen). Each side compiles+matches with its OWN regex_t
//! (ABI-compatible layout). Run: cargo run --release --example regex_ab --features abi-bench
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type CompFn = unsafe extern "C" fn(*mut libc::regex_t, *const i8, i32) -> i32;
type ExecFn =
    unsafe extern "C" fn(*const libc::regex_t, *const i8, usize, *mut libc::regmatch_t, i32) -> i32;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let gc: CompFn = unsafe { std::mem::transmute(libc::dlsym(h, b"regcomp\0".as_ptr().cast())) };
    let ge: ExecFn = unsafe { std::mem::transmute(libc::dlsym(h, b"regexec\0".as_ptr().cast())) };
    // Dotstar POSITION sweep: `X.*Y` — verify the greedy leftmost-longest SPAN (rm_so,rm_eo)
    // matches glibc EXACTLY, not just match/nomatch (the subtle part of the fast path).
    {
        let mut checks = 0u64;
        for pfx in ["", "a", "ab", "z"] {
            for sfx in ["", "z", "az", "a"] {
                let pat = std::ffi::CString::new(format!("{pfx}.*{sfx}")).unwrap();
                let mut fre: libc::regex_t = unsafe { std::mem::zeroed() };
                let mut gre: libc::regex_t = unsafe { std::mem::zeroed() };
                assert_eq!(
                    unsafe {
                        frankenlibc_abi::string_abi::regcomp(
                            &mut fre as *mut _ as *mut std::ffi::c_void,
                            pat.as_ptr(),
                            0,
                        )
                    },
                    0
                );
                assert_eq!(unsafe { gc(&mut gre, pat.as_ptr(), 0) }, 0);
                for txt in [
                    "",
                    "a",
                    "z",
                    "az",
                    "za",
                    "aXz",
                    "aXzYz",
                    "zzaz",
                    "aaz",
                    "azaza",
                    "XaYbZzQ",
                    "ababzz",
                    "abXYabZaz",
                    "nomatch",
                    "aa",
                    "zz",
                    "abc",
                    "azazaz",
                ] {
                    let ct = std::ffi::CString::new(txt).unwrap();
                    let mut fpm = [libc::regmatch_t {
                        rm_so: -9,
                        rm_eo: -9,
                    }];
                    let mut gpm = [libc::regmatch_t {
                        rm_so: -9,
                        rm_eo: -9,
                    }];
                    let fm = unsafe {
                        frankenlibc_abi::string_abi::regexec(
                            &fre as *const _ as *const std::ffi::c_void,
                            ct.as_ptr(),
                            1,
                            fpm.as_mut_ptr() as *mut std::ffi::c_void,
                            0,
                        )
                    };
                    let gm = unsafe { ge(&gre, ct.as_ptr(), 1, gpm.as_mut_ptr(), 0) };
                    assert_eq!(fm == 0, gm == 0, "match {pfx}.*{sfx} on {txt:?}");
                    if fm == 0 {
                        assert_eq!(
                            (fpm[0].rm_so, fpm[0].rm_eo),
                            (gpm[0].rm_so, gpm[0].rm_eo),
                            "SPAN {pfx}.*{sfx} on {txt:?}"
                        );
                    }
                    checks += 1;
                }
            }
        }
        println!("dotstar-positions: {checks} spans fl == glibc ✓");
    }
    for (pat, txt) in [
        ("hello", "xxxxx hello world"),
        ("[0-9]+", "abc 12345 def"),
        ("^foo", "foobar baz"),
        ("a.*z", "aXXXXXXXXXXz"),
        (".*z", "XXXXXXXXXXXXz"),
        ("a.*", "aXXXXXXXXXXXX"),
        ("(ab|cd)+", "ababcdab end"),
    ] {
        let cp = std::ffi::CString::new(pat).unwrap();
        let ct = std::ffi::CString::new(txt).unwrap();
        // fl compile
        let mut fre: libc::regex_t = unsafe { std::mem::zeroed() };
        let frc = unsafe {
            frankenlibc_abi::string_abi::regcomp(
                &mut fre as *mut _ as *mut std::ffi::c_void,
                cp.as_ptr(),
                0,
            )
        };
        let mut gre: libc::regex_t = unsafe { std::mem::zeroed() };
        let grc = unsafe { gc(&mut gre, cp.as_ptr(), 0) };
        assert_eq!(frc, 0, "fl regcomp {pat}");
        assert_eq!(grc, 0, "g regcomp {pat}");
        // correctness: match result agrees
        let fm = unsafe {
            frankenlibc_abi::string_abi::regexec(
                &fre as *const _ as *const std::ffi::c_void,
                ct.as_ptr(),
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        let gm = unsafe { ge(&gre, ct.as_ptr(), 0, std::ptr::null_mut(), 0) };
        assert_eq!(fm == 0, gm == 0, "match {pat} vs {txt}");
        let lit = 50_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..80 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe {
                        frankenlibc_abi::string_abi::regexec(
                            &fre as *const _ as *const std::ffi::c_void,
                            ct.as_ptr(),
                            0,
                            std::ptr::null_mut(),
                            0,
                        )
                    });
                }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { ge(&gre, ct.as_ptr(), 0, std::ptr::null_mut(), 0) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            } else {
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe { ge(&gre, ct.as_ptr(), 0, std::ptr::null_mut(), 0) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / lit as f64);
                let t = Instant::now();
                for _ in 0..lit {
                    black_box(unsafe {
                        frankenlibc_abi::string_abi::regexec(
                            &fre as *const _ as *const std::ffi::c_void,
                            ct.as_ptr(),
                            0,
                            std::ptr::null_mut(),
                            0,
                        )
                    });
                }
                fl.push(t.elapsed().as_nanos() as f64 / lit as f64);
            }
        }
        let (f10, g10) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "REGEXEC {pat:<10} fl={f10:.1} glibc={g10:.1} fl/glibc={:.3}",
            f10 / g10
        );
    }
}
