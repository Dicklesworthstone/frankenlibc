//! fl f64 math vs glibc (dlmopen) over a value range. Find clean losses.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type F1 = unsafe extern "C" fn(f64) -> f64;
type F2 = unsafe extern "C" fn(f64, f64) -> f64;
macro_rules! b1 {
    ($name:expr,$fl:expr,$g:expr,$xs:expr) => {{
        let flf: F1 = $fl;
        let gf: F1 = unsafe { std::mem::transmute(libc::dlsym($g.0, $g.1)) };
        let xs = $xs;
        let iters = 200_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..40 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..iters {
                    for &x in &xs {
                        black_box(unsafe { flf(black_box(x)) });
                    }
                }
                fl.push(t.elapsed().as_nanos() as f64 / (iters * xs.len() as u64) as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    for &x in &xs {
                        black_box(unsafe { gf(black_box(x)) });
                    }
                }
                gl.push(t.elapsed().as_nanos() as f64 / (iters * xs.len() as u64) as f64);
            } else {
                let t = Instant::now();
                for _ in 0..iters {
                    for &x in &xs {
                        black_box(unsafe { gf(black_box(x)) });
                    }
                }
                gl.push(t.elapsed().as_nanos() as f64 / (iters * xs.len() as u64) as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    for &x in &xs {
                        black_box(unsafe { flf(black_box(x)) });
                    }
                }
                fl.push(t.elapsed().as_nanos() as f64 / (iters * xs.len() as u64) as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "{:<10} fl={f:6.2} glibc={gg:6.2} fl/glibc={:.3}{}",
            $name,
            f / gg,
            if f / gg > 1.25 {
                "  <-- LOSS"
            } else if f / gg < 0.9 {
                "  win"
            } else {
                "  ~par"
            }
        );
    }};
}
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libm.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let xs = [0.3, 0.7, 1.5, 2.3, 3.9, 5.1, 7.7, 0.01, 12.0, 0.9];
    use frankenlibc_abi::math_abi as m;
    b1!("sin", m::sin as F1, (h, b"sin\0".as_ptr() as *const i8), xs);
    b1!("cos", m::cos as F1, (h, b"cos\0".as_ptr() as *const i8), xs);
    b1!("tan", m::tan as F1, (h, b"tan\0".as_ptr() as *const i8), xs);
    b1!("exp", m::exp as F1, (h, b"exp\0".as_ptr() as *const i8), xs);
    b1!("log", m::log as F1, (h, b"log\0".as_ptr() as *const i8), xs);
    b1!(
        "log2",
        m::log2 as F1,
        (h, b"log2\0".as_ptr() as *const i8),
        xs
    );
    b1!(
        "log10",
        m::log10 as F1,
        (h, b"log10\0".as_ptr() as *const i8),
        xs
    );
    b1!(
        "exp2",
        m::exp2 as F1,
        (h, b"exp2\0".as_ptr() as *const i8),
        xs
    );
    b1!(
        "exp10",
        m::exp10 as F1,
        (h, b"exp10\0".as_ptr() as *const i8),
        xs
    );
    b1!(
        "cbrt",
        m::cbrt as F1,
        (h, b"cbrt\0".as_ptr() as *const i8),
        xs
    );
    b1!(
        "atan",
        m::atan as F1,
        (h, b"atan\0".as_ptr() as *const i8),
        xs
    );
    b1!(
        "asin",
        m::asin as F1,
        (h, b"asin\0".as_ptr() as *const i8),
        [0.3, 0.7, 0.1, 0.5, 0.9, 0.2, 0.6, 0.05, 0.8, 0.4]
    );
    b1!(
        "sinh",
        m::sinh as F1,
        (h, b"sinh\0".as_ptr() as *const i8),
        xs
    );
    b1!(
        "tanh",
        m::tanh as F1,
        (h, b"tanh\0".as_ptr() as *const i8),
        xs
    );
    b1!("erf", m::erf as F1, (h, b"erf\0".as_ptr() as *const i8), xs);
    b1!(
        "erfc",
        m::erfc as F1,
        (h, b"erfc\0".as_ptr() as *const i8),
        xs
    );
    b1!(
        "lgamma",
        m::lgamma as F1,
        (h, b"lgamma\0".as_ptr() as *const i8),
        xs
    );
    b1!(
        "tgamma",
        m::tgamma as F1,
        (h, b"tgamma\0".as_ptr() as *const i8),
        xs
    );
    b1!(
        "expm1",
        m::expm1 as F1,
        (h, b"expm1\0".as_ptr() as *const i8),
        xs
    );
    b1!(
        "log1p",
        m::log1p as F1,
        (h, b"log1p\0".as_ptr() as *const i8),
        xs
    );
}
