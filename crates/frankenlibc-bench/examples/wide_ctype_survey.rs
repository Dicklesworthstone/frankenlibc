//! Survey fl wide ctype (isw*/tow*) vs glibc (dlmopen), ASCII inputs (the hot case).
//! Each is called in a tight loop over the 128 ASCII codepoints so the per-call cost
//! (fl's OnceLock+Box BMP table vs glibc's thread-local ctype table) dominates.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type Fn1 = unsafe extern "C" fn(i32) -> i32;
fn bench2<A: Fn(), B: Fn()>(a: A, b: B) -> (f64, f64) {
    let (mut fa, mut fb) = (Vec::new(), Vec::new());
    for r in 0..50 {
        if r % 2 == 0 {
            let t = Instant::now();
            a();
            fa.push(t.elapsed().as_nanos() as f64);
            let t = Instant::now();
            b();
            fb.push(t.elapsed().as_nanos() as f64);
        } else {
            let t = Instant::now();
            b();
            fb.push(t.elapsed().as_nanos() as f64);
            let t = Instant::now();
            a();
            fa.push(t.elapsed().as_nanos() as f64);
        }
    }
    (pctl(&fa, 0.1), pctl(&fb, 0.1))
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
    unsafe {
        let sl: unsafe extern "C" fn(i32, *const i8) -> *mut i8 =
            std::mem::transmute(libc::dlsym(h, b"setlocale\0".as_ptr().cast()));
        sl(6, b"C.UTF-8\0".as_ptr().cast());
    }
    macro_rules! g {
        ($n:literal) => {
            unsafe {
                std::mem::transmute::<_, Fn1>(libc::dlsym(h, concat!($n, "\0").as_ptr().cast()))
            }
        };
    }
    use frankenlibc_abi::wchar_abi as wa;
    let iters = 30_000u64;
    // (name, fl fn, glibc fn)
    macro_rules! row {
        ($name:literal,$fl:path,$g:expr) => {{
            let gf: Fn1 = $g;
            let (f, gg) = bench2(
                || {
                    for _ in 0..iters {
                        for w in 0..128i32 {
                            black_box(unsafe { $fl(black_box(w as u32)) });
                        }
                    }
                },
                || {
                    for _ in 0..iters {
                        for w in 0..128i32 {
                            black_box(unsafe { gf(black_box(w)) });
                        }
                    }
                },
            );
            let per_f = f / (iters as f64 * 128.0);
            let per_g = gg / (iters as f64 * 128.0);
            println!(
                "{:<10} fl={per_f:5.2}ns glibc={per_g:5.2}ns fl/glibc={:.3}{}",
                $name,
                per_f / per_g,
                if per_f / per_g > 1.25 {
                    "  <-- LOSS"
                } else if per_f / per_g < 0.9 {
                    "  win"
                } else {
                    "  ~par"
                }
            );
        }};
    }
    row!("iswalpha", wa::iswalpha, g!("iswalpha"));
    row!("iswdigit", wa::iswdigit, g!("iswdigit"));
    row!("iswalnum", wa::iswalnum, g!("iswalnum"));
    row!("iswspace", wa::iswspace, g!("iswspace"));
    row!("iswupper", wa::iswupper, g!("iswupper"));
    row!("iswlower", wa::iswlower, g!("iswlower"));
    row!("iswpunct", wa::iswpunct, g!("iswpunct"));
    row!("iswprint", wa::iswprint, g!("iswprint"));
    row!("iswcntrl", wa::iswcntrl, g!("iswcntrl"));
    row!("iswxdigit", wa::iswxdigit, g!("iswxdigit"));
    row!("towlower", wa::towlower, g!("towlower"));
    row!("towupper", wa::towupper, g!("towupper"));
}
