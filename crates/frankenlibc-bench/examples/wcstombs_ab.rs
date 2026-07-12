//! fl wcstombs vs glibc (dlmopen), ASCII + mixed wide source, UTF-8 locale.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type WcFn = unsafe extern "C" fn(*mut i8, *const i32, usize) -> usize;
type SlFn = unsafe extern "C" fn(i32, *const i8) -> *mut i8;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let sl: SlFn =
        unsafe { std::mem::transmute(libc::dlsym(h, b"setlocale\0".as_ptr() as *const i8)) };
    unsafe {
        let _ = sl(6, b"C.UTF-8\0".as_ptr() as *const i8);
    }
    unsafe {
        libc::setlocale(libc::LC_ALL, b"C.UTF-8\0".as_ptr() as *const i8);
    }
    let g: WcFn =
        unsafe { std::mem::transmute(libc::dlsym(h, b"wcstombs\0".as_ptr() as *const i8)) };
    use frankenlibc_abi::wchar_abi as wa;
    // ascii wide + a few multibyte codepoints
    let wsrc: Vec<u32> = "the quick brown fox 0123456789 café résumé ñ"
        .chars()
        .map(|c| c as u32)
        .chain(std::iter::once(0))
        .collect();
    let n = wsrc.len() - 1;
    let sp = wsrc.as_ptr();
    let mut fd = vec![0i8; n * 4 + 8];
    let mut gd = vec![0i8; n * 4 + 8];
    let fr = unsafe { wa::wcstombs(fd.as_mut_ptr() as *mut u8, sp, fd.len()) };
    let gr = unsafe { g(gd.as_mut_ptr(), sp as *const i32, gd.len()) };
    assert_eq!(fr, gr, "count fl={fr} g={gr}");
    assert_eq!(&fd[..fr], &gd[..fr], "data");
    let iters = 800_000u64;
    let (mut fl, mut gl) = (Vec::new(), Vec::new());
    for r in 0..50 {
        if r % 2 == 0 {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(unsafe { wa::wcstombs(fd.as_mut_ptr() as *mut u8, sp, fd.len()) });
            }
            fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            let t = Instant::now();
            for _ in 0..iters {
                black_box(unsafe { g(gd.as_mut_ptr(), sp as *const i32, gd.len()) });
            }
            gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
        } else {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(unsafe { g(gd.as_mut_ptr(), sp as *const i32, gd.len()) });
            }
            gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            let t = Instant::now();
            for _ in 0..iters {
                black_box(unsafe { wa::wcstombs(fd.as_mut_ptr() as *mut u8, sp, fd.len()) });
            }
            fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
        }
    }
    let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
    eprintln!(
        "wcstombs n={n} fl={f:6.1} glibc={gg:6.1} fl/glibc={:.3}{}",
        f / gg,
        if f / gg > 1.25 {
            "  <-- LOSS"
        } else if f / gg < 0.9 {
            "  win"
        } else {
            "  ~par"
        }
    );
}
