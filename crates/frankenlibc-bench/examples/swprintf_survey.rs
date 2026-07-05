//! Survey fl swprintf vs glibc (dlmopen) for common wide formats.

use std::hint::black_box;
use std::time::Instant;

type PdFn = unsafe extern "C" fn(*mut i32, usize, *const i32, i32) -> i32;
type PsFn = unsafe extern "C" fn(*mut i32, usize, *const i32, *const i32) -> i32;

fn pctl(samples: &[f64], q: f64) -> f64 {
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

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

fn bench3<A: FnMut(), B: FnMut(), C: FnMut()>(
    mut a: A,
    mut b: B,
    mut c: C,
) -> (f64, f64, f64) {
    let (mut fa, mut fb, mut fc) = (Vec::new(), Vec::new(), Vec::new());
    for r in 0..60 {
        match r % 3 {
            0 => {
                let t = Instant::now();
                a();
                fa.push(t.elapsed().as_nanos() as f64);
                let t = Instant::now();
                b();
                fb.push(t.elapsed().as_nanos() as f64);
                let t = Instant::now();
                c();
                fc.push(t.elapsed().as_nanos() as f64);
            }
            1 => {
                let t = Instant::now();
                b();
                fb.push(t.elapsed().as_nanos() as f64);
                let t = Instant::now();
                c();
                fc.push(t.elapsed().as_nanos() as f64);
                let t = Instant::now();
                a();
                fa.push(t.elapsed().as_nanos() as f64);
            }
            _ => {
                let t = Instant::now();
                c();
                fc.push(t.elapsed().as_nanos() as f64);
                let t = Instant::now();
                a();
                fa.push(t.elapsed().as_nanos() as f64);
                let t = Instant::now();
                b();
                fb.push(t.elapsed().as_nanos() as f64);
            }
        }
    }
    (pctl(&fa, 0.1), pctl(&fb, 0.1), pctl(&fc, 0.1))
}

fn tag(ratio: f64) -> &'static str {
    if ratio > 1.25 {
        "LOSS"
    } else if ratio < 0.9 {
        "WIN"
    } else {
        "PAR"
    }
}

fn mk(s: &str) -> Vec<i32> {
    s.chars()
        .map(|c| c as i32)
        .chain(std::iter::once(0))
        .collect()
}

unsafe fn old_exact_ls(dst: *mut i32, n: usize, arg: *const i32) -> i32 {
    let segments = frankenlibc_core::stdio::parse_format_string(b"%ls");
    black_box(frankenlibc_core::stdio::count_printf_args(&segments));

    let mut utf8 = Vec::new();
    let mut i = 0usize;
    while !arg.is_null() {
        let wc = unsafe { *arg.add(i) } as u32;
        if wc == 0 {
            break;
        }
        if let Some(ch) = char::from_u32(wc) {
            let mut buf = [0u8; 4];
            utf8.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        } else {
            utf8.extend_from_slice("\u{fffd}".as_bytes());
        }
        i += 1;
    }
    if arg.is_null() {
        utf8.extend_from_slice(b"(null)");
    }

    let mut wide = Vec::new();
    let mut pos = 0usize;
    while pos < utf8.len() {
        let (cp, advance) = frankenlibc_core::string::wchar::decode_utf8_lossy(&utf8[pos..]);
        wide.push(cp as i32);
        pos += advance;
    }

    if !dst.is_null() && n != 0 {
        let copy = wide.len().min(n - 1);
        if copy != 0 {
            unsafe { std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, copy) };
        }
        unsafe { *dst.add(copy) = 0 };
    }

    if wide.len() >= n {
        -1
    } else {
        wide.len() as i32
    }
}

fn same_prefix(a: &[i32], an: i32, b: &[i32], bn: i32) -> bool {
    an == bn && an >= 0 && a[..an as usize] == b[..bn as usize]
}

fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let sym = unsafe { libc::dlsym(h, c"swprintf".as_ptr()) };
    assert!(!sym.is_null());
    let g_pd: PdFn = unsafe { std::mem::transmute(sym) };
    let g_ps: PsFn = unsafe { std::mem::transmute(sym) };
    use frankenlibc_abi::wchar_abi as wa;

    let iters = 50_000u64;
    let mut fb = [0i32; 256];
    let mut gb = [0i32; 256];
    let fbp = fb.as_mut_ptr();
    let gbp = gb.as_mut_ptr();

    let f = mk("%d");
    let fp = f.as_ptr();
    let flf: PdFn = unsafe { std::mem::transmute(wa::swprintf as *const ()) };
    let fn2 = unsafe { flf(fbp, 256, fp, 12345) };
    let gn = unsafe { g_pd(gbp, 256, fp, 12345) };
    let same = same_prefix(&fb, fn2, &gb, gn);
    let (a, b) = bench2(
        || {
            for _ in 0..iters {
                black_box(unsafe { flf(black_box(fbp), 256, fp, 12345) });
            }
        },
        || {
            for _ in 0..iters {
                black_box(unsafe { g_pd(black_box(gbp), 256, fp, 12345) });
            }
        },
    );
    println!(
        "swprintf %d       fl={:7.2}ns glibc={:7.2}ns fl/glibc={:.3} {} match={}",
        a / iters as f64,
        b / iters as f64,
        a / b,
        tag(a / b),
        same
    );

    let f = mk("%ls");
    let fp = f.as_ptr();
    let arg = mk("hello world");
    let ap = arg.as_ptr();
    let flf: PsFn = unsafe { std::mem::transmute(wa::swprintf as *const ()) };
    let mut old_buf = [0i32; 256];
    let mut new_buf = [0i32; 256];
    let mut glibc_buf = [0i32; 256];
    let on = unsafe { old_exact_ls(old_buf.as_mut_ptr(), 256, ap) };
    let nn = unsafe { flf(new_buf.as_mut_ptr(), 256, fp, ap) };
    let gn = unsafe { g_ps(glibc_buf.as_mut_ptr(), 256, fp, ap) };
    assert!(same_prefix(&old_buf, on, &new_buf, nn));
    assert!(same_prefix(&new_buf, nn, &glibc_buf, gn));

    let (old, new, glibc) = bench3(
        || {
            for _ in 0..iters {
                black_box(unsafe { old_exact_ls(black_box(old_buf.as_mut_ptr()), 256, ap) });
            }
        },
        || {
            for _ in 0..iters {
                black_box(unsafe { flf(black_box(new_buf.as_mut_ptr()), 256, fp, ap) });
            }
        },
        || {
            for _ in 0..iters {
                black_box(unsafe { g_ps(black_box(glibc_buf.as_mut_ptr()), 256, fp, ap) });
            }
        },
    );
    let old_ns = old / iters as f64;
    let new_ns = new / iters as f64;
    let glibc_ns = glibc / iters as f64;
    println!(
        "swprintf %ls      old={old_ns:7.2}ns new={new_ns:7.2}ns glibc={glibc_ns:7.2}ns new/old={:.3} {} new/glibc={:.3} {} match=true",
        new_ns / old_ns,
        tag(new_ns / old_ns),
        new_ns / glibc_ns,
        tag(new_ns / glibc_ns)
    );
}
