//! Deployed fl vs host glibc (dlmopen) for the wide copy/fill family: wcscpy and
//! wmemset. Measures the DEPLOYED strict fast paths (frankenlibc_abi::wchar_abi::*),
//! not core. Finds any size band where fl loses to glibc.
use std::sync::OnceLock;
use std::time::Instant;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

type CpyFn = unsafe extern "C" fn(*mut u32, *const u32) -> *mut u32;
type SetFn = unsafe extern "C" fn(*mut u32, u32, usize) -> *mut u32;

fn sym<T: Copy>(name: &[u8]) -> T {
    static H: OnceLock<usize> = OnceLock::new();
    let h = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
        assert!(!h.is_null()); h as usize
    });
    let p = unsafe { libc::dlsym(h as *mut _, name.as_ptr().cast()) };
    assert!(!p.is_null());
    unsafe { std::mem::transmute_copy::<usize, T>(&(p as usize)) }
}

fn pctl(s: &[f64], q: f64) -> f64 { let mut v=s.to_vec(); v.sort_by(|a,b|a.partial_cmp(b).unwrap()); let r=q*(v.len()-1) as f64; let(lo,hi)=(r.floor() as usize,r.ceil() as usize); if lo==hi{v[lo]}else{v[lo]*(1.0-(r-lo as f64))+v[hi]*(r-lo as f64)} }

fn bench(c: &mut Criterion) {
    let g_cpy: CpyFn = sym(b"wcscpy\0");
    let g_set: SetFn = sym(b"wmemset\0");
    let mut grp = c.benchmark_group("wide_copyfill"); grp.sample_size(10);
    let it = 4000u64;

    for &n in &[4usize, 16, 32, 64, 128, 256, 1024] {
        // wcscpy: NUL-terminated src of n 'a's.
        let mut src: Vec<u32> = std::iter::repeat(b'a' as u32).take(n).collect(); src.push(0);
        let mut dfl = vec![0u32; n + 1];
        let mut dgl = vec![0u32; n + 1];
        let sp = src.as_ptr();
        unsafe { frankenlibc_abi::wchar_abi::wcscpy(dfl.as_mut_ptr(), sp); }
        unsafe { g_cpy(dgl.as_mut_ptr(), sp); }
        assert_eq!(dfl, dgl, "wcscpy mismatch n={n}");
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { frankenlibc_abi::wchar_abi::wcscpy(black_box(dfl.as_mut_ptr()), black_box(sp)) }); } fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { g_cpy(black_box(dgl.as_mut_ptr()), black_box(sp)) }); } gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        println!("WCSCPY n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fs,0.5), pctl(&gs,0.5), pctl(&fs,0.5)/pctl(&gs,0.5));
    }

    let g_pcpy: CpyFn = sym(b"wcpcpy\0");
    for &n in &[4usize, 16, 32, 64, 128, 256, 1024] {
        let mut src: Vec<u32> = std::iter::repeat(b'a' as u32).take(n).collect(); src.push(0);
        let mut dfl = vec![0u32; n + 1];
        let mut dgl = vec![0u32; n + 1];
        let sp = src.as_ptr();
        let efl = unsafe { frankenlibc_abi::wchar_abi::wcpcpy(dfl.as_mut_ptr(), sp) };
        let egl = unsafe { g_pcpy(dgl.as_mut_ptr(), sp) };
        assert_eq!(dfl, dgl, "wcpcpy mismatch n={n}");
        assert_eq!(efl as usize - dfl.as_ptr() as usize, egl as usize - dgl.as_ptr() as usize, "wcpcpy end-ptr n={n}");
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { frankenlibc_abi::wchar_abi::wcpcpy(black_box(dfl.as_mut_ptr()), black_box(sp)) }); } fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { g_pcpy(black_box(dgl.as_mut_ptr()), black_box(sp)) }); } gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        println!("WCPCPY n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fs,0.5), pctl(&gs,0.5), pctl(&fs,0.5)/pctl(&gs,0.5));
    }

    let g_cat: CpyFn = sym(b"wcscat\0");
    let pre = 3usize;
    for &n in &[4usize, 16, 32, 64, 128, 256, 1024] {
        let mut src: Vec<u32> = std::iter::repeat(b'a' as u32).take(n).collect(); src.push(0);
        let sp = src.as_ptr();
        // dst = 'b'*pre + NUL, buffer sized for prefix + src + NUL.
        let mk = || { let mut d = vec![0u32; pre + n + 1]; for k in 0..pre { d[k] = b'b' as u32; } d };
        let (mut dfl, mut dgl) = (mk(), mk());
        unsafe { frankenlibc_abi::wchar_abi::wcscat(dfl.as_mut_ptr(), sp); g_cat(dgl.as_mut_ptr(), sp); }
        assert_eq!(dfl, dgl, "wcscat mismatch n={n}");
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now(); for _ in 0..it { unsafe { dfl[pre] = 0; black_box(frankenlibc_abi::wchar_abi::wcscat(black_box(dfl.as_mut_ptr()), black_box(sp))); } } fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { unsafe { dgl[pre] = 0; black_box(g_cat(black_box(dgl.as_mut_ptr()), black_box(sp))); } } gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        println!("WCSCAT n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fs,0.5), pctl(&gs,0.5), pctl(&fs,0.5)/pctl(&gs,0.5));
    }

    for &n in &[4usize, 16, 32, 64, 128, 256, 1024] {
        let mut bfl = vec![0u32; n];
        let mut bgl = vec![0u32; n];
        unsafe { frankenlibc_abi::wchar_abi::wmemset(bfl.as_mut_ptr(), 0x41, n); }
        unsafe { g_set(bgl.as_mut_ptr(), 0x41, n); }
        assert_eq!(bfl, bgl, "wmemset mismatch n={n}");
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { frankenlibc_abi::wchar_abi::wmemset(black_box(bfl.as_mut_ptr()), 0x41, black_box(n)) }); } fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { g_set(black_box(bgl.as_mut_ptr()), 0x41, black_box(n)) }); } gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        println!("WMEMSET n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fs,0.5), pctl(&gs,0.5), pctl(&fs,0.5)/pctl(&gs,0.5));
    }

    grp.bench_function("noop", |b| b.iter(|| black_box(1u8))); grp.finish();
}
criterion_group!(benches, bench); criterion_main!(benches);
