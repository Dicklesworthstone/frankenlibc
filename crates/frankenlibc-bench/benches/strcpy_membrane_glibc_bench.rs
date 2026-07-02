//! Deployed fl strcpy/stpcpy vs host glibc (dlmopen). strcpy_core has NO
//! strict_passthrough fast path (unlike wcscpy/strncpy), so every call pays the full
//! membrane (stage_context_two + decide + observe + record_string_stage_outcome). This
//! measures whether that membrane tax is a real gap on the hot narrow copy path.
use std::os::raw::c_char;
use std::sync::OnceLock;
use std::time::Instant;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

type CpyFn = unsafe extern "C" fn(*mut c_char, *const c_char) -> *mut c_char;
fn sym(name: &[u8]) -> CpyFn {
    static H: OnceLock<usize> = OnceLock::new();
    let h = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
        assert!(!h.is_null()); h as usize
    });
    let p = unsafe { libc::dlsym(h as *mut _, name.as_ptr().cast()) };
    assert!(!p.is_null());
    unsafe { std::mem::transmute::<usize, CpyFn>(p as usize) }
}

fn pctl(s: &[f64], q: f64) -> f64 { let mut v=s.to_vec(); v.sort_by(|a,b|a.partial_cmp(b).unwrap()); let r=q*(v.len()-1) as f64; let(lo,hi)=(r.floor() as usize,r.ceil() as usize); if lo==hi{v[lo]}else{v[lo]*(1.0-(r-lo as f64))+v[hi]*(r-lo as f64)} }

fn bench(c: &mut Criterion) {
    let g_cpy = sym(b"strcpy\0");
    let mut grp = c.benchmark_group("strcpy_membrane"); grp.sample_size(10);
    let it = 4000u64;
    for &n in &[4usize, 16, 32, 64, 128, 256, 1024] {
        let mut src: Vec<u8> = std::iter::repeat(b'a').take(n).collect(); src.push(0);
        let sp = src.as_ptr() as *const c_char;
        let (mut dfl, mut dgl) = (vec![0u8; n + 1], vec![0u8; n + 1]);
        unsafe { frankenlibc_abi::string_abi::strcpy(dfl.as_mut_ptr() as *mut c_char, sp); g_cpy(dgl.as_mut_ptr() as *mut c_char, sp); }
        assert_eq!(dfl, dgl, "strcpy mismatch n={n}");
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { frankenlibc_abi::string_abi::strcpy(black_box(dfl.as_mut_ptr() as *mut c_char), black_box(sp)) }); } fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { g_cpy(black_box(dgl.as_mut_ptr() as *mut c_char), black_box(sp)) }); } gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        println!("STRCPY n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fs,0.5), pctl(&gs,0.5), pctl(&fs,0.5)/pctl(&gs,0.5));
    }
    let g_cat = sym(b"strcat\0");
    let pre = 3usize;
    for &n in &[4usize, 16, 32, 64, 128, 256, 1024] {
        let mut src: Vec<u8> = std::iter::repeat(b'a').take(n).collect(); src.push(0);
        let sp = src.as_ptr() as *const c_char;
        let mk = || { let mut d = vec![0u8; pre + n + 1]; for k in 0..pre { d[k] = b'b'; } d };
        let (mut dfl, mut dgl) = (mk(), mk());
        unsafe { frankenlibc_abi::string_abi::strcat(dfl.as_mut_ptr() as *mut c_char, sp); g_cat(dgl.as_mut_ptr() as *mut c_char, sp); }
        assert_eq!(dfl, dgl, "strcat mismatch n={n}");
        let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now(); for _ in 0..it { unsafe { dfl[pre] = 0; black_box(frankenlibc_abi::string_abi::strcat(black_box(dfl.as_mut_ptr() as *mut c_char), black_box(sp))); } } fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { unsafe { dgl[pre] = 0; black_box(g_cat(black_box(dgl.as_mut_ptr() as *mut c_char), black_box(sp))); } } gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        println!("STRCAT n={n} fl={:.2} glibc={:.2} fl/glibc={:.3}", pctl(&fs,0.5), pctl(&gs,0.5), pctl(&fs,0.5)/pctl(&gs,0.5));
    }

    grp.bench_function("noop", |b| b.iter(|| black_box(1u8))); grp.finish();
}
criterion_group!(benches, bench); criterion_main!(benches);
