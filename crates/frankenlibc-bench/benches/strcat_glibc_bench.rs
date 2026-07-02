//! strcat A/B: deployed FrankenLibC vs host glibc. Measures the new strict
//! fast-path (membrane removal). glibc via dlmopen. Default strict mode.
use std::ffi::{c_char, c_void};
use std::sync::OnceLock;
use std::time::Instant;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
type Fn_ = unsafe extern "C" fn(*mut c_char, *const c_char) -> *mut c_char;
fn host() -> Fn_ {
    static H: OnceLock<usize> = OnceLock::new();
    let a = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
        assert!(!h.is_null()); libc::dlsym(h, b"strcat\0".as_ptr().cast()) as usize
    });
    unsafe { std::mem::transmute::<usize, Fn_>(a) }
}
fn pctl(s: &[f64], q: f64) -> f64 { let mut v=s.to_vec(); v.sort_by(|a,b|a.partial_cmp(b).unwrap()); let r=q*(v.len()-1) as f64; let(lo,hi)=(r.floor() as usize,r.ceil() as usize); if lo==hi{v[lo]}else{v[lo]*(1.0-(r-lo as f64))+v[hi]*(r-lo as f64)} }
fn bench(c: &mut Criterion) {
    let g = host();
    let mut grp = c.benchmark_group("strcat"); grp.sample_size(30);
    // dst prefix len, src len
    for &(dlen, slen) in &[(8usize, 8usize), (16, 16), (64, 32), (256, 64)] {
        let src: Vec<u8> = std::iter::repeat(b'x').take(slen).chain(std::iter::once(0)).collect();
        let sp = src.as_ptr().cast::<c_char>();
        // capacity buffer big enough; reset dst prefix each call.
        let mut buf = vec![0u8; dlen + slen + 64];
        let prefix: Vec<u8> = std::iter::repeat(b'a').take(dlen).collect();
        buf[..dlen].copy_from_slice(&prefix); buf[dlen] = 0;
        let reset = |b: &mut [u8]| { b[dlen] = 0; }; // O(1): strcat only writes [dlen..]
        // byte-identity
        reset(&mut buf); let mut b2 = buf.clone();
        unsafe { frankenlibc_abi::string_abi::strcat(buf.as_mut_ptr().cast(), sp); g(b2.as_mut_ptr().cast(), sp); }
        assert_eq!(buf, b2, "strcat fl!=glibc dlen={dlen} slen={slen}");
        let it = 2000u64; let (mut fs, mut gs) = (Vec::new(), Vec::new());
        for _ in 0..100 {
            let t = Instant::now();
            for _ in 0..it { reset(&mut buf); black_box(unsafe { frankenlibc_abi::string_abi::strcat(black_box(buf.as_mut_ptr().cast()), black_box(sp)) }); }
            fs.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now();
            for _ in 0..it { reset(&mut buf); black_box(unsafe { g(black_box(buf.as_mut_ptr().cast()), black_box(sp)) }); }
            gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        let (fp,gp)=(pctl(&fs,0.5),pctl(&gs,0.5));
        println!("STRCAT dlen={dlen} slen={slen} fl_p50={fp:.2}ns glibc_p50={gp:.2}ns ratio_fl_over_glibc={:.2}", fp/gp);
    }
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8))); grp.finish();
}
criterion_group!(benches, bench); criterion_main!(benches);
