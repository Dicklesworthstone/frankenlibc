//! Size-sweep wmemchr: per-byte gap vs glibc? Absent needle, full scan. fl fold is 128B
//! (32 wchar); does it lose enough at large n to warrant a wider tier? vs glibc (dlmopen).
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type WcFn=unsafe extern "C" fn(*const i32,i32,usize)->*mut i32;
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  let g:WcFn=unsafe{std::mem::transmute(libc::dlsym(h,b"wmemchr\0".as_ptr().cast()))};
  use frankenlibc_abi::wchar_abi as wa;
  for &n in &[64usize,256,1024,4096]{
    let s:Vec<u32>=vec![b'a' as u32;n]; let sp=s.as_ptr(); let needle=b'z' as u32; // absent
    assert_eq!(unsafe{wa::wmemchr(sp,needle,n)}.is_null(), unsafe{g(sp as *const i32,needle as i32,n)}.is_null(),"wmemchr n={n}");
    let iters=300_000u64; let(mut fl,mut gl)=(Vec::new(),Vec::new());
    for r in 0..50{
      if r%2==0{let t=Instant::now();for _ in 0..iters{black_box(unsafe{wa::wmemchr(black_box(sp),needle,n)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{g(black_box(sp as *const i32),needle as i32,n)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
      }else{let t=Instant::now();for _ in 0..iters{black_box(unsafe{g(black_box(sp as *const i32),needle as i32,n)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{wa::wmemchr(black_box(sp),needle,n)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);}
    }
    let(f,gg)=(pctl(&fl,0.1),pctl(&gl,0.1));
    println!("wmemchr n={n:<5} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",f/gg,if f/gg>1.2{"  <-- LOSS"}else{""});
  }
}
