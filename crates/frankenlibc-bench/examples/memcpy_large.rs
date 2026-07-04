//! Aligned memcpy at large sizes: does fl's AVX vmovdqu loop lose to glibc (NT stores /
//! rep movsb) as n grows past L2? Both dst/src 32-aligned. fl uses AVX loop [128,131072),
//! rep movsb >=131072. If a growing gap appears in [32K,128K), NT stores are the lever.
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type CpFn=unsafe extern "C" fn(*mut core::ffi::c_void,*const core::ffi::c_void,usize)->*mut core::ffi::c_void;
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  let g:CpFn=unsafe{std::mem::transmute(libc::dlsym(h,b"memcpy\0".as_ptr().cast()))};
  use frankenlibc_abi::string_abi as fa;
  let cap=1usize<<20;
  let src=vec![0x5au8;cap+64]; let mut dst=vec![0u8;cap+64];
  let sp=unsafe{((src.as_ptr() as usize+31)&!31) as *const u8} as *const core::ffi::c_void;
  let dp=unsafe{((dst.as_mut_ptr() as usize+31)&!31) as *mut u8} as *mut core::ffi::c_void;
  for &n in &[16384usize,32768,65536,131072,262144,524288]{
    let iters=(1u64<<32)/(n as u64); // ~constant total bytes
    let(mut fl,mut gl)=(Vec::new(),Vec::new());
    for r in 0..40{
      if r%2==0{let t=Instant::now();for _ in 0..iters{black_box(unsafe{fa::memcpy(dp,sp,n)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{g(dp,sp,n)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
      }else{let t=Instant::now();for _ in 0..iters{black_box(unsafe{g(dp,sp,n)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{fa::memcpy(dp,sp,n)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);}
    }
    let(f,gg)=(pctl(&fl,0.1),pctl(&gl,0.1));
    println!("memcpy n={n:<7} fl={f:9.1} glibc={gg:9.1} fl/glibc={:.3}{}",f/gg,if f/gg>1.15{"  <-- LOSS"}else{""});
  }
}
