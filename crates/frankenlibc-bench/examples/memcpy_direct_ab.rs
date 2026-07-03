//! DIRECT fl memcpy symbol vs glibc memcpy (dlmopen): correctness sweep + perf A/B.
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type CpFn=unsafe extern "C" fn(*mut core::ffi::c_void,*const core::ffi::c_void,usize)->*mut core::ffi::c_void;
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  let g:CpFn=unsafe{std::mem::transmute(libc::dlsym(h,b"memcpy\0".as_ptr().cast()))};
  use frankenlibc_abi::string_abi as fa;
  // Correctness: byte-exact vs a reference copy across sizes×align (src distinct bytes)
  let mut checks=0u64;
  for n in [1usize,15,16,63,64,65,127,128,129,255,256,1023,2048,4095,4096,8192,131071,131072,131073,262144].iter().copied(){
    for sa in 0..8usize{ for da in 0..8usize{
      let src:Vec<u8>=(0..n+16).map(|i|(i*31+7) as u8).collect();
      let mut fb=vec![0xa5u8;n+da+16]; let mut gb=vec![0xa5u8;n+da+16];
      unsafe{fa::memcpy(fb.as_mut_ptr().add(da).cast(),src.as_ptr().add(sa).cast(),n);}
      unsafe{g(gb.as_mut_ptr().add(da).cast(),src.as_ptr().add(sa).cast(),n);}
      assert_eq!(fb,gb,"MISMATCH n={n} sa={sa} da={da}"); checks+=1;
    }}
  }
  println!("correctness: {checks} (size×srcalign×dstalign) combos fl == glibc byte-for-byte ✓");
  for &n in &[256usize,1024,2048,4096,8192,16384,32768,65536,131072,262144]{
    let src=vec![0x5au8;n+256]; let mut dst=vec![0u8;n+256];
    let (dp,sp)=(unsafe{dst.as_mut_ptr().add(96)} as *mut core::ffi::c_void, src.as_ptr() as *const core::ffi::c_void);
    let iters=if n<=1024{2_000_000u64}else{300_000};
    let(mut fl,mut gl)=(Vec::new(),Vec::new());
    for r in 0..60{
      if r%2==0{let t=Instant::now();for _ in 0..iters{black_box(unsafe{fa::memcpy(dp,sp,n)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{g(dp,sp,n)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
      }else{let t=Instant::now();for _ in 0..iters{black_box(unsafe{g(dp,sp,n)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{fa::memcpy(dp,sp,n)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);}
    }
    let(f,gg)=(pctl(&fl,0.1),pctl(&gl,0.1));
    println!("memcpy n={n:<6} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",f/gg,if f/gg>1.25{"  <-- LOSS"}else if f/gg<0.95{"  win"}else{"  ~par"});
  }
}
