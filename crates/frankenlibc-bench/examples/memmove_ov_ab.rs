//! fl memmove vs glibc (dlmopen) — OVERLAP CORRECTNESS sweep (both dirs, many deltas) + perf.
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type MvFn=unsafe extern "C" fn(*mut core::ffi::c_void,*const core::ffi::c_void,usize)->*mut core::ffi::c_void;
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  let g:MvFn=unsafe{std::mem::transmute(libc::dlsym(h,b"memmove\0".as_ptr().cast()))};
  use frankenlibc_abi::string_abi as fa;
  // Correctness: for each n and signed delta (dst = src+delta), compare fl vs glibc result.
  let mut checks=0u64;
  for n in [1usize,7,15,16,17,31,32,33,63,64,65,127,128,129,255,256,300,1000,4096].iter().copied(){
    for delta in [-129i64,-128,-65,-64,-33,-32,-17,-16,-8,-3,-1,1,3,8,16,17,32,33,64,65,128,129].iter().copied(){
      let pad=200usize;
      let init:Vec<u8>=(0..n+2*pad).map(|i|(i*37+11) as u8).collect();
      let mut fb=init.clone(); let mut gb=init.clone();
      // src at pad; dst at pad+delta
      let sidx=pad; let didx=(pad as i64+delta) as usize;
      unsafe{fa::memmove(fb.as_mut_ptr().add(didx).cast(), fb.as_ptr().add(sidx).cast(), n);}
      unsafe{g(gb.as_mut_ptr().add(didx).cast(), gb.as_ptr().add(sidx).cast(), n);}
      assert_eq!(fb,gb,"MISMATCH n={n} delta={delta}"); checks+=1;
    }
  }
  println!("overlap-correctness: {checks} (n×delta) combos fl == glibc byte-for-byte ✓");
  // Perf: overlapping fwd (dst<src) + bwd (dst>src)
  for &n in &[256usize,1024,4096,16384,65536]{
    let mut buf=vec![0x5au8;n+256]; let base=buf.as_mut_ptr();
    let (dpb,spb)=(unsafe{base.add(64)} as *mut core::ffi::c_void, base as *const core::ffi::c_void);
    let (dpf,spf)=(base as *mut core::ffi::c_void, unsafe{base.add(64)} as *const core::ffi::c_void);
    let iters=if n<=1024{1_500_000u64}else{300_000};
    for (tag,dp,sp) in [("bwd",dpb,spb),("fwd",dpf,spf)]{
      let(mut fl,mut gl)=(Vec::new(),Vec::new());
      for r in 0..50{
        if r%2==0{let t=Instant::now();for _ in 0..iters{black_box(unsafe{fa::memmove(dp,sp,n)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);
          let t=Instant::now();for _ in 0..iters{black_box(unsafe{g(dp,sp,n)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
        }else{let t=Instant::now();for _ in 0..iters{black_box(unsafe{g(dp,sp,n)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
          let t=Instant::now();for _ in 0..iters{black_box(unsafe{fa::memmove(dp,sp,n)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);}
      }
      let(f,gg)=(pctl(&fl,0.1),pctl(&gl,0.1));
      println!("memmove-{tag} n={n:<6} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",f/gg,if f/gg>1.25{"  <-- LOSS"}else if f/gg<0.95{"  win"}else{"  ~par"});
    }
  }
}
