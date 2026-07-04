//! Clean deployed measurement of narrow strftime for literal-heavy / short formats vs glibc,
//! to evaluate the literal-run bulk-copy change (own file, not the shared strftime_survey).
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type SfFn=unsafe extern "C" fn(*mut i8,usize,*const i8,*const libc::tm)->usize;
fn bench2<A:Fn(),B:Fn()>(a:A,b:B)->(f64,f64){
  let(mut fa,mut fb)=(Vec::new(),Vec::new());
  for r in 0..50{
    if r%2==0{let t=Instant::now();a();fa.push(t.elapsed().as_nanos()as f64);let t=Instant::now();b();fb.push(t.elapsed().as_nanos()as f64);}
    else{let t=Instant::now();b();fb.push(t.elapsed().as_nanos()as f64);let t=Instant::now();a();fa.push(t.elapsed().as_nanos()as f64);}
  }
  (pctl(&fa,0.1),pctl(&fb,0.1))
}
fn tag(r:f64)->&'static str{ if r>1.25{"  LOSS"}else if r<0.9{"  win"}else{"  ~par"} }
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  unsafe{ let sl:unsafe extern "C" fn(i32,*const i8)->*mut i8=std::mem::transmute(libc::dlsym(h,b"setlocale\0".as_ptr().cast())); sl(6,b"C\0".as_ptr().cast()); }
  let g_sf:SfFn=unsafe{std::mem::transmute(libc::dlsym(h,b"strftime\0".as_ptr().cast()))};
  use frankenlibc_abi::time_abi as ta;
  let e:i64=1_700_000_000; let mut tm:libc::tm=unsafe{std::mem::zeroed()}; unsafe{ ta::gmtime_r(&e,&mut tm); }
  let tmp=tm; let tmpp=&tmp as *const libc::tm;
  let iters=100_000u64;
  let mut fb=[0i8;256]; let mut gb=[0i8;256]; let fbp=fb.as_mut_ptr(); let gbp=gb.as_mut_ptr();
  for fmt in [&b"just text no directives\0"[..], &b"%H:%M\0"[..], &b"a longer literal string of text with no percent directives at all here\0"[..], &b"%Y-%m-%d %H:%M:%S\0"[..]]{
    let fp=fmt.as_ptr() as *const i8;
    unsafe{ ta::strftime(fbp,256,fp,tmpp); g_sf(gbp,256,fp,tmpp); }
    let same=fb.iter().zip(gb.iter()).take_while(|(a,_)|**a!=0).all(|(a,b)|a==b);
    let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{ta::strftime(black_box(fbp),256,fp,tmpp)});}},
                    ||{for _ in 0..iters{black_box(unsafe{g_sf(black_box(gbp),256,fp,tmpp)});}});
    println!("strftime [{:<40}] fl={:7.2}ns glibc={:7.2}ns fl/glibc={:.3}{} match={}",
      String::from_utf8_lossy(&fmt[..fmt.len()-1]),f/iters as f64,g/iters as f64,f/g,tag(f/g),same);
  }
}
