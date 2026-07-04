//! Survey fl swprintf vs glibc (dlmopen) for common wide formats (fixed arg signatures).
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type PdFn=unsafe extern "C" fn(*mut i32,usize,*const i32,i32)->i32;
type PsFn=unsafe extern "C" fn(*mut i32,usize,*const i32,*const i32)->i32;
fn bench2<A:Fn(),B:Fn()>(a:A,b:B)->(f64,f64){
  let(mut fa,mut fb)=(Vec::new(),Vec::new());
  for r in 0..50{
    if r%2==0{let t=Instant::now();a();fa.push(t.elapsed().as_nanos()as f64);let t=Instant::now();b();fb.push(t.elapsed().as_nanos()as f64);}
    else{let t=Instant::now();b();fb.push(t.elapsed().as_nanos()as f64);let t=Instant::now();a();fa.push(t.elapsed().as_nanos()as f64);}
  }
  (pctl(&fa,0.1),pctl(&fb,0.1))
}
fn tag(r:f64)->&'static str{ if r>1.25{"  LOSS"}else if r<0.9{"  win"}else{"  ~par"} }
fn mk(s:&str)->Vec<i32>{ s.chars().map(|c|c as i32).chain(std::iter::once(0)).collect() }
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  let g_pd:PdFn=unsafe{std::mem::transmute(libc::dlsym(h,b"swprintf\0".as_ptr().cast()))};
  let g_ps:PsFn=unsafe{std::mem::transmute(libc::dlsym(h,b"swprintf\0".as_ptr().cast()))};
  use frankenlibc_abi::wchar_abi as wa;
  let iters=50_000u64;
  let mut fb=[0i32;256]; let mut gb=[0i32;256]; let fbp=fb.as_mut_ptr(); let gbp=gb.as_mut_ptr();
  // %d
  { let f=mk("%d"); let fp=f.as_ptr();
    let flf:PdFn=unsafe{std::mem::transmute(wa::swprintf as *const ())};
    let fn2=unsafe{flf(fbp,256,fp,12345)}; let gn=unsafe{g_pd(gbp,256,fp,12345)};
    let same=fn2==gn && fb[..fn2 as usize].iter().zip(gb[..gn as usize].iter()).all(|(a,b)|a==b);
    let(a,bb)=bench2(||{for _ in 0..iters{black_box(unsafe{flf(black_box(fbp),256,fp,12345)});}},
                     ||{for _ in 0..iters{black_box(unsafe{g_pd(black_box(gbp),256,fp,12345)});}});
    println!("swprintf %d       fl={:7.2}ns glibc={:7.2}ns fl/glibc={:.3}{} match={}",a/iters as f64,bb/iters as f64,a/bb,tag(a/bb),same);
  }
  // %s (wide string arg)
  { let f=mk("%ls"); let fp=f.as_ptr(); let arg=mk("hello world"); let ap=arg.as_ptr();
    let flf:PsFn=unsafe{std::mem::transmute(wa::swprintf as *const ())};
    let fn2=unsafe{flf(fbp,256,fp,ap)}; let gn=unsafe{g_ps(gbp,256,fp,ap)};
    let same=fn2==gn && fb[..fn2 as usize].iter().zip(gb[..gn as usize].iter()).all(|(a,b)|a==b);
    let(a,bb)=bench2(||{for _ in 0..iters{black_box(unsafe{flf(black_box(fbp),256,fp,ap)});}},
                     ||{for _ in 0..iters{black_box(unsafe{g_ps(black_box(gbp),256,fp,ap)});}});
    println!("swprintf %ls      fl={:7.2}ns glibc={:7.2}ns fl/glibc={:.3}{} match={}",a/iters as f64,bb/iters as f64,a/bb,tag(a/bb),same);
  }
}
