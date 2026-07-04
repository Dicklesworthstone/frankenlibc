//! Survey fl integer-parse family vs glibc (dlmopen): strtol, strtoul, strtoll, atoi.
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type StrtolFn=unsafe extern "C" fn(*const i8,*mut *mut i8,i32)->i64;
type AtoiFn=unsafe extern "C" fn(*const i8)->i32;
fn bench2<A:Fn(),B:Fn()>(a:A,b:B)->(f64,f64){
  let(mut fa,mut fb)=(Vec::new(),Vec::new());
  for r in 0..50{
    if r%2==0{let t=Instant::now();a();fa.push(t.elapsed().as_nanos()as f64);let t=Instant::now();b();fb.push(t.elapsed().as_nanos()as f64);}
    else{let t=Instant::now();b();fb.push(t.elapsed().as_nanos()as f64);let t=Instant::now();a();fa.push(t.elapsed().as_nanos()as f64);}
  }
  (pctl(&fa,0.1),pctl(&fb,0.1))
}
fn tag(r:f64)->&'static str{ if r>1.25{"  <-- LOSS"}else if r<0.9{"  win"}else{"  ~par"} }
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  let g_strtol:StrtolFn=unsafe{std::mem::transmute(libc::dlsym(h,b"strtol\0".as_ptr().cast()))};
  let g_strtoul:StrtolFn=unsafe{std::mem::transmute(libc::dlsym(h,b"strtoul\0".as_ptr().cast()))};
  let g_strtoll:StrtolFn=unsafe{std::mem::transmute(libc::dlsym(h,b"strtoll\0".as_ptr().cast()))};
  let g_atoi:AtoiFn=unsafe{std::mem::transmute(libc::dlsym(h,b"atoi\0".as_ptr().cast()))};
  use frankenlibc_abi::stdlib_abi as sa;
  let iters=200_000u64;
  let inputs:[&[u8];5]=[b"42\0", b"-2147483648\0", b"1234567890\0", b"  +0xDEADBEEF\0", b"9223372036854775807\0"];
  for inp in inputs{
    let p=inp.as_ptr() as *const i8;
    let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{sa::strtol(p,std::ptr::null_mut(),10)});}},
                    ||{for _ in 0..iters{black_box(unsafe{g_strtol(p,std::ptr::null_mut(),10)});}});
    println!("strtol   {:<22} fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}",String::from_utf8_lossy(&inp[..inp.len()-1]),f/iters as f64,g/iters as f64,f/g,tag(f/g));
  }
  let p=b"0xDEADBEEF\0".as_ptr() as *const i8;
  let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{sa::strtol(p,std::ptr::null_mut(),0)});}},
                  ||{for _ in 0..iters{black_box(unsafe{g_strtol(p,std::ptr::null_mut(),0)});}});
  println!("strtol   {:<22} fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}","0xDEADBEEF base0",f/iters as f64,g/iters as f64,f/g,tag(f/g));
  let p=b"1234567890\0".as_ptr() as *const i8;
  let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{sa::strtoul(p,std::ptr::null_mut(),10)});}},
                  ||{for _ in 0..iters{black_box(unsafe{g_strtoul(p,std::ptr::null_mut(),10)});}});
  println!("strtoul  {:<22} fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}","1234567890",f/iters as f64,g/iters as f64,f/g,tag(f/g));
  let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{sa::strtoll(p,std::ptr::null_mut(),10)});}},
                  ||{for _ in 0..iters{black_box(unsafe{g_strtoll(p,std::ptr::null_mut(),10)});}});
  println!("strtoll  {:<22} fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}","1234567890",f/iters as f64,g/iters as f64,f/g,tag(f/g));
  let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{sa::atoi(p)});}},
                  ||{for _ in 0..iters{black_box(unsafe{g_atoi(p)});}});
  println!("atoi     {:<22} fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}","1234567890",f/iters as f64,g/iters as f64,f/g,tag(f/g));
}
