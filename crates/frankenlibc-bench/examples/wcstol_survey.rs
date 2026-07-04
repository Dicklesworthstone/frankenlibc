//! Survey fl wide integer parse (wcstol/wcstoul/wcstoll) vs glibc (dlmopen).
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type Fn3=unsafe extern "C" fn(*const i32,*mut *mut i32,i32)->i64;
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
  let g_wcstol:Fn3=unsafe{std::mem::transmute(libc::dlsym(h,b"wcstol\0".as_ptr().cast()))};
  let g_wcstoul:Fn3=unsafe{std::mem::transmute(libc::dlsym(h,b"wcstoul\0".as_ptr().cast()))};
  let g_wcstoll:Fn3=unsafe{std::mem::transmute(libc::dlsym(h,b"wcstoll\0".as_ptr().cast()))};
  use frankenlibc_abi::wchar_abi as wa;
  let iters=200_000u64;
  // wide strings as Vec<u32> (wchar_t = i32)
  let mk=|s:&str|->Vec<i32>{ s.chars().map(|c|c as i32).chain(std::iter::once(0)).collect() };
  for txt in ["42","-2147483648","1234567890","  +0xDEADBEEF","9223372036854775807"]{
    let w=mk(txt); let p=w.as_ptr();
    let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{wa::wcstol(black_box(p),std::ptr::null_mut(),10)});}},
                    ||{for _ in 0..iters{black_box(unsafe{g_wcstol(black_box(p),std::ptr::null_mut(),10)});}});
    println!("wcstol   {:<22} fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}",txt,f/iters as f64,g/iters as f64,f/g,tag(f/g));
  }
  let w=mk("1234567890"); let p=w.as_ptr();
  let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{wa::wcstoul(black_box(p),std::ptr::null_mut(),10)});}},
                  ||{for _ in 0..iters{black_box(unsafe{g_wcstoul(black_box(p),std::ptr::null_mut(),10)});}});
  println!("wcstoul  {:<22} fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}","1234567890",f/iters as f64,g/iters as f64,f/g,tag(f/g));
  let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{wa::wcstoll(black_box(p),std::ptr::null_mut(),10)});}},
                  ||{for _ in 0..iters{black_box(unsafe{g_wcstoll(black_box(p),std::ptr::null_mut(),10)});}});
  println!("wcstoll  {:<22} fl={:6.2}ns glibc={:6.2}ns fl/glibc={:.3}{}","1234567890",f/iters as f64,g/iters as f64,f/g,tag(f/g));
}
