//! fl strfromd vs glibc (dlmopen) + in-process alloc isolation.
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type SfFn=unsafe extern "C" fn(*mut i8,usize,*const i8,f64)->i32;
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  let g:SfFn=unsafe{std::mem::transmute(libc::dlsym(h,b"strfromd\0".as_ptr() as *const i8))};
  use frankenlibc_abi::string_abi as sa;
  let vals=[3.14159f64,2.71828,1234.5678,0.0001234,9.99e10,42.0];
  for (tag,fmt) in [("%g","%g\0"),("%.6f","%.6f\0"),("%e","%e\0")]{
    let fp=fmt.as_ptr() as *const i8;
    let mut db=[0i8;64]; let mut gb=[0i8;64];
    // correctness
    for &v in &vals{ unsafe{sa::strfromd(db.as_mut_ptr(),64,fp,v);} unsafe{g(gb.as_mut_ptr(),64,fp,v);}
      let ds=unsafe{std::ffi::CStr::from_ptr(db.as_ptr())}; let gs=unsafe{std::ffi::CStr::from_ptr(gb.as_ptr())};
      assert_eq!(ds,gs,"{tag} {v}: fl={ds:?} g={gs:?}"); }
    let iters=200_000u64; let n=vals.len() as u64; let(mut fl,mut gl)=(Vec::new(),Vec::new());
    for r in 0..50{
      if r%2==0{let t=Instant::now();for _ in 0..iters{for &v in &vals{black_box(unsafe{sa::strfromd(db.as_mut_ptr(),64,fp,black_box(v))});}}fl.push(t.elapsed().as_nanos()as f64/(iters*n)as f64);
        let t=Instant::now();for _ in 0..iters{for &v in &vals{black_box(unsafe{g(gb.as_mut_ptr(),64,fp,black_box(v))});}}gl.push(t.elapsed().as_nanos()as f64/(iters*n)as f64);
      }else{let t=Instant::now();for _ in 0..iters{for &v in &vals{black_box(unsafe{g(gb.as_mut_ptr(),64,fp,black_box(v))});}}gl.push(t.elapsed().as_nanos()as f64/(iters*n)as f64);
        let t=Instant::now();for _ in 0..iters{for &v in &vals{black_box(unsafe{sa::strfromd(db.as_mut_ptr(),64,fp,black_box(v))});}}fl.push(t.elapsed().as_nanos()as f64/(iters*n)as f64);}
    }
    let(f,gg)=(pctl(&fl,0.1),pctl(&gl,0.1)); println!("strfromd {tag:<5} fl={f:6.1} glibc={gg:6.1} fl/glibc={:.3}{}",f/gg,if f/gg>1.25{"  <-- LOSS"}else if f/gg<0.9{"  win"}else{"  ~par"});
  }
}
