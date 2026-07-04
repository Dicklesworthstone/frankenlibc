//! fl wcstod vs glibc wcstod (dlmopen). Short float + float-in-long-buffer.
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type WdFn=unsafe extern "C" fn(*const i32,*mut *mut i32)->f64;
fn wide(s:&str, pad:usize)->Vec<i32>{ let mut v:Vec<i32>=s.chars().map(|c|c as i32).collect(); for _ in 0..pad { v.push(b' ' as i32);} v.push(0); v }
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  let g:WdFn=unsafe{std::mem::transmute(libc::dlsym(h,b"wcstod\0".as_ptr().cast()))};
  use frankenlibc_abi::wchar_abi as wa;
  for (tag,s,pad) in [("short","3.14159",0usize),("sci","1.5e-10",0),("long-buf","2.71828",4096)]{
    let w=wide(s,pad); let p=w.as_ptr();
    // correctness
    let fv=unsafe{wa::wcstod(p,std::ptr::null_mut())}; let gv=unsafe{g(p,std::ptr::null_mut())};
    assert!((fv-gv).abs()<1e-12,"val mismatch {tag}: fl={fv} glibc={gv}");
    let iters=2_000_000u64; let(mut fl,mut gl)=(Vec::new(),Vec::new());
    for r in 0..60{
      if r%2==0{let t=Instant::now();for _ in 0..iters{black_box(unsafe{wa::wcstod(p,std::ptr::null_mut())});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{g(p,std::ptr::null_mut())});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
      }else{let t=Instant::now();for _ in 0..iters{black_box(unsafe{g(p,std::ptr::null_mut())});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{wa::wcstod(p,std::ptr::null_mut())});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);}
    }
    let(f,gg)=(pctl(&fl,0.1),pctl(&gl,0.1));
    println!("wcstod {tag:<9} fl={f:7.1} glibc={gg:7.1} fl/glibc={:.3}{}",f/gg,if f/gg>1.25{"  <-- LOSS"}else if f/gg<0.95{"  win"}else{"  ~par"});
  }
}
