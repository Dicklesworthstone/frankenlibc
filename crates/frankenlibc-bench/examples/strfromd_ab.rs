//! fl strfromd vs glibc (dlmopen). Run: cargo run --release --example strfromd_ab --features abi-bench
use std::hint::black_box; use std::time::Instant;
type Fn4=unsafe extern "C" fn(*mut i8,usize,*const i8,f64)->i32;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  let g:Fn4=unsafe{std::mem::transmute(libc::dlsym(h,b"strfromd\0".as_ptr().cast()))};
  for (fmt,val) in [("%.6f",3.14159265),("%g",2.5),("%.2f",100.0),("%e",1234567.89)]{
    let cf=std::ffi::CString::new(fmt).unwrap();
    let mut fb=[0i8;64]; let mut gb=[0i8;64];
    let fr=unsafe{frankenlibc_abi::string_abi::strfromd(fb.as_mut_ptr(),64,cf.as_ptr(),val)};
    let gr=unsafe{g(gb.as_mut_ptr(),64,cf.as_ptr(),val)};
    assert_eq!(fr,gr,"strfromd {fmt} {val}");
    assert_eq!(unsafe{std::ffi::CStr::from_ptr(fb.as_ptr())},unsafe{std::ffi::CStr::from_ptr(gb.as_ptr())},"out {fmt}");
    let lit=50_000u64;let(mut fl,mut gl)=(Vec::new(),Vec::new());
    for r in 0..80{
      if r%2==0{
        let t=Instant::now();for _ in 0..lit{black_box(unsafe{frankenlibc_abi::string_abi::strfromd(fb.as_mut_ptr(),64,cf.as_ptr(),val)});}fl.push(t.elapsed().as_nanos()as f64/lit as f64);
        let t=Instant::now();for _ in 0..lit{black_box(unsafe{g(gb.as_mut_ptr(),64,cf.as_ptr(),val)});}gl.push(t.elapsed().as_nanos()as f64/lit as f64);
      }else{
        let t=Instant::now();for _ in 0..lit{black_box(unsafe{g(gb.as_mut_ptr(),64,cf.as_ptr(),val)});}gl.push(t.elapsed().as_nanos()as f64/lit as f64);
        let t=Instant::now();for _ in 0..lit{black_box(unsafe{frankenlibc_abi::string_abi::strfromd(fb.as_mut_ptr(),64,cf.as_ptr(),val)});}fl.push(t.elapsed().as_nanos()as f64/lit as f64);
      }
    }
    let(f10,g10)=(pctl(&fl,0.1),pctl(&gl,0.1));
    println!("STRFROMD {fmt:<6} fl={f10:.1} glibc={g10:.1} fl/glibc={:.3}",f10/g10);
  }
}
