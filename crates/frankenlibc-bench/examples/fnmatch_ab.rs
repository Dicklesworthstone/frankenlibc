//! fl fnmatch vs glibc (dlmopen). Run: cargo run --release --example fnmatch_ab --features abi-bench
use std::hint::black_box; use std::time::Instant;
type FnmFn=unsafe extern "C" fn(*const i8,*const i8,i32)->i32;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  let g:FnmFn=unsafe{std::mem::transmute(libc::dlsym(h,b"fnmatch\0".as_ptr().cast()))};
  for (pat,txt) in [("*.txt","document_final_v2.txt"),("foo*","foobarbazqux"),("a?c","abc"),("[abc]*","cxxxxx"),("*abc*","xxxxxxxxxxxxxxxxxxxxabcyyy"),("*a*b*c*","xxxaxxxbxxxcxxx"),("literal","literal")]{
    let cp=std::ffi::CString::new(pat).unwrap(); let ct=std::ffi::CString::new(txt).unwrap();
    let fm=unsafe{frankenlibc_abi::string_abi::fnmatch(cp.as_ptr(),ct.as_ptr(),0)};
    let gm=unsafe{g(cp.as_ptr(),ct.as_ptr(),0)};
    assert_eq!(fm==0,gm==0,"fnmatch {pat} {txt}");
    let lit=50_000u64;let(mut fl,mut gl)=(Vec::new(),Vec::new());
    for r in 0..80{
      if r%2==0{
        let t=Instant::now();for _ in 0..lit{black_box(unsafe{frankenlibc_abi::string_abi::fnmatch(cp.as_ptr(),ct.as_ptr(),0)});}fl.push(t.elapsed().as_nanos()as f64/lit as f64);
        let t=Instant::now();for _ in 0..lit{black_box(unsafe{g(cp.as_ptr(),ct.as_ptr(),0)});}gl.push(t.elapsed().as_nanos()as f64/lit as f64);
      }else{
        let t=Instant::now();for _ in 0..lit{black_box(unsafe{g(cp.as_ptr(),ct.as_ptr(),0)});}gl.push(t.elapsed().as_nanos()as f64/lit as f64);
        let t=Instant::now();for _ in 0..lit{black_box(unsafe{frankenlibc_abi::string_abi::fnmatch(cp.as_ptr(),ct.as_ptr(),0)});}fl.push(t.elapsed().as_nanos()as f64/lit as f64);
      }
    }
    let(f10,g10)=(pctl(&fl,0.1),pctl(&gl,0.1));
    println!("FNMATCH {pat:<9} fl={f10:.1} glibc={g10:.1} fl/glibc={:.3}",f10/g10);
  }
}
