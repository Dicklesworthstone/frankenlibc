//! fl strverscmp vs glibc (dlmopen). Run: cargo run --release --example strverscmp_ab --features abi-bench
use std::hint::black_box; use std::time::Instant;
type Fn2=unsafe extern "C" fn(*const i8,*const i8)->i32;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  let g:Fn2=unsafe{std::mem::transmute(libc::dlsym(h,b"strverscmp\0".as_ptr().cast()))};
  for (a,b) in [("file1.txt","file10.txt"),("foo-1.2.3","foo-1.2.10"),("aaaa","aaab"),("version-2024-06-15","version-2024-06-16")]{
    let ca=std::ffi::CString::new(a).unwrap(); let cb=std::ffi::CString::new(b).unwrap();
    let fm=unsafe{frankenlibc_abi::string_abi::strverscmp(ca.as_ptr(),cb.as_ptr())};
    let gm=unsafe{g(ca.as_ptr(),cb.as_ptr())};
    assert_eq!(fm.signum(),gm.signum(),"strverscmp {a} {b}");
    let lit=100_000u64;let(mut fl,mut gl)=(Vec::new(),Vec::new());
    for r in 0..80{
      if r%2==0{
        let t=Instant::now();for _ in 0..lit{black_box(unsafe{frankenlibc_abi::string_abi::strverscmp(ca.as_ptr(),cb.as_ptr())});}fl.push(t.elapsed().as_nanos()as f64/lit as f64);
        let t=Instant::now();for _ in 0..lit{black_box(unsafe{g(ca.as_ptr(),cb.as_ptr())});}gl.push(t.elapsed().as_nanos()as f64/lit as f64);
      }else{
        let t=Instant::now();for _ in 0..lit{black_box(unsafe{g(ca.as_ptr(),cb.as_ptr())});}gl.push(t.elapsed().as_nanos()as f64/lit as f64);
        let t=Instant::now();for _ in 0..lit{black_box(unsafe{frankenlibc_abi::string_abi::strverscmp(ca.as_ptr(),cb.as_ptr())});}fl.push(t.elapsed().as_nanos()as f64/lit as f64);
      }
    }
    let(f10,g10)=(pctl(&fl,0.1),pctl(&gl,0.1));
    println!("STRVERSCMP {a:<20} fl={f10:.1} glibc={g10:.1} fl/glibc={:.3}",f10/g10);
  }
}
