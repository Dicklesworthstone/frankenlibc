//! fl mbstowcs vs glibc (dlmopen), ASCII + UTF-8 source, C/UTF-8 locale.
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type MbFn=unsafe extern "C" fn(*mut i32,*const i8,usize)->usize;
type SlFn=unsafe extern "C" fn(i32,*const i8)->*mut i8;
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  // set UTF-8 locale in the dlmopen'd libc so its mbstowcs decodes UTF-8
  let setlocale:SlFn=unsafe{std::mem::transmute(libc::dlsym(h,b"setlocale\0".as_ptr() as *const i8))};
  unsafe{ let _=setlocale(6 /*LC_ALL*/, b"C.UTF-8\0".as_ptr() as *const i8); }
  unsafe{ libc::setlocale(libc::LC_ALL, b"C.UTF-8\0".as_ptr() as *const i8); }
  let g:MbFn=unsafe{std::mem::transmute(libc::dlsym(h,b"mbstowcs\0".as_ptr() as *const i8))};
  use frankenlibc_abi::wchar_abi as wa;
  for (tag,src) in [("ascii64",&b"the quick brown fox jumps over the lazy dog 0123456789 abcde\0"[..])]{
    let sp=src.as_ptr() as *const i8; let n=src.len()-1;
    let mut fd=vec![0u32;n+8]; let mut gd=vec![0u32;n+8];
    let fr=unsafe{wa::mbstowcs(fd.as_mut_ptr(),sp as *const u8,n)}; let gr=unsafe{g(gd.as_mut_ptr() as *mut i32,sp,n)};
    assert_eq!(fr,gr,"{tag} count"); assert_eq!(&fd[..n],&gd[..n],"{tag} data");
    let iters=1_000_000u64; let(mut fl,mut gl)=(Vec::new(),Vec::new());
    for r in 0..50{
      if r%2==0{let t=Instant::now();for _ in 0..iters{black_box(unsafe{wa::mbstowcs(fd.as_mut_ptr(),sp as *const u8,n)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{g(gd.as_mut_ptr() as *mut i32,sp,n)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
      }else{let t=Instant::now();for _ in 0..iters{black_box(unsafe{g(gd.as_mut_ptr() as *mut i32,sp,n)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{wa::mbstowcs(fd.as_mut_ptr(),sp as *const u8,n)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);}
    }
    let(f,gg)=(pctl(&fl,0.1),pctl(&gl,0.1)); eprintln!("mbstowcs {tag:<8} n={n} fl={f:6.1} glibc={gg:6.1} fl/glibc={:.3}{}",f/gg,if f/gg>1.25{"  <-- LOSS"}else if f/gg<0.9{"  win"}else{"  ~par"});
  }
}
