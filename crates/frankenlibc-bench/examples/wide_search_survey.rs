//! Survey fl wide search/scan family vs glibc (dlmopen): wcsrchr, wcspbrk, wcsspn,
//! wcscspn, wcsstr, wcscasecmp. Finds the biggest per-size gap for a follow-up lever.
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type ChrFn=unsafe extern "C" fn(*const i32,i32)->*mut i32;
type SetPFn=unsafe extern "C" fn(*const i32,*const i32)->*mut i32;
type SetNFn=unsafe extern "C" fn(*const i32,*const i32)->usize;
type StrFn=unsafe extern "C" fn(*const i32,*const i32)->*mut i32;
type CmpFn=unsafe extern "C" fn(*const i32,*const i32)->i32;
fn bench2<A:Fn(),B:Fn()>(a:A,b:B)->(f64,f64){
  let(mut fa,mut fb)=(Vec::new(),Vec::new());
  for r in 0..40{
    if r%2==0{let t=Instant::now();a();fa.push(t.elapsed().as_nanos()as f64);let t=Instant::now();b();fb.push(t.elapsed().as_nanos()as f64);}
    else{let t=Instant::now();b();fb.push(t.elapsed().as_nanos()as f64);let t=Instant::now();a();fa.push(t.elapsed().as_nanos()as f64);}
  }
  (pctl(&fa,0.1),pctl(&fb,0.1))
}
fn tag(r:f64)->&'static str{ if r>1.25{"  <-- LOSS"}else if r<0.9{"  win"}else{"  ~par"} }
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  macro_rules! sym{($n:literal,$t:ty)=>{unsafe{std::mem::transmute::<_,$t>(libc::dlsym(h,concat!($n,"\0").as_ptr().cast()))}}}
  let g_rchr:ChrFn=sym!("wcsrchr",ChrFn);
  let g_pbrk:SetPFn=sym!("wcspbrk",SetPFn);
  let g_spn:SetNFn=sym!("wcsspn",SetNFn);
  let g_cspn:SetNFn=sym!("wcscspn",SetNFn);
  let g_str:StrFn=sym!("wcsstr",StrFn);
  let g_case:CmpFn=sym!("wcscasecmp",CmpFn);
  use frankenlibc_abi::wchar_abi as wa;
  let iters=200_000u64;
  for &n in &[16usize,64,256,1024]{
    let s:Vec<u32>=(0..n as u32).map(|x|b'a' as u32+(x%20)).chain(std::iter::once(0)).collect();
    let sp=s.as_ptr(); let spi=sp as *const i32;
    // wcsrchr: search for a char present once near the middle
    let c=(b'a' as u32)+((n/2%20) as u32);
    let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{wa::wcsrchr(black_box(sp),c)});}},
                    ||{for _ in 0..iters{black_box(unsafe{g_rchr(black_box(spi),c as i32)});}});
    println!("wcsrchr  n={n:<5} fl={:6.2} glibc={:6.2} fl/glibc={:.3}{}",f/iters as f64,g/iters as f64,f/g,tag(f/g));
    // set functions: accept/reject a small set NOT in s (forces full scan)
    let set:Vec<u32>=vec![b'X' as u32,b'Y' as u32,b'Z' as u32,0]; let setp=set.as_ptr(); let seti=setp as *const i32;
    let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{wa::wcspbrk(black_box(sp),setp)});}},
                    ||{for _ in 0..iters{black_box(unsafe{g_pbrk(black_box(spi),seti)});}});
    println!("wcspbrk  n={n:<5} fl={:6.2} glibc={:6.2} fl/glibc={:.3}{}",f/iters as f64,g/iters as f64,f/g,tag(f/g));
    // wcsspn: accept set = all present chars (full scan). Use a 20-char accept set.
    let acc:Vec<u32>=(0..20u32).map(|x|b'a' as u32+x).chain(std::iter::once(0)).collect(); let accp=acc.as_ptr(); let acci=accp as *const i32;
    let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{wa::wcsspn(black_box(sp),accp)});}},
                    ||{for _ in 0..iters{black_box(unsafe{g_spn(black_box(spi),acci)});}});
    println!("wcsspn   n={n:<5} fl={:6.2} glibc={:6.2} fl/glibc={:.3}{}",f/iters as f64,g/iters as f64,f/g,tag(f/g));
    let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{wa::wcscspn(black_box(sp),setp)});}},
                    ||{for _ in 0..iters{black_box(unsafe{g_cspn(black_box(spi),seti)});}});
    println!("wcscspn  n={n:<5} fl={:6.2} glibc={:6.2} fl/glibc={:.3}{}",f/iters as f64,g/iters as f64,f/g,tag(f/g));
    // wcsstr: needle absent (full scan)
    let ndl:Vec<u32>=vec![b'q' as u32,b'q' as u32,b'q' as u32,0]; let np=ndl.as_ptr(); let ni=np as *const i32;
    let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{wa::wcsstr(black_box(sp),np)});}},
                    ||{for _ in 0..iters{black_box(unsafe{g_str(black_box(spi),ni)});}});
    println!("wcsstr   n={n:<5} fl={:6.2} glibc={:6.2} fl/glibc={:.3}{}",f/iters as f64,g/iters as f64,f/g,tag(f/g));
    // wcscasecmp: identical strings (full scan)
    let s2=s.clone(); let s2p=s2.as_ptr() as *const i32;
    let(f,g)=bench2(||{for _ in 0..iters{black_box(unsafe{wa::wcscasecmp(black_box(sp),black_box(s2.as_ptr()))});}},
                    ||{for _ in 0..iters{black_box(unsafe{g_case(black_box(spi),black_box(s2p))});}});
    println!("wcscasecmp n={n:<3} fl={:6.2} glibc={:6.2} fl/glibc={:.3}{}",f/iters as f64,g/iters as f64,f/g,tag(f/g));
  }
}
