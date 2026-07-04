//! Size-sweep: does fl strcspn/strpbrk lose to glibc per-byte for long strings with a
//! late/no delimiter? Bitmap scan tests each byte against a 256-bit set. vs glibc (dlmopen).
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type SpnFn=unsafe extern "C" fn(*const i8,*const i8)->usize;
type PbrkFn=unsafe extern "C" fn(*const i8,*const i8)->*mut i8;
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  let g_spn:SpnFn=unsafe{std::mem::transmute(libc::dlsym(h,b"strcspn\0".as_ptr().cast()))};
  let g_pbrk:PbrkFn=unsafe{std::mem::transmute(libc::dlsym(h,b"strpbrk\0".as_ptr().cast()))};
  use frankenlibc_abi::string_abi as fa;
  let reject=b"<>&\"'\0".as_ptr() as *const i8; // 5-char set (HTML-escape-ish), common
  for &n in &[64usize,256,1024]{
    // 'a'*n + NUL, none of the reject chars present -> full scan
    let mut s=vec![b'a';n+1]; s[n]=0; let sp=s.as_ptr() as *const i8;
    assert_eq!(unsafe{fa::strcspn(sp,reject)}, unsafe{g_spn(sp,reject)}, "strcspn n={n}");
    assert_eq!(unsafe{fa::strpbrk(sp,reject)}.is_null(), unsafe{g_pbrk(sp,reject)}.is_null(),"strpbrk n={n}");
    let iters=400_000u64;
    let(mut fl,mut gl)=(Vec::new(),Vec::new());
    for r in 0..50{
      if r%2==0{let t=Instant::now();for _ in 0..iters{black_box(unsafe{fa::strcspn(black_box(sp),reject)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{g_spn(black_box(sp),reject)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
      }else{let t=Instant::now();for _ in 0..iters{black_box(unsafe{g_spn(black_box(sp),reject)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{fa::strcspn(black_box(sp),reject)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);}
    }
    let(f,gg)=(pctl(&fl,0.1),pctl(&gl,0.1));
    println!("strcspn n={n:<5} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",f/gg,if f/gg>1.2{"  <-- LOSS"}else{""});
  }
}
