//! fl memfrob (deployed scalar) vs glibc (dlmopen) AND an in-process A/B: scalar vs 32B SIMD
//! XOR-with-42. Byte-identity asserted. memfrob is a bounded op (no NUL/page concern).
#![feature(portable_simd)]
use std::hint::black_box; use std::time::Instant;
use std::simd::Simd;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
type MfFn=unsafe extern "C" fn(*mut std::ffi::c_void,usize)->*mut std::ffi::c_void;

unsafe fn scalar(p:*mut u8,n:usize){ for i in 0..n{ unsafe{*p.add(i)^=42}; } }
unsafe fn simd(p:*mut u8,n:usize){
  const L:usize=32; let k=Simd::<u8,L>::splat(42); let mut i=0;
  while i+L<=n{
    let v=Simd::<u8,L>::from_slice(unsafe{std::slice::from_raw_parts(p.add(i),L)});
    (v^k).copy_to_slice(unsafe{std::slice::from_raw_parts_mut(p.add(i),L)});
    i+=L;
  }
  while i<n{ unsafe{*p.add(i)^=42}; i+=1; }
}

fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libc.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  let g_mf:MfFn=unsafe{std::mem::transmute(libc::dlsym(h,b"memfrob\0".as_ptr().cast()))};
  use frankenlibc_abi::unistd_abi as ua;
  for &n in &[16usize,64,256,1024,4096]{
    // byte-identity: scalar vs simd
    let mut a:Vec<u8>=(0..n).map(|x|(x*7+1)as u8).collect();
    let mut b=a.clone();
    unsafe{scalar(a.as_mut_ptr(),n); simd(b.as_mut_ptr(),n);}
    assert_eq!(a,b,"mismatch n={n}");
    let mut buf:Vec<u8>=(0..n).map(|x|(x*3+1)as u8).collect(); let bp=buf.as_mut_ptr();
    let iters=300_000u64;
    // deployed fl vs glibc
    let(mut fl,mut gl)=(Vec::new(),Vec::new());
    for r in 0..40{
      if r%2==0{let t=Instant::now();for _ in 0..iters{black_box(unsafe{ua::memfrob(black_box(bp as *mut std::ffi::c_void),n)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{g_mf(black_box(bp as *mut std::ffi::c_void),n)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);}
      else{let t=Instant::now();for _ in 0..iters{black_box(unsafe{g_mf(black_box(bp as *mut std::ffi::c_void),n)});}gl.push(t.elapsed().as_nanos()as f64/iters as f64);
        let t=Instant::now();for _ in 0..iters{black_box(unsafe{ua::memfrob(black_box(bp as *mut std::ffi::c_void),n)});}fl.push(t.elapsed().as_nanos()as f64/iters as f64);}
    }
    let(f,g)=(pctl(&fl,0.1),pctl(&gl,0.1));
    // in-process scalar vs simd A/B
    let(mut sv,mut mv)=(Vec::new(),Vec::new());
    for r in 0..40{
      let so=||{let t=Instant::now();for _ in 0..iters{black_box(unsafe{scalar(black_box(bp),n)});}t.elapsed().as_nanos()as f64/iters as f64};
      let mo=||{let t=Instant::now();for _ in 0..iters{black_box(unsafe{simd(black_box(bp),n)});}t.elapsed().as_nanos()as f64/iters as f64};
      if r%2==0{sv.push(so());mv.push(mo());}else{mv.push(mo());sv.push(so());}
    }
    let(sc,sm)=(pctl(&sv,0.1),pctl(&mv,0.1));
    eprintln!("memfrob n={n:<5} fl={f:6.2} glibc={g:6.2} fl/glibc={:.3} | AB scalar={sc:6.2} simd={sm:6.2} simd/scalar={:.3}",f/g,sm/sc);
  }
}
