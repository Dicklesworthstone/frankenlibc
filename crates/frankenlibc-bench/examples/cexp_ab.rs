//! fl cexp/csinh/ccosh/ctanh vs glibc (dlmopen libm) — one-reduction sincos fix.
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
#[repr(C)] #[derive(Clone,Copy,Debug)] struct C{re:f64,im:f64}
type CF=unsafe extern "C" fn(C)->C;
fn main(){
  let h=unsafe{libc::dlmopen(libc::LM_ID_NEWLM,b"libm.so.6\0".as_ptr().cast(),libc::RTLD_LAZY|libc::RTLD_LOCAL)};assert!(!h.is_null());
  use frankenlibc_abi::math_abi as m;
  let zs=[C{re:0.5,im:0.7},C{re:1.2,im:2.3},C{re:-0.8,im:1.1},C{re:0.3,im:5.0},C{re:2.0,im:-1.5}];
  for (name,fl_ptr,gsym) in [
    ("cexp", m::cexp as usize, b"cexp\0".as_ref()),
    ("csinh", m::csinh as usize, b"csinh\0".as_ref()),
    ("ccosh", m::ccosh as usize, b"ccosh\0".as_ref()),
    ("ctanh", m::ctanh as usize, b"ctanh\0".as_ref()),
  ]{
    let fl:CF=unsafe{std::mem::transmute(fl_ptr)};
    let g:CF=unsafe{std::mem::transmute(libc::dlsym(h,gsym.as_ptr() as *const i8))};
    // correctness
    for &z in &zs{ let a=unsafe{fl(z)}; let b=unsafe{g(z)};
      assert!((a.re-b.re).abs()<=1e-12*(1.0+b.re.abs()) && (a.im-b.im).abs()<=1e-12*(1.0+b.im.abs()),"{name} {z:?}: fl=({},{}) g=({},{})",a.re,a.im,b.re,b.im); }
    let iters=400_000u64; let n=zs.len() as u64; let(mut flv,mut glv)=(Vec::new(),Vec::new());
    for r in 0..40{
      if r%2==0{let t=Instant::now();for _ in 0..iters{for &z in &zs{black_box(unsafe{fl(black_box(z))});}}flv.push(t.elapsed().as_nanos()as f64/(iters*n)as f64);
        let t=Instant::now();for _ in 0..iters{for &z in &zs{black_box(unsafe{g(black_box(z))});}}glv.push(t.elapsed().as_nanos()as f64/(iters*n)as f64);
      }else{let t=Instant::now();for _ in 0..iters{for &z in &zs{black_box(unsafe{g(black_box(z))});}}glv.push(t.elapsed().as_nanos()as f64/(iters*n)as f64);
        let t=Instant::now();for _ in 0..iters{for &z in &zs{black_box(unsafe{fl(black_box(z))});}}flv.push(t.elapsed().as_nanos()as f64/(iters*n)as f64);}
    }
    let(f,gg)=(pctl(&flv,0.1),pctl(&glv,0.1)); println!("{:<7} fl={f:6.2} glibc={gg:6.2} fl/glibc={:.3}{}",name,f/gg,if f/gg>1.25{"  <-- LOSS"}else if f/gg<0.9{"  win"}else{"  ~par"});
  }
}
