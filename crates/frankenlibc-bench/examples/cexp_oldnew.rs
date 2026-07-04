//! In-process A/B: OLD cexp (separate sin+cos = 2 reductions) vs NEW (sincos = 1 reduction).
//! Ratio cancels worker contention. Isolates exactly what the shipped fix changes.
use std::hint::black_box; use std::time::Instant;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
fn main(){
  use frankenlibc_core::math;
  let zs=[(0.5f64,0.7f64),(1.2,2.3),(-0.8,1.1),(0.3,5.0),(2.0,-1.5),(0.9,0.4),(1.7,3.1),(-1.3,0.6)];
  // verify bit-identity old vs new
  for &(re,im) in &zs{
    let r=math::exp(re);
    let old=(r*math::cos(im), r*math::sin(im));
    let (s,c)=math::sincos(im); let new=(r*c, r*s);
    assert_eq!(old.0.to_bits(),new.0.to_bits(),"re mismatch"); assert_eq!(old.1.to_bits(),new.1.to_bits(),"im mismatch");
  }
  let iters=1_000_000u64; let n=zs.len() as u64;
  let(mut ov,mut nv)=(Vec::new(),Vec::new());
  for r in 0..60{
    let old=||{let t=Instant::now();for _ in 0..iters{for &(re,im) in &zs{let r=math::exp(black_box(re));black_box((r*math::cos(black_box(im)),r*math::sin(black_box(im))));}}t.elapsed().as_nanos()as f64/(iters*n)as f64};
    let new=||{let t=Instant::now();for _ in 0..iters{for &(re,im) in &zs{let r=math::exp(black_box(re));let (s,c)=math::sincos(black_box(im));black_box((r*c,r*s));}}t.elapsed().as_nanos()as f64/(iters*n)as f64};
    if r%2==0{ov.push(old());nv.push(new());}else{nv.push(new());ov.push(old());}
  }
  let(o,nn)=(pctl(&ov,0.1),pctl(&nv,0.1));
  println!("cexp-core  OLD(sin+cos)={o:.2}ns  NEW(sincos)={nn:.2}ns  new/old={:.3}  ({:.2}x faster)",nn/o,o/nn);
}
