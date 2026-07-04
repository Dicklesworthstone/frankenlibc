//! Rust std {:.6e} vs {:.6} cost (is scientific formatting the %e bottleneck?).
use std::hint::black_box; use std::time::Instant; use std::fmt::Write;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
fn main(){
  let vals=[3.14159f64,2.71828,1234.5678,0.0001234,9.99e10,42.0];
  let iters=1_000_000u64; let n=vals.len() as u64;
  let mut buf=String::with_capacity(64);
  let f=||{let mut b=String::with_capacity(64);let mut v=Vec::new();for _ in 0..40{let t=Instant::now();for _ in 0..iters{for &x in &vals{b.clear();write!(b,"{:.6}",black_box(x)).unwrap();black_box(&b);}}v.push(t.elapsed().as_nanos()as f64/(iters*n)as f64);}pctl(&v,0.1)};
  let e=||{let mut b=String::with_capacity(64);let mut v=Vec::new();for _ in 0..40{let t=Instant::now();for _ in 0..iters{for &x in &vals{b.clear();write!(b,"{:.6e}",black_box(x)).unwrap();black_box(&b);}}v.push(t.elapsed().as_nanos()as f64/(iters*n)as f64);}pctl(&v,0.1)};
  let _=&mut buf;
  println!("write!(.6f)={:.1}ns  write!(.6e)={:.1}ns  e/f={:.2}",f(),e(),e()/f());
}
