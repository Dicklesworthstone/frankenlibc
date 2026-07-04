//! In-process A/B: %.Nf of an EXACT-INTEGER double via Rust std `{:.N}` (flt2dec) vs a
//! direct integer-digits + zero-pad fast path. Byte-identity asserted. Ratio cancels contention.
use std::hint::black_box; use std::time::Instant; use std::fmt::Write;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
// OLD: Rust std fixed-point formatting (what render_pct_f/{:.prec} do today)
fn old(x:f64,prec:usize)->String{ let mut s=String::new(); let _=write!(s,"{x:.prec$}"); s }
// NEW: exact-integer fast path — value is integral and |value| < 2^64.
// Digits of (value as u64) + '.' + prec zeros. Byte-identical to correctly-rounded output
// because an exact integer's fractional part is exactly zero.
fn new(x:f64,prec:usize)->String{
  debug_assert!(x.fract()==0.0 && x.abs()<1.8446744073709552e19);
  let neg = x.is_sign_negative();
  let mag = x.abs() as u64;
  let mut s=String::with_capacity(24+prec);
  if neg { s.push('-'); }
  let _=write!(s,"{mag}");
  if prec>0 { s.push('.'); for _ in 0..prec { s.push('0'); } }
  s
}
fn main(){
  let cases:&[(f64,usize)]=&[
    (42.0,6),(100.0,2),(0.0,6),(7.0,0),(1000000.0,3),(255.0,2),
    (1234567.0,6),(9.0,1),(1000000000000000.0,2),(3.0,6),(-8.0,2),(2.0,0),
  ];
  for &(x,p) in cases{ assert_eq!(old(x,p),new(x,p),"mismatch {x} .{p}: old={} new={}",old(x,p),new(x,p)); }
  let iters=2_000_000u64; let n=cases.len() as u64;
  let(mut ov,mut nv)=(Vec::new(),Vec::new());
  for r in 0..60{
    let o=||{let t=Instant::now();for _ in 0..iters{for &(x,p) in cases{black_box(old(black_box(x),p));}}t.elapsed().as_nanos()as f64/(iters*n)as f64};
    let nw=||{let t=Instant::now();for _ in 0..iters{for &(x,p) in cases{black_box(new(black_box(x),p));}}t.elapsed().as_nanos()as f64/(iters*n)as f64};
    if r%2==0{ov.push(o());nv.push(nw());}else{nv.push(nw());ov.push(o());}
  }
  let(o,nn)=(pctl(&ov,0.1),pctl(&nv,0.1));
  println!("intf OLD(std .Nf)={o:.1}ns NEW(int-fast)={nn:.1}ns  new/old={:.3} ({:.2}x faster)",nn/o,o/nn);
}
