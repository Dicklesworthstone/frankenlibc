//! In-process A/B: memchr skip-loop at 256B/iter (4x Simd<u8,64>, current) vs 512B/iter
//! (8x Simd<u8,64>). Wider was proven better (Simd64>Simd32); does 512B beat 256B? Absent
//! needle. Ratio cancels worker.
#![feature(portable_simd)]
use std::hint::black_box; use std::time::Instant;
use std::simd::Simd; use std::simd::cmp::SimdPartialEq;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}
fn has256(b:&[u8],nd:Simd<u8,64>)->bool{
  let p0=Simd::<u8,64>::from_slice(&b[0..64]).simd_eq(nd);
  let p1=Simd::<u8,64>::from_slice(&b[64..128]).simd_eq(nd);
  let p2=Simd::<u8,64>::from_slice(&b[128..192]).simd_eq(nd);
  let p3=Simd::<u8,64>::from_slice(&b[192..256]).simd_eq(nd);
  (p0|p1|p2|p3).any()
}
fn has512(b:&[u8],nd:Simd<u8,64>)->bool{
  let mut acc=Simd::<u8,64>::splat(0).simd_ne(Simd::splat(0));
  let mut o=0; while o<512{ acc|=Simd::<u8,64>::from_slice(&b[o..o+64]).simd_eq(nd); o+=64; } acc.any()
}
fn scan256(hs:&[u8],needle:u8)->Option<usize>{ let nd=Simd::<u8,64>::splat(needle); let n=hs.len(); let mut base=0;
  while n-base>=256{ if has256(&hs[base..base+256],nd){ for j in base..base+256{if hs[j]==needle{return Some(j);}} } base+=256; }
  hs[base..].iter().position(|&x|x==needle).map(|j|base+j) }
fn scan512(hs:&[u8],needle:u8)->Option<usize>{ let nd=Simd::<u8,64>::splat(needle); let n=hs.len(); let mut base=0;
  while n-base>=512{ if has512(&hs[base..base+512],nd){ for j in base..base+512{if hs[j]==needle{return Some(j);}} } base+=512; }
  while n-base>=256{ if has256(&hs[base..base+256],nd){ for j in base..base+256{if hs[j]==needle{return Some(j);}} } base+=256; }
  hs[base..].iter().position(|&x|x==needle).map(|j|base+j) }
fn main(){
  for &n in &[512usize,1024,4096,16384,65536]{
    let hs=vec![b'a';n]; let needle=b'z';
    assert_eq!(scan256(&hs,needle),scan512(&hs,needle),"mismatch n={n}");
    let iters=200_000u64; let(mut ov,mut nv)=(Vec::new(),Vec::new());
    for r in 0..60{
      let o=||{let t=Instant::now();for _ in 0..iters{black_box(scan256(black_box(&hs),needle));}t.elapsed().as_nanos()as f64/iters as f64};
      let nw=||{let t=Instant::now();for _ in 0..iters{black_box(scan512(black_box(&hs),needle));}t.elapsed().as_nanos()as f64/iters as f64};
      if r%2==0{ov.push(o());nv.push(nw());}else{nv.push(nw());ov.push(o());}
    }
    let(oo,nn)=(pctl(&ov,0.1),pctl(&nv,0.1));
    println!("memchr-fold n={n:<6} 256B={oo:7.1}ns 512B={nn:7.1}ns  512/256={:.3} ({:.2}x)",nn/oo,oo/nn);
  }
}
