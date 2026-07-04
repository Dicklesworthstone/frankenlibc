//! In-process A/B for wcsrchr's scan (wide_last_before_nul_simd): current 8-lane (32B/iter)
//! vs a page-guarded 128B (4x8-lane) fold tier. wcsrchr always scans to the NUL tracking the
//! LAST match, so most blocks (no c, no NUL) are pure skip-scan — a wider fold cuts loop
//! overhead 4x. On a block containing c-or-NUL, scalar-rescan it (track last c, stop at NUL).
//! Byte-identity of (last_index, span) asserted. Tests c-absent (full scan) and c-once-mid.
#![feature(portable_simd)]
use std::hint::black_box; use std::time::Instant;
use std::simd::Simd; use std::simd::cmp::SimdPartialEq;
fn pctl(s:&[f64],q:f64)->f64{let mut v=s.to_vec();v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[((q*(v.len()-1)as f64).round()as usize).min(v.len()-1)]}

// CURRENT: 8-lane (mirrors deployed wide_last_before_nul_simd, c!=0 path).
unsafe fn scan8(s:*const u32,c:u32)->(Option<usize>,usize){
  const L:usize=8; let mut last=None; let mut i=0;
  let head=((32-((s as usize)&31))&31)/4;
  while i<head{ let ch=unsafe{*s.add(i)}; if ch==c{last=Some(i);} if ch==0{return(last,i+1);} i+=1; }
  let cv=Simd::<u32,L>::splat(c); let zv=Simd::<u32,L>::splat(0);
  loop{
    let v=Simd::<u32,L>::from_array(unsafe{core::ptr::read(s.add(i).cast::<[u32;L]>())});
    if (v.simd_eq(cv)|v.simd_eq(zv)).any(){
      for j in 0..L{ let ch=unsafe{*s.add(i+j)}; if ch==c{last=Some(i+j);} if ch==0{return(last,i+j+1);} }
    }
    i+=L;
  }
}
// NEW: mask-based 8-lane — extract the last match position from the SIMD bitmask directly,
// NO scalar rescan of the chunk (what glibc does). On the NUL chunk, mask off c-matches at/
// after the NUL and take the highest remaining bit.
unsafe fn scan8_mask(s:*const u32,c:u32)->(Option<usize>,usize){
  const L:usize=8; let mut last=None; let mut i=0;
  let head=((32-((s as usize)&31))&31)/4;
  while i<head{ let ch=unsafe{*s.add(i)}; if ch==c{last=Some(i);} if ch==0{return(last,i+1);} i+=1; }
  let cv=Simd::<u32,L>::splat(c); let zv=Simd::<u32,L>::splat(0);
  loop{
    let v=Simd::<u32,L>::from_array(unsafe{core::ptr::read(s.add(i).cast::<[u32;L]>())});
    let eqc=v.simd_eq(cv); let eqz=v.simd_eq(zv);
    if (eqc|eqz).any(){ // cheap skip test (same as current), extract only on a hit
      let zm=eqz.to_bitmask();
      if zm!=0{
        let p=zm.trailing_zeros() as usize;
        let cm_before=eqc.to_bitmask() & ((1u64<<p)-1);
        if cm_before!=0{ last=Some(i + (63 - cm_before.leading_zeros() as usize)); }
        return(last, i+p+1);
      }
      last=Some(i + (63 - eqc.to_bitmask().leading_zeros() as usize)); // cm!=0 here
    }
    i+=L;
  }
}

fn main(){
  for &n in &[16usize,64,256,1024,4096]{
    let base:Vec<u32>=(0..n as u32).map(|x|b'a' as u32+(x%20)).chain(std::iter::once(0)).collect();
    let sp=base.as_ptr();
    for (tag,c) in [("absent",b'Z' as u32),("mid",(b'a' as u32)+((n/2%20)as u32))]{
      assert_eq!(unsafe{scan8(sp,c)},unsafe{scan8_mask(sp,c)},"mismatch n={n} {tag}");
      let iters=300_000u64; let(mut ov,mut nv)=(Vec::new(),Vec::new());
      for r in 0..50{
        let o=||{let t=Instant::now();for _ in 0..iters{black_box(unsafe{scan8(black_box(sp),c)});}t.elapsed().as_nanos()as f64/iters as f64};
        let nw=||{let t=Instant::now();for _ in 0..iters{black_box(unsafe{scan8_mask(black_box(sp),c)});}t.elapsed().as_nanos()as f64/iters as f64};
        if r%2==0{ov.push(o());nv.push(nw());}else{nv.push(nw());ov.push(o());}
      }
      let(o,nn)=(pctl(&ov,0.1),pctl(&nv,0.1));
      eprintln!("wcsrchr n={n:<5} {tag:<7} 8lane={o:7.2}ns 128B={nn:7.2}ns  new/old={:.3} ({:.2}x)",nn/o,o/nn);
    }
  }
}
