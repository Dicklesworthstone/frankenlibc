const N: usize = 8; const TLEN: usize = 1<<N;
const C2: f64=-0.7213475204444817; const C3: f64=0.4808983469629878; const C4: f64=-0.36067376022240424; const C5: f64=0.2885390081777927;
const INVLN2_HI: f64=f64::from_bits(0x3FF7154765200000); const INVLN2_LO: f64=f64::from_bits(0x3DE705FC2EEFA200);
const A1: f64=2.885390081777926774; const A3: f64=A1/3.0; const A5: f64=A1/5.0; const A7: f64=A1/7.0; const A9: f64=A1/9.0; const A11: f64=A1/11.0; const A13: f64=A1/13.0; const A15: f64=A1/15.0;
fn two_sum(a:f64,b:f64)->(f64,f64){let s=a+b;let bb=s-a;(s,(a-(s-bb))+(b-bb))}
fn two_prod(a:f64,b:f64)->(f64,f64){let p=a*b;(p,a.mul_add(b,-p))}
fn dd_add(a:(f64,f64),b:(f64,f64))->(f64,f64){let(s,e)=two_sum(a.0,b.0);let lo=e+a.1+b.1;let(h,l)=two_sum(s,lo);(h,l)}
fn dd_mul(a:(f64,f64),b:(f64,f64))->(f64,f64){let(p,e)=two_prod(a.0,b.0);let lo=e+a.0*b.1+a.1*b.0;let(h,l)=two_sum(p,lo);(h,l)}
// log2(v) for v in [1,2) in double-double via atanh series. Returns hi f64.
fn dd_log2(v:f64)->(f64,f64){
    // t = (v-1)/(v+1), dd
    let nn=v-1.0; let dd=v+1.0;
    let tq=nn/dd; let tr=(-tq).mul_add(dd,nn)/dd; let t=(tq,tr);
    let t2=dd_mul(t,t);
    let mut acc=t; let mut term=t; // term=t^k
    let mut k=3.0f64;
    for _ in 0..40 {
        term=dd_mul(term,t2); // t^k
        let recip=(1.0/k,0.0);
        acc=dd_add(acc,dd_mul(term,recip));
        k+=2.0;
    }
    // ln(v)=2*acc ; log2 = ln*1/ln2
    let ln=dd_mul((2.0,0.0),acc);
    const INVLN2:(f64,f64)=(1.4426950408889634,2.0355273740931033e-17);
    dd_mul(ln,INVLN2)
}
fn build()->(Vec<f64>,Vec<f64>,Vec<f64>){let mut iv=vec![0.0;TLEN];let mut lh=vec![0.0;TLEN];let mut ll=vec![0.0;TLEN];for i in 0..TLEN{let m=1.0+(i as f64+0.5)/(TLEN as f64);let c=1.0/m;iv[i]=c;let (h,l)=dd_log2(1.0/c);lh[i]=h;ll[i]=l;}(iv,lh,ll)}
fn lg(x:f64,iv:&[f64],lh:&[f64],ll:&[f64])->f64{
    const SQRT2:f64=std::f64::consts::SQRT_2;
    let f=x-1.0;
    if f.abs()<0.13{let s=f/(2.0+f);let s2=s*s;return s*(A1+s2*(A3+s2*(A5+s2*(A7+s2*(A9+s2*(A11+s2*(A13+s2*A15)))))));}
    let bits=x.to_bits(); let e=((bits>>52)&0x7FF) as i64-1023; let mb=bits&0x000F_FFFF_FFFF_FFFF;
    if mb==0 {return e as f64;}
    let m=f64::from_bits(mb|0x3FF0_0000_0000_0000); let i=(mb>>(52-N)) as usize; let c=iv[i]; let r=m.mul_add(c,-1.0);
    let (ek,l)=if m>=SQRT2{((e+1) as f64,lh[i]-1.0)}else{(e as f64,lh[i])};
    let l_lo=ll[i];
    let r2=r*r;
    let w=r*INVLN2_HI;
    let plog_lo=l_lo + r*INVLN2_LO + r2*(C2+r*(C3+r*(C4+r*C5)));
    let (s1,e1)=two_sum(l,w);
    let (s2,e2)=two_sum(ek,s1);
    s2 + (e1 + e2 + plog_lo)
}
fn ulp(a:f64,b:f64)->i64{if a==b{0}else if a.is_nan()||b.is_nan()||a.is_sign_negative()!=b.is_sign_negative(){i64::MAX}else{(a.to_bits() as i64-b.to_bits() as i64).abs()}}
extern "C"{#[link_name="log2"] fn cl(x:f64)->f64;}

fn true_log2(x:f64)->f64{
    let bits=x.to_bits(); let e=((bits>>52)&0x7FF) as i64-1023; let mb=bits&0x000F_FFFF_FFFF_FFFF;
    if mb==0 {return e as f64;}
    let m=f64::from_bits(mb|0x3FF0_0000_0000_0000);
    let (h,l)=dd_log2(m); // log2(m), m in [1,2)
    // e + (h,l)
    let (s,er)=two_sum(e as f64,h); s + (er + l)
}

fn main(){let (iv,lh,ll)=build();
 // full geometric, coarse-ish but representative
 let mut worst=0i64;let mut wx=0.0;let mut x=1e-300;
 while x<1e300{ if x!=1.0{let u=ulp(lg(x,&iv,&lh,&ll),unsafe{cl(x)});if u>worst{worst=u;wx=x;}} x*=1.001;}
 println!("GEOM(coarse) worst {worst} ULP at {wx:e}");
 // near-1 dense 1M
 let mut w2=0i64;let mut wx2=0.0; for d in 0..1_000_000i64{let x=1.0+(d as f64)*2e-9; let u=ulp(lg(x,&iv,&lh,&ll),unsafe{cl(x)}); if u>w2{w2=u;wx2=x;}}
 println!("NEAR1(1M) worst {w2} ULP at {wx2}");
 // bench range
 let mut w3=0i64;let mut x=0.5; while x<=2.5{let u=ulp(lg(x,&iv,&lh,&ll),unsafe{cl(x)});if u>w3{w3=u;} x+=1e-5;}
 println!("BENCH[0.5,2.5] worst {w3} ULP");
 // powers of 2 bit-exact
 let mut pf=0; for k in -200i32..=200{let p=(k as f64).exp2(); if lg(p,&iv,&lh,&ll).to_bits()!=unsafe{cl(p)}.to_bits(){pf+=1;}}
 println!("POW2 bit-exact failures: {pf}");
 // vs TRUE (dd) reference
 let mut wt=0i64;let mut wtx=0.0;let mut x=0.5; while x<=2.5{let u=ulp(lg(x,&iv,&lh,&ll),true_log2(x));if u>wt{wt=u;wtx=x;} x+=1e-5;}
 println!("BENCH vs TRUE worst {wt} ULP at {wtx}");
 // glibc vs true at the worst point
 let xb=0.8617554520428125f64; println!("at x={xb}: mine={:.20e} glibc={:.20e} true={:.20e}",lg(xb,&iv,&lh,&ll),unsafe{cl(xb)},true_log2(xb));
}
