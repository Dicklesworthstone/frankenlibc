//! Isolate strfromd %.6f cost: raw std format+alloc vs write-into-pooled vs render_strfrom-ish.
use std::fmt::Write;
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
fn main() {
    let vals = [3.14159f64, 2.71828, 1234.5678, 0.0001234, 9.99e10, 42.0];
    let iters = 1_000_000u64;
    let n = vals.len() as u64;
    let meas = |f: &dyn Fn()| {
        let mut v = Vec::new();
        for _ in 0..50 {
            let t = Instant::now();
            for _ in 0..iters {
                for &val in &vals {
                    f_call(f, val);
                }
            }
            v.push(t.elapsed().as_nanos() as f64 / (iters * n) as f64);
        }
        pctl(&v, 0.1)
    };
    fn f_call(_f: &dyn Fn(), _v: f64) {}
    let _ = meas;
    let _ = f_call;
    // A: fresh String each call (alloc + std dtoa)
    let a = || {
        let mut v = Vec::new();
        for _ in 0..50 {
            let t = Instant::now();
            for _ in 0..iters {
                for &val in &vals {
                    let s = format!("{:.6}", black_box(val));
                    black_box(&s);
                }
            }
            v.push(t.elapsed().as_nanos() as f64 / (iters * n) as f64);
        }
        pctl(&v, 0.1)
    };
    // B: reuse one String (no per-call alloc), std dtoa via write!
    let b = || {
        let mut buf = String::with_capacity(64);
        let mut v = Vec::new();
        for _ in 0..50 {
            let t = Instant::now();
            for _ in 0..iters {
                for &val in &vals {
                    buf.clear();
                    write!(buf, "{:.6}", black_box(val)).unwrap();
                    black_box(&buf);
                }
            }
            v.push(t.elapsed().as_nanos() as f64 / (iters * n) as f64);
        }
        pctl(&v, 0.1)
    };
    let av = a();
    let bv = b();
    println!(
        "format!(alloc)={av:.1}ns  write!(pooled)={bv:.1}ns  alloc_cost={:.1}ns  dtoa_only={bv:.1}ns",
        av - bv
    );
}
