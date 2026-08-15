//! Characterize fl strchr vs glibc strchr (dlmopen) across sizes, target ABSENT (full
//! scan to NUL = throughput). The probe showed n=256 at ~2.9x; this maps the curve so a
//! scanner change can be validated for no-regression at every size. Timed rows
//! use the campaign's balanced `ABBAABBA` square: both arms have equal early,
//! late, and total exposure, while each arm's contemporaneous early/late A/A
//! null makes a busy worker observable rather than a reason to wait forever.
//!
//! Run: cargo run --release --example strchr_largen_ab --features abi-bench

use std::hint::black_box;
use std::time::Instant;

type StrchrFn = unsafe extern "C" fn(*const i8, i32) -> *mut i8;

unsafe fn dl(h: *mut libc::c_void, n: &[u8]) -> StrchrFn {
    let p = unsafe { libc::dlsym(h, n.as_ptr().cast()) };
    assert!(!p.is_null());
    unsafe { std::mem::transmute::<*mut libc::c_void, StrchrFn>(p) }
}

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

const SQUARE: [u8; 8] = *b"ABBAABBA";
const NULL_BOUND: f64 = 0.02;

/// Hash the executable from inside the process that is timing the row. Remote
/// builds use worker-local target directories, so a shell-side hash would not
/// establish which ELF actually executed.
fn self_elf_sha256() -> String {
    use sha2::{Digest, Sha256};

    let path = std::env::current_exe().expect("resolve running benchmark ELF");
    let bytes = std::fs::read(path).expect("read running benchmark ELF");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

struct SquareRow {
    fl: f64,
    glibc: f64,
    ratio: f64,
    null_fl: f64,
    null_glibc: f64,
    checksum: usize,
}

impl SquareRow {
    fn verdict(&self) -> &'static str {
        if (self.null_fl - 1.0).abs() > NULL_BOUND || (self.null_glibc - 1.0).abs() > NULL_BOUND {
            "NULL-FAILED"
        } else if self.ratio > 1.0 {
            "ADMISSIBLE FL_SLOWER"
        } else {
            "ADMISSIBLE FL_FASTER"
        }
    }
}

/// Compare the two live implementations in four interleaved slots each. The
/// decision value is the median of per-round FL/glibc ratios, never a ratio of
/// independently sampled medians. Each arm's first two slots divided by its
/// final two slots is an A/A null from the same invocation.
fn balanced_square<F, G>(mut fl_arm: F, mut glibc_arm: G, rounds: usize, iters: u64) -> SquareRow
where
    F: FnMut(u64) -> usize,
    G: FnMut(u64) -> usize,
{
    let mut checksum = fl_arm(iters.min(2_000)) ^ glibc_arm(iters.min(2_000));
    let (mut ratios, mut fl_samples, mut glibc_samples) = (Vec::new(), Vec::new(), Vec::new());
    let (mut nulls_fl, mut nulls_glibc) = (Vec::new(), Vec::new());

    for _ in 0..rounds {
        let (mut fl_slots, mut glibc_slots) = (Vec::new(), Vec::new());
        for slot in SQUARE {
            let start = Instant::now();
            let elapsed = if slot == b'A' {
                checksum ^= fl_arm(iters);
                &mut fl_slots
            } else {
                checksum ^= glibc_arm(iters);
                &mut glibc_slots
            };
            elapsed.push(start.elapsed().as_nanos() as f64 / iters as f64);
        }

        ratios.push(pctl(&fl_slots, 0.5) / pctl(&glibc_slots, 0.5));
        fl_samples.extend(fl_slots.iter().copied());
        glibc_samples.extend(glibc_slots.iter().copied());
        nulls_fl.push(pctl(&fl_slots[..2], 0.5) / pctl(&fl_slots[2..], 0.5));
        nulls_glibc.push(pctl(&glibc_slots[..2], 0.5) / pctl(&glibc_slots[2..], 0.5));
    }

    SquareRow {
        fl: pctl(&fl_samples, 0.5),
        glibc: pctl(&glibc_samples, 0.5),
        ratio: pctl(&ratios, 0.5),
        null_fl: pctl(&nulls_fl, 0.5),
        null_glibc: pctl(&nulls_glibc, 0.5),
        checksum,
    }
}

fn main() {
    println!("ELF_SHA256={}", self_elf_sha256());
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g_strchr: StrchrFn = unsafe { dl(h, b"strchr\0") };

    // Correctness cross-check (present + absent) vs glibc across alignments/lengths.
    {
        let mut checks = 0u64;
        for align in 0..70usize {
            for len in 0..300usize {
                let mut buf = vec![0u8; align + len + 1 + 160];
                for k in 0..len {
                    buf[align + k] = b'a' + ((align + k) % 25) as u8;
                }
                buf[align + len] = 0;
                let sp = unsafe { buf.as_ptr().add(align) as *const i8 };
                // absent target 'Z'
                let f = unsafe { frankenlibc_abi::string_abi::strchr(sp, b'Z' as i32) };
                let g = unsafe { g_strchr(sp, b'Z' as i32) };
                assert_eq!(f as usize, g as usize, "absent align={align} len={len}");
                // present target: last char (if any)
                if len > 0 {
                    let t = buf[align + len - 1] as i32;
                    let f2 = unsafe { frankenlibc_abi::string_abi::strchr(sp, t) };
                    let g2 = unsafe { g_strchr(sp, t) };
                    assert_eq!(f2 as usize, g2 as usize, "present align={align} len={len}");
                }
                checks += 1;
            }
        }
        println!("correctness: {checks} (align×len) fl strchr == glibc ✓");
    }

    let sizes = [64usize, 128, 256, 512, 1024, 2048, 4096, 16384];
    for &n in &sizes {
        let mut buf = vec![b'x'; n + 16];
        buf[n] = 0;
        let scp = unsafe { buf.as_ptr().add(0) as *const i8 };
        let row = balanced_square(
            |iters| {
                let mut checksum = 0usize;
                for _ in 0..iters {
                    checksum ^=
                        black_box(unsafe { frankenlibc_abi::string_abi::strchr(scp, b'Z' as i32) })
                            as usize;
                }
                checksum
            },
            |iters| {
                let mut checksum = 0usize;
                for _ in 0..iters {
                    checksum ^= black_box(unsafe { g_strchr(scp, b'Z' as i32) }) as usize;
                }
                checksum
            },
            41,
            20_000,
        );
        println!(
            "STRCHR n={n:<6} median: fl={:.2} glibc={:.2} fl/glibc={:.4} \\
             null_fl={:.4} null_glibc={:.4} bound=+/-{NULL_BOUND:.2} ck={:#x} :: {}",
            row.fl,
            row.glibc,
            row.ratio,
            row.null_fl,
            row.null_glibc,
            row.checksum,
            row.verdict(),
        );
    }
}
