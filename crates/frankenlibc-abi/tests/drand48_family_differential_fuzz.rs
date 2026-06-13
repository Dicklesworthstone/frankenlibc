#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc drand48 family oracle

//! Randomized live differential fuzzer for the SVID `drand48` 48-bit PRNG family
//! vs host glibc. fl and glibc keep INDEPENDENT internal state (separate
//! symbols), so seeding both identically must yield bit-identical sequences.
//! Covers the global-state generators (`srand48`/`seed48`/`lcong48` →
//! `drand48`/`lrand48`/`mrand48`) and the caller-state generators
//! (`erand48`/`nrand48`/`jrand48` with an `xsubi[3]` buffer), comparing the raw
//! double BITS, the integer results, and the mutated `xsubi` buffer.

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn srand48(seed: libc::c_long);
    fn seed48(seed16v: *mut libc::c_ushort) -> *mut libc::c_ushort;
    fn lcong48(param: *mut libc::c_ushort);
    fn drand48() -> libc::c_double;
    fn lrand48() -> libc::c_long;
    fn mrand48() -> libc::c_long;
    fn erand48(xsubi: *mut libc::c_ushort) -> libc::c_double;
    fn nrand48(xsubi: *mut libc::c_ushort) -> libc::c_long;
    fn jrand48(xsubi: *mut libc::c_ushort) -> libc::c_long;
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
    fn u16(&mut self) -> u16 {
        (self.next() >> 17) as u16
    }
}

#[test]
fn drand48_family_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0xd1a8_4842_f00d_1357);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..50_000 {
        // --- Seed both engines identically, three different ways. ---
        let seed_kind = r.below(3);
        let seed_desc;
        match seed_kind {
            0 => {
                let s = r.next() as i64; // full 64-bit; glibc uses low 32 bits
                unsafe {
                    fl::srand48(s);
                    srand48(s);
                }
                seed_desc = format!("srand48({s:#x})");
            }
            1 => {
                let mut a = [r.u16(), r.u16(), r.u16()];
                let mut b = a;
                unsafe {
                    fl::seed48(a.as_mut_ptr());
                    seed48(b.as_mut_ptr());
                }
                seed_desc = format!("seed48({a:?})");
            }
            _ => {
                // lcong48: 7 u16 — Xi[0..3], a[3..6], c[6].
                let mut a = [
                    r.u16(),
                    r.u16(),
                    r.u16(),
                    r.u16(),
                    r.u16(),
                    r.u16(),
                    r.u16(),
                ];
                let mut b = a;
                unsafe {
                    fl::lcong48(a.as_mut_ptr());
                    lcong48(b.as_mut_ptr());
                }
                seed_desc = format!("lcong48({a:?})");
            }
        }

        // --- Draw a short random sequence from the global generators. ---
        let draws = 1 + r.below(6);
        for _ in 0..draws {
            match r.below(3) {
                0 => {
                    let f = unsafe { fl::drand48() }.to_bits();
                    let g = unsafe { drand48() }.to_bits();
                    compared += 1;
                    if f != g && divs.len() < 30 {
                        divs.push(format!(
                            "{seed_desc} -> drand48 fl={f:#018x} glibc={g:#018x}"
                        ));
                    }
                }
                1 => {
                    let f = unsafe { fl::lrand48() };
                    let g = unsafe { lrand48() };
                    compared += 1;
                    if f != g && divs.len() < 30 {
                        divs.push(format!("{seed_desc} -> lrand48 fl={f} glibc={g}"));
                    }
                }
                _ => {
                    let f = unsafe { fl::mrand48() };
                    let g = unsafe { mrand48() };
                    compared += 1;
                    if f != g && divs.len() < 30 {
                        divs.push(format!("{seed_desc} -> mrand48 fl={f} glibc={g}"));
                    }
                }
            }
        }

        // --- Caller-state generators: independent xsubi copies. ---
        let base = [r.u16(), r.u16(), r.u16()];
        for _ in 0..(1 + r.below(4)) {
            let mut xf = base;
            let mut xg = base;
            let kind = r.below(3);
            let (fv, gv): (u64, u64) = match kind {
                0 => (
                    unsafe { fl::erand48(xf.as_mut_ptr()) }.to_bits(),
                    unsafe { erand48(xg.as_mut_ptr()) }.to_bits(),
                ),
                1 => (unsafe { fl::nrand48(xf.as_mut_ptr()) } as u64, unsafe {
                    nrand48(xg.as_mut_ptr())
                }
                    as u64),
                _ => (unsafe { fl::jrand48(xf.as_mut_ptr()) } as u64, unsafe {
                    jrand48(xg.as_mut_ptr())
                }
                    as u64),
            };
            compared += 1;
            if (fv != gv || xf != xg) && divs.len() < 30 {
                let name = ["erand48", "nrand48", "jrand48"][kind];
                divs.push(format!(
                    "{name}(base={base:?}) fl=({fv:#x},{xf:?}) glibc=({gv:#x},{xg:?})"
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "drand48 family diverged from glibc ({compared} compared):\n{}",
        divs.join("\n")
    );
    eprintln!("drand48 family fuzz: {compared} compared, 0 divergences vs host glibc");
}
