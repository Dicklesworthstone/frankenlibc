#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc random_r/srandom_r/initstate_r/setstate_r oracle

//! Randomized live differential fuzzer for the reentrant `random_r` family vs
//! host glibc.
//!
//! glibc's `random_r`/`srandom_r`/`initstate_r`/`setstate_r` run the same five
//! additive-feedback generators (TYPE_0..4, selected by state-buffer size) as
//! `random()` — but on caller-owned state (`struct random_data` + statebuf),
//! with no global lock. frankenlibc's previous reentrant implementation was a
//! stub (a single LCG step over the first 4 bytes), diverging from glibc on the
//! very first draw.
//!
//! This drives the pure-safe-Rust core API (`frankenlibc_core::stdlib::
//! random_r_*`) directly rather than the C-ABI wrappers, so the frankenlibc
//! membrane allocator never runs alongside the host glibc allocator (the known
//! heap-coexistence crash, bd-2g7oyh.212). The generator math — what this test
//! pins — is exercised faithfully against the live oracle.

use std::ffi::{c_char, c_int, c_uint};

use frankenlibc_core::stdlib::{
    RandomRState, random_r_flush, random_r_initstate, random_r_setstate, random_r_srandom,
    random_r_step,
};

// glibc `struct random_data` is 48 bytes on LP64 and holds internal pointers
// into the statebuf; treat it as an opaque, 8-aligned blob.
#[repr(C, align(8))]
struct RandomData([u8; 48]);

unsafe extern "C" {
    fn random_r(buf: *mut RandomData, result: *mut i32) -> c_int;
    fn srandom_r(seed: c_uint, buf: *mut RandomData) -> c_int;
    fn initstate_r(seed: c_uint, statebuf: *mut c_char, statelen: usize, buf: *mut RandomData)
    -> c_int;
    fn setstate_r(statebuf: *mut c_char, buf: *mut RandomData) -> c_int;
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
}

/// A live host-glibc reentrant generator over its own statebuf.
struct HostGen {
    rd: Box<RandomData>,
    // Heap-stable statebuf; glibc stores pointers into it inside `rd`.
    state: Vec<i32>,
}

impl HostGen {
    fn init(seed: c_uint, statelen: usize) -> Self {
        let mut rd = Box::new(RandomData([0u8; 48]));
        let mut state = vec![0i32; statelen / 4];
        unsafe {
            initstate_r(
                seed,
                state.as_mut_ptr() as *mut c_char,
                statelen,
                rd.as_mut() as *mut RandomData,
            );
        }
        HostGen { rd, state }
    }
    fn draw(&mut self) -> i32 {
        let mut r: i32 = 0;
        unsafe {
            random_r(self.rd.as_mut() as *mut RandomData, &mut r);
        }
        r
    }
    fn reseed(&mut self, seed: c_uint) {
        unsafe {
            srandom_r(seed, self.rd.as_mut() as *mut RandomData);
        }
    }
    fn setstate(&mut self) {
        unsafe {
            setstate_r(
                self.state.as_mut_ptr() as *mut c_char,
                self.rd.as_mut() as *mut RandomData,
            );
        }
    }
}

/// The frankenlibc core reentrant generator over its own word buffer.
struct FlGen {
    words: Vec<i32>,
    st: RandomRState,
}

impl FlGen {
    fn init(seed: u32, statelen: usize) -> Self {
        let mut words = vec![0i32; statelen / 4];
        let st = random_r_initstate(seed, &mut words).expect("statelen >= 8");
        FlGen { words, st }
    }
    fn draw(&mut self) -> i32 {
        random_r_step(&mut self.words, &mut self.st)
    }
    fn reseed(&mut self, seed: u32) {
        random_r_srandom(seed, &mut self.words, &mut self.st);
    }
    fn setstate(&mut self) {
        // glibc setstate_r saves the live cursor into the old statebuf's
        // encoding word, then restores from the target buffer. On the same
        // buffer this preserves the live cursor. The ABI performs the same
        // flush-then-restore using the random_data's bound statebuf.
        random_r_flush(&mut self.words, &self.st);
        self.st = random_r_setstate(&self.words).expect("valid encoding");
    }
}

const SIZES: &[usize] = &[8, 16, 32, 48, 64, 96, 128, 192, 256, 512];

#[test]
fn random_r_initstate_sequence_vs_glibc() {
    let mut r = Lcg(0x1234_face_b00c_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..3000 {
        let seed = (r.next() >> 32) as u32;
        for &size in SIZES {
            let mut host = HostGen::init(seed, size);
            let mut fl = FlGen::init(seed, size);
            let host_v: Vec<i32> = (0..32).map(|_| host.draw()).collect();
            let fl_v: Vec<i32> = (0..32).map(|_| fl.draw()).collect();
            compared += 1;
            if host_v != fl_v && divs.len() < 20 {
                let idx = fl_v.iter().zip(&host_v).position(|(a, b)| a != b).unwrap_or(0);
                divs.push(format!(
                    "seed={seed} size={size}: first diff at call {idx}\n    fl   ={:?}\n    glibc={:?}",
                    &fl_v[idx..(idx + 4).min(fl_v.len())],
                    &host_v[idx..(idx + 4).min(host_v.len())],
                ));
            }
        }
    }
    assert!(
        divs.is_empty(),
        "random_r/initstate_r diverged on {} cases (showing up to 20):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("random_r initstate fuzz: {compared} comparisons, 0 divergences vs host glibc");
}

#[test]
fn srandom_r_reseed_and_setstate_r_vs_glibc() {
    let mut r = Lcg(0xfeed_0042_dead_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..2000 {
        let seed = (r.next() >> 32) as u32;
        let reseed = (r.next() >> 32) as u32;
        for &size in SIZES {
            let mut host = HostGen::init(seed, size);
            let mut fl = FlGen::init(seed, size);

            // Draw a few, reseed mid-stream, draw, then setstate_r (resets the
            // rear cursor to the encoded position) and draw again.
            let warm = (r.next() % 8) as usize;
            for _ in 0..warm {
                host.draw();
                fl.draw();
            }
            host.reseed(reseed);
            fl.reseed(reseed);
            let h1: Vec<i32> = (0..8).map(|_| host.draw()).collect();
            let f1: Vec<i32> = (0..8).map(|_| fl.draw()).collect();

            host.setstate();
            fl.setstate();
            let h2: Vec<i32> = (0..8).map(|_| host.draw()).collect();
            let f2: Vec<i32> = (0..8).map(|_| fl.draw()).collect();

            compared += 1;
            if h1 != f1 && divs.len() < 20 {
                divs.push(format!(
                    "[srandom_r] seed={seed} reseed={reseed} size={size} warm={warm}\n    fl   ={f1:?}\n    glibc={h1:?}"
                ));
            } else if h2 != f2 && divs.len() < 20 {
                divs.push(format!(
                    "[setstate_r] seed={seed} reseed={reseed} size={size} warm={warm}\n    fl   ={f2:?}\n    glibc={h2:?}"
                ));
            }
        }
    }
    assert!(
        divs.is_empty(),
        "srandom_r/setstate_r diverged on {} cases (showing up to 20):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("srandom_r/setstate_r fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
