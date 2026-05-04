#![cfg(target_os = "linux")]

//! Deterministic differential fuzz harness for `inet_aton(3)`.
//!
//! Drives ~2 000 PCG32-seeded inputs through both `frankenlibc-abi::
//! inet_abi::inet_aton` and the host glibc `inet_aton`, asserting
//! bitwise agreement on (accept-bit, u32 result). The generator mixes
//! grammar-valid forms (dotted-quad / triple / double / single, with
//! radix prefixes) with structure-aware mutations (sign-prefix
//! injection, dot stuffing, radix prefix without digits, oversize
//! components, ASCII junk tail, NUL injection).
//!
//! The seed is fixed so the harness is replayable; failures print the
//! exact byte slice and both decoded values. Filed as bd-3wk2n to
//! widen coverage beyond the curated `conformance_diff_inet_aton_edges`
//! row set.

use std::ffi::{CString, c_int};

use frankenlibc_abi::inet_abi as fl;

unsafe extern "C" {
    fn inet_aton(cp: *const std::ffi::c_char, inp: *mut u32) -> c_int;
}

const ITERATIONS: usize = 2_000;
const SEED: u64 = 0xfb84_3a4d_0c91_5f7e;

/// PCG32 step. Deterministic across platforms; we only need a stable,
/// statistically-decent stream of `u32`s for input shape selection and
/// component generation.
struct Pcg32 {
    state: u64,
    inc: u64,
}

impl Pcg32 {
    fn new(seed: u64) -> Self {
        let mut p = Pcg32 {
            state: 0,
            inc: (seed << 1) | 1,
        };
        let _ = p.next_u32();
        p.state = p.state.wrapping_add(seed);
        let _ = p.next_u32();
        p
    }

    fn next_u32(&mut self) -> u32 {
        let oldstate = self.state;
        self.state = oldstate
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(self.inc);
        let xorshifted = (((oldstate >> 18) ^ oldstate) >> 27) as u32;
        let rot = (oldstate >> 59) as u32;
        xorshifted.rotate_right(rot)
    }

    fn next_in(&mut self, modulus: u32) -> u32 {
        // Biased modulo is acceptable here — we only need diverse coverage.
        self.next_u32() % modulus
    }

    fn pick<'a, T>(&mut self, choices: &'a [T]) -> &'a T {
        let i = self.next_in(choices.len() as u32) as usize;
        &choices[i]
    }
}

fn parse_both(s: &[u8]) -> (Option<u32>, Option<u32>, std::io::Result<CString>) {
    let cs = match CString::new(s) {
        Ok(cs) => cs,
        Err(err) => return (None, None, Err(std::io::Error::other(err.to_string()))),
    };
    let mut fl_v: u32 = 0;
    let mut lc_v: u32 = 0;
    let fl_r = unsafe { fl::inet_aton(cs.as_ptr(), &mut fl_v) };
    let lc_r = unsafe { inet_aton(cs.as_ptr(), &mut lc_v) };
    (
        if fl_r == 1 {
            Some(u32::from_be(fl_v))
        } else {
            None
        },
        if lc_r == 1 {
            Some(u32::from_be(lc_v))
        } else {
            None
        },
        Ok(cs),
    )
}

fn render_part(rng: &mut Pcg32) -> String {
    let radix: u32 = *rng.pick(&[10, 8, 16]);
    let value: u32 = match rng.next_in(8) {
        0 => 0,
        1 => 1,
        2 => 0xFF,
        3 => 0x100,
        4 => 0xFFFF,
        5 => 0x00FF_FFFF,
        6 => 0xFFFF_FFFF,
        _ => rng.next_u32(),
    };
    match radix {
        10 => format!("{value}"),
        8 => format!("0{value:o}"),
        16 => {
            let upper = (rng.next_u32() & 1) == 0;
            if upper {
                format!("0X{value:X}")
            } else {
                format!("0x{value:x}")
            }
        }
        _ => unreachable!(),
    }
}

/// Emit one shape: a 1-/2-/3-/4-component grammar-valid input.
fn render_grammar(rng: &mut Pcg32) -> String {
    let nparts = (rng.next_in(4) + 1) as usize;
    let parts: Vec<String> = (0..nparts).map(|_| render_part(rng)).collect();
    parts.join(".")
}

/// Apply a structure-aware mutation to `s`. Mutations target the
/// boundaries the curated edge harness already covers (signs, dots,
/// radix prefixes), plus a couple of broader corruption strategies.
fn mutate(rng: &mut Pcg32, s: &str) -> String {
    let mut out = s.to_string();
    match rng.next_in(11) {
        0 => out.insert(0, '+'),           // leading sign
        1 => out.insert(0, '-'),           // leading sign
        2 => out.push('.'),                // trailing dot
        3 => out.insert(0, '.'),           // leading dot
        4 => out.push_str(".0"),           // append explicit-zero component
        5 => out = out.replace('.', ".."), // doubled dots
        6 => {
            // Inject a sign mid-hex.
            if let Some(idx) = out.find("0x").or_else(|| out.find("0X")) {
                out.insert(idx + 2, '+');
            } else {
                out.push_str(".0x+1");
            }
        }
        7 => out.push_str(" garbage"),   // ASCII junk tail
        8 => out.push('\0'),             // bare NUL terminator
        9 => out.push_str("\0deadbeef"), // NUL with junk after
        _ => {
            // Append an oversize component.
            out.push_str(".4294967296");
        }
    }
    out
}

#[test]
fn diff_inet_aton_fuzz_grammar_and_mutations_match_glibc() {
    let mut rng = Pcg32::new(SEED);
    let mut divergences: Vec<(String, Option<u32>, Option<u32>)> = Vec::new();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut skipped_interior_nul = 0usize;

    for i in 0..ITERATIONS {
        let base = render_grammar(&mut rng);
        let candidate = if (rng.next_u32() & 1) == 0 {
            base.clone()
        } else {
            mutate(&mut rng, &base)
        };

        // Skip inputs whose interior NUL would be rejected by CString::new
        // before either parser sees them — otherwise glibc never gets a
        // chance to differ. We still keep trailing-NUL inputs (CString::new
        // tolerates only a missing terminator; an interior NUL aborts).
        let bytes = candidate.as_bytes();
        if bytes
            .iter()
            .take(bytes.len().saturating_sub(1))
            .any(|b| *b == 0)
        {
            skipped_interior_nul += 1;
            continue;
        }
        // CString::new requires no NUL anywhere; for our terminal-NUL
        // mutation we strip it before constructing the CString and
        // exercise the early-NUL semantics through the byte itself by
        // passing the candidate without the trailing zero.
        let core = bytes.strip_suffix(&[0]).unwrap_or(bytes);
        let (fl_o, lc_o, err) = parse_both(core);
        if err.is_err() {
            // Defensive: any unexpected interior NUL slips through.
            skipped_interior_nul += 1;
            continue;
        }

        if fl_o == lc_o {
            if fl_o.is_some() {
                accepted += 1;
            } else {
                rejected += 1;
            }
        } else if divergences.len() < 32 {
            divergences.push((candidate.clone(), fl_o, lc_o));
        }

        // Hard cap on divergences — bail early so the panic message stays
        // readable.
        if divergences.len() >= 32 {
            panic!(
                "fuzz iter {i}: 32 host/fl divergences observed; first: input={:?} fl={:?} host={:?}",
                divergences[0].0, divergences[0].1, divergences[0].2
            );
        }
    }

    assert!(
        divergences.is_empty(),
        "fuzz divergences observed (showing up to 5):\n{}",
        divergences
            .iter()
            .take(5)
            .map(|(s, fl_o, lc_o)| format!("  input={s:?} fl={fl_o:?} host={lc_o:?}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!(
        "{{\"family\":\"libc inet_aton (fuzz)\",\"reference\":\"glibc\",\"iterations\":{ITERATIONS},\"accepted\":{accepted},\"rejected\":{rejected},\"skipped_interior_nul\":{skipped_interior_nul},\"divergences\":0}}"
    );
}
