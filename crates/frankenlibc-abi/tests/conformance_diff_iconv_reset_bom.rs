#![cfg(target_os = "linux")]

//! Differential gate: what a `iconv(cd, NULL, NULL, ...)` reset call writes.
//!
//! POSIX says a reset "returns the conversion state to the initial state" and,
//! if an output buffer is supplied, stores the sequence needed to do so. It does
//! NOT say what that sequence is, and the two families answer differently:
//!
//!   * **Stateful destinations** (ISO-2022-*, the EBCDIC DBCS pages, UTF-7)
//!     really do emit a return-to-initial-state sequence — `ESC ( B` for
//!     ISO-2022-JP, SI for the shift-out codecs — whenever the stream is not
//!     already in its initial state.
//!   * **The BOM-carrying Unicode destinations** (UTF-16, UTF-32, UNICODE) emit
//!     **nothing**. glibc holds the pending BOM back and writes it in front of
//!     the first converted character instead.
//!
//! fl had the first half right and the second half wrong (bd-xh08pf). It emitted
//! the BOM on the reset call, and — worse — failed the reset with `E2BIG` when
//! fewer than the BOM's bytes were free, on a call glibc treats as a guaranteed
//! no-op for these encodings. The concatenated output byte stream came out the
//! same either way, which is why no existing gate saw it: the only observable is
//! `*outbytesleft` after the reset, which is exactly what a caller sizing or
//! chunking its buffer reads back.
//!
//! The divergence was found by burning down a dead inline `#[cfg(test)]` block in
//! `iconv_abi.rs` whose `iconv_null_inbuf_emits_bom_for_utf32` asserted fl's
//! behaviour — a test that had never compiled, pinning the wrong contract.
//!
//! ## Oracle
//!
//! The host arm is resolved through `common/dlsym_oracle`, not a link-time
//! `extern` block. fl exports `iconv`/`iconv_open`/`iconv_close` under
//! `#[no_mangle]` in release builds, so a link-time declaration in a release
//! test binary binds to **fl**, and the gate would compare fl against itself and
//! pass unconditionally (bd-v0388t, bd-0q7ba9). `host_fn` refuses that by
//! asserting the resolved address differs from fl's own definition.

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::iconv_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

const ICONV_ERROR: usize = usize::MAX;

type IconvOpenFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type IconvFn = unsafe extern "C" fn(
    *mut c_void,
    *mut *mut c_char,
    *mut usize,
    *mut *mut c_char,
    *mut usize,
) -> usize;
type IconvCloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type ErrnoLocationFn = unsafe extern "C" fn() -> *mut c_int;

/// One arm of the comparison: an implementation plus its own errno slot.
///
/// The errno slot is part of the arm because fl and glibc keep separate errno
/// storage. Reading fl's `__errno_location` after calling the host would report
/// whatever fl last set — a comparison of one implementation against itself, in
/// the one place (the E2BIG question) where errno is the whole point.
struct Arm {
    name: &'static str,
    open: IconvOpenFn,
    convert: IconvFn,
    close: IconvCloseFn,
    errno_location: ErrnoLocationFn,
}

fn fl_arm() -> Arm {
    Arm {
        name: "fl",
        open: fl::iconv_open,
        convert: fl::iconv,
        close: fl::iconv_close,
        errno_location: frankenlibc_abi::errno_abi::__errno_location,
    }
}

fn glibc_arm() -> Arm {
    // SAFETY: every signature below matches the C declaration of the symbol.
    unsafe {
        Arm {
            name: "glibc",
            open: dlsym_oracle::host_fn(c"iconv_open", fl::iconv_open as *const ()),
            convert: dlsym_oracle::host_fn(c"iconv", fl::iconv as *const ()),
            close: dlsym_oracle::host_fn(c"iconv_close", fl::iconv_close as *const ()),
            errno_location: dlsym_oracle::host_fn(
                c"__errno_location",
                frankenlibc_abi::errno_abi::__errno_location as *const (),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Step {
    /// `iconv(cd, NULL, NULL, &out, &out_left)` — the reset call under test.
    Reset,
    /// An ordinary conversion of a byte slice.
    Convert(&'static [u8]),
}

/// What one step did, in the terms a C caller can actually observe.
#[derive(PartialEq, Eq, Debug)]
struct StepOutcome {
    errored: bool,
    errno: c_int,
    /// Bytes this step took out of the shared output buffer — i.e. how far
    /// `*outbytesleft` moved. This is the field the BOM bug moved.
    out_consumed: usize,
    in_left: usize,
}

#[derive(PartialEq, Eq, Debug)]
struct RunOutcome {
    steps: Vec<StepOutcome>,
    written: Vec<u8>,
}

/// Drive `steps` through one implementation, sharing a single output buffer of
/// `out_len` bytes across them exactly as a streaming caller would.
///
/// Returns `None` if `iconv_open` refused the pair, which the caller compares
/// across arms before looking at anything else.
fn run(
    arm: &Arm,
    tocode: &str,
    fromcode: &str,
    out_len: usize,
    steps: &[Step],
) -> Option<RunOutcome> {
    let to = CString::new(tocode).unwrap();
    let from = CString::new(fromcode).unwrap();
    // SAFETY: both names are NUL-terminated and outlive the call.
    let cd = unsafe { (arm.open)(to.as_ptr(), from.as_ptr()) };
    if cd.is_null() || cd as usize == ICONV_ERROR {
        return None;
    }

    let mut out = vec![0u8; out_len];
    let mut out_ptr = out.as_mut_ptr().cast::<c_char>();
    let mut out_left = out_len;
    let mut outcomes = Vec::with_capacity(steps.len());

    for step in steps {
        let before = out_left;
        // SAFETY: the errno slot belongs to the same implementation as `convert`.
        unsafe { *(arm.errno_location)() = 0 };
        let (rc, in_left) = match step {
            Step::Reset => {
                // SAFETY: a NULL inbuf is the documented reset form; the output
                // pointers address `out`, which outlives the call.
                let rc = unsafe {
                    (arm.convert)(
                        cd,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        &mut out_ptr,
                        &mut out_left,
                    )
                };
                (rc, 0)
            }
            Step::Convert(src) => {
                let mut input = src.to_vec();
                let mut in_ptr = input.as_mut_ptr().cast::<c_char>();
                let mut in_left = input.len();
                // SAFETY: all four pointers address live locals for the call.
                let rc = unsafe {
                    (arm.convert)(cd, &mut in_ptr, &mut in_left, &mut out_ptr, &mut out_left)
                };
                (rc, in_left)
            }
        };
        // SAFETY: same slot as the seed above.
        let errno = unsafe { *(arm.errno_location)() };
        outcomes.push(StepOutcome {
            errored: rc == ICONV_ERROR,
            // An errno is only meaningful on failure; glibc leaves it alone on
            // success and fl need not match a value nobody may read.
            errno: if rc == ICONV_ERROR { errno } else { 0 },
            out_consumed: before - out_left,
            in_left,
        });
    }

    let written = out_len - out_left;
    // SAFETY: `cd` came from this arm's own `open` and is closed exactly once.
    assert_eq!(
        unsafe { (arm.close)(cd) },
        0,
        "{} iconv_close failed",
        arm.name
    );
    out.truncate(written);
    Some(RunOutcome {
        steps: outcomes,
        written: out,
    })
}

struct Case {
    tocode: &'static str,
    fromcode: &'static str,
    out_len: usize,
    steps: &'static [Step],
}

const RESET_ONLY: &[Step] = &[Step::Reset];
const RESET_TWICE_THEN_CONVERT: &[Step] = &[Step::Reset, Step::Reset, Step::Convert(b"AB")];
const RESET_THEN_CONVERT: &[Step] = &[Step::Reset, Step::Convert(b"A")];
const CONVERT_THEN_RESET: &[Step] = &[Step::Convert(b"A"), Step::Reset];
/// U+3042 HIRAGANA LETTER A — forces ISO-2022-JP out of its initial G0
/// designation, so the following reset has a real sequence to emit.
const CONVERT_KANA_THEN_RESET: &[Step] = &[Step::Convert("\u{3042}".as_bytes()), Step::Reset];

/// The BOM-carrying Unicode destinations: a reset must write nothing at all,
/// whatever the output buffer looks like, and the BOM must survive to the first
/// conversion.
const UNICODE_CASES: &[Case] = &[
    Case {
        tocode: "UTF-32",
        fromcode: "UTF-8",
        out_len: 16,
        steps: RESET_ONLY,
    },
    // Fewer bytes free than the BOM needs. fl used to return E2BIG here.
    Case {
        tocode: "UTF-32",
        fromcode: "UTF-8",
        out_len: 3,
        steps: RESET_ONLY,
    },
    // No bytes free at all.
    Case {
        tocode: "UTF-32",
        fromcode: "UTF-8",
        out_len: 0,
        steps: RESET_ONLY,
    },
    Case {
        tocode: "UTF-32",
        fromcode: "UTF-8",
        out_len: 32,
        steps: RESET_TWICE_THEN_CONVERT,
    },
    Case {
        tocode: "UTF-16",
        fromcode: "UTF-8",
        out_len: 16,
        steps: RESET_ONLY,
    },
    Case {
        tocode: "UTF-16",
        fromcode: "UTF-8",
        out_len: 1,
        steps: RESET_ONLY,
    },
    Case {
        tocode: "UTF-16",
        fromcode: "UTF-8",
        out_len: 32,
        steps: RESET_THEN_CONVERT,
    },
    Case {
        tocode: "UTF-16",
        fromcode: "UTF-8",
        out_len: 32,
        steps: CONVERT_THEN_RESET,
    },
    // UCS-2 is bare little-endian BMP UTF-16 with NO BOM in glibc; it is here so
    // a fix that suppressed the BOM everywhere instead of deferring it would
    // still have to keep this case's byte stream identical.
    Case {
        tocode: "UCS-2",
        fromcode: "UTF-8",
        out_len: 16,
        steps: RESET_THEN_CONVERT,
    },
    Case {
        tocode: "UTF-16LE",
        fromcode: "UTF-8",
        out_len: 16,
        steps: RESET_THEN_CONVERT,
    },
    Case {
        tocode: "UTF-8",
        fromcode: "UTF-8",
        out_len: 16,
        steps: RESET_ONLY,
    },
];

/// The other half of the split: destinations that DO emit on reset. These are
/// the control group — a fix that turned every reset into a no-op would pass
/// `reset_on_unicode_targets_matches_glibc` and fail here.
const STATEFUL_CASES: &[Case] = &[
    Case {
        tocode: "ISO-2022-JP",
        fromcode: "UTF-8",
        out_len: 32,
        steps: CONVERT_KANA_THEN_RESET,
    },
    // Already in the initial state, so even a stateful destination writes nothing.
    Case {
        tocode: "ISO-2022-JP",
        fromcode: "UTF-8",
        out_len: 32,
        steps: RESET_ONLY,
    },
];

fn compare(cases: &[Case]) -> Vec<String> {
    let fl = fl_arm();
    let host = glibc_arm();
    let mut divergences = Vec::new();

    for case in cases {
        let label = format!(
            "{} -> {} out_len={} steps={:?}",
            case.fromcode, case.tocode, case.out_len, case.steps
        );
        let fl_run = run(&fl, case.tocode, case.fromcode, case.out_len, case.steps);
        let host_run = run(&host, case.tocode, case.fromcode, case.out_len, case.steps);
        match (fl_run, host_run) {
            (None, None) => {
                divergences.push(format!(
                    "{label}: NEITHER implementation could open this pair, so the \
                     case measures nothing — remove it or pick a supported codec"
                ));
            }
            (Some(_), None) | (None, Some(_)) => {
                divergences.push(format!("{label}: iconv_open succeeded on only one arm"));
            }
            (Some(f), Some(h)) => {
                if f != h {
                    divergences.push(format!("{label}\n    fl:    {f:?}\n    glibc: {h:?}"));
                }
            }
        }
    }
    divergences
}

#[test]
fn reset_on_unicode_targets_matches_glibc() {
    let divergences = compare(UNICODE_CASES);
    assert!(
        divergences.is_empty(),
        "{} of {} UTF-16/UTF-32/UCS-2 reset cases diverge from live glibc:\n  {}",
        divergences.len(),
        UNICODE_CASES.len(),
        divergences.join("\n  ")
    );
}

#[test]
fn reset_on_stateful_targets_still_emits_the_return_sequence() {
    let divergences = compare(STATEFUL_CASES);
    assert!(
        divergences.is_empty(),
        "{} of {} ISO-2022 reset cases diverge from live glibc:\n  {}",
        divergences.len(),
        STATEFUL_CASES.len(),
        divergences.join("\n  ")
    );
}

/// The control group has to actually be a control: if the ISO-2022-JP reset
/// wrote nothing, the test above would be satisfied by the same "no-op" bug it
/// exists to rule out. Assert the non-empty sequence directly.
#[test]
fn the_stateful_control_group_really_does_write_on_reset() {
    let host = glibc_arm();
    let outcome = run(&host, "ISO-2022-JP", "UTF-8", 32, CONVERT_KANA_THEN_RESET)
        .expect("glibc must support ISO-2022-JP");
    let reset = &outcome.steps[1];
    assert!(
        reset.out_consumed > 0,
        "glibc wrote nothing on the ISO-2022-JP reset, so STATEFUL_CASES is not a \
         control group any more: {outcome:?}"
    );
    assert!(
        outcome.written.ends_with(&[0x1B, 0x28, 0x42]),
        "expected a trailing `ESC ( B` return-to-ASCII, got {:02x?}",
        outcome.written
    );
}
