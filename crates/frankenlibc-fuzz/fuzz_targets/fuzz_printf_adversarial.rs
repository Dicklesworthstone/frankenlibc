#![no_main]
//! Adversarial fuzz target for FrankenLibC printf: attacker-controlled
//! format strings with width/precision chaos, positional abuse, %n
//! refusal, and buffer-exhaustion probes.
//!
//! Unlike `fuzz_printf` (which covers correctness of well-formed
//! specifiers against structured args), this target exercises security
//! invariants for formats that a remote attacker could supply.
//! Against CVE-class bugs it checks:
//!
//! - CVE-2023-25139 style: `%n` within width-modifier chains must either
//!   be honored with a valid pointer or refused, never write to garbage.
//! - CVE-2010-0296 style: deeply nested positional refs and `%*.*` chains
//!   must not recurse unbounded or exhaust the stack.
//! - Integer overflow in parsed width (`%2147483648d`): the numeric
//!   parser must saturate/reject without UB.
//! - Off-by-one in buffer truncation: guard-byte sentinels on either
//!   side of the destination must remain untouched after every call.
//!
//! Safety contract: because variadic dispatch to a C `snprintf` with an
//! attacker-controlled format is UB at the language level, this target
//! keeps the format string under fuzzer control **only** when it is
//! routed through the Rust parsing entrypoints (`parse_format_string`,
//! `parse_format_spec`). ABI entrypoints are always invoked with
//! literal compile-time format strings whose specifier types exactly
//! match the args the fuzzer provides; the fuzzer controls the
//! *numeric* inputs (width/precision magnitudes, ptr values, etc.).
//!
//! Bead: bd-drs1c

use std::ffi::{CString, c_char, c_int};
use std::sync::Once;

use arbitrary::{Arbitrary, Unstructured};
use frankenlibc_abi::stdio_abi::snprintf;
use frankenlibc_core::stdio::printf::{parse_format_spec, parse_format_string};
use libfuzzer_sys::fuzz_target;

/// Guard-byte sentinel appended before and after every writable buffer
/// so we detect the narrowest off-by-one without relying on ASAN.
const GUARD_BYTES: usize = 64;
/// 0xFD is a distinctive pattern neither all-ones nor all-zeros; a
/// single off-by-one write leaves a visible hole.
const GUARD_BYTE: u8 = 0xFD;
/// Hard cap on format-byte length to keep the fuzzer from exploring
/// arbitrary memory-consumption corners — the format-string CVEs we
/// care about live in the parser, not in gigantic buffers.
const MAX_FORMAT_BYTES: usize = 1024;
/// Cap on destination size the fuzzer may pick.
const MAX_DST_SIZE: usize = 512;

#[derive(Debug, Arbitrary)]
struct PrintfAdversarialFuzzInput {
    /// Raw format bytes — may contain arbitrary `%` patterns.
    format: Vec<u8>,
    /// Padded arg vector for typed ABI calls.
    int_args: [i32; 8],
    /// Attacker-chosen width/precision magnitudes for the `%*.*` path.
    width_a: i32,
    width_b: i32,
    precision_a: i32,
    precision_b: i32,
    /// Destination buffer size the attacker convinces the caller to pass.
    dst_size: u16,
    /// Archetype selector.
    op: u8,
    /// Case selector for the fixed overflow-width format table.
    overflow_case: u8,
    /// String argument for `%s` archetypes.
    str_arg: Vec<u8>,
}

fn directive_input(op: u8, payload: &[u8]) -> PrintfAdversarialFuzzInput {
    let payload = trim_seed_newline(payload);
    let mut format = payload.to_vec();
    format.truncate(MAX_FORMAT_BYTES);
    let mut str_arg = payload.to_vec();
    str_arg.truncate(MAX_FORMAT_BYTES);
    let dst_size = u16::try_from(payload.len().clamp(1, MAX_DST_SIZE))
        .unwrap_or(512)
        .max(16);

    PrintfAdversarialFuzzInput {
        format,
        int_args: [0, 1, -1, i32::MAX, i32::MIN, 42, -42, 0x5a5a],
        width_a: i32::MAX,
        width_b: -1024,
        precision_a: i32::MAX,
        precision_b: 64,
        dst_size,
        op,
        overflow_case: 0,
        str_arg,
    }
}

fn input_from_directive_seed(data: &[u8]) -> Option<PrintfAdversarialFuzzInput> {
    if let Some(payload) = data.strip_prefix(b"parser:") {
        Some(directive_input(0, payload))
    } else if let Some(payload) = data.strip_prefix(b"width:") {
        Some(directive_input(1, payload))
    } else if let Some(payload) = data.strip_prefix(b"bracket-int:") {
        Some(directive_input(2, payload))
    } else if let Some(payload) = data.strip_prefix(b"bracket-str:") {
        Some(directive_input(3, payload))
    } else if let Some(payload) = data.strip_prefix(b"percent-n:") {
        Some(directive_input(4, payload))
    } else if let Some(payload) = data.strip_prefix(b"positional:") {
        Some(directive_input(6, payload))
    } else if let Some(payload) = data.strip_prefix(b"storm:") {
        Some(directive_input(7, payload))
    } else if let Some(payload) = data.strip_prefix(b"overflow0:") {
        let mut input = directive_input(5, payload);
        input.overflow_case = 0;
        Some(input)
    } else if let Some(payload) = data.strip_prefix(b"overflow1:") {
        let mut input = directive_input(5, payload);
        input.overflow_case = 1;
        Some(input)
    } else if let Some(payload) = data.strip_prefix(b"overflow2:") {
        let mut input = directive_input(5, payload);
        input.overflow_case = 2;
        Some(input)
    } else if let Some(payload) = data.strip_prefix(b"overflow3:") {
        let mut input = directive_input(5, payload);
        input.overflow_case = 3;
        Some(input)
    } else {
        None
    }
}

fn trim_seed_newline(payload: &[u8]) -> &[u8] {
    payload
        .strip_suffix(b"\r\n")
        .or_else(|| payload.strip_suffix(b"\n"))
        .unwrap_or(payload)
}

fn init_hardened_printf_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: the fuzz target sets the process mode once, before any ABI
        // entrypoint is exercised, and never mutates it again.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn make_dst(size: usize) -> Vec<u8> {
    let mut v = vec![GUARD_BYTE; size + 2 * GUARD_BYTES];
    // Make sure even index 0 of the dst region is initialized to GUARD_BYTE so
    // that a spurious write of 0 is detectable.
    for slot in &mut v[GUARD_BYTES..GUARD_BYTES + size] {
        *slot = GUARD_BYTE;
    }
    v
}

fn check_guards(buf: &[u8], dst_size: usize) {
    for (i, &b) in buf[..GUARD_BYTES].iter().enumerate() {
        assert_eq!(
            b, GUARD_BYTE,
            "underflow guard corrupted at byte {i} (dst_size={dst_size})"
        );
    }
    for (i, &b) in buf[GUARD_BYTES + dst_size..].iter().enumerate() {
        assert_eq!(
            b, GUARD_BYTE,
            "overflow guard corrupted at byte {i} past dst_size={dst_size}"
        );
    }
}

fn sanitize_c_string(bytes: &[u8], limit: usize) -> CString {
    let sanitized: Vec<u8> = bytes
        .iter()
        .copied()
        .take(limit)
        .map(|b| if b == 0 { b'?' } else { b })
        .collect();
    CString::new(sanitized).expect("NULs replaced above")
}

/// Archetype 0: parser robustness — feed arbitrary bytes to
/// `parse_format_string` and `parse_format_spec` and assert only that
/// they terminate, produce a bounded segment count, and do not panic.
fn adv_parser_panic(input: &PrintfAdversarialFuzzInput) {
    let segments = parse_format_string(&input.format);
    // Segment count is bounded by input length plus the number of '%'
    // literal splits; a sane parser cannot invent new segments out of
    // thin air.
    assert!(segments.len() <= input.format.len() + 1);

    // parse_format_spec also needs to terminate on any byte sequence
    // (the caller feeds it whatever follows a '%').
    if let Some((_spec, consumed)) = parse_format_spec(&input.format) {
        assert!(consumed <= input.format.len());
    }
}

/// Archetype 1: huge attacker-chosen width via the `%*d` dynamic-width
/// path. The format literal is safe (`"%*d"`), the attacker controls
/// the width int and value.
fn adv_huge_dynamic_width(input: &PrintfAdversarialFuzzInput) {
    let dst_size = (input.dst_size as usize % MAX_DST_SIZE).max(1);
    let mut buf = make_dst(dst_size);
    let rc = unsafe {
        snprintf(
            buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
            dst_size,
            c"%*d".as_ptr(),
            input.width_a as c_int,
            input.int_args[0] as c_int,
        )
    };
    assert!(
        rc >= -1,
        "snprintf %*d must return -1 on error or a non-negative length"
    );
    check_guards(&buf, dst_size);
    if rc >= 0 && dst_size > 0 {
        assert_eq!(
            buf[GUARD_BYTES + dst_size - 1],
            0,
            "snprintf must NUL-terminate at dst_size-1"
        );
    }
}

/// Archetype 2: `%*.*` bracket-bomb — attacker picks both the width
/// and precision magnitudes; tests that the hot parse path does not
/// recurse on extreme parameters.
fn adv_bracket_bomb(input: &PrintfAdversarialFuzzInput) {
    let dst_size = (input.dst_size as usize % MAX_DST_SIZE).max(1);
    let mut buf = make_dst(dst_size);
    let rc = unsafe {
        snprintf(
            buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
            dst_size,
            c"%*.*d".as_ptr(),
            input.width_a as c_int,
            input.precision_a as c_int,
            input.int_args[0] as c_int,
        )
    };
    assert!(rc >= -1);
    check_guards(&buf, dst_size);
    if rc >= 0 && dst_size > 0 {
        assert_eq!(buf[GUARD_BYTES + dst_size - 1], 0);
    }
}

/// Archetype 3: bracketed `%*.*s` with both width and precision dynamic
/// plus an attacker-supplied string; exercises the string-truncation
/// path under width+precision chaos.
fn adv_bracket_bomb_string(input: &PrintfAdversarialFuzzInput) {
    let dst_size = (input.dst_size as usize % MAX_DST_SIZE).max(1);
    let mut buf = make_dst(dst_size);
    let s = sanitize_c_string(&input.str_arg, 256);
    let rc = unsafe {
        snprintf(
            buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
            dst_size,
            c"%*.*s".as_ptr(),
            input.width_b as c_int,
            input.precision_b as c_int,
            s.as_ptr(),
        )
    };
    assert!(rc >= -1);
    check_guards(&buf, dst_size);
    if rc >= 0 && dst_size > 0 {
        assert_eq!(buf[GUARD_BYTES + dst_size - 1], 0);
    }
}

/// Archetype 4: `%n` refusal path. Under hardened mode (set globally
/// in this target), `%n` must either refuse the directive entirely or
/// write only to the pointer the caller supplied — it must never crash
/// or write to garbage.
fn adv_percent_n_refusal(input: &PrintfAdversarialFuzzInput) {
    let dst_size = (input.dst_size as usize % MAX_DST_SIZE).max(1);
    let mut buf = make_dst(dst_size);
    let mut count: c_int = -1;
    // Literal format — attacker cannot add a stray %n here; what we're
    // testing is hardened mode's handling of *a legitimate* %n call.
    let rc = unsafe {
        snprintf(
            buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
            dst_size,
            c"ab%nc".as_ptr(),
            &mut count,
        )
    };
    // `rc < 0` means hardened mode refused — acceptable.
    // `rc >= 0` means it honored the call — then the count must match.
    assert!(rc >= -1);
    check_guards(&buf, dst_size);
    if rc >= 0 {
        assert!(
            count == 2 || count == -1,
            "%n under hardened mode must be honored (count=2) or refused (count=-1); got {count}"
        );
    }
}

/// Archetype 5: integer-overflow width encoded as a decimal literal
/// inside a compile-time format string. We pick the string from a
/// small fixed set indexed by the fuzzer so we never pass
/// attacker-controlled variadic args to `snprintf`.
fn adv_overflow_width_literal(input: &PrintfAdversarialFuzzInput) {
    let dst_size = (input.dst_size as usize % MAX_DST_SIZE).max(1);
    let mut buf = make_dst(dst_size);
    // Each of these exercises a width larger than i32 / usize on 32-bit
    // hosts; the parser must clamp or refuse rather than wrap.
    // Do not reuse `op`: this function is only reached when `op % 8 == 5`,
    // which pins `op & 0b11` to one value and leaves most cases unreachable.
    let rc = match input.overflow_case & 0b11 {
        0 => unsafe {
            snprintf(
                buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
                dst_size,
                c"%2147483648d".as_ptr(),
                input.int_args[0] as c_int,
            )
        },
        1 => unsafe {
            snprintf(
                buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
                dst_size,
                c"%99999999999d".as_ptr(),
                input.int_args[0] as c_int,
            )
        },
        2 => unsafe {
            snprintf(
                buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
                dst_size,
                c"%.99999999999d".as_ptr(),
                input.int_args[0] as c_int,
            )
        },
        _ => unsafe {
            snprintf(
                buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
                dst_size,
                c"%9999999999.9999999999d".as_ptr(),
                input.int_args[0] as c_int,
            )
        },
    };
    assert!(rc >= -1);
    check_guards(&buf, dst_size);
    if rc >= 0 && dst_size > 0 {
        assert_eq!(buf[GUARD_BYTES + dst_size - 1], 0);
    }
}

/// Archetype 6: positional-arg-out-of-range. We pass one int, but use
/// a format requiring arg 99; the implementation must return an error
/// rather than reading past the supplied varargs.
fn adv_positional_out_of_range(input: &PrintfAdversarialFuzzInput) {
    let dst_size = (input.dst_size as usize % MAX_DST_SIZE).max(1);
    let mut buf = make_dst(dst_size);
    let rc = unsafe {
        snprintf(
            buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>(),
            dst_size,
            c"%99$d".as_ptr(),
            input.int_args[0] as c_int,
        )
    };
    // The only guarantee is that the call does not crash and keeps the
    // guards intact. Implementations are free to either refuse (rc<0)
    // or emit something best-effort.
    assert!(rc >= -1);
    check_guards(&buf, dst_size);
}

/// Archetype 7: parser fed with a format string that is purely `%`
/// characters, a stress test against unbalanced-specifier paths.
fn adv_percent_storm(input: &PrintfAdversarialFuzzInput) {
    let len = (input.dst_size as usize % 256).max(1);
    let bomb: Vec<u8> = (0..len).map(|_| b'%').collect();
    let segments = parse_format_string(&bomb);
    assert!(segments.len() <= bomb.len() + 1);
}

fn run_input(input: PrintfAdversarialFuzzInput) {
    if input.format.len() > MAX_FORMAT_BYTES || input.str_arg.len() > MAX_FORMAT_BYTES {
        return;
    }

    init_hardened_printf_mode();

    match input.op % 8 {
        0 => adv_parser_panic(&input),
        1 => adv_huge_dynamic_width(&input),
        2 => adv_bracket_bomb(&input),
        3 => adv_bracket_bomb_string(&input),
        4 => adv_percent_n_refusal(&input),
        5 => adv_overflow_width_literal(&input),
        6 => adv_positional_out_of_range(&input),
        7 => adv_percent_storm(&input),
        _ => unreachable!(),
    }
}

fuzz_target!(|data: &[u8]| {
    if let Some(input) = input_from_directive_seed(data) {
        run_input(input);
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let Ok(input) = PrintfAdversarialFuzzInput::arbitrary(&mut unstructured) else {
        return;
    };

    run_input(input);
});
