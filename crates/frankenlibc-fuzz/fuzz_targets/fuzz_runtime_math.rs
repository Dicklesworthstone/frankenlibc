#![no_main]
//! Structure-aware fuzz target for the runtime math decision kernel.
//!
//! Exercises `RuntimeMathKernel::decide` and `observe_validation_result`
//! across API families, modes, contention hints, and adverse outcomes.
//! Invariants:
//! - No panics across repeated decision/observation cycles
//! - Risk bounds remain within ppm range
//! - Repair/full-validate actions always imply full validation
//!
//! Bead: bd-1oz.7

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use frankenlibc_membrane::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeMathKernel, SafetyLevel,
};

const DIRECTED_PREFIX: &[u8] = b"runtime-math:";

#[derive(Debug, Arbitrary)]
struct RuntimeMathFuzzInput {
    family: u8,
    mode: u8,
    addr_hint: u64,
    requested_bytes: u16,
    contention_hint: u16,
    cost_seed: u16,
    iterations: u8,
    adverse_mask: u32,
    is_write: bool,
    bloom_negative: bool,
}

fuzz_target!(|data: &[u8]| {
    if let Some(input) = directed_input(data) {
        fuzz_runtime_math(input);
        return;
    }

    let mut raw = Unstructured::new(data);
    let Ok(input) = RuntimeMathFuzzInput::arbitrary(&mut raw) else {
        return;
    };

    fuzz_runtime_math(input);
});

fn fuzz_runtime_math(input: RuntimeMathFuzzInput) {
    let mode = match input.mode % 3 {
        0 => SafetyLevel::Strict,
        1 => SafetyLevel::Hardened,
        _ => SafetyLevel::Off,
    };
    let _bounded_hint_len = input.addr_hint.to_le_bytes().len().min(8);
    let kernel = RuntimeMathKernel::new_for_mode(mode);
    let mirror_kernel = RuntimeMathKernel::new_for_mode(mode);
    let iterations = usize::from(input.iterations).min(15) + 1;
    let mut addr_hint = input.addr_hint as usize;

    for step in 0..iterations {
        let family = api_family((usize::from(input.family) + step) % ApiFamily::COUNT);
        let requested_bytes = usize::from(input.requested_bytes).saturating_add(step * 17);
        let ctx = RuntimeContext {
            family,
            addr_hint,
            requested_bytes,
            is_write: if step.is_multiple_of(2) {
                input.is_write
            } else {
                !input.is_write
            },
            contention_hint: input.contention_hint.wrapping_add(step as u16),
            bloom_negative: if step.is_multiple_of(3) {
                input.bloom_negative
            } else {
                !input.bloom_negative
            },
        };

        let decision = kernel.decide(mode, ctx);
        let mirror_decision = mirror_kernel.decide(mode, ctx);
        assert_eq!(
            decision.profile, mirror_decision.profile,
            "determinism: profile should be stable for identical seed context"
        );
        assert_eq!(
            decision.action, mirror_decision.action,
            "determinism: action should be stable for identical seed context"
        );
        assert!(
            decision.risk_upper_bound_ppm <= 1_000_000,
            "risk bound out of range: {}",
            decision.risk_upper_bound_ppm
        );
        match decision.action {
            MembraneAction::FullValidate | MembraneAction::Repair(_) => {
                assert!(
                    decision.requires_full_validation(),
                    "full-validation action must require full validation"
                );
            }
            MembraneAction::Allow | MembraneAction::Deny => {}
        }

        let estimated_cost_ns = 1 + (u64::from(input.cost_seed) + step as u64 * 13) % 5_000;
        let adverse = ((input.adverse_mask >> (step % 32)) & 1) == 1;
        kernel.observe_validation_result(
            mode,
            family,
            decision.profile,
            estimated_cost_ns,
            adverse,
        );
        mirror_kernel.observe_validation_result(
            mode,
            family,
            mirror_decision.profile,
            estimated_cost_ns,
            adverse,
        );

        addr_hint = addr_hint.rotate_left(5) ^ requested_bytes ^ step;
    }
}

/// Decode readable directed seeds shaped as:
///
/// ```text
/// runtime-math:<scenario>
/// mode:<strict|hardened|off>
/// family:<pointer|allocator|string_memory|...>
/// addr:<u64 decimal-or-hex>
/// bytes:<u16>
/// contention:<u16>
/// cost:<u16>
/// iterations:<u8>
/// adverse:<u32 decimal-or-hex>
/// write:<true|false>
/// bloom:<true|false>
/// ```
///
/// Header fields are optional and override scenario defaults. Legacy
/// libFuzzer corpus bytes still use the `Arbitrary` struct path.
fn directed_input(data: &[u8]) -> Option<RuntimeMathFuzzInput> {
    let rest = data.strip_prefix(DIRECTED_PREFIX)?;
    let (scenario, header) = split_once_byte(rest, b'\n').unwrap_or((rest, b""));
    let mut input = directed_defaults(scenario)?;

    for raw_line in header.split(|&byte| byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        let (key, value) = split_once_byte(line, b':')?;
        match key {
            b"mode" => input.mode = directed_mode(value)?,
            b"family" => input.family = directed_family(value)?,
            b"addr" => input.addr_hint = parse_directed_u64(value)?,
            b"bytes" => input.requested_bytes = parse_directed_u16(value)?,
            b"contention" => input.contention_hint = parse_directed_u16(value)?,
            b"cost" => input.cost_seed = parse_directed_u16(value)?,
            b"iterations" => input.iterations = parse_directed_u8(value)?,
            b"adverse" => input.adverse_mask = parse_directed_u32(value)?,
            b"write" => input.is_write = parse_directed_bool(value)?,
            b"bloom" => input.bloom_negative = parse_directed_bool(value)?,
            _ => return None,
        }
    }

    Some(input)
}

fn directed_defaults(scenario: &[u8]) -> Option<RuntimeMathFuzzInput> {
    let mut input = RuntimeMathFuzzInput {
        family: 0,
        mode: 0,
        addr_hint: 0x1000,
        requested_bytes: 64,
        contention_hint: 0,
        cost_seed: 16,
        iterations: 4,
        adverse_mask: 0,
        is_write: false,
        bloom_negative: false,
    };

    match scenario {
        b"strict_pointer" => {}
        b"hardened_locale" => {
            input.mode = 1;
            input.family = 14;
            input.addr_hint = 0x7fff_0000;
            input.requested_bytes = 256;
            input.contention_hint = 32;
        }
        b"hardened_resolver_adverse" => {
            input.mode = 1;
            input.family = 5;
            input.addr_hint = 0x2000;
            input.requested_bytes = 512;
            input.contention_hint = 128;
            input.cost_seed = 997;
            input.iterations = 14;
            input.adverse_mask = 0xaaaa_5555;
            input.bloom_negative = true;
        }
        b"off_socket_high_addr" => {
            input.mode = 2;
            input.family = 13;
            input.addr_hint = u64::MAX - 4095;
            input.requested_bytes = u16::MAX;
            input.cost_seed = u16::MAX;
            input.iterations = 8;
            input.is_write = true;
        }
        b"strict_stdio_contention" => {
            input.family = 3;
            input.addr_hint = 0x4040_4040;
            input.requested_bytes = 4096;
            input.contention_hint = u16::MAX;
            input.cost_seed = 4095;
            input.iterations = 10;
            input.is_write = true;
        }
        b"hardened_allocator_bloom_negative" => {
            input.mode = 1;
            input.family = 1;
            input.addr_hint = 0xdead_beef;
            input.requested_bytes = 128;
            input.contention_hint = 16;
            input.iterations = 6;
            input.adverse_mask = 0x11;
            input.is_write = true;
            input.bloom_negative = true;
        }
        _ => return None,
    }

    Some(input)
}

fn directed_mode(value: &[u8]) -> Option<u8> {
    match value {
        b"strict" => Some(0),
        b"hardened" => Some(1),
        b"off" => Some(2),
        _ => parse_directed_u8(value),
    }
}

fn directed_family(value: &[u8]) -> Option<u8> {
    match value {
        b"pointer" | b"pointer_validation" => Some(0),
        b"allocator" => Some(1),
        b"string" | b"string_memory" => Some(2),
        b"stdio" => Some(3),
        b"threading" => Some(4),
        b"resolver" => Some(5),
        b"math" | b"math_fenv" => Some(6),
        b"loader" => Some(7),
        b"stdlib" => Some(8),
        b"ctype" => Some(9),
        b"time" => Some(10),
        b"signal" => Some(11),
        b"io" | b"io_fd" => Some(12),
        b"socket" => Some(13),
        b"locale" => Some(14),
        b"termios" => Some(15),
        b"inet" => Some(16),
        b"process" => Some(17),
        b"virtual_memory" | b"vm" => Some(18),
        b"poll" => Some(19),
        _ => parse_directed_u8(value),
    }
}

fn split_once_byte(data: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    let split_at = data.iter().position(|&b| b == byte)?;
    let (head, tail) = data.split_at(split_at);
    Some((head, tail.get(1..)?))
}

fn parse_directed_u8(value: &[u8]) -> Option<u8> {
    u8::try_from(parse_directed_u64(value)?).ok()
}

fn parse_directed_u16(value: &[u8]) -> Option<u16> {
    u16::try_from(parse_directed_u64(value)?).ok()
}

fn parse_directed_u32(value: &[u8]) -> Option<u32> {
    u32::try_from(parse_directed_u64(value)?).ok()
}

fn parse_directed_u64(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let (digits, radix) = value
        .strip_prefix(b"0x")
        .or_else(|| value.strip_prefix(b"0X"))
        .map_or((value, 10), |hex| (hex, 16));
    if digits.is_empty() || !digits.iter().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(core::str::from_utf8(digits).ok()?, radix).ok()
}

fn parse_directed_bool(value: &[u8]) -> Option<bool> {
    match value {
        b"true" | b"1" | b"yes" => Some(true),
        b"false" | b"0" | b"no" => Some(false),
        _ => None,
    }
}

fn api_family(index: usize) -> ApiFamily {
    match index {
        0 => ApiFamily::PointerValidation,
        1 => ApiFamily::Allocator,
        2 => ApiFamily::StringMemory,
        3 => ApiFamily::Stdio,
        4 => ApiFamily::Threading,
        5 => ApiFamily::Resolver,
        6 => ApiFamily::MathFenv,
        7 => ApiFamily::Loader,
        8 => ApiFamily::Stdlib,
        9 => ApiFamily::Ctype,
        10 => ApiFamily::Time,
        11 => ApiFamily::Signal,
        12 => ApiFamily::IoFd,
        13 => ApiFamily::Socket,
        14 => ApiFamily::Locale,
        15 => ApiFamily::Termios,
        16 => ApiFamily::Inet,
        17 => ApiFamily::Process,
        18 => ApiFamily::VirtualMemory,
        _ => ApiFamily::Poll,
    }
}
