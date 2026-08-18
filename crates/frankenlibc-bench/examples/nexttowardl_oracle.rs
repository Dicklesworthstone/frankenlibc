//! A differential oracle for `nexttowardl`, which currently has none.
//!
//! `conformance_diff_math_multi_output.rs` excludes the `nexttoward*` family and
//! says why: the C second argument is `long double`, "which cannot be passed
//! from Rust over the x86-64 SysV ABI". True of a plain `extern "C"` declaration
//! — Rust has no x87 80-bit type — but not of the ABI itself. FrankenLibC's own
//! `global_asm!` trampolines already marshal these arguments; this driver does
//! the inverse, so a C `nexttowardl` can be called from here and compared
//! against glibc's bit for bit.
//!
//! Why it matters: `nexttowardl` is one of the three symbols still missing from
//! the export surface (bd-6xstqa), and the fix — converting the trampoline to a
//! `#[unsafe(naked)] #[unsafe(no_mangle)]` fn — touches x87 argument placement.
//! Changing that with no oracle is how a silent ABI break ships. This is the
//! oracle, written before the fix.
//!
//! ABI, read off fl's own trampoline (`math_abi.rs`, which does
//! `sub rsp,24; lea rdi,[rsp+32]; lea rsi,[rsp+48]`): each `long double`
//! argument occupies a 16-byte stack slot, the first at callee `rsp+8` and the
//! second at `rsp+24`, with the value in the low 10 bytes. The result comes back
//! in `st(0)`.

use std::ffi::{c_char, c_int, c_void, CString};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

// Call `fn(long double, long double) -> long double` with both arguments taken
// from 16-byte buffers, storing the 80-bit result into `out`.
//
// rdi = target, rsi = &x[16], rdx = &y[16], rcx = &mut out[16].
//
// Alignment: at entry rsp ≡ 8 (mod 16); `push rbx` makes it ≡ 0, and `sub rsp,32`
// keeps it ≡ 0, so rsp is 16-byte aligned immediately before `call`, as SysV
// requires. rbx is callee-saved and holds `out` across the call because rcx is
// not preserved by the callee.
core::arch::global_asm!(
    ".global fl_call_long_double_binary",
    ".type fl_call_long_double_binary, @function",
    "fl_call_long_double_binary:",
    "  push rbx",
    "  mov rbx, rcx",
    "  mov r11, rdi",
    "  sub rsp, 32",
    "  mov rax, [rsi]",
    "  mov [rsp], rax",
    "  mov rax, [rsi + 8]",
    "  mov [rsp + 8], rax",
    "  mov rax, [rdx]",
    "  mov [rsp + 16], rax",
    "  mov rax, [rdx + 8]",
    "  mov [rsp + 24], rax",
    "  call r11",
    "  add rsp, 32",
    "  fstp TBYTE PTR [rbx]",
    "  pop rbx",
    "  ret",
    ".size fl_call_long_double_binary, .-fl_call_long_double_binary",
);

unsafe extern "C" {
    fn fl_call_long_double_binary(
        target: *const c_void,
        x: *const u8,
        y: *const u8,
        out: *mut u8,
    );
}

// The OTHER two signatures in the family place their arguments differently, so
// they need their own shims: `double nexttoward(double, long double)` and
// `float nexttowardf(float, long double)` pass the first argument in xmm0 and
// only the second on the stack, and return in xmm0 rather than st(0). Reusing
// the ld(ld,ld) shim for these would silently pass garbage.
//
// rdi = target, xmm0 = x, rsi = &y[16].
//
// Alignment: at entry rsp ≡ 8 (mod 16); `sub rsp,24` makes it ≡ 0, so rsp is
// aligned immediately before `call`, and the 16-byte long double slot sits at
// [rsp..rsp+16) — where the callee sees it at rsp+8.
core::arch::global_asm!(
    ".global fl_call_double_long_double",
    ".type fl_call_double_long_double, @function",
    "fl_call_double_long_double:",
    "  sub rsp, 24",
    "  mov rax, [rsi]",
    "  mov [rsp], rax",
    "  mov rax, [rsi + 8]",
    "  mov [rsp + 8], rax",
    "  call rdi",
    "  add rsp, 24",
    "  ret",
    ".size fl_call_double_long_double, .-fl_call_double_long_double",
    // Byte-identical body; a separate symbol only so the return type can be
    // declared as f32 without declaring one symbol at two Rust signatures.
    ".global fl_call_float_long_double",
    ".type fl_call_float_long_double, @function",
    "fl_call_float_long_double:",
    "  sub rsp, 24",
    "  mov rax, [rsi]",
    "  mov [rsp], rax",
    "  mov rax, [rsi + 8]",
    "  mov [rsp + 8], rax",
    "  call rdi",
    "  add rsp, 24",
    "  ret",
    ".size fl_call_float_long_double, .-fl_call_float_long_double",
);

unsafe extern "C" {
    fn fl_call_double_long_double(target: *const c_void, x: f64, y: *const u8) -> f64;
    fn fl_call_float_long_double(target: *const c_void, x: f32, y: *const u8) -> f32;
}

fn call_double(target: *const c_void, x: f64, y: &[u8; 16]) -> f64 {
    // SAFETY: `target` is a `double(double, long double)` resolved by dlsym; the
    // shim places `y` in the stack slot the ABI requires.
    unsafe { fl_call_double_long_double(target, x, y.as_ptr()) }
}

fn call_float(target: *const c_void, x: f32, y: &[u8; 16]) -> f32 {
    // SAFETY: as above, for `float(float, long double)`.
    unsafe { fl_call_float_long_double(target, x, y.as_ptr()) }
}

/// An x87 80-bit value built from its parts: sign, 15-bit exponent, 64-bit
/// significand (explicit integer bit included, unlike IEEE binary64).
fn x87(sign: u8, exponent: u16, significand: u64) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&significand.to_le_bytes());
    let high = (u16::from(sign) << 15) | (exponent & 0x7fff);
    bytes[8..10].copy_from_slice(&high.to_le_bytes());
    bytes
}

/// 1.0 has exponent 0x3fff and the explicit integer bit set.
fn one() -> [u8; 16] {
    x87(0, 0x3fff, 0x8000_0000_0000_0000)
}

fn zero() -> [u8; 16] {
    x87(0, 0, 0)
}

fn two() -> [u8; 16] {
    x87(0, 0x4000, 0x8000_0000_0000_0000)
}

fn infinity(sign: u8) -> [u8; 16] {
    x87(sign, 0x7fff, 0x8000_0000_0000_0000)
}

fn call(target: *const c_void, x: &[u8; 16], y: &[u8; 16]) -> [u8; 10] {
    let mut out = [0u8; 16];
    // SAFETY: `target` is a `long double(long double, long double)` resolved by
    // dlsym; the shim marshals both arguments into the stack slots that ABI
    // requires and writes exactly 10 bytes of result into `out`.
    unsafe { fl_call_long_double_binary(target, x.as_ptr(), y.as_ptr(), out.as_mut_ptr()) };
    let mut result = [0u8; 10];
    result.copy_from_slice(&out[..10]);
    result
}

fn resolve(handle: *mut c_void, symbol: &str) -> Option<*const c_void> {
    let name = CString::new(symbol).expect("symbol name");
    let address = unsafe { dlsym(handle, name.as_ptr()) };
    (!address.is_null()).then_some(address.cast_const())
}

fn main() {
    let libm = CString::new("libm.so.6").expect("libm");
    let handle = unsafe { dlopen(libm.as_ptr(), RTLD_NOW) };
    assert!(!handle.is_null(), "could not dlopen libm.so.6");

    let Some(glibc) = resolve(handle, "nexttowardl") else {
        println!("ORACLE_UNAVAILABLE reason=glibc_nexttowardl_not_found");
        std::process::exit(2);
    };

    // POSITIVE CONTROL FIRST. If the shim's argument marshalling is wrong, every
    // comparison below is meaningless, so prove the shim can reproduce answers
    // that are known independently of any implementation under test:
    //   nexttowardl(1, 1) == 1        (equal arguments return y)
    //   nexttowardl(1, 2) >  1        (steps up, so the significand increments)
    //   nexttowardl(1, 0) <  1        (steps down)
    let same = call(glibc, &one(), &one());
    let up = call(glibc, &one(), &two());
    let down = call(glibc, &one(), &zero());
    let one_bits = {
        let mut bits = [0u8; 10];
        bits.copy_from_slice(&one()[..10]);
        bits
    };
    println!("ORACLE_CONTROL same={same:02x?}");
    println!("ORACLE_CONTROL up={up:02x?}");
    println!("ORACLE_CONTROL down={down:02x?}");
    assert_eq!(same, one_bits, "shim is broken: nexttowardl(1,1) != 1");
    assert_ne!(up, one_bits, "shim is broken: nexttowardl(1,2) did not move");
    assert_ne!(down, one_bits, "shim is broken: nexttowardl(1,0) did not move");
    // Stepping up from 1.0 sets the low significand bit; stepping down does not.
    assert_eq!(up[0], 0x01, "shim is broken: unexpected step-up pattern");
    println!("ORACLE_CONTROL_OK");

    // The sibling signatures, each with its own controls. These are exactly
    // checkable against IEEE-754 binary64/binary32 neighbours, so they verify
    // the two new shims independently of any implementation under test.
    let glibc_nexttoward = resolve(handle, "nexttoward").expect("glibc nexttoward");
    let glibc_nexttowardf = resolve(handle, "nexttowardf").expect("glibc nexttowardf");

    let d_same = call_double(glibc_nexttoward, 1.0, &one());
    let d_up = call_double(glibc_nexttoward, 1.0, &two());
    let d_down = call_double(glibc_nexttoward, 1.0, &zero());
    println!("ORACLE_CONTROL nexttoward same={d_same} up={d_up:.17} down={d_down:.17}");
    assert_eq!(d_same, 1.0, "shim broken: nexttoward(1,1) != 1");
    assert_eq!(d_up, f64::from_bits(1.0f64.to_bits() + 1), "shim broken: nexttoward(1,2)");
    assert_eq!(d_down, f64::from_bits(1.0f64.to_bits() - 1), "shim broken: nexttoward(1,0)");

    let f_same = call_float(glibc_nexttowardf, 1.0, &one());
    let f_up = call_float(glibc_nexttowardf, 1.0, &two());
    let f_down = call_float(glibc_nexttowardf, 1.0, &zero());
    println!("ORACLE_CONTROL nexttowardf same={f_same} up={f_up:.9} down={f_down:.9}");
    assert_eq!(f_same, 1.0, "shim broken: nexttowardf(1,1) != 1");
    assert_eq!(f_up, f32::from_bits(1.0f32.to_bits() + 1), "shim broken: nexttowardf(1,2)");
    assert_eq!(f_down, f32::from_bits(1.0f32.to_bits() - 1), "shim broken: nexttowardf(1,0)");
    println!("ORACLE_CONTROL_SIBLINGS_OK");

    // Now the differential, if FrankenLibC exports the symbol at all. It does
    // not today (bd-6xstqa) — that is the point of writing this first.
    let object = format!(
        "{}/release/libfrankenlibc_abi.so",
        std::env::var("FRANKENLIBC_BENCH_TARGET_DIR")
            .or_else(|_| std::env::var("CARGO_TARGET_DIR"))
            .unwrap_or_else(|_| "target".to_owned())
    );
    let path = CString::new(object.clone()).expect("object path");
    let fl_handle = unsafe { dlopen(path.as_ptr(), RTLD_NOW) };
    if fl_handle.is_null() {
        println!("ORACLE_FL_UNAVAILABLE object={object}");
        std::process::exit(0);
    }
    let Some(fl) = resolve(fl_handle, "nexttowardl") else {
        println!("ORACLE_FL_SYMBOL_ABSENT symbol=nexttowardl object={object}");
        println!("ORACLE_READY_FOR_FIX shim=verified differential=blocked_on_export");
        std::process::exit(0);
    };

    let cases: [(&str, [u8; 16], [u8; 16]); 6] = [
        ("one_to_two", one(), two()),
        ("one_to_zero", one(), zero()),
        ("one_to_one", one(), one()),
        ("zero_to_one", zero(), one()),
        ("inf_to_zero", infinity(0), zero()),
        ("neg_inf_to_zero", infinity(1), zero()),
    ];
    let mut divergences = 0usize;
    for (name, x, y) in cases {
        let want = call(glibc, &x, &y);
        let got = call(fl, &x, &y);
        if want == got {
            println!("ORACLE case={name} status=match bits={got:02x?}");
        } else {
            divergences += 1;
            println!("ORACLE case={name} status=DIVERGE glibc={want:02x?} fl={got:02x?}");
        }
    }
    println!("ORACLE_SUMMARY cases={} divergences={divergences}", cases.len());
    assert_eq!(divergences, 0, "nexttowardl diverges from glibc");
    println!("ORACLE_OK");
}
