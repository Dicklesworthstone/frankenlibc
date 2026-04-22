#![no_main]
//! Fuzz target for FrankenLibC's setjmp / longjmp surface:
//!
//!   setjmp, _setjmp, sigsetjmp, longjmp, _longjmp, siglongjmp
//!
//! These are the control-flow integrity surface — a corrupted or
//! misaligned jmp_buf plus a longjmp is a classic CFI bypass. The
//! harness exercises the round-trip path where setjmp returns
//! twice (first with 0, then with the caller-supplied val after
//! longjmp) and asserts POSIX semantics:
//!
//! - `setjmp(env)` returns 0 on the direct call.
//! - `longjmp(env, val)` causes `setjmp(env)` to return with val,
//!   except that val == 0 is remapped to 1 (POSIX §7.13.2.1).
//! - `sigsetjmp(env, 0)` behaves like `setjmp`; `sigsetjmp(env, 1)`
//!   additionally saves/restores the sigmask.
//!
//! Safety:
//! - We only longjmp back to a setjmp in the SAME frame of the fuzz
//!   target body. Cross-frame unwind into libFuzzer's own harness
//!   is not exercised (that's a known-risky pattern).
//! - The jmp_buf is a fixed [u64; 64] buffer (512 bytes) on a
//!   naturally 8-aligned stack slot — more than enough for
//!   glibc's jmp_buf on any Linux target we care about.
//! - Each op allocates a fresh jmp_buf so a longjmp on iteration N
//!   can't see a stale env from iteration N-1.
//!
//! Bead: bd-dvr22 priority-5

use std::ffi::c_int;
use std::sync::Once;

use arbitrary::Arbitrary;
use frankenlibc_abi::setjmp_abi::{_longjmp, _setjmp, longjmp, setjmp, siglongjmp, sigsetjmp};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
enum Op {
    SetjmpRoundTrip { val: i32, use_underscore: bool },
    SigsetjmpRoundTrip { val: i32, savemask: bool, use_siglongjmp: bool },
}

#[derive(Debug, Arbitrary)]
struct SetjmpFuzzInput {
    ops: Vec<Op>,
}

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: mode set once before any ABI call.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

#[repr(align(16))]
struct JmpBuf([u64; 64]);

fn new_jmp_buf() -> Box<JmpBuf> {
    Box::new(JmpBuf([0u64; 64]))
}

fn expected_longjmp_return(val: i32) -> c_int {
    // POSIX: longjmp(env, 0) must appear as setjmp returning 1.
    if val == 0 { 1 } else { val }
}

fn apply_setjmp_rt(val: i32, use_underscore: bool) {
    let mut buf = new_jmp_buf();
    let env = buf.0.as_mut_ptr().cast::<std::ffi::c_void>();

    // SAFETY: jmp_buf is a fresh, fully-initialized [u64; 64] aligned
    // to 16 bytes; setjmp / longjmp only touch this storage.
    // The round-trip stays within this frame.
    let rc = unsafe {
        if use_underscore {
            _setjmp(env)
        } else {
            setjmp(env)
        }
    };
    if rc == 0 {
        // First call — longjmp back with val. The ABI is `-> !`, so
        // control never falls through this block. Any byte beyond
        // `longjmp` / `_longjmp` is unreachable by the function's
        // type contract.
        unsafe {
            if use_underscore {
                _longjmp(env, val as c_int);
            } else {
                longjmp(env, val as c_int);
            }
        }
    } else {
        assert_eq!(
            rc,
            expected_longjmp_return(val),
            "setjmp returned wrong value after longjmp(val={val}): got {rc}"
        );
    }
    drop(buf);
}

fn apply_sigsetjmp_rt(val: i32, savemask: bool, use_siglongjmp: bool) {
    let mut buf = new_jmp_buf();
    let env = buf.0.as_mut_ptr().cast::<std::ffi::c_void>();
    let savemask_i = if savemask { 1 } else { 0 };

    // SAFETY: same contract as apply_setjmp_rt; savemask controls whether
    // sigsetjmp additionally captures the sigmask.
    let rc = unsafe { sigsetjmp(env, savemask_i) };
    if rc == 0 {
        // `-> !` — never returns; anything after is unreachable by contract.
        unsafe {
            if use_siglongjmp {
                siglongjmp(env, val as c_int);
            } else {
                longjmp(env, val as c_int);
            }
        }
    } else {
        assert_eq!(
            rc,
            expected_longjmp_return(val),
            "sigsetjmp returned wrong value after (sig)longjmp(val={val}): got {rc}"
        );
    }
    drop(buf);
}

fuzz_target!(|input: SetjmpFuzzInput| {
    if input.ops.len() > 16 {
        return;
    }
    init_hardened_mode();

    for op in &input.ops {
        match op {
            Op::SetjmpRoundTrip { val, use_underscore } => {
                apply_setjmp_rt(*val, *use_underscore)
            }
            Op::SigsetjmpRoundTrip {
                val,
                savemask,
                use_siglongjmp,
            } => apply_sigsetjmp_rt(*val, *savemask, *use_siglongjmp),
        }
    }
});
