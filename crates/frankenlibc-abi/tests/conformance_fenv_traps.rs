//! Conformance gate for the GNU/C23 fenv exception-trap extensions
//! feenableexcept/fedisableexcept/fegetexcept/fesetexcept/fetestexceptflag,
//! replicating the exact sequence + return values of host glibc (captured from
//! a gcc oracle). These were -1 stubs; now real MXCSR/x87 manipulation.
//! The test saves/restores the trap mask so it never leaves SIGFPE traps armed.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use frankenlibc_abi::fenv_abi as fe;
use std::ffi::c_int;

const FE_INVALID: c_int = 0x01;
const FE_DIVBYZERO: c_int = 0x04;
const FE_OVERFLOW: c_int = 0x08;
const FE_UNDERFLOW: c_int = 0x10;
const FE_INEXACT: c_int = 0x20;
const FE_ALL: c_int = 0x3D | 0x02; // all 6 hw exceptions

unsafe extern "C" {
    fn feclearexcept(e: c_int) -> c_int;
    fn fetestexcept(e: c_int) -> c_int;
    fn feraiseexcept(e: c_int) -> c_int;
    fn fegetexceptflag(p: *mut u16, e: c_int) -> c_int;
}

#[test]
fn fenv_trap_extensions_match_glibc() {
    let mut d: Vec<String> = Vec::new();
    macro_rules! eq {
        ($l:literal, $got:expr, $want:expr) => {
            let (g, w) = ($got, $want);
            if g != w {
                d.push(format!("{}: got {} want {}", $l, g, w));
            }
        };
    }
    unsafe {
        // start from a clean, fully-masked state
        fe::fedisableexcept(FE_ALL);
        eq!("init fegetexcept", fe::fegetexcept(), 0);

        eq!(
            "feenableexcept(INV|OVF) ret",
            fe::feenableexcept(FE_INVALID | FE_OVERFLOW),
            0
        );
        eq!(
            "fegetexcept after",
            fe::fegetexcept(),
            FE_INVALID | FE_OVERFLOW
        ); // 9
        eq!(
            "feenableexcept(DBZ) ret",
            fe::feenableexcept(FE_DIVBYZERO),
            FE_INVALID | FE_OVERFLOW
        ); // 9
        eq!(
            "fegetexcept after2",
            fe::fegetexcept(),
            FE_INVALID | FE_OVERFLOW | FE_DIVBYZERO
        ); // 13
        eq!(
            "fedisableexcept(INV) ret",
            fe::fedisableexcept(FE_INVALID),
            13
        );
        eq!(
            "fegetexcept after3",
            fe::fegetexcept(),
            FE_OVERFLOW | FE_DIVBYZERO
        ); // 12

        // CRITICAL: re-mask everything so no later FP op traps.
        fe::fedisableexcept(FE_ALL);
        eq!("fegetexcept cleared", fe::fegetexcept(), 0);

        // fesetexcept sets flags without trapping.
        feclearexcept(FE_ALL);
        eq!(
            "fesetexcept ret",
            fe::fesetexcept(FE_INEXACT | FE_UNDERFLOW),
            0
        );
        eq!(
            "fetestexcept(INX)",
            (fetestexcept(FE_INEXACT) != 0) as c_int,
            1
        );
        eq!(
            "fetestexcept(UND)",
            (fetestexcept(FE_UNDERFLOW) != 0) as c_int,
            1
        );
        eq!(
            "fetestexcept(INV)",
            (fetestexcept(FE_INVALID) != 0) as c_int,
            0
        );

        // fetestexceptflag on a saved fexcept_t.
        feclearexcept(FE_ALL);
        feraiseexcept(FE_OVERFLOW | FE_INVALID);
        let mut saved: u16 = 0;
        fegetexceptflag(&mut saved, FE_ALL);
        eq!(
            "fetestexceptflag(OVF)",
            fe::fetestexceptflag(&saved, FE_OVERFLOW),
            FE_OVERFLOW
        );
        eq!(
            "fetestexceptflag(INV)",
            fe::fetestexceptflag(&saved, FE_INVALID),
            FE_INVALID
        );
        eq!(
            "fetestexceptflag(DBZ)",
            fe::fetestexceptflag(&saved, FE_DIVBYZERO),
            0
        );
        eq!(
            "fetestexceptflag(ALL)",
            fe::fetestexceptflag(&saved, FE_ALL),
            FE_OVERFLOW | FE_INVALID
        ); // 9
        eq!(
            "fetestexceptflag(null)",
            fe::fetestexceptflag(std::ptr::null(), FE_ALL),
            0
        );
        fe::fedisableexcept(FE_ALL);
        feclearexcept(FE_ALL);

        // --- fegetmode / fesetmode ---
        const FE_UPWARD: c_int = 0x800;
        const FE_DOWNWARD: c_int = 0x400;
        const FE_TONEAREST: c_int = 0x000;
        let fe_dfl_mode = usize::MAX as *const fe::FeMode;

        fe::fesetround(FE_UPWARD);
        fe::feenableexcept(FE_INVALID | FE_OVERFLOW);
        let mut saved = std::mem::MaybeUninit::<fe::FeMode>::uninit();
        eq!("fegetmode ret", fe::fegetmode(saved.as_mut_ptr()), 0);
        // change everything
        fe::fesetround(FE_DOWNWARD);
        fe::fedisableexcept(FE_ALL);
        fe::feenableexcept(FE_DIVBYZERO);
        // restore
        eq!("fesetmode ret", fe::fesetmode(saved.as_ptr()), 0);
        eq!("fesetmode round restored", fe::fegetround(), FE_UPWARD);
        eq!(
            "fesetmode en restored",
            fe::fegetexcept(),
            FE_INVALID | FE_OVERFLOW
        );
        // fesetmode must NOT clear a raised status flag
        feclearexcept(FE_ALL);
        feraiseexcept(FE_INEXACT);
        fe::fesetmode(saved.as_ptr());
        eq!(
            "fesetmode preserves INEXACT",
            (fetestexcept(FE_INEXACT) != 0) as c_int,
            1
        );
        // FE_DFL_MODE resets to round-nearest, all masked
        fe::fesetround(FE_DOWNWARD);
        fe::feenableexcept(FE_OVERFLOW);
        eq!("fesetmode(FE_DFL_MODE) ret", fe::fesetmode(fe_dfl_mode), 0);
        eq!("FE_DFL round", fe::fegetround(), FE_TONEAREST);
        eq!("FE_DFL en", fe::fegetexcept(), 0);

        fe::fedisableexcept(FE_ALL);
        feclearexcept(FE_ALL);
    }
    assert!(
        d.is_empty(),
        "fenv trap-extension divergences ({}):\n  {}",
        d.len(),
        d.join("\n  ")
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn synchronous_exception_delivery() {
    use frankenlibc_abi::stdlib_abi;
    use std::os::unix::process::ExitStatusExt;

    const CHILD: &str = "FRANKENLIBC_TEST_FENV_TRAP";
    if let Ok(case) = std::env::var(CHILD) {
        let (op, bit) = case.split_once('/').unwrap();
        let bit = bit.parse::<c_int>().unwrap();
        unsafe {
            fe::fedisableexcept(FE_ALL);
            // Initialize the same conversion path before enabling traps.
            std::hint::black_box(stdlib_abi::strtod(c"1".as_ptr(), std::ptr::null_mut()));
            fe::feclearexcept(FE_ALL);
            assert_eq!(fe::feenableexcept(bit), 0);
            match op {
                "raise" => {
                    fe::feraiseexcept(bit);
                }
                "restore" => {
                    let mut saved = [0u32; 8];
                    assert_eq!(fe::feholdexcept(saved.as_mut_ptr().cast()), 0);
                    fe::feraiseexcept(bit);
                    fe::feupdateenv(saved.as_ptr().cast());
                }
                "set" => {
                    fe::fesetexcept(bit);
                    core::arch::asm!("fwait", options(nostack, preserves_flags));
                    assert_eq!(fe::fetestexcept(bit), bit);
                }
                "exact" | "convert" => {
                    let input = match (op, bit) {
                        ("exact", _) => c"0x1p0",
                        (_, FE_OVERFLOW) => c"1e9999",
                        (_, FE_UNDERFLOW) => c"1e-9999",
                        (_, FE_INEXACT) => c"0x1.00000000000008p0",
                        _ => unreachable!(),
                    };
                    std::hint::black_box(stdlib_abi::strtod(input.as_ptr(), std::ptr::null_mut()));
                }
                _ => unreachable!(),
            }
            fe::fedisableexcept(FE_ALL);
            fe::feclearexcept(FE_ALL);
        }
        return;
    }

    // Each enabled exception runs in a fresh process with the default SIGFPE
    // disposition. A normal return from raise, restore or convert is a failure.
    for (op, bits, traps) in [
        (
            "raise",
            &[FE_INVALID, FE_DIVBYZERO, FE_OVERFLOW, FE_UNDERFLOW, FE_INEXACT][..],
            true,
        ),
        ("restore", &[FE_DIVBYZERO][..], true),
        ("convert", &[FE_OVERFLOW, FE_UNDERFLOW, FE_INEXACT][..], true),
        ("exact", &[FE_INEXACT][..], false),
        ("set", &[FE_OVERFLOW][..], false),
    ] {
        for bit in bits {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "synchronous_exception_delivery", "--nocapture"])
                .env(CHILD, format!("{op}/{bit}"))
                .output()
                .unwrap();
            if traps {
                assert_eq!(
                    output.status.signal(),
                    Some(libc::SIGFPE),
                    "{op}/{bit}: {output:?}"
                );
            } else {
                assert!(output.status.success(), "{op}/{bit}: {output:?}");
            }
        }
    }
}
