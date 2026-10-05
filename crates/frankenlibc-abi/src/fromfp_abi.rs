//! C23 floating-return exports alongside the original integer-return ABI.
//!
//! This module is enabled only in deployed x86-64 ELF interposer builds. The
//! single ABI codegen unit keeps each .symver directive with its definition;
//! `remove` also rewrites references within that object to the legacy version.
//! The public Rust facade separately pins cross-object legacy calls.

use frankenlibc_core::math::fromfp::{Format, Rounded, round_to_width};

fn finish(result: Rounded, signal_inexact: bool) -> u128 {
    // No floating arithmetic occurred in the core. Raise only the required
    // exception, without clearing a caller's existing flags or changing its
    // rounding mode. Domain errors must not add FE_INEXACT.
    if result.invalid {
        // SAFETY: scalar fenv/errno entry points, with x86-64 FE_INVALID.
        unsafe {
            crate::fenv_abi::feraiseexcept(0x01);
            crate::errno_abi::set_abi_errno(libc::EDOM);
        }
    } else if signal_inexact && result.inexact {
        // SAFETY: x86-64 FE_INEXACT; no pointers or external resources.
        unsafe { crate::fenv_abi::feraiseexcept(0x20) };
    }
    result.bits
}

macro_rules! floating {
    ($name:ident, $ty:ty, $bits:ty, $format:ident, $unsigned:expr, $inexact:expr) => {
        #[unsafe(export_name = concat!("__frankenlibc_c23_", stringify!($name)))]
        pub extern "C" fn $name(x: $ty, direction: i32, width: u32) -> $ty {
            let rounded = round_to_width(
                x.to_bits() as u128, Format::$format, direction, width, $unsigned,
            );
            <$ty>::from_bits(finish(rounded, $inexact) as $bits)
        }
    };
}
macro_rules! family {
    ($ty:ty, $bits:ty, $format:ident, $s:ident, $sx:ident, $u:ident, $ux:ident) => {
        floating!($s, $ty, $bits, $format, false, false);
        floating!($sx, $ty, $bits, $format, false, true);
        floating!($u, $ty, $bits, $format, true, false);
        floating!($ux, $ty, $bits, $format, true, true);
    };
}
family!(f64, u64, Binary64, fromfp, fromfpx, ufromfp, ufromfpx);
family!(f32, u32, Binary32, fromfpf, fromfpxf, ufromfpf, ufromfpxf);
family!(f32, u32, Binary32, fromfpf32, fromfpxf32, ufromfpf32, ufromfpxf32);
family!(f64, u64, Binary64, fromfpf64, fromfpxf64, ufromfpf64, ufromfpxf64);
family!(f64, u64, Binary64, fromfpf32x, fromfpxf32x, ufromfpf32x, ufromfpxf32x);
family!(f128, u128, Binary128, fromfpf128, fromfpxf128, ufromfpf128, ufromfpxf128);

unsafe extern "C" fn long_double(
    slot: *const u8, direction: i32, width: u32, unsigned: bool, inexact: bool,
) -> u128 {
    // SAFETY: the naked entry passes its caller's 16-byte long-double argument
    // slot. Read only the ten value bytes, never its indeterminate padding.
    let bits = unsafe {
        u128::from(slot.cast::<u64>().read_unaligned())
            | (u128::from(slot.add(8).cast::<u16>().read_unaligned()) << 64)
    };
    finish(round_to_width(bits, Format::Extended80, direction, width, unsigned), inexact)
}

macro_rules! extended {
    ($name:ident, $unsigned:literal, $inexact:literal) => {
        // Rust has no binary80 type. The naked entry's actual C ABI is
        // (long double, int, unsigned) -> long double: stack input, ST(0) output.
        #[unsafe(naked)]
        #[unsafe(export_name = concat!("__frankenlibc_c23_", stringify!($name)))]
        pub unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "mov edx, esi",
                "mov esi, edi",
                "lea rdi, [rsp + 8]",
                "mov ecx, {unsigned}",
                "mov r8d, {inexact}",
                "sub rsp, 8",
                "call {helper}",
                "sub rsp, 16",
                "mov [rsp], rax",
                "mov [rsp + 8], rdx",
                "fld tbyte ptr [rsp]",
                "add rsp, 24",
                "ret",
                helper = sym long_double,
                unsigned = const $unsigned,
                inexact = const $inexact,
            );
        }
    };
}
extended!(fromfpl, 0, 0);
extended!(fromfpxl, 0, 1);
extended!(ufromfpl, 1, 0);
extended!(ufromfpxl, 1, 1);
extended!(fromfpf64x, 0, 0);
extended!(fromfpxf64x, 0, 1);
extended!(ufromfpf64x, 1, 0);
extended!(ufromfpxf64x, 1, 1);

macro_rules! versions {
    ($version:literal; $($name:ident),+ $(,)?) => {
        $(core::arch::global_asm!(concat!(
            ".symver ", stringify!($name), ",", stringify!($name), "@", $version, ",remove\n",
            ".symver __frankenlibc_c23_", stringify!($name), ",", stringify!($name),
            "@@GLIBC_2.43,remove\n",
        ));)+
    };
}
versions!("GLIBC_2.25";
    fromfp, fromfpf, fromfpl, fromfpx, fromfpxf, fromfpxl,
    ufromfp, ufromfpf, ufromfpl, ufromfpx, ufromfpxf, ufromfpxl,
);
versions!("GLIBC_2.26"; fromfpf128, fromfpxf128, ufromfpf128, ufromfpxf128);
versions!("GLIBC_2.27";
    fromfpf32, fromfpf64, fromfpf32x, fromfpf64x,
    fromfpxf32, fromfpxf64, fromfpxf32x, fromfpxf64x,
    ufromfpf32, ufromfpf64, ufromfpf32x, ufromfpf64x,
    ufromfpxf32, ufromfpxf64, ufromfpxf32x, ufromfpxf64x,
);
