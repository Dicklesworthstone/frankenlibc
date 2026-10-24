//! Rust API compatibility facade for the versioned ELF math exports.
//!
//! C23 changes the C return types, not existing Rust callers of math_abi.
//! Most entries are unchanged. These explicit wrappers shadow the glob import
//! and pin cross-object calls to the integer-return version, rather than letting
//! an unversioned Rust reference bind to the new floating-return default.
pub use crate::legacy_math_abi::*;

macro_rules! legacy {
    ($ty:ty, $ret:ty, $version:literal; $($name:ident),+ $(,)?) => {
        $(
            #[cfg(all(target_os = "linux", target_arch = "x86_64",
                not(debug_assertions), not(test), not(feature = "standalone")))]
            #[inline]
            pub unsafe extern "C" fn $name(x: $ty, direction: i32, width: u32) -> $ret {
                unsafe extern "C" {
                    #[link_name = concat!(stringify!($name), "@", $version)]
                    fn integer_entry(x: $ty, direction: i32, width: u32) -> $ret;
                }
                // SAFETY: the pinned legacy version has exactly this ABI.
                unsafe { integer_entry(x, direction, width) }
            }
        )+
    };
}
legacy!(f64, i64, "GLIBC_2.25"; fromfp, fromfpx);
legacy!(f64, u64, "GLIBC_2.25"; ufromfp, ufromfpx);
legacy!(f32, i64, "GLIBC_2.25"; fromfpf, fromfpxf);
legacy!(f32, u64, "GLIBC_2.25"; ufromfpf, ufromfpxf);
legacy!(f32, i64, "GLIBC_2.27"; fromfpf32, fromfpxf32);
legacy!(f32, u64, "GLIBC_2.27"; ufromfpf32, ufromfpxf32);
legacy!(f64, i64, "GLIBC_2.27"; fromfpf64, fromfpxf64, fromfpf32x, fromfpxf32x);
legacy!(f64, u64, "GLIBC_2.27"; ufromfpf64, ufromfpxf64, ufromfpf32x, ufromfpxf32x);
legacy!(f128, i64, "GLIBC_2.26"; fromfpf128, fromfpxf128);
legacy!(f128, u64, "GLIBC_2.26"; ufromfpf128, ufromfpxf128);
// The x86-64 Rust `l`/`f64x` placeholders are already mangled Rust functions;
// the real binary80 C entries are separate naked shims, so need no override.
