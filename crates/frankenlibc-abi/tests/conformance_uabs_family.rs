//! Gate: NetBSD uabs(3) family computes |signed| as the unsigned type.
//! These take a SIGNED operand and return its absolute value as the
//! corresponding unsigned type — precisely so |INT_MIN| etc. is representable
//! without the signed-abs UB. (No glibc equivalent, so golden values.)
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use frankenlibc_abi::glibc_internal_abi as fl;
use std::os::raw::{c_int, c_long, c_uint, c_ulong};
#[test]
fn uabs_family_returns_absolute_value() {
    unsafe {
        assert_eq!(fl::uabs(5), 5);
        assert_eq!(fl::uabs(-5), 5);
        assert_eq!(fl::uabs(0), 0);
        assert_eq!(fl::uabs(c_int::MAX), c_int::MAX as c_uint);
        // |INT_MIN| == 2^31, representable only because the return type is unsigned.
        assert_eq!(fl::uabs(c_int::MIN), 2147483648u32);

        assert_eq!(fl::ulabs(-7), 7);
        assert_eq!(fl::ulabs(c_long::MIN), 9223372036854775808u64 as c_ulong);
        assert_eq!(fl::ulabs(c_long::MAX), c_long::MAX as c_ulong);

        assert_eq!(fl::ullabs(-7), 7);
        assert_eq!(fl::ullabs(i64::MIN), 9223372036854775808u64);
        assert_eq!(fl::ullabs(i64::MAX), i64::MAX as u64);

        assert_eq!(fl::uimaxabs(-123), 123);
        assert_eq!(fl::uimaxabs(i64::MIN), 9223372036854775808u64);
    }
}
