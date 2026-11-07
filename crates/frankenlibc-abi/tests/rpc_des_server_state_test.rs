//! Execute the production AUTH_DES cache/publication unit tests even though
//! rpc_abi is excluded from the ABI library's cfg(test) build.
//!
//! Crypto and protocol checks use the real core crate. These five tests do not
//! call the ABI/NSS boundaries below; each deliberately panics if reached. The
//! deployed check_rpc_auth_des.py --server-only runner covers those boundaries.

#[allow(dead_code)]
mod io_abi {
    pub mod iov_snapshot {
        pub unsafe fn copy_user_bytes(_: *const u8, _: *mut u8, _: usize) -> Result<(), i32> {
            panic!("state tests must not enter the ABI importer")
        }
    }
}

use std::ffi::{c_char, c_int, c_void};

#[repr(C)]
struct NetObj {
    len: u32,
    bytes: *mut c_char,
}

#[repr(C)]
struct OpaqueAuth {
    oa_flavor: c_int,
    oa_base: *mut c_char,
    oa_length: u32,
}

fn known_remaining(_: usize) -> Option<usize> {
    panic!("state tests must not enter the ABI allocator")
}

fn rpc_lookup_netid_user(_: &[u8]) -> Option<frankenlibc_core::rpc::NetidUser> {
    panic!("state tests must not enter NSS")
}

unsafe extern "C" fn getpublickey(_: *const c_char, _: *mut c_char) -> c_int {
    panic!("state tests must not enter public-key NSS")
}

unsafe extern "C-unwind" fn key_decryptsession_pk(
    _: *const c_char,
    _: *mut c_void,
    _: *mut c_void,
) -> c_int {
    panic!("state tests must not enter the keyserver")
}

#[allow(dead_code)]
#[path = "../src/rpc_svc_des.rs"]
mod rpc_svc_des;
