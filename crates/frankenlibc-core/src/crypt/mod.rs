//! `<crypt.h>` — password-hash building blocks.
//!
//! Pure-safe Rust port of the salt prefix parsing, crypt(3)-style
//! base-64 encoding, and the SHA-512 / SHA-256 / MD5 password hashing
//! algorithms. Each lived inline in frankenlibc-abi/src/unistd_abi.rs
//! before being lifted here. The abi `crypt()` entry point is a thin
//! shim that dispatches on the salt prefix and packs the result into
//! a thread-local `*mut c_char` buffer.

pub mod base64;
pub mod md5;
pub mod salt;
pub mod sha256;
pub mod sha512;
