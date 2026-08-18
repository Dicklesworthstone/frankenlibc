//! `<crypt.h>` — password-hash building blocks.
//!
//! Pure-safe Rust port of the salt prefix parsing, crypt(3)-style base-64
//! encoding, and the password hashing schemes: SHA-512 (`$6$`), SHA-256
//! (`$5$`), MD5 (`$1$`), bcrypt (`$2*$`) and traditional DES (two-character
//! salt), plus the scrypt KDF and its
//! PBKDF2-HMAC-SHA-256 dependency, which `$7$` and `$y$` are built on.
//! The SHA/MD5 schemes lived inline in frankenlibc-abi/src/unistd_abi.rs
//! before being lifted here. The abi `crypt()` entry point is a thin
//! shim that dispatches on the salt prefix and packs the result into
//! a thread-local `*mut c_char` buffer.

pub mod base64;
pub mod bcrypt;
pub mod blowfish;
pub mod des;
pub mod md5;
pub mod pbkdf2;
pub mod salt;
pub mod scrypt;
pub mod scrypt_crypt;
pub mod sha256;
pub mod sha512;
pub mod yescrypt_params;
