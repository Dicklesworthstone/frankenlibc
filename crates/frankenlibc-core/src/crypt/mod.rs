//! `<crypt.h>` — password-hash building blocks (salt parser today).
//!
//! Pure-safe Rust port of the byte-level prefix logic that previously
//! lived inline in frankenlibc-abi/src/unistd_abi.rs::parse_crypt_salt.
//! The actual SHA-256/SHA-512/MD5/DES key-stretching loops still live
//! in the abi alongside the corresponding crypt() entry points; this
//! module covers the format-specific parsing piece that's reusable
//! and trivial to test in isolation.

pub mod salt;
