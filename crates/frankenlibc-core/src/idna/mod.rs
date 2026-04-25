//! IDNA (Internationalized Domain Names in Applications) primitives.
//!
//! Pure-safe Rust implementations of the byte-level building blocks
//! used by `__idna_to_dns_encoding` / `__idna_from_dns_encoding` in
//! the abi layer. Today this is just RFC 3492 Punycode; future work
//! could add the IDNA 2008 mapping tables (UTS #46) here too.

pub mod punycode;
