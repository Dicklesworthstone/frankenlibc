//! GNU argp support: the reentrant option scanner argp drives, and (in
//! `help`) the help/usage formatter. The ABI layer owns the C structures and
//! the parser-callback protocol; everything here is pure safe Rust.

pub mod help;
pub mod scan;
