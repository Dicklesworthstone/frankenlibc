//! Standard library utilities.
//!
//! Implements `<stdlib.h>` functions: numeric conversion, sorting, searching,
//! environment variables, random numbers, and process termination.

pub mod conversion;
pub mod env;
pub mod exit;
pub mod math;
pub mod random;
pub mod sort;

pub use conversion::{
    atof, atoi, atol, atoll, strtod, strtof, strtoimax, strtol, strtoll, strtoul, strtoull,
    strtoumax,
};
pub use env::{entry_matches, entry_value, valid_env_name, valid_env_value};
pub use exit::{atexit, exit};
pub use math::{
    DivResult, LdivResult, LldivResult, abs, div, ffs, ffsl, ffsll, labs, ldiv, llabs, lldiv,
};
pub use random::{RAND_MAX, rand, rand_r, srand};
pub use sort::{bsearch, qsort};
