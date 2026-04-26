//! Standard library utilities.
//!
//! Implements `<stdlib.h>` functions: numeric conversion, sorting, searching,
//! environment variables, random numbers, process termination, base-64,
//! drand48 family, System V random, suboption parsing, and legacy float conversion.

pub mod base64;
pub mod conversion;
pub mod ecvt;
pub mod env;
pub mod exit;
pub mod getbsize;
pub mod math;
pub mod random;
pub mod random48;
pub mod random_sv;
pub mod sort;
pub mod strtonum;
pub mod subopt;
pub mod wordexp;

pub use base64::{a64l, l64a};
pub use conversion::{
    atof, atoi, atol, atoll, strtod, strtof, strtoimax, strtol, strtoll, strtoul, strtoull,
    strtoumax,
};
pub use ecvt::{ecvt, fcvt, gcvt};
pub use env::{entry_matches, entry_value, valid_env_name, valid_env_value};
pub use exit::{atexit, exit, run_atexit_handlers};
pub use math::{
    DivResult, LdivResult, LldivResult, abs, div, ffs, ffsl, ffsll, labs, ldiv, llabs, lldiv,
};
pub use random::{RAND_MAX, rand, rand_r, srand};
pub use random_sv::{initstate, random as sv_random, setstate, srandom};
pub use random48::{
    drand48, erand48, jrand48, lcong48, lrand48, mrand48, nrand48, seed48, srand48,
};
pub use sort::{bsearch, qsort};
pub use subopt::getsubopt;
