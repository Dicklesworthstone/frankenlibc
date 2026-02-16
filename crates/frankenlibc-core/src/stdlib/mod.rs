//! Standard library utilities.
//!
//! Implements `<stdlib.h>` functions: numeric conversion, sorting, searching,
//! environment variables, random numbers, and process termination.

pub mod conversion;
pub mod env;
pub mod exit;
pub mod random;
pub mod sort;

pub use conversion::{atoi, atol, atoll, strtoimax, strtol, strtoll, strtoul, strtoull, strtoumax};
pub use env::{entry_matches, entry_value, valid_env_name, valid_env_value};
pub use exit::{atexit, exit};
pub use random::{rand, srand};
pub use sort::{bsearch, qsort};
