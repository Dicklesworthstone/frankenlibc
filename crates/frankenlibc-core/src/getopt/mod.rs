//! POSIX `<unistd.h>` `getopt` family — argument parsing.
//!
//! This module is a clean-room native Rust port of the helpers and
//! state machine that previously lived in
//! `frankenlibc-abi/src/unistd_abi.rs` (~391 lines, lines 2113-2510).
//!
//! Sub-bead 1 (this commit, bd-go-1) lifts the pure parse helpers
//! into core. Sub-bead 2 will add the full state machine.
//! Sub-bead 3 will wire the abi shims.

pub mod parse;
pub mod state;

pub use parse::{GetoptArgMode, getopt_arg_mode, getopt_prefers_colon};
pub use state::{ArgRef, GetoptState, StepOutcome, step_short};
