//! Pure state machine for POSIX `getopt` short-option scanning.
//!
//! The traditional `getopt` ABI exposes three globals (`optind`,
//! `optarg`, `optopt`) plus an internal "next char" pointer used to
//! step through bundled short options like `-abc`. This module
//! captures all of that in a single [`GetoptState`] value so the
//! state machine is pure-safe Rust and unit-testable in isolation.
//! The abi layer [`getopt`-shim](crate) marshals the global externs
//! to/from this state across each call.

use super::parse::{GetoptArgMode, getopt_arg_mode, getopt_prefers_colon};

/// Reference to a byte within `argv`, used to encode `optarg` and
/// the bundled-short-option scan position without raw pointers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArgRef {
    /// Index into `argv`.
    pub argv_idx: usize,
    /// Byte offset within `argv[argv_idx]`.
    pub byte_offset: usize,
}

/// Mutable state for a getopt scan over an argv slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetoptState {
    /// Next argv index to examine. Start with 1 (argv[0] is the program
    /// name). The state machine increments it as args are consumed.
    pub optind: usize,
    /// `None` when not in the middle of bundled short options.
    /// `Some(ArgRef{argv_idx, byte_offset})` when the next short option
    /// to dispatch is `argv[argv_idx][byte_offset]`.
    pub nextchar: Option<ArgRef>,
    /// Last error/unknown option byte. Set to the offending byte when
    /// the scan returns `'?'` or `':'`.
    pub optopt: u8,
    /// Reference to the most recent option argument (either inline
    /// after the option char or in the next argv slot). `None` when
    /// the option had no argument or no scan has happened yet.
    pub optarg: Option<ArgRef>,
}

impl Default for GetoptState {
    fn default() -> Self {
        Self {
            optind: 1,
            nextchar: None,
            optopt: 0,
            optarg: None,
        }
    }
}

/// Outcome of one [`step_short`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    /// No more options to scan; argv consumed (or first non-option
    /// reached). Caller should stop calling `step_short`.
    Done,
    /// Found an option. `code` is the option byte as `i32`, or `'?'`
    /// for unknown options, or `':'` (when optspec begins with `:`)
    /// for missing required arguments.
    Found(i32),
}

/// One step of the short-option scanner.
///
/// Reads from `argv` starting at `state.optind` (or continuing the
/// bundled scan at `state.nextchar`), updates `state` in place to
/// reflect progress, and returns the next outcome.
///
/// `optspec` is the user's getopt optstring (e.g. `b"abc:d::"`).
/// A leading `:` enables the GNU silent-error mode where missing
/// required arguments report `:` instead of `?`.
pub fn step_short(argv: &[&[u8]], optspec: &[u8], state: &mut GetoptState) -> StepOutcome {
    if argv.is_empty() {
        return StepOutcome::Done;
    }

    // Defensive: optind <= 0 is treated like 1 by glibc.
    if state.optind == 0 {
        state.optind = 1;
        state.nextchar = None;
    }
    if state.optind >= argv.len() {
        state.nextchar = None;
        return StepOutcome::Done;
    }

    // If not in the middle of bundled short opts, look at the current arg.
    if state.nextchar.is_none() {
        let current = argv[state.optind];
        if current.first() != Some(&b'-') || current.len() < 2 {
            // Not an option (no leading '-', or just "-" alone).
            return StepOutcome::Done;
        }
        if current == b"--" {
            // Explicit end-of-options.
            state.optind += 1;
            state.nextchar = None;
            return StepOutcome::Done;
        }
        // Begin bundled scan at byte 1 (after the '-').
        state.nextchar = Some(ArgRef {
            argv_idx: state.optind,
            byte_offset: 1,
        });
    }

    let nc = state.nextchar.unwrap();
    let current = argv[nc.argv_idx];
    let option = current[nc.byte_offset];

    // Advance scan position by one byte.
    let after_pos = nc.byte_offset + 1;
    let at_end = after_pos >= current.len();

    state.nextchar = Some(ArgRef {
        argv_idx: nc.argv_idx,
        byte_offset: after_pos,
    });
    state.optarg = None;

    let missing_code = if getopt_prefers_colon(optspec) {
        b':' as i32
    } else {
        b'?' as i32
    };

    match getopt_arg_mode(optspec, option) {
        None => {
            // Unknown option.
            state.optopt = option;
            if at_end {
                state.optind += 1;
                state.nextchar = None;
            }
            StepOutcome::Found(b'?' as i32)
        }
        Some(GetoptArgMode::None) => {
            if at_end {
                state.optind += 1;
                state.nextchar = None;
            }
            StepOutcome::Found(option as i32)
        }
        Some(GetoptArgMode::Required) => {
            if !at_end {
                // Argument is the rest of the current argv element.
                state.optarg = Some(ArgRef {
                    argv_idx: nc.argv_idx,
                    byte_offset: after_pos,
                });
                state.optind += 1;
                state.nextchar = None;
                return StepOutcome::Found(option as i32);
            }
            // Argument is the next argv slot.
            if state.optind + 1 >= argv.len() {
                state.optopt = option;
                state.optind += 1;
                state.nextchar = None;
                return StepOutcome::Found(missing_code);
            }
            state.optind += 1;
            let next_idx = state.optind;
            state.optarg = Some(ArgRef {
                argv_idx: next_idx,
                byte_offset: 0,
            });
            state.optind += 1;
            state.nextchar = None;
            StepOutcome::Found(option as i32)
        }
        Some(GetoptArgMode::Optional) => {
            if !at_end {
                state.optarg = Some(ArgRef {
                    argv_idx: nc.argv_idx,
                    byte_offset: after_pos,
                });
            }
            state.optind += 1;
            state.nextchar = None;
            StepOutcome::Found(option as i32)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(argv_strs: &[&str], optspec: &str) -> (Vec<i32>, GetoptState, Vec<Option<String>>) {
        let argv: Vec<&[u8]> = argv_strs.iter().map(|s| s.as_bytes()).collect();
        let optspec = optspec.as_bytes();
        let mut state = GetoptState::default();
        let mut codes = Vec::new();
        let mut args: Vec<Option<String>> = Vec::new();
        loop {
            match step_short(&argv, optspec, &mut state) {
                StepOutcome::Done => break,
                StepOutcome::Found(c) => {
                    codes.push(c);
                    args.push(state.optarg.map(|a| {
                        let s = argv[a.argv_idx];
                        std::str::from_utf8(&s[a.byte_offset..])
                            .unwrap_or("")
                            .to_string()
                    }));
                }
            }
            if codes.len() > 32 {
                break;
            }
        }
        (codes, state, args)
    }

    #[test]
    fn empty_argv_done() {
        let mut state = GetoptState::default();
        let argv: Vec<&[u8]> = vec![];
        assert_eq!(step_short(&argv, b"abc", &mut state), StepOutcome::Done);
    }

    #[test]
    fn single_short_option() {
        let (codes, state, args) = run(&["prog", "-a"], "abc");
        assert_eq!(codes, vec![b'a' as i32]);
        assert_eq!(args[0], None);
        assert_eq!(state.optind, 2);
    }

    #[test]
    fn bundled_short_options() {
        let (codes, state, args) = run(&["prog", "-abc"], "abc");
        assert_eq!(codes, vec![b'a' as i32, b'b' as i32, b'c' as i32]);
        assert!(args.iter().all(|a| a.is_none()));
        assert_eq!(state.optind, 2);
    }

    #[test]
    fn required_arg_attached() {
        let (codes, _, args) = run(&["prog", "-aval"], "a:");
        assert_eq!(codes, vec![b'a' as i32]);
        assert_eq!(args[0].as_deref(), Some("val"));
    }

    #[test]
    fn required_arg_separated() {
        let (codes, state, args) = run(&["prog", "-a", "val"], "a:");
        assert_eq!(codes, vec![b'a' as i32]);
        assert_eq!(args[0].as_deref(), Some("val"));
        assert_eq!(state.optind, 3);
    }

    #[test]
    fn missing_required_arg_returns_question() {
        let (codes, state, _) = run(&["prog", "-a"], "a:");
        assert_eq!(codes, vec![b'?' as i32]);
        assert_eq!(state.optopt, b'a');
    }

    #[test]
    fn missing_required_arg_returns_colon_in_silent_mode() {
        let (codes, state, _) = run(&["prog", "-a"], ":a:");
        assert_eq!(codes, vec![b':' as i32]);
        assert_eq!(state.optopt, b'a');
    }

    #[test]
    fn unknown_option_returns_question() {
        let (codes, state, _) = run(&["prog", "-x"], "abc");
        assert_eq!(codes, vec![b'?' as i32]);
        assert_eq!(state.optopt, b'x');
    }

    #[test]
    fn double_dash_terminates_options() {
        let (codes, state, _) = run(&["prog", "-a", "--", "-b"], "ab");
        assert_eq!(codes, vec![b'a' as i32]);
        // optind points past the "--"
        assert_eq!(state.optind, 3);
    }

    #[test]
    fn optional_arg_attached() {
        let (codes, _, args) = run(&["prog", "-aval"], "a::");
        assert_eq!(codes, vec![b'a' as i32]);
        assert_eq!(args[0].as_deref(), Some("val"));
    }

    #[test]
    fn optional_arg_absent() {
        // Optional arg is NOT taken from the next argv slot per glibc.
        let (codes, state, args) = run(&["prog", "-a", "next"], "a::");
        assert_eq!(codes, vec![b'a' as i32]);
        assert_eq!(args[0], None);
        // optind only advances past "-a" — "next" is not consumed.
        assert_eq!(state.optind, 2);
    }

    #[test]
    fn nonoption_argument_stops_scan() {
        let (codes, state, _) = run(&["prog", "file", "-a"], "a");
        assert_eq!(codes, Vec::<i32>::new());
        assert_eq!(state.optind, 1);
    }

    #[test]
    fn lone_dash_stops_scan() {
        let (codes, _state, _) = run(&["prog", "-"], "a");
        assert_eq!(codes, Vec::<i32>::new());
    }

    #[test]
    fn mixed_options_and_args() {
        // -a b c (where 'a' takes required arg) should yield ['a' -> "b"]
        // and stop, not continuing past 'c'.
        let (codes, state, args) = run(&["prog", "-a", "b", "c"], "a:");
        assert_eq!(codes, vec![b'a' as i32]);
        assert_eq!(args[0].as_deref(), Some("b"));
        assert_eq!(state.optind, 3);
    }

    #[test]
    fn arg_ref_position_persists_after_step() {
        // Verify that ArgRef encoding lets the caller re-construct
        // the optarg byte slice from argv.
        let argv: Vec<&[u8]> = vec![b"prog", b"-aXYZ"];
        let optspec = b"a:";
        let mut state = GetoptState::default();
        let r = step_short(&argv, optspec, &mut state);
        assert_eq!(r, StepOutcome::Found(b'a' as i32));
        let arg = state.optarg.expect("optarg set");
        let slice = &argv[arg.argv_idx][arg.byte_offset..];
        assert_eq!(slice, b"XYZ");
    }
}
