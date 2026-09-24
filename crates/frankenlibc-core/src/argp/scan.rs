//! Reentrant GNU-style option scanner for argp.
//!
//! GNU argp drives a private getopt: it must not disturb the application's
//! `optind`/`optarg`/`opterr` globals, and it restarts cleanly for every
//! `argp_parse`. This scanner reproduces the observable GNU getopt_long
//! contract that argp exposes through `state->next`, the final argv order and
//! the diagnostics on stderr:
//!
//! * three orderings — PERMUTE (default: operands are skipped in place and
//!   rotated behind the options once, when the scan ends), REQUIRE_ORDER (stop
//!   at the first operand) and RETURN_IN_ORDER (operands are reported in
//!   place);
//! * `--` ends option scanning; a lone `-` is an operand;
//! * short-option clusters (`-vqoFILE`), required and optional arguments;
//! * long options with `=value`, unique-prefix abbreviation, ambiguity
//!   detection that ignores prefixes naming the same option, and
//!   long-only mode (`-name`) with fallback to short options;
//! * `optind` advances exactly when GNU getopt's does (e.g. not until a short
//!   cluster is exhausted), because argp reports it to parsers.
//!
//! The scanner never owns argv: it reads elements through [`ArgvView`] and
//! asks it to rotate ranges, so the ABI layer can mirror the permutation onto
//! the caller's real `char **argv`.

/// Whether an option takes an argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HasArg {
    No,
    Required,
    Optional,
}

/// A short option: `ch` is the option byte, `id` is returned on a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortOpt {
    pub ch: u8,
    pub has_arg: HasArg,
    pub id: usize,
}

/// A long option. Two entries with equal `has_arg` and `id` name the same
/// option (aliases), which matters for abbreviation ambiguity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongOpt {
    pub name: Vec<u8>,
    pub has_arg: HasArg,
    pub id: usize,
}

/// Operand ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ordering {
    Permute,
    RequireOrder,
    ReturnInOrder,
}

/// Read access to argv plus the one mutation getopt performs.
pub trait ArgvView {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn arg(&self, i: usize) -> &[u8];
    /// Rotate `[bottom, top)` left by `middle - bottom`, so the elements in
    /// `[middle, top)` come first.
    fn rotate(&mut self, bottom: usize, middle: usize, top: usize);
}

impl ArgvView for Vec<Vec<u8>> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
    fn arg(&self, i: usize) -> &[u8] {
        &self[i]
    }
    fn rotate(&mut self, bottom: usize, middle: usize, top: usize) {
        self[bottom..top].rotate_left(middle - bottom);
    }
}

/// Where an option argument lives: `argv[index][offset..]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArgPos {
    pub index: usize,
    pub offset: usize,
}

/// One scanner step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// An option matched; `arg` is its argument, if any.
    Opt { id: usize, arg: Option<ArgPos> },
    /// RETURN_IN_ORDER operand at `argv[index]`.
    Operand { index: usize },
    /// Option scanning is over; `optind` is the first unscanned element.
    End,
    /// Unknown/ambiguous option or bad argument. `message` is the GNU
    /// diagnostic line (`"prog: ...\n"`), present when errors are printed.
    Error { message: Option<Vec<u8>> },
}

/// Scanner configuration.
#[derive(Clone, Debug)]
pub struct Options {
    pub shorts: Vec<ShortOpt>,
    pub longs: Vec<LongOpt>,
    pub ordering: Ordering,
    pub long_only: bool,
    pub print_errors: bool,
}

/// Scanner state. `optind == 0` (re)initialises on the next step.
#[derive(Clone, Debug, Default)]
pub struct Scanner {
    pub optind: usize,
    nextchar: Option<(usize, usize)>,
    first_nonopt: usize,
    last_nonopt: usize,
    initialized: bool,
}

fn is_operand(s: &[u8]) -> bool {
    s.first() != Some(&b'-') || s.len() == 1
}

impl Scanner {
    pub fn new() -> Self {
        Self::default()
    }

    fn exchange<A: ArgvView>(&mut self, argv: &mut A) {
        let (bottom, middle, top) = (self.first_nonopt, self.last_nonopt, self.optind);
        if bottom < middle && middle < top {
            argv.rotate(bottom, middle, top);
        }
        self.first_nonopt += self.optind - self.last_nonopt;
        self.last_nonopt = self.optind;
    }

    /// Advance one step.
    pub fn step<A: ArgvView>(&mut self, argv: &mut A, opts: &Options) -> Event {
        let argc = argv.len();
        if self.optind == 0 || !self.initialized {
            if self.optind == 0 {
                self.optind = 1;
            }
            self.first_nonopt = self.optind;
            self.last_nonopt = self.optind;
            self.nextchar = None;
            self.initialized = true;
        }

        if self.nextchar.is_none() {
            self.last_nonopt = self.last_nonopt.min(self.optind);
            self.first_nonopt = self.first_nonopt.min(self.optind);

            if opts.ordering == Ordering::Permute {
                if self.first_nonopt != self.last_nonopt && self.last_nonopt != self.optind {
                    self.exchange(argv);
                } else if self.last_nonopt != self.optind {
                    self.first_nonopt = self.optind;
                }
                while self.optind < argc && is_operand(argv.arg(self.optind)) {
                    self.optind += 1;
                }
                self.last_nonopt = self.optind;
            }

            if self.optind != argc && argv.arg(self.optind) == b"--" {
                self.optind += 1;
                if self.first_nonopt != self.last_nonopt && self.last_nonopt != self.optind {
                    self.exchange(argv);
                } else if self.first_nonopt == self.last_nonopt {
                    self.first_nonopt = self.optind;
                }
                self.last_nonopt = argc;
                self.optind = argc;
            }

            if self.optind >= argc {
                if self.first_nonopt != self.last_nonopt {
                    self.optind = self.first_nonopt;
                }
                return Event::End;
            }

            if is_operand(argv.arg(self.optind)) {
                if opts.ordering == Ordering::RequireOrder {
                    return Event::End;
                }
                let index = self.optind;
                self.optind += 1;
                return Event::Operand { index };
            }

            let cur = argv.arg(self.optind);
            let dashes = if cur.get(1) == Some(&b'-') { 2 } else { 1 };
            if !opts.longs.is_empty()
                && (dashes == 2
                    || (opts.long_only && (cur.len() > 2 || short_lookup(opts, cur[1]).is_none())))
            {
                if let Some(ev) = self.long_option(argv, opts, dashes) {
                    return ev;
                }
                // Long-only fallback: "-x..." whose first byte is a short
                // option is parsed as a short cluster; anything else is
                // unrecognized.
                let cur = argv.arg(self.optind);
                if !opts.long_only || dashes == 2 || short_lookup(opts, cur[1]).is_none() {
                    let message = opts.print_errors.then(|| {
                        let prefix: &[u8] = if dashes == 2 { b"--" } else { b"-" };
                        diag(
                            argv.arg(0),
                            &[b"unrecognized option '", prefix, &cur[dashes..], b"'"],
                        )
                    });
                    self.optind += 1;
                    self.nextchar = None;
                    return Event::Error { message };
                }
            }
            self.nextchar = Some((self.optind, 1));
        }

        self.short_option(argv, opts)
    }

    fn short_option<A: ArgvView>(&mut self, argv: &mut A, opts: &Options) -> Event {
        let argc = argv.len();
        let (idx, off) = self.nextchar.expect("short scan position");
        let elem_len = argv.arg(idx).len();
        let c = argv.arg(idx)[off];
        let rest = off + 1;
        if rest >= elem_len {
            self.optind += 1;
        }
        let Some(found) = short_lookup(opts, c) else {
            self.nextchar = (rest < elem_len).then_some((idx, rest));
            let message = opts
                .print_errors
                .then(|| diag(argv.arg(0), &[b"invalid option -- '", &[c], b"'"]));
            return Event::Error { message };
        };
        match found.has_arg {
            HasArg::No => {
                self.nextchar = (rest < elem_len).then_some((idx, rest));
                Event::Opt {
                    id: found.id,
                    arg: None,
                }
            }
            HasArg::Optional => {
                self.nextchar = None;
                if rest < elem_len {
                    self.optind += 1;
                    Event::Opt {
                        id: found.id,
                        arg: Some(ArgPos {
                            index: idx,
                            offset: rest,
                        }),
                    }
                } else {
                    Event::Opt {
                        id: found.id,
                        arg: None,
                    }
                }
            }
            HasArg::Required => {
                self.nextchar = None;
                if rest < elem_len {
                    self.optind += 1;
                    Event::Opt {
                        id: found.id,
                        arg: Some(ArgPos {
                            index: idx,
                            offset: rest,
                        }),
                    }
                } else if self.optind >= argc {
                    let message = opts.print_errors.then(|| {
                        diag(
                            argv.arg(0),
                            &[b"option requires an argument -- '", &[c], b"'"],
                        )
                    });
                    Event::Error { message }
                } else {
                    let index = self.optind;
                    self.optind += 1;
                    Event::Opt {
                        id: found.id,
                        arg: Some(ArgPos { index, offset: 0 }),
                    }
                }
            }
        }
    }

    /// Match `argv[optind][dashes..]` against the long options. `None` means
    /// no option matched (the caller decides between error and fallback).
    fn long_option<A: ArgvView>(
        &mut self,
        argv: &mut A,
        opts: &Options,
        dashes: usize,
    ) -> Option<Event> {
        let argc = argv.len();
        let idx = self.optind;
        let elem = argv.arg(idx);
        let body = &elem[dashes..];
        let name_len = body.iter().position(|&b| b == b'=').unwrap_or(body.len());
        let name = &body[..name_len];
        let prefix: &[u8] = if dashes == 2 { b"--" } else { b"-" };

        let found = match opts.longs.iter().position(|o| o.name == name) {
            Some(i) => i,
            None => {
                let mut first: Option<usize> = None;
                let mut ambiguous: Vec<usize> = Vec::new();
                for (i, o) in opts.longs.iter().enumerate() {
                    if !o.name.starts_with(name) {
                        continue;
                    }
                    match first {
                        None => first = Some(i),
                        Some(f) => {
                            let p = &opts.longs[f];
                            if opts.long_only || o.has_arg != p.has_arg || o.id != p.id {
                                if ambiguous.is_empty() {
                                    ambiguous.push(f);
                                }
                                ambiguous.push(i);
                            }
                        }
                    }
                }
                if !ambiguous.is_empty() {
                    let message = opts.print_errors.then(|| {
                        let mut parts: Vec<&[u8]> =
                            vec![b"option '", prefix, name, b"' is ambiguous; possibilities:"];
                        for &i in &ambiguous {
                            parts.extend_from_slice(&[b" '", prefix, &opts.longs[i].name, b"'"]);
                        }
                        diag(argv.arg(0), &parts)
                    });
                    self.optind += 1;
                    self.nextchar = None;
                    return Some(Event::Error { message });
                }
                first?
            }
        };

        let opt = &opts.longs[found];
        self.optind += 1;
        self.nextchar = None;
        if name_len < body.len() {
            if opt.has_arg == HasArg::No {
                let message = opts.print_errors.then(|| {
                    diag(
                        argv.arg(0),
                        &[
                            b"option '",
                            prefix,
                            &opt.name,
                            b"' doesn't allow an argument",
                        ],
                    )
                });
                return Some(Event::Error { message });
            }
            return Some(Event::Opt {
                id: opt.id,
                arg: Some(ArgPos {
                    index: idx,
                    offset: dashes + name_len + 1,
                }),
            });
        }
        if opt.has_arg == HasArg::Required {
            if self.optind >= argc {
                let message = opts.print_errors.then(|| {
                    diag(
                        argv.arg(0),
                        &[b"option '", prefix, &opt.name, b"' requires an argument"],
                    )
                });
                return Some(Event::Error { message });
            }
            let index = self.optind;
            self.optind += 1;
            return Some(Event::Opt {
                id: opt.id,
                arg: Some(ArgPos { index, offset: 0 }),
            });
        }
        Some(Event::Opt {
            id: opt.id,
            arg: None,
        })
    }
}

fn short_lookup(opts: &Options, c: u8) -> Option<ShortOpt> {
    if c == b':' || c == b';' {
        return None;
    }
    opts.shorts.iter().copied().find(|s| s.ch == c)
}

fn diag(prog: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut m = prog.to_vec();
    m.extend_from_slice(b": ");
    for p in parts {
        m.extend_from_slice(p);
    }
    m.push(b'\n');
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(v: &[&str]) -> Vec<Vec<u8>> {
        v.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    fn opts(ordering: Ordering) -> Options {
        Options {
            shorts: vec![
                ShortOpt {
                    ch: b'v',
                    has_arg: HasArg::No,
                    id: 1,
                },
                ShortOpt {
                    ch: b'o',
                    has_arg: HasArg::Required,
                    id: 2,
                },
                ShortOpt {
                    ch: b'p',
                    has_arg: HasArg::Optional,
                    id: 3,
                },
            ],
            longs: vec![
                LongOpt {
                    name: b"verbose".to_vec(),
                    has_arg: HasArg::No,
                    id: 1,
                },
                LongOpt {
                    name: b"out".to_vec(),
                    has_arg: HasArg::Required,
                    id: 2,
                },
                LongOpt {
                    name: b"output".to_vec(),
                    has_arg: HasArg::Required,
                    id: 2,
                },
                LongOpt {
                    name: b"opt".to_vec(),
                    has_arg: HasArg::Optional,
                    id: 3,
                },
            ],
            ordering,
            long_only: false,
            print_errors: true,
        }
    }

    /// Run to End, returning (id-or-operand, arg text, optind) per event.
    fn run(a: &mut Vec<Vec<u8>>, o: &Options) -> Vec<(String, usize)> {
        let mut s = Scanner::new();
        let mut out = Vec::new();
        loop {
            let ev = s.step(a, o);
            let text = match &ev {
                Event::Opt { id, arg } => format!(
                    "{id}:{}",
                    arg.map_or(String::from("-"), |p| String::from_utf8_lossy(
                        &a[p.index][p.offset..]
                    )
                    .into_owned())
                ),
                Event::Operand { index } => {
                    format!("arg:{}", String::from_utf8_lossy(&a[*index]))
                }
                Event::End => format!("end@{}", s.optind),
                Event::Error { message } => {
                    format!(
                        "err:{}",
                        String::from_utf8_lossy(message.as_deref().unwrap_or(b""))
                    )
                }
            };
            out.push((text, s.optind));
            if matches!(ev, Event::End | Event::Error { .. }) {
                return out;
            }
        }
    }

    #[test]
    fn permute_defers_rotation_and_reports_gnu_optind() {
        let mut a = argv(&[
            "prog", "-v", "a", "-o", "F", "b", "--out=G", "c", "-oH", "d",
        ]);
        let r = run(&mut a, &opts(Ordering::Permute));
        let got: Vec<_> = r.iter().map(|(t, i)| format!("{t}@{i}")).collect();
        assert_eq!(got, ["1:-@2", "2:F@5", "2:G@7", "2:H@9", "end@6@6"]);
        assert_eq!(
            a,
            argv(&[
                "prog", "-v", "-o", "F", "--out=G", "-oH", "a", "b", "c", "d"
            ])
        );
    }

    #[test]
    fn clusters_advance_optind_only_when_exhausted() {
        let mut a = argv(&["prog", "-vvoFILE", "-vp", "-pX"]);
        let r = run(&mut a, &opts(Ordering::Permute));
        let got: Vec<_> = r.iter().map(|(t, i)| format!("{t}@{i}")).collect();
        assert_eq!(
            got,
            [
                "1:-@1", "1:-@1", "2:FILE@2", "1:-@2", "3:-@3", "3:X@4", "end@4@4"
            ]
        );
    }

    #[test]
    fn double_dash_and_in_order_and_require_order() {
        let mut a = argv(&["prog", "-v", "x", "--", "-o", "y"]);
        run(&mut a, &opts(Ordering::Permute));
        assert_eq!(a, argv(&["prog", "-v", "--", "x", "-o", "y"]));

        let mut a = argv(&["prog", "-v", "a", "-o", "F", "b"]);
        let r = run(&mut a, &opts(Ordering::ReturnInOrder));
        let got: Vec<_> = r.into_iter().map(|(t, _)| t).collect();
        assert_eq!(got, ["1:-", "arg:a", "2:F", "arg:b", "end@6"]);

        let mut a = argv(&["prog", "-v", "a", "-o", "F"]);
        let r = run(&mut a, &opts(Ordering::RequireOrder));
        assert_eq!(r.last().unwrap().0, "end@2");
    }

    #[test]
    fn long_matching_abbreviation_aliases_and_errors() {
        let o = opts(Ordering::Permute);
        // "--outp" uniquely abbreviates the alias "output".
        let mut a = argv(&["prog", "--verb", "--outp=B"]);
        let got: Vec<_> = run(&mut a, &o).into_iter().map(|(t, _)| t).collect();
        assert_eq!(got, ["1:-", "2:B", "end@3"]);
        // "--o" matches out/output (same option) and opt: ambiguous.
        let mut a = argv(&["prog", "--o", "x"]);
        assert_eq!(
            run(&mut a, &o)[0].0,
            "err:prog: option '--o' is ambiguous; possibilities: '--out' '--opt'\n"
        );
        for (args, msg) in [
            (
                &["prog", "--nope=1"][..],
                "prog: unrecognized option '--nope=1'\n",
            ),
            (
                &["prog", "--verbose=1"],
                "prog: option '--verbose' doesn't allow an argument\n",
            ),
            (
                &["prog", "--ou"],
                "prog: option '--out' requires an argument\n",
            ),
            (&["prog", "-z"], "prog: invalid option -- 'z'\n"),
            (
                &["prog", "a", "-o"],
                "prog: option requires an argument -- 'o'\n",
            ),
        ] {
            let mut a = argv(args);
            assert_eq!(
                run(&mut a, &o).last().unwrap().0,
                format!("err:{msg}"),
                "{args:?}"
            );
        }
    }

    #[test]
    fn long_only_prefers_long_then_falls_back_to_short() {
        let mut o = opts(Ordering::Permute);
        o.long_only = true;
        let mut a = argv(&["prog", "-verbose", "-out", "F", "-v", "-vo", "G"]);
        let got: Vec<_> = run(&mut a, &o).into_iter().map(|(t, _)| t).collect();
        // "-vo" is not a long option: parsed as the short cluster -v -o G.
        assert_eq!(got, ["1:-", "2:F", "1:-", "1:-", "2:G", "end@7"]);
    }
}
