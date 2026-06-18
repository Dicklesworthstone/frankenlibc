# bd-2g7oyh.482 - passwd field scanner code-first ledger

## Candidate

- Surface: `/etc/passwd` parser hot path (`pwd::parse_passwd_line`).
- Lever: replace temporary colon-field `Vec<&[u8]>` plus shell-tail `join` with a borrowed `splitn(7)` scanner; replace UTF-8 + `str::parse::<u32>` uid/gid parsing with a checked byte decimal parser.
- Bench target: `resolv_parsers_bench` row `parse_passwd_line_typical`.
- Conformance guard: existing passwd parser tests plus focused guards for minimal fields, empty optional fields, shell-tail colon absorption, sign/junk rejection, and u32 overflow rejection.

## Negative-Evidence Screen

- Do not retry `memchr_absent`, `memcmp`, malloc hot-cycle micro-levers, or `log2f` atanh-series families from prior ledgers; this candidate is a different NSS/parser primitive.
- Do not take `bd-tkcv3c` in this cargo-check-only turn: that realloc in-place path needs malloc stress/differential proof before it is correctness-safe.
- Do not overlap active `cod-b` resolver/group parser leaves (`bd-9ran7n`, `bd-xxrfvu`, `bd-43e21q`, `bd-4crkqx`, `bd-2g7oyh.481`).

## Proof Obligation

- `splitn(7)` maps fields as:
  - 0: name
  - 1: passwd
  - 2: uid
  - 3: gid
  - 4: gecos, optional empty default
  - 5: dir, optional empty default
  - 6: shell including any remaining colons
- The byte decimal parser preserves the previous contract:
  - skips leading glibc whitespace,
  - accepts one leading `+`,
  - requires at least one digit,
  - rejects signs, junk, trailing whitespace, empty fields, and overflow,
  - accepts `0..=u32::MAX`.

## Pending Verdict

- Status: code-first batch-test pending.
- Landing note: source changes were swept into shared commit `2c04ac56a423d8cf772486f49ad2b32ad5939f54`; this artifact remains the bead-specific negative-evidence ledger and verdict anchor.
- Keep only if the later same-worker benchmark shows `parse_passwd_line_typical` improvement with no passwd conformance regression.
- Reject and restore this lever if the focused row regresses or any differential/conformance guard fails.
