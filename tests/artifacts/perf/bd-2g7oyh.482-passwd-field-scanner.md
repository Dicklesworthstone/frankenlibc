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

## Measured Verdict

- Status: measured reject; optimization reverted.
- Landing note: source changes were originally swept into shared commit
  `2c04ac56a423d8cf772486f49ad2b32ad5939f54`; this gauntlet pass converted the
  pending claim into deployed ABI evidence against host glibc.
- Bench command:

  ```bash
  AGENT_NAME=cod-a \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-a/criterion-bd-2g7oyh-482-passwd \
  rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
    --bench baseline_capture_bench nss_passwd_lookup -- --noplot
  ```

- Worker: `ovh-a`.
- `getpwnam("root")`: FrankenLibC p50 `10.906 us`, glibc p50 `10.013 us`,
  ratio `1.089x`; mean ratio `1.088x`; **LOSS**.
- `getpwuid(0)`: FrankenLibC p50 `31.495 us`, glibc p50 `9.957 us`, ratio
  `3.163x`; mean ratio `3.326x`; **LOSS**.
- Action: reverted `parse_passwd_line` to the prior colon-field
  `Vec<&[u8]>`, shell-tail `join`, and UTF-8 + `str::parse` numeric path.

## Post-Revert Validation

- `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a rch exec -- cargo test -p frankenlibc-core pwd:: --lib`: 79 passed.
- `AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a rch exec -- cargo check -p frankenlibc-bench --features abi-bench --bench baseline_capture_bench`: passed.
- `rustfmt --edition 2024 --config skip_children=true --check crates/frankenlibc-core/src/pwd/mod.rs crates/frankenlibc-bench/benches/baseline_capture_bench.rs`: passed.
- `cargo clippy -p frankenlibc-core --lib -- -D warnings`: blocked on rch because
  `cargo-clippy` is not installed for `nightly-2026-04-28-x86_64-unknown-linux-gnu`.

## Retry Predicate

Do not retry the passwd colon-field scanner or byte-decimal parser as a standalone
perf lever. Future passwd/NSS perf work should target lookup/cache behavior,
especially the deployed `getpwuid(0)` scan path, and must use a fresh ABI vs
host-glibc benchmark.
