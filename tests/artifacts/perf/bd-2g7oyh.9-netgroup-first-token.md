# bd-2g7oyh.9 netgroup parser first-token early reject

## Profile target

- Bead: `bd-2g7oyh.9`
- Target: `crates/frankenlibc-core/src/netgroup/mod.rs::parse_netgroup_triples`
- Scenario: `/etc/netgroup` content with comments, four nonmatching groups, and two matching `admins` lines.
- Baseline command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench resolv_parsers_bench`
- Baseline worker: `vmi1153651`

## Baseline p50

| Bench | p50 ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: |
| `parse_hosts_line_typical` | 155.349 | 207.492 | 281.132 |
| `parse_services_line_typical` | 183.302 | 261.814 | 279.851 |
| `parse_protocols_line_typical` | 154.435 | 215.014 | 253.814 |
| `parse_networks_line_typical` | 196.953 | 249.486 | 304.294 |
| `parse_aliases_line_typical` | 159.468 | 255.565 | 308.351 |
| `parse_netgroup_triples_match` | 775.335 | 1425.271 | 1827.021 |

Additional non-string profile context: `stdio_bench` showed stream setup/buffering rows at `full_buffered_write=717.36 ns` and `line_buffered_write=690.41 ns`, but that target was setup/allocation-heavy and weaker for a narrow semantic lever than the parser hotspot.

## Alien primitive

Canonical source: `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` section 7.5, ART prefix-gated lookup / path compression; supporting pattern from `high_level_summary_of_frankensuite_planned_and_implemented_features_and_concepts.md`, staged early-exit validation.

Recommendation card:

- Primitive: inspect the discriminating first token before entering heavier line comment stripping and triple extraction.
- Runtime artifact: private scalar `first_token_bounds` prefilter with exact fallback to the existing parser for matching lines.
- Fallback: revert if existing netgroup output hash changes, comment semantics change, or post-RCH p50 regresses.
- EV score: Impact 3 x Confidence 4 / Effort 1 = 12.0.

## Isomorphism proof

- Ordering preserved: lines are still visited in original order; matching duplicate group lines still append triples in encounter order.
- Tie-breaking unchanged: the first nonempty token after leading space/tab remains the group selector.
- Case matching unchanged: group names still use exact `eq_ignore_ascii_case`.
- Comment semantics preserved: leading comments still skip the line; `#` inside or after the group token truncates the parse tail; triples after an inline comment are ignored.
- Field parsing unchanged: matching lines still use the same `extract_triples_into`, comma split, ASCII trim, missing-field defaults, and owned field vectors.
- Floating-point: N/A.
- RNG: N/A.

## Golden behavior proof

- Pre command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core netgroup --lib -- --nocapture --test-threads=1`
- Pre existing 15-test line sha256: `379ccb0b102eb727a6f7fa2568c6c4727acc492c5018ff21a89a3554a84c6a9d`
- Post command: same as pre.
- Post existing 15-test line sha256: `379ccb0b102eb727a6f7fa2568c6c4727acc492c5018ff21a89a3554a84c6a9d`
- Post full 17-test line sha256: `2d3d6fbe5d75d95adbd61791ea095821c64e99944eaf7dff9d276e4455125ff0`

## Post benchmark

- Command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench resolv_parsers_bench`
- Worker: `vmi1153651`

| Bench | Baseline p50 ns/op | Post p50 ns/op | Delta |
| --- | ---: | ---: | ---: |
| `parse_netgroup_triples_match` | 775.335 | 601.990 | 1.29x faster |

Tail movement: p95 `1425.271 -> 819.517 ns`; p99 `1827.021 -> 949.700 ns`.

Gate decision: kept. The targeted parser row improves p50 by 22.4%, p95 by 42.5%, and p99 by 48.0% with unchanged behavior hash.

## Validation

- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core netgroup --lib -- --nocapture --test-threads=1` passed 17/17.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets` passed.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings` passed.
- `TMPDIR=/data/tmp cargo fmt --check -p frankenlibc-core` passed locally.
- `git diff --check` passed for the reserved files.

## Source

- Pre `netgroup/mod.rs` sha256: `bc39ed92ccce19d695ff81d90c954d1ca9dc059b682bffd84497caad126b9f6c`
- Post `netgroup/mod.rs` sha256: `20b75904117ab5ea83dbc29836aa4ea02efa60b219be6d077b48bf5207a28621`
