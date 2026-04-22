# Dependency Upgrade Log

**Project:** frankenlibc  |  **Language:** Rust

## 2026-04-21 — asupersync-conformance 0.2.5 → 0.3.0

- **Scope:** workspace `Cargo.toml` [workspace.dependencies] only. No other deps touched.
- **Consumers:** `frankenlibc-membrane`, `frankenlibc_conformance`, `frankenlibc-harness`.
- **Breaking change summary (upstream CHANGELOG):** `ObjectParams.source_blocks` widened `u8 → u16` in the top-level `asupersync` crate. The `asupersync-conformance` sub-crate had no breaking API changes documented, and none affected our call sites.
- **Build:** `rch exec -- cargo check --all-targets` → clean on asupersync-conformance v0.3.0.
- **Tests:** `rch exec -- cargo test -p frankenlibc-membrane -p frankenlibc_conformance -p frankenlibc-harness --lib` → 1339/1340 + 114/114 passed. One transient membrane `runtime_math::localization_chooser::observe_throughput_below_strict_budget` flake (perf-sensitive under shared rch-worker load) passes in isolation; unrelated to this bump.
- **Call-site edits:** none required.

## 2026-04-22 — asupersync-conformance 0.3.0 → 0.3.1

- **Commit:** 50b30a9
- **Scope:** workspace root Cargo.toml + crates/frankenlibc_conformance/Cargo.toml
- **Breaking:** None (patch bump on crates.io published at 2026-04-21T23:58:52Z)
- **Note:** The base `asupersync` crate is NOT a dependency of this workspace; only `asupersync-conformance` is.
- **Build:** `rch exec -- cargo check --workspace --all-targets` → clean.

## 2026-04-22 — Library-updater session

**Agent:** Clawdstein-libupdater-frankenlibc

### Discovery — dep gap analysis

| Dep | Installed | Latest stable | Gap type |
|---|---|---|---|
| parking_lot | 0.12.5 | 0.12.5 | up-to-date |
| thiserror | 2.0.18 | 2.0.18 | up-to-date |
| serde | 1.0.228 | 1.0.228 | up-to-date |
| serde_json | 1.0.149 | 1.0.149 | up-to-date |
| serde_yaml | 0.9.34+deprecated | 0.9.34+deprecated | up-to-date (deprecated crate) |
| tracing | 0.1.44 | 0.1.44 | up-to-date |
| libm | 0.2.16 | 0.2.16 | up-to-date |
| blake3 | 1.8.3 | 1.8.4 | patch |
| libc | 0.2.183 | 0.2.185 | patch |
| clap | 4.6.0 | 4.6.1 | patch |
| proptest | 1.10.0 | 1.11.0 | minor (cargo update only) |
| sha2 | 0.10.9 | 0.11.0 | 0.x minor-major (breaking in ecosystem) |
| md-5 | 0.10.6 | 0.11.0 | 0.x minor-major (breaking in ecosystem) |
| criterion | 0.5.1 | 0.8.2 | multi-major |
| ftui-* | 0.2.1 | 0.3.1 | 0.x minor-major |

### Updates

#### blake3: manifest floor 1.5 -> 1.8 (actual 1.8.3 -> 1.8.4)
- **Scope:** workspace root Cargo.toml
- **Breaking:** None (still 1.x, patch). Brings caret floor up to latest 1.8.x.
- **Build:** `rch exec -- cargo check --workspace --all-targets` -> clean.

#### clap: manifest floor 4.5 -> 4.6 (actual 4.6.0 -> 4.6.1)
- **Scope:** workspace root Cargo.toml + crates/frankenlibc_conformance/Cargo.toml (pinned separately there)
- **Breaking:** None (still 4.x, patch).
- **Build:** `rch exec -- cargo check --workspace --all-targets` -> clean.

#### ftui-* (core/layout/render/style/widgets/harness): 0.2.1 -> 0.3.1
- **Scope:** workspace root Cargo.toml + crates/frankenlibc-harness/Cargo.toml + crates/frankenlibc-membrane/Cargo.toml + crates/frankenlibc_conformance/Cargo.toml
- **Breaking:** 0.x minor-major (0.2.1 -> 0.3.1). Tested against our 52 call sites in 6 files; all compile cleanly with no API change needed.
- **Build:** `rch exec -- cargo check --workspace --all-targets` -> clean.
- **Tests:** `rch exec -- cargo test -p frankenlibc-membrane --lib` -> 1339/1340 pass; 1 pre-existing flake (`runtime_math::localization_chooser::tests::observe_throughput_below_strict_budget`, passes in isolation) identical to the one noted in the previous asupersync bump session. Unrelated to ftui.

#### proptest: 1.6 -> 1.11 (dev-dep)
- **Scope:** crates/frankenlibc-core/Cargo.toml, crates/frankenlibc-membrane/Cargo.toml
- **Breaking:** None published between 1.6 and 1.11 that affect our call sites (no strategy/config API changes).
- **Build:** `rch exec -- cargo check --workspace --all-targets` -> clean.
- **Tests:** `rch exec -- cargo test -p frankenlibc-core --lib` -> 1211 passed, 1 flaky concurrency test (`malloc::allocator::tests::free_matches_waiting_consumer_through_elimination`) that passes in isolation / single-threaded. This is an elimination-based allocator concurrency test, unrelated to proptest — same category as the previously-noted `runtime_math::localization_chooser::observe_throughput_below_strict_budget` flake under shared rch-worker load.

