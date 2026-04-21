# Dependency Upgrade Log

**Project:** frankenlibc  |  **Language:** Rust

## 2026-04-21 — asupersync-conformance 0.2.5 → 0.3.0

- **Scope:** workspace `Cargo.toml` [workspace.dependencies] only. No other deps touched.
- **Consumers:** `frankenlibc-membrane`, `frankenlibc_conformance`, `frankenlibc-harness`.
- **Breaking change summary (upstream CHANGELOG):** `ObjectParams.source_blocks` widened `u8 → u16` in the top-level `asupersync` crate. The `asupersync-conformance` sub-crate had no breaking API changes documented, and none affected our call sites.
- **Build:** `rch exec -- cargo check --all-targets` → clean on asupersync-conformance v0.3.0.
- **Tests:** `rch exec -- cargo test -p frankenlibc-membrane -p frankenlibc_conformance -p frankenlibc-harness --lib` → 1339/1340 + 114/114 passed. One transient membrane `runtime_math::localization_chooser::observe_throughput_below_strict_budget` flake (perf-sensitive under shared rch-worker load) passes in isolation; unrelated to this bump.
- **Call-site edits:** none required.

