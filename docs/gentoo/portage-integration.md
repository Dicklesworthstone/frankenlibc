# Gentoo Portage Integration for FrankenLibC

This guide documents how to run Gentoo package builds and tests with FrankenLibC interposition in a way that is reproducible and debuggable.

## Scope

- Target deployment model: `LD_PRELOAD` interposition using `libfrankenlibc_abi.so`.
- Runtime mode: `FRANKENLIBC_MODE=strict|hardened` (default recommended: `hardened` for ecosystem validation).
- Primary objective: validate package build/test behavior and capture healing telemetry.

## Portage Workflow Refresher

For a package atom like `dev-db/redis`, the high-level flow is:

1. Dependency resolution (`emerge -pv` / graph solve).
2. Ebuild phase execution:
   - `pkg_pretend`
   - `pkg_setup`
   - `src_unpack`
   - `src_prepare`
   - `src_configure`
   - `src_compile`
   - `src_test`
   - `src_install`
   - `pkg_preinst`
   - `pkg_postinst`
3. Optional package test invocation with `FEATURES="test"`.
4. Binpkg or install result recording via Portage logs.

Key observation: `LD_PRELOAD` is most useful in runtime-heavy phases (`src_test`, optionally selected `src_compile` workloads that execute generated binaries/tools).

## Integration Points

## 1) Global Bashrc Hook

Portage supports a global hook file at `/etc/portage/bashrc` that runs in ebuild phase context.

Recommended pattern:

- Keep `/etc/portage/bashrc` small.
- Source a dedicated hook file (`scripts/gentoo/frankenlibc-ebuild-hooks.sh`).
- Gate activation by phase and package allow/block lists.

Template file in this repo:

- `configs/gentoo/portage-bashrc`
- legacy alias: `configs/gentoo/frankenlibc.bashrc`

Hook implementation in this repo:

- `scripts/gentoo/frankenlibc-ebuild-hooks.sh`
- integration image: `docker/gentoo/Dockerfile.frankenlibc`
- log tooling: `scripts/gentoo/collect-logs.sh`, `scripts/gentoo/analyze-logs.py`

## 2) Per-Package Environment Overrides

For package-specific behavior:

- `/etc/portage/env/<category>/<package>` for environment overrides.
- `/etc/portage/package.env` to map package atoms to env files.

Use this for packages needing:

- different phase allowlists,
- strict mode instead of hardened,
- temporary disablement of interposition.

## 3) make.conf Baseline Knobs

Relevant baseline knobs in `/etc/portage/make.conf`:

- `FEATURES="test"` to run package test suites.
- `CFLAGS`/`CXXFLAGS`/`LDFLAGS` for reproducible build settings.
- `PORTAGE_TMPDIR` and `PORTAGE_LOGDIR` for artifact collection.

## Build-Time vs Runtime Evidence Capture

## Dependency and Build-Time Traceability

Use:

- `emerge -ptv <atom>` for dependency tree and USE-expanded plan.
- `emerge --tree --verbose <atom>` for readable transitive dependency view.

Store command outputs into run artifacts for reproducibility.

## Runtime Interposition Evidence

Use:

- `FRANKENLIBC_LOG` or project-specific telemetry envs to emit JSONL evidence.
- package-scoped log directories (for example, `/var/log/frankenlibc/portage/<atom>/`).

At minimum capture:

- package atom,
- ebuild phase,
- mode (`strict`/`hardened`),
- outcome/exit code,
- FrankenLibC log path.

## Test-Suite Execution with Interposition

Recommended command form:

```bash
FEATURES="test" emerge -1v dev-db/redis
```

With hook-based preload active for test phases, this exercises package tests under FrankenLibC without modifying ebuilds.

## Static Linking and setuid Caveats

`LD_PRELOAD` will not reliably affect:

- statically linked binaries,
- setuid/setgid execution paths (dynamic linker sanitizes preload env).

Operational policy:

1. Detect and flag static binaries in package artifacts.
2. Treat setuid-sensitive packages as exclusions or special-case runs.
3. Record these in a package exclusion policy artifact.

## Portage Sandbox Notes

Typical Gentoo hardening features include `sandbox`, `usersandbox`, and `userpriv`.

Implications:

- preload logs must be written to sandbox-allowed paths,
- phase hooks should avoid ad-hoc writes outside configured log dirs,
- if a package needs extra writable paths, prefer per-package env/sandbox configuration rather than global bypass.

## Recommended Starter Validation Set

Validated starter workflow for three representative packages:

1. `sys-apps/which` (simple baseline).
2. `sys-apps/coreutils` (common libc surface).
3. `net-misc/curl` (network + TLS + parser pressure).

For each package:

1. Dry-run dependency plan (`emerge -ptv`).
2. Build with `FEATURES="test"` and hook-enabled preload.
3. Archive Portage logs + FrankenLibC JSONL logs.
4. Record pass/fail and healing summary.

## Operational Checklist

1. Install FrankenLibC ABI library to host path (for example `/opt/frankenlibc/lib/libfrankenlibc_abi.so`).
2. Install hook script and bashrc template.
3. Enable `FEATURES="test"` for validation runs.
4. Start with test-phase-only preload (`src_test pkg_test`) before expanding to compile phases.
5. Maintain package blocklist for problematic atoms.
6. Keep per-package artifacts for reproducibility.

## Related Documents

- `docs/gentoo/binary-cache.md` — build-once/test-many cache policy and commands.
