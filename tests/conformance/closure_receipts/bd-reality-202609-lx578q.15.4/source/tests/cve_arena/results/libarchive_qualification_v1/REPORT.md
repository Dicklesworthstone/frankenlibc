# FrankenLibC Bounded Application Security Qualification Report (`libarchive`)

- **Profile ID:** `libarchive-confined-archive-worker-v1`
- **Integrated S22 Disposition:** `not_qualified`
- **Candidate Artifact (`libfrankenlibc_abi.so`):** `c8fe407190a3a8936b3c48b4bbd9a9c5354a3b49d343554d1fdb9b4a0c29da6c`
- **Confinement Backend:** `bwrap-ro-root-isolated-staging`

## 1. Public Scoped Evidence Summary (`SQ.10` Template)

On ordinary `-O2` upstream `libarchive` builds (`v3.8.7` commit `ded82291ab41` for `CVE-2026-45308` / `GHSA-xgqq-r5j8-3mch` and `v3.7.9` commit `8a7a9cc527fd` for `CVE-2025-5915` / `GHSA-6vpf-5947-22g5`), untrusted archive inputs reached dynamically linked `malloc`/`realloc`/`memcpy`/`free` symbols. Under `libarchive-confined-archive-worker-v1` (`FRANKENLIBC_MODE=hardened` inside `bwrap` read-only root + isolated staging + stock-glibc `v3.8.8` output validation), we observed hardware-watchpoint-confirmed out-of-bounds heap write (`offset +65536`) and out-of-bounds heap read (64-byte LZSS window over-read across live neighbor canary block) in both `H` (stock glibc) and `S` (FrankenLibC `strict`), and measured exclusion of both out-of-bounds accesses in `F` (FrankenLibC `hardened`, `ClampSize` bounds clamping) with quarantined non-publication of truncated ZIP output (`S11`). Benign multi-format conversions (`5/5` cells) passed independent `v3.8.8` archive validation with paired `F/H` wall-time ratio `1.512x` (95% CI `[1.1393, 2.1116]`). Explicit exclusions remain: compiler-inlined direct pointer stores bypassing libc entrypoints (`S23_holdout_boundary_inlined_direct_write_bypass` -> `unsupported`), `strict` mode (`observed_harm`), static binaries, custom non-malloc arenas, and cross-application generalization beyond tested `libarchive` paths.

## 2. Primary 4-Arm + Patched Counterfactual Matrix (`S08-S09`, `S13-S14`)

| Case | Arm | Provider / Mode | Watchpoint Armed | Watchpoint Triggered | Unobserved Exit | Published | Qualification |
|------|-----|-----------------|------------------|----------------------|-----------------|-----------|---------------|
| `S09_zip_cd_68000_overflow` | `H` | `host_glibc` (`none`) | `5` | `True` | `134` | `False` | `experiment_only` (`detected_after_harm`) |
| `S09_zip_cd_68000_overflow` | `S` | `frankenlibc` (`strict`) | `5` | `True` | `134` | `False` | `experiment_only` (`detected_after_harm`) |
| `S09_zip_cd_68000_overflow` | `F` | `frankenlibc` (`hardened`) | `6` | `False` | `0` | `False` | `profile_accepted` (`safe_rejection_in_tested_case`) |
| `S09_zip_cd_68000_overflow` | `P` | `host_glibc` (`none`) | `3` | `False` | `11` | `False` | `profile_accepted` (`safe_rejection_in_tested_case`) |
| `S09_zip_cd_68000_overflow` | `PF` | `frankenlibc` (`hardened`) | `3` | `False` | `11` | `False` | `profile_accepted` (`safe_rejection_in_tested_case`) |
| `S14_rar_lzss_64_oob_read` | `H` | `host_glibc` (`none`) | `2` | `True` | `12` | `False` | `experiment_only` (`observed_harm`) |
| `S14_rar_lzss_64_oob_read` | `S` | `frankenlibc` (`strict`) | `2` | `True` | `12` | `False` | `experiment_only` (`observed_harm`) |
| `S14_rar_lzss_64_oob_read` | `F` | `frankenlibc` (`hardened`) | `2` | `False` | `12` | `False` | `profile_accepted` (`safe_rejection_in_tested_case`) |
| `S14_rar_lzss_64_oob_read` | `P` | `host_glibc` (`none`) | `2` | `False` | `12` | `False` | `profile_accepted` (`safe_rejection_in_tested_case`) |
| `S14_rar_lzss_64_oob_read` | `PF` | `frankenlibc` (`hardened`) | `2` | `False` | `12` | `False` | `profile_accepted` (`safe_rejection_in_tested_case`) |

## 3. Legitimate Corpus (`S10`), Staging Lifecycle (`S17`), Performance (`S15`) & Holdouts (`S23`)

- **S10 Benign Multi-Format Corpus:** `all_passed=True` (`5` cells across `H, S, F, P, PF`)
- **S11 Corrupt/Clamped ZIP Non-Publication:** `published=False` (`reason=independent_validator_failed`)
- **S14 Synthetic Marker Disclosure (`F`):** `marker_disclosed=False`
- **S15 Paired Performance (`30` randomized blocks after `3` warmups):**
  - `H` (stock glibc): `p50=25.4415 ms`, `p95=63.747 ms`, `VmData_max=508.0 KiB`
  - `S` (strict): `p50=22.4545 ms`, `p95=103.2616 ms`, `ratio=1.2751x` (95% CI `[0.8927, 1.6063]`)
  - `F` (hardened): `p50=39.047 ms`, `p95=139.057 ms`, `ratio=1.512x` (95% CI `[1.1393, 2.1116]`), `within_budget=False`
- **S17 Supervisor Failure & Escape Controls:** `all_passed=True` (`published_files_after_failures=0`)
- **S23 Adversarial Holdout & Non-Coverage Boundary:** `all_passed=True` (`5` cases, including `inlined_bypass -> unsupported`)

## 4. Reproduce & Independently Verify

```bash
tests/cve_arena/runner.sh --qualification-manifest tests/cve_arena/qualification_manifest.v1.json --results-dir <new-empty-dir>
tests/cve_arena/report.sh --qualification <bundle-root> --verify
```
