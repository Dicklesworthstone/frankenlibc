# FrankenLibC Security Validation Methodology

This document describes how FrankenLibC's security value is validated through the Gentoo ecosystem build process.

## Overview

FrankenLibC claims to prevent memory safety issues through its healing actions membrane. The Gentoo validation provides empirical evidence by:

1. Building packages with FrankenLibC instrumentation
2. Recording all healing actions during build and test
3. Correlating healing actions with known CVEs
4. Calculating prevention rates by CVE class

## CVE Classification

### CVE Classes and Healing Actions

| CVE Class | Healing Actions | Prevention Level |
|-----------|-----------------|------------------|
| Buffer Overflow | ClampSize | High |
| Buffer Over-read | ClampSize | High |
| Use-After-Free | GenerationCheck, QuarantinePointer | Partial |
| Double Free | IgnoreDoubleFree | High |
| Format String | UpgradeToSafeVariant | High |
| Integer Overflow | ClampSize, SaturatingArithmetic | Partial |
| Null Pointer | ReturnSafeDefault | Partial |
| Uninitialized Memory | ZeroInitialize | High |

### Prevention Levels

- **High**: FrankenLibC reliably prevents exploitation
- **Partial**: FrankenLibC mitigates but may not fully prevent
- **None**: FrankenLibC cannot prevent (logic bugs, etc.)

## Validation Process

### 1. Build Phase

```bash
# Build package with FrankenLibC
FRANKENLIBC_MODE=hardened \
FRANKENLIBC_LOG=/results/frankenlibc.jsonl \
FRANKENLIBC_HEAL_LOG=1 \
emerge --quiet $PACKAGE
```

### 2. Log Collection

All healing actions are logged in JSONL format:

```json
{
  "timestamp": "2026-02-13T00:00:00Z",
  "action": "ClampSize",
  "call": "memcpy",
  "original_size": 65536,
  "clamped_size": 256,
  "callsite": "ssl/record/rec_layer_d1.c:123"
}
```

### 3. CVE Correlation

The security analyzer cross-references healing actions with known CVEs:

```python
# Example: Heartbleed (CVE-2014-0160)
# - Class: buffer_over_read
# - Relevant action: ClampSize on memcpy
# - Evidence: ClampSize triggered during SSL record processing
```

### 4. Report Generation

```bash
python scripts/gentoo/generate_security_report.py \
  --log-dir artifacts/gentoo-builds \
  --cve-db data/gentoo/cve_database.json \
  --output-md docs/gentoo/security-report.md \
  --output-json artifacts/security-report.json
```

## Security Score and Counterfactual Qualification (`SQ.6` / `SQ.11`)

Telemetry-only healing logs record **membrane intervention activity**, not exploit prevention. Under the `SQ.6`/`SQ.11` oracle contract enforced by `scripts/gentoo/security_analyzer.py`:

- Without an external memory-effect and output oracle (`qualified(c) == true`), every CVE entry evaluates to `would_prevent = False` and `qualification_status = "unqualified"`, regardless of how many `ClampSize` or other healing events appear in JSONL logs.
- Packages with zero known CVEs evaluate to `"unassessed"` (`security_score = None`), never `100%` prevention.
- A `"prevented"` or `"profile_accepted"` verdict requires a confined 4-arm counterfactual `(H, S, F, P)` with pinned artifact SHA-256s:
  - `H` (`stock glibc`): reproduces nominated baseline memory harm (`H_stock == true`) under an external watchpoint/sanitizer/disclosure oracle.
  - `S` (`FRANKENLIBC_MODE=strict`): ablation control separating interposition artifacts from hardened repairs.
  - `F` (`FRANKENLIBC_MODE=hardened`): excludes the nominated memory harm (`watchpoint_triggered == false`, `marker_disclosed == false`) AND either produces independently validated output or safely rejects/quarantines corrupted staged output without publication.
  - `P` (patched upstream reference): confirms expected safe behavior on the fixed upstream revision.

### Evidence Requirements

For any CVE or application profile to move beyond `"unqualified"` telemetry correlation:

1. **Baseline Harm Proof (`H`)**: External hardware watchpoint, sanitizer, or canary-disclosure oracle confirms out-of-bounds/temporal harm on stock glibc.
2. **Hardened Harm Exclusion (`F`)**: Identical input and confinement show the external oracle armed and untriggered under `FRANKENLIBC_MODE=hardened`.
3. **Output Integrity (`S11`/`S17`)**: Any truncated or clamped output is rejected by an independent out-of-process validator in staging and never published.
4. **Honest Non-Promotion**: Cases where compiler-inlined direct stores bypass libc entrypoints (`unsupported`) or where paired latency/RSS budgets fail (`not_qualified`) retain their measured negative/boundary verdicts.

## Limitations

### What FrankenLibC CANNOT Prevent

1. **Logic Bugs**: Incorrect business logic, authorization bypass
2. **Race Conditions**: Some TOCTOU issues
3. **Pre-Load Vulnerabilities**: Issues before FrankenLibC loads (e.g., CVE-2023-4911)
4. **Kernel Vulnerabilities**: FrankenLibC operates in userspace

### Caveats

1. **Observation ≠ Prevention**: Healing actions show potential prevention, not actual exploit blocking
2. **Coverage Varies**: Some code paths may not be exercised during build/test
3. **False Positives**: Some healing actions may be overly aggressive

## CVE Database

The CVE database (`data/gentoo/cve_database.json`) contains:

- Known CVEs for top 100 Gentoo packages
- CVE classification by vulnerability type
- Expected prevention status
- Prevention mechanism description

### Adding CVEs

```json
{
  "id": "CVE-2024-XXXXX",
  "class": "buffer_overflow",
  "severity": "high",
  "cvss": 8.5,
  "description": "Description of the vulnerability",
  "expected_prevention": true,
  "prevention_mechanism": "ClampSize prevents buffer overflow"
}
```

## Usage

### Analyze Single Package

```bash
python scripts/gentoo/security_analyzer.py \
  --package dev-libs/openssl \
  --log-dir artifacts/gentoo-builds \
  --output artifacts/openssl-security.json
```

### Generate Full Report

```bash
python scripts/gentoo/generate_security_report.py \
  --log-dir artifacts/gentoo-builds \
  --output-md docs/gentoo/security-report.md
```

### Run Security Tests

```bash
pytest tests/gentoo/test_security_validation.py
```

## Interpreting Results

### Good Results

- Prevention rate > 80% for buffer overflow/over-read
- ClampSize actions observed in network/parsing code
- GenerationCheck actions in memory management code

### Warning Signs

- Low prevention rate for expected vulnerabilities
- Missing healing actions for known vulnerable code paths
- High false positive rate

## References

- [FrankenLibC Architecture](../ARCHITECTURE.md)
- [Healing Actions Reference](../healing-actions.md)
- [CVE Database Schema](../../data/gentoo/cve_database.json)
