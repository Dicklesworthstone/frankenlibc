# bd-2g7oyh.61 - wmemcmp 32-lane equality panel rejected

## Target

- Bead: `bd-2g7oyh.61`
- Target: `crates/frankenlibc-core/src/string/wide.rs::wmemcmp`
- Lever attempted: widen only `WIDE_COMPARE_SIMD_LANES` from 16 to 32.
- Alien primitive: grouped vector equality probing / block amortization.
- Keep rule: retain only if `Impact * Confidence / Effort >= 2.0`.

## Baseline

Baseline from the RCH re-profile after `f10635db` on worker `vmi1149989`:

- `wmemcmp_equal_4096`: p50 `181.325 ns/op`, p95 `220.012`, p99 `321.000`, mean `188.129`.
- Nearby profile rows: `wcsrchr_absent_4096` p50 `191.416`, `wcschr_absent_4096` p50 `184.969`, `wcsstr_absent_4096` p50 `158.516`, `wcslen_4096` p50 `147.088`.

The baseline source hash for `wide.rs` was:

```text
e9e94a1c03458a08ba3651e8fa353dfdc7ca0e559450aab63dcaa599c6c94226
```

## Post-Lever Benchmark

Focused RCH command:

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wmemcmp_equal' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Worker: `vmi1227854`.

Results with the 32-lane lever applied:

| Benchmark | Baseline p50 | Post p50 | Post p95 | Post p99 | Post mean | Decision |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `wmemcmp_equal_16` | `2.739` | `9.973` | `27.500` | `341.000` | `17.525` | regress |
| `wmemcmp_equal_64` | `5.756` | `4.315` | `10.000` | `50.000` | `5.606` | weak win |
| `wmemcmp_equal_256` | `17.802` | `12.252` | `22.500` | `80.000` | `14.263` | win |
| `wmemcmp_equal_1024` | `48.588` | `44.476` | `55.000` | `130.000` | `47.358` | weak win |
| `wmemcmp_equal_4096` | `181.325` | `175.651` | `206.562` | `341.000` | `180.537` | weak win |

## Isomorphism Proof

- Lexicographic behavior would be unchanged by the attempted lever because the SIMD panel only filters all-equal panels.
- The first unequal panel would still resolve scalar left-to-right, preserving signed `wchar_t` ordering and tie-breaking.
- Length tie-breaking would stay after the shared-prefix scan.
- Floating-point and RNG behavior are not involved.
- Golden fixture sha256 verification passed before and after the attempted lever.

Golden check:

```text
fixture_verify_strict_hardened.v1.md: OK
fixture_verify_strict_hardened.v1.json: OK
```

## Rejection

Score: `(Impact 0.5 * Confidence 2.0) / Effort 1.0 = 1.0`.

The 4096-row p50 win was only `1.03x` and the mean win was only `1.04x`; the 16-element row regressed sharply. This fails the `>= 2.0` keep threshold, so the source change was restored.

Restored `wide.rs` hash:

```text
e9e94a1c03458a08ba3651e8fa353dfdc7ca0e559450aab63dcaa599c6c94226
```

Next direction: stop widening the current `wmemcmp` panel. Attack a different primitive from the latest profile instead, starting with branchless/grouped candidate-index extraction for the wide char-or-NUL scan cluster or another profile-backed hotspot after re-coordination.
