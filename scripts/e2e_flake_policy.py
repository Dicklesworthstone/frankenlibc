#!/usr/bin/env python3
"""Deterministic retry/flake policy helper for E2E suite (bd-b5a.3)."""

from __future__ import annotations

import argparse
import json
from typing import Iterable


def parse_csv_ints(raw: str) -> list[int]:
    values = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        values.append(int(token))
    return values


def flake_score(exit_codes: Iterable[int]) -> float:
    codes = list(exit_codes)
    if len(codes) < 2:
        return 0.0
    outcomes = [code == 0 for code in codes]
    pass_count = sum(1 for outcome in outcomes if outcome)
    fail_count = len(outcomes) - pass_count
    if pass_count == 0 or fail_count == 0:
        return 0.0
    minority = min(pass_count, fail_count)
    return minority / len(outcomes)


def transitions(exit_codes: Iterable[int]) -> int:
    codes = list(exit_codes)
    if len(codes) < 2:
        return 0
    outcomes = [code == 0 for code in codes]
    return sum(1 for i in range(1, len(outcomes)) if outcomes[i] != outcomes[i - 1])


def classify_attempts(exit_codes: list[int], quarantine_threshold: float) -> dict[str, object]:
    if not exit_codes:
        raise ValueError("exit_codes must not be empty")

    score = flake_score(exit_codes)
    transition_count = transitions(exit_codes)
    is_flaky = int(transition_count > 0)
    final_exit_code = exit_codes[-1]
    final_outcome = "pass" if final_exit_code == 0 else "fail"
    retry_count = max(0, len(exit_codes) - 1)

    if final_outcome == "pass":
        if is_flaky and score >= quarantine_threshold:
            verdict = "quarantined_flake"
        elif is_flaky:
            verdict = "pass_with_retry"
        else:
            verdict = "pass"
    elif is_flaky:
        verdict = "fail_flaky"
    else:
        verdict = "fail"

    return {
        "retry_count": retry_count,
        "flake_score": score,
        "verdict": verdict,
        "final_outcome": final_outcome,
        "final_exit_code": final_exit_code,
        "is_flaky": is_flaky,
        "should_quarantine": int(verdict == "quarantined_flake"),
        "attempt_count": len(exit_codes),
        "transition_count": transition_count,
    }


def should_retry(
    *,
    exit_code: int,
    attempt_index: int,
    max_retries: int,
    retry_on_any_nonzero: bool,
    retryable_codes: set[int],
) -> bool:
    if exit_code == 0:
        return False
    if attempt_index >= max_retries:
        return False
    if retry_on_any_nonzero:
        return True
    return exit_code in retryable_codes


def cmd_classify(args: argparse.Namespace) -> int:
    codes = parse_csv_ints(args.exit_codes)
    result = classify_attempts(codes, args.quarantine_threshold)
    if args.format == "json":
        print(json.dumps(result))
        return 0
    print(
        "\t".join(
            [
                str(result["retry_count"]),
                f"{float(result['flake_score']):.6f}",
                str(result["verdict"]),
                str(result["final_outcome"]),
                str(result["final_exit_code"]),
                str(result["is_flaky"]),
                str(result["should_quarantine"]),
            ]
        )
    )
    return 0


def cmd_should_retry(args: argparse.Namespace) -> int:
    retryable_codes = set(parse_csv_ints(args.retryable_codes))
    decision = should_retry(
        exit_code=args.exit_code,
        attempt_index=args.attempt_index,
        max_retries=args.max_retries,
        retry_on_any_nonzero=bool(args.retry_on_any_nonzero),
        retryable_codes=retryable_codes,
    )
    print("1" if decision else "0")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="E2E deterministic retry/flake policy")
    sub = parser.add_subparsers(dest="command", required=True)

    p_classify = sub.add_parser("classify", help="Classify attempt exit-code history")
    p_classify.add_argument("--exit-codes", required=True, help="CSV exit codes, e.g. 124,0")
    p_classify.add_argument(
        "--quarantine-threshold",
        type=float,
        default=0.34,
        help="flake score threshold for quarantine labeling",
    )
    p_classify.add_argument(
        "--format",
        choices=["tsv", "json"],
        default="tsv",
        help="output format",
    )
    p_classify.set_defaults(handler=cmd_classify)

    p_retry = sub.add_parser("should-retry", help="Decide whether to retry after an attempt")
    p_retry.add_argument("--exit-code", required=True, type=int)
    p_retry.add_argument("--attempt-index", required=True, type=int)
    p_retry.add_argument("--max-retries", required=True, type=int)
    p_retry.add_argument(
        "--retry-on-any-nonzero",
        choices=["0", "1"],
        default="1",
        help="retry all non-zero exits when set to 1",
    )
    p_retry.add_argument(
        "--retryable-codes",
        default="124,125",
        help="CSV exit codes retried when retry-on-any-nonzero=0",
    )
    p_retry.set_defaults(handler=cmd_should_retry)

    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
