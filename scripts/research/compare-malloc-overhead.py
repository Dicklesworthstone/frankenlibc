#!/usr/bin/env python3
"""Compare fixed per-allocation overhead assumptions across allocators.

This utility is intentionally simple and deterministic for bead bd-2icq.1.
It lets us compare modeled overhead for a list of allocation sizes.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Model:
    name: str
    fixed_overhead_bytes: int


def parse_sizes(raw: str) -> list[int]:
    parts = [item.strip() for item in raw.split(",") if item.strip()]
    if not parts:
        raise ValueError("expected at least one size")
    sizes: list[int] = []
    for part in parts:
        value = int(part)
        if value <= 0:
            raise ValueError(f"size must be > 0: {part}")
        sizes.append(value)
    return sizes


def render_table(models: Iterable[Model], sizes: list[int]) -> str:
    model_list = list(models)
    if len(model_list) < 2:
        raise ValueError("expected at least two models to compare")

    header = [
        "requested_bytes",
        *[f"{m.name}_overhead_bytes" for m in model_list],
        *[f"{m.name}_overhead_pct" for m in model_list],
        "delta_overhead_bytes",
    ]
    lines = ["\t".join(header)]

    baseline = model_list[0]
    for size in sizes:
        row: list[str] = [str(size)]
        for model in model_list:
            row.append(str(model.fixed_overhead_bytes))
        for model in model_list:
            pct = (model.fixed_overhead_bytes / size) * 100.0
            row.append(f"{pct:.2f}")
        delta = model_list[1].fixed_overhead_bytes - baseline.fixed_overhead_bytes
        row.append(str(delta))
        lines.append("\t".join(row))

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare modeled fixed overhead across allocator designs."
    )
    parser.add_argument(
        "--sizes",
        default="16,32,64,128,256,512,1024,4096",
        help="Comma-separated requested allocation sizes in bytes.",
    )
    parser.add_argument(
        "--franken-fixed-overhead",
        type=int,
        default=24,
        help="FrankenLibC fixed metadata overhead in bytes (default: 24).",
    )
    parser.add_argument(
        "--llvm-fixed-overhead",
        type=int,
        default=16,
        help=(
            "LLVM model fixed overhead in bytes for comparison. "
            "Tune this using measured allocator internals."
        ),
    )
    parser.add_argument(
        "--llvm-model-name",
        default="llvm_overlay_model",
        help="Name label for the LLVM-side model in output.",
    )

    args = parser.parse_args()
    sizes = parse_sizes(args.sizes)
    models = [
        Model(name="frankenlibc", fixed_overhead_bytes=args.franken_fixed_overhead),
        Model(name=args.llvm_model_name, fixed_overhead_bytes=args.llvm_fixed_overhead),
    ]

    print(render_table(models, sizes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
