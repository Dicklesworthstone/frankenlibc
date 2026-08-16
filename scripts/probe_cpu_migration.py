"""Does a pinned single-threaded benchmark actually migrate between CPUs?

This is the load-immune half of the cross-core audit. The frequency spread on this
host is real (1429-4001 MHz), but it can only corrupt an ABBAABBA square if the
thread MOVES between the A and B slots. That is a scheduler question, not a timing
question, so it can be answered while the host is busy.

Mirrors what `incumbent_coverage_ab` does: sched_setaffinity over the N quietest
CPUs, one thread, a tight loop. Samples sched_getcpu() and counts transitions.
"""

import ctypes
import os
import sys

libc = ctypes.CDLL("libc.so.6", use_errno=True)


def quietest(n):
    """The n least-busy CPUs, the same selection the harness makes."""

    def snap():
        out = {}
        for line in open("/proc/stat"):
            if line.startswith("cpu") and line[3].isdigit():
                f = line.split()
                out[int(f[0][3:])] = (sum(int(x) for x in f[1:]), int(f[4]))
        return out

    import time

    a = snap()
    time.sleep(1.0)
    b = snap()
    busy = []
    for c in a:
        dt = b[c][0] - a[c][0]
        di = b[c][1] - a[c][1]
        busy.append((100.0 * (dt - di) / max(1, dt), c))
    busy.sort()
    return [c for _, c in busy[:n]]


def run(width, samples=200_000):
    cpus = quietest(width)
    mask = 0
    for c in cpus:
        mask |= 1 << c
    size = (os.cpu_count() + 63) // 64 * 8
    buf = mask.to_bytes(size, "little")
    if libc.sched_setaffinity(0, size, buf) != 0:
        raise OSError(ctypes.get_errno(), "sched_setaffinity")

    seen = {}
    moves = 0
    last = -1
    acc = 0
    for i in range(samples):
        # A little work between samples, as the square does between slots.
        acc = (acc * 1103515245 + 12345) & 0xFFFFFFFF
        cpu = libc.sched_getcpu()
        seen[cpu] = seen.get(cpu, 0) + 1
        if last != -1 and cpu != last:
            moves += 1
        last = cpu
    return cpus, seen, moves, acc


for width in (1, 4, 8):
    cpus, seen, moves, _ = run(width)
    occupancy = ", ".join(f"cpu{c}:{n}" for c, n in sorted(seen.items(), key=lambda kv: -kv[1])[:6])
    print(
        f"pin={width:<2} allowed={sorted(cpus)}  distinct_cpus_used={len(seen)}  "
        f"migrations={moves}  occupancy[{occupancy}]"
    )
