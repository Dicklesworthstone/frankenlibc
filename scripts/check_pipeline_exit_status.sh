#!/usr/bin/env bash
# check_pipeline_exit_status.sh — CI gate for bd-5n7ks2
#
# Catches the "silence read as success" family: constructs whose exit status
# comes from the wrong command, so a failure reports as a pass.
#
# WHY, with the number that justifies it:
#
#     TWO BROKEN TARGETS REPORTED VERSUS SIXTY-EIGHT.
#
# Same tree, same day (2026-08-06). `cargo check --workspace --all-targets` —
# what scripts/ci.sh ran — stops at the first failing target and reported 2. The
# same command with --keep-going reported 68. A 34x under-report of the repo's
# real breakage, sustained for weeks, by the gate whose entire job is to say what
# is broken. Everything in that gap was invisible: 62 A/B perf harnesses
# (bd-25bzch), the f128 conformance family (bd-ocwiw9), and bench hooks deleted
# from under a published vs-glibc claim (bd-5ibpa3).
#
# The same shape at CI scale: .github/workflows/ci.yml ran every step as
# `bash -e {0}` (no pipefail) while piping 31 gate invocations through `tee`, so
# tee's success masked each gate's failure.
#
# WHAT IT CHECKS
#   1. .sh files that use a pipeline but never `set -o pipefail`.
#   2. `$?` read from a pipeline — `cmd | tail; rc=$?` reports tail's status.
#   3. `&&` / `||` chained off a filtering pipeline — `cmd | tail && echo OK`.
#   4. GitHub workflows that pipe without pipefail (no `defaults.run.shell` and
#      no per-step `shell:`).
#
# EXIT 3 = NOTHING WAS SCANNED. Modelled on ubs, which already does exactly this
# and prints "nothing was checked (this is NOT a pass)". A gate that can do zero
# work must distinguish that from passing, or it becomes the very bug it hunts.
# Set PIPELINE_LINT_ALLOW_NO_SCAN=1 to accept an empty scan.
#
# Exit 0 = clean, 1 = findings, 3 = nothing scanned.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "=== pipeline exit-status gate (bd-5n7ks2) ==="

python3 - "$REPO_ROOT" <<'PY'
import os, re, sys, pathlib

root = pathlib.Path(sys.argv[1])
findings = []
scanned = 0

# A pipe that is a real pipeline: not ||, not |&, not inside an obvious [[ ]].
PIPE = re.compile(r'(?<![|&>])\|(?!\|)')
STATUS = re.compile(r'\$\?')
# Filters whose own exit status is meaningless as a verdict on the command.
FILTERS = r'(tail|head|tee|cut|tr|sort|uniq|sed|awk|column|jq|fmt|nl|rev|wc)'
PIPE_THEN_CHAIN = re.compile(r'\|\s*' + FILTERS + r'\b[^|]*?(&&|\|\|)\s*\S')

def strip_comment(line):
    # good enough: drop a trailing comment that is not inside quotes
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q: q = None
        elif ch in '"\'':
            q = ch
        elif ch == '#' and (i == 0 or line[i-1].isspace()):
            return line[:i]
    return line

HEREDOC_OPEN = re.compile(r"<<-?\s*'?\"?([A-Za-z_][A-Za-z0-9_]*)'?\"?")
# `|| true` / `|| :` is an EXPLICIT discard of the status — the author has said
# in the code that they do not care. That is the opposite of the bug, which is
# silently inheriting the wrong status while believing you checked something.
EXPLICIT_DISCARD = re.compile(r'\|\|\s*(true|:)\s*$')

def shell_lines(text):
    """Yield (lineno, code) for real shell lines, skipping heredoc bodies.

    Gates here routinely embed python via `python3 - <<'PY' ... PY`; scanning
    that body as shell produces confident nonsense, which would make this gate
    an instance of the very thing it checks for."""
    delim = None
    for n, raw in enumerate(text.splitlines(), 1):
        if delim is not None:
            if raw.strip() == delim:
                delim = None
            continue
        code = strip_comment(raw)
        m = HEREDOC_OPEN.search(code)
        if m:
            delim = m.group(1)
            continue
        yield n, code

# ---- 1..3: shell scripts -------------------------------------------------
for p in sorted(root.joinpath('scripts').rglob('*.sh')):
    text = p.read_text(errors='replace')
    scanned += 1
    code = list(shell_lines(text))
    has_pipefail = any(re.search(r'set\s+-[a-zA-Z]*o\s+pipefail|set\s+-o\s+pipefail', l) for _, l in code)
    # A file meant to be SOURCED must not impose shell options on its caller.
    sourced = 'ntended to be sourced' in text
    uses_pipe = any(PIPE.search(l) for _, l in code)
    rel = p.relative_to(root).as_posix()

    if uses_pipe and not has_pipefail and not sourced:
        findings.append((rel, 0, "uses pipelines but never sets `-o pipefail`"))

    # UNDER pipefail these constructs are CORRECT: the pipeline already returns
    # the first failing stage's status, so `cmd | tail && ...` and `rc=$?` after
    # a pipeline both judge `cmd`. Flagging them anyway would bury the real
    # finding in noise and train readers to ignore this gate — which is how a
    # check stops being one.
    if has_pipefail:
        continue

    for idx, (n, line) in enumerate(code):
        if not PIPE.search(line) or EXPLICIT_DISCARD.search(line):
            continue
        if PIPE_THEN_CHAIN.search(line):
            findings.append((rel, n, "`&&`/`||` chained off a filtering pipeline — judges the filter, not the command"))
        if STATUS.search(line) and line.index('|') < line.rindex('$?'):
            findings.append((rel, n, "`$?` read after a pipeline on the same line — reports the LAST stage's status"))
            continue
        for _, look in code[idx+1:idx+3]:
            if not look.strip():
                continue
            if re.search(r'\b\w+=\$\?|echo\s+"?\$\?', look):
                findings.append((rel, n, "pipeline immediately followed by a `$?` read — reports the LAST stage's status"))
            break

# ---- 4: GitHub workflows -------------------------------------------------
wf_dir = root/'.github'/'workflows'
if wf_dir.is_dir():
    for p in sorted(wf_dir.glob('*.y*ml')):
        text = p.read_text(errors='replace')
        scanned += 1
        rel = p.relative_to(root).as_posix()
        pipes = sum(1 for l in text.splitlines() if PIPE.search(strip_comment(l)))
        if pipes == 0:
            continue
        has_defaults = re.search(r'^defaults:\s*$', text, re.M) and re.search(r'^\s+shell:\s*bash\s*$', text, re.M)
        if not has_defaults:
            findings.append((rel, 0,
                f"{pipes} piped lines but no `defaults: run: shell: bash` — GitHub runs steps as "
                f"`bash -e {{0}}` WITHOUT pipefail, so a pipe to `tee` masks the command's failure"))

# ---- verdict -------------------------------------------------------------
if scanned == 0:
    print("")
    print("Nothing was scanned: no shell scripts or workflows found. This is NOT a pass.")
    print("Set PIPELINE_LINT_ALLOW_NO_SCAN=1 to accept an empty scan.")
    sys.exit(0 if os.environ.get('PIPELINE_LINT_ALLOW_NO_SCAN') == '1' else 3)

print(f"files scanned: {scanned}")
print(f"findings     : {len(findings)}")
if findings:
    print("")
    for rel, line, msg in findings:
        where = f"{rel}:{line}" if line else rel
        print(f"  {where}: {msg}")
    print("")
    print("Fix by asserting the POSITIVE fact, not the absence of a complaint:")
    print("  cmd >out.txt 2>&1; rc=$?      # status of cmd, and the output is kept")
    print("  set -o pipefail               # in scripts")
    print("  defaults: {run: {shell: bash}} # in workflows")
    sys.exit(1)

print("")
print("PASS: no pipeline exit-status traps found.")
sys.exit(0)
PY
