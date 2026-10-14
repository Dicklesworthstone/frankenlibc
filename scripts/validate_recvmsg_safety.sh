#!/usr/bin/env bash
# Run from an applied checkout. Mutations are restricted to disposable CI checkouts.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
export FRANKENLIBC_RUNTIME_MATH=off
export CARGO_TERM_COLOR=never
unset FRANKENLIBC_RECVMSG_CHILD FRANKENLIBC_SOCKET_MESSAGE_CHILD
cargo test -p frankenlibc-abi --test recvmsg_snapshot_test --test recvmsg_bounds_test \
  --test msg_snapshot_test --test socket_message_bounds_test --test socket_abi_test --no-run
for mode in strict hardened; do
  FRANKENLIBC_MODE="$mode" cargo test -p frankenlibc-abi \
    --test recvmsg_snapshot_test --test msg_snapshot_test --test socket_abi_test -- --test-threads=1
 done
cargo test -p frankenlibc-abi --test recvmsg_bounds_test --test socket_message_bounds_test \
  -- --nocapture --test-threads=1
if [[ "${1:-}" != --mutations ]]; then exit 0; fi
if [[ "${CI:-}" != true ]]; then
  echo 'Mutation execution requires a disposable CI=true checkout; ordinary validation does not edit source.' >&2
  exit 2
fi
scratch="$(mktemp -d "${RUNNER_TEMP:-/tmp}/recvmsg-mutations.XXXXXXXX")"
source_file=crates/frankenlibc-abi/src/socket_abi.rs
cp "$source_file" "$scratch/socket_abi.rs"
restore() { cp "$scratch/socket_abi.rs" "$source_file"; }
trap restore EXIT
for mutation in unchecked skipped_outputs; do
  restore
  python3 - "$source_file" "$mutation" <<'PY'
from pathlib import Path
import sys
path, mutation = Path(sys.argv[1]), sys.argv[2]
s = path.read_text()
start = s.index('pub(crate) unsafe fn recvmsg_cp(')
end = s.index('\n// ---------------------------------------------------------------------------', start)
body = s[start:end]
if mutation == 'unchecked':
    old = 'let mut prepared = if mode.heals_enabled() {'
    new = 'let mut prepared = if false && mode.heals_enabled() {'
else:
    old = 'unsafe { message.copy_received_outputs(msg) }'
    new = '{ let _ = message; Ok::<(), c_int>(()) }'
assert body.count(old) == 1, (mutation, 'mutation anchor changed')
path.write_text(s[:start] + body.replace(old, new, 1) + s[end:])
PY
  # A compilation failure is NOT evidence that the ABI regression caught a bypass.
  cargo test -p frankenlibc-abi --test recvmsg_bounds_test --no-run
  if [[ "$mutation" == unchecked ]]; then
    selection=recvmsg:oversize
    expected='rejected input reached socket I/O'
  else
    selection=recvmsg:valid
    expected='flags not copied back'
  fi
  log="$scratch/$mutation.log"
  if FRANKENLIBC_MODE=hardened FRANKENLIBC_RECVMSG_CHILD="$selection" \
     cargo test -p frankenlibc-abi --test recvmsg_bounds_test -- \
       --exact recvmsg_bounds_matrix --nocapture --test-threads=1 >"$log" 2>&1; then
    cat "$log"
    echo "Mutation $mutation incorrectly passed" >&2
    exit 1
  fi
  cat "$log"
  grep -F "$expected" "$log" >/dev/null
  if [[ "$mutation" == unchecked ]]; then
    grep -E 'left: +65' "$log" >/dev/null
    grep -E 'right: +-1' "$log" >/dev/null
  fi
done
restore
cmp "$scratch/socket_abi.rs" "$source_file"
cargo test -p frankenlibc-abi --test recvmsg_bounds_test -- --nocapture --test-threads=1
printf 'Both mutations were compiled and caught; restored ABI matrix passed. Logs: %s\n' "$scratch"
