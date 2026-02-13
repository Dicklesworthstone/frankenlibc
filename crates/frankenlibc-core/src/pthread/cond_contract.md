# Clean-Room Condvar Semantics Contract (bd-blg)

This contract defines phase-scoped behavior for `pthread_cond_*` without consulting legacy implementation internals.

## Scope

- Operations: `init`, `destroy`, `wait`, `timedwait`, `signal`, `broadcast`
- Clocks: `CLOCK_REALTIME` (default), `CLOCK_MONOTONIC`
- Modes: strict/hardened share the same functional errno contract in this phase.
- Deferred features (explicit): process-shared condvars.

## State Model

- `Uninitialized`
- `Idle` — initialized, zero waiters
- `Waiting` — initialized, one or more threads blocked in wait/timedwait
- `Destroyed`

The executable contract is implemented in `condvar_contract_transition` in `crates/frankenlibc-core/src/pthread/cond.rs`.

## Operations

### `init`

- Initializes the condvar. Optionally accepts a condattr specifying clock.
- Default clock: `CLOCK_REALTIME`.
- Transitions `Uninitialized`/`Destroyed` -> `Idle`.
- Re-init of an initialized condvar: `EBUSY` (strict), same as mutex contract.

### `destroy`

- Frees condvar resources.
- Only valid when no threads are waiting (`Idle`).
- `Waiting + destroy` -> `EBUSY` (undefined per POSIX; we choose deterministic error).
- `Idle + destroy` -> `Destroyed` (0).
- `Uninitialized/Destroyed + destroy` -> `EINVAL`.

### `wait`

Atomically performs three steps:
1. Releases the associated mutex.
2. Blocks the calling thread on the condvar.
3. On unblock (signal/broadcast/spurious), reacquires the mutex before returning.

Preconditions:
- Caller must hold the associated mutex.
- All concurrent waiters on the same condvar must use the same mutex. Using a different mutex is undefined per POSIX; we return `EINVAL` in strict mode.

Returns:
- `0` on success (including spurious wakeup).
- `EINVAL` for uninitialized/destroyed condvar, null pointers, or mutex mismatch.
- `EPERM` if the caller does not own the mutex (detectable only for ERRORCHECK/RECURSIVE mutexes).

### `timedwait`

Same as `wait` with an absolute timeout deadline:
- Deadline is specified as `struct timespec` in the clock domain of the condvar's configured clock.
- If the deadline has already passed or passes while waiting, returns `ETIMEDOUT` after reacquiring the mutex.
- A past deadline still atomically releases and reacquires the mutex.

Returns:
- `0` on signal/broadcast/spurious wakeup before deadline.
- `ETIMEDOUT` if deadline expires.
- `EINVAL` for invalid condvar, null pointers, negative timespec, or mutex mismatch.
- `EPERM` if caller does not own the mutex.

### `signal`

Wakes at least one thread waiting on the condvar.
- If no threads are waiting, this is a no-op (returns `0`).
- The woken thread must reacquire the associated mutex before returning from `wait`/`timedwait`.
- Which thread is woken is scheduling-dependent (no FIFO guarantee).

Returns:
- `0` on success.
- `EINVAL` for uninitialized/destroyed condvar.

### `broadcast`

Wakes all threads waiting on the condvar.
- If no threads are waiting, this is a no-op (returns `0`).
- All woken threads contend for the associated mutex; only one proceeds at a time.

Returns:
- `0` on success.
- `EINVAL` for uninitialized/destroyed condvar.

## Transition Table

| State          | Operation   | Result                    | errno      | Notes                                        |
|----------------|-------------|---------------------------|------------|----------------------------------------------|
| Uninitialized  | init        | -> Idle                   | 0          |                                              |
| Uninitialized  | destroy     | stays Uninitialized       | EINVAL     |                                              |
| Uninitialized  | wait        | stays Uninitialized       | EINVAL     |                                              |
| Uninitialized  | timedwait   | stays Uninitialized       | EINVAL     |                                              |
| Uninitialized  | signal      | stays Uninitialized       | EINVAL     |                                              |
| Uninitialized  | broadcast   | stays Uninitialized       | EINVAL     |                                              |
| Idle           | init        | stays Idle                | EBUSY      | Re-init without destroy                      |
| Idle           | destroy     | -> Destroyed              | 0          |                                              |
| Idle           | wait        | -> Waiting                | 0          | Blocks; mutex released then reacquired       |
| Idle           | timedwait   | -> Waiting                | 0/ETIMEOUT | Blocks with deadline                         |
| Idle           | signal      | stays Idle                | 0          | No-op: no waiters                            |
| Idle           | broadcast   | stays Idle                | 0          | No-op: no waiters                            |
| Waiting        | init        | stays Waiting             | EBUSY      |                                              |
| Waiting        | destroy     | stays Waiting             | EBUSY      | Waiters exist; UB per POSIX, EBUSY for us    |
| Waiting        | wait        | stays Waiting             | 0          | Additional waiter joins                      |
| Waiting        | timedwait   | stays Waiting             | 0/ETIMEOUT | Additional waiter joins with deadline         |
| Waiting        | signal      | -> Idle or stays Waiting  | 0          | Wakes one; Idle if last waiter               |
| Waiting        | broadcast   | -> Idle                   | 0          | Wakes all; transitions to Idle               |
| Destroyed      | init        | -> Idle                   | 0          | Reinitialize after destroy                   |
| Destroyed      | destroy     | stays Destroyed           | EINVAL     |                                              |
| Destroyed      | wait        | stays Destroyed           | EINVAL     |                                              |
| Destroyed      | timedwait   | stays Destroyed           | EINVAL     |                                              |
| Destroyed      | signal      | stays Destroyed           | EINVAL     |                                              |
| Destroyed      | broadcast   | stays Destroyed           | EINVAL     |                                              |

## Clock Handling

- `CLOCK_REALTIME` (id=0): wall-clock time. Affected by `settimeofday`/`clock_settime`. Default.
- `CLOCK_MONOTONIC` (id=1): monotonic time. Not affected by system clock changes.
- Set via `pthread_condattr_setclock` before `init`.
- Invalid clock ids are rejected with `EINVAL`.

### Timeout Conversion Rules

- `timedwait` deadline is always **absolute** (not relative).
- For `CLOCK_REALTIME`: compare `clock_gettime(CLOCK_REALTIME)` against deadline.
- For `CLOCK_MONOTONIC`: compare `clock_gettime(CLOCK_MONOTONIC)` against deadline.
- Relative-to-absolute conversion: `deadline = clock_gettime(clock_id) + relative_duration`.
- If `timespec.tv_nsec < 0` or `>= 1_000_000_000`, return `EINVAL`.

## Spurious Wakeup Policy

Per POSIX.1-2017: "Spurious wakeups from `pthread_cond_wait` or `pthread_cond_timedwait` may occur."

**Required caller predicate-loop pattern:**
```c
pthread_mutex_lock(&mutex);
while (!predicate) {
    pthread_cond_wait(&cond, &mutex);
}
// predicate is true, mutex is held
pthread_mutex_unlock(&mutex);
```

Callers MUST NOT assume a single `wait` return implies the predicate is satisfied.

FrankenLibC implementation notes:
- **strict mode**: futex wakeups map directly; the kernel may deliver spurious wakeups.
- **hardened mode**: same contract. No additional spurious wakeup suppression is provided because the predicate-loop is mandatory per POSIX.

## Attribute Handling Matrix

Current phase support is intentionally conservative:

- Supported:
  - default/private condvar attributes
  - `pthread_condattr_setclock` / `pthread_condattr_getclock` (REALTIME, MONOTONIC)
- Deferred (deterministic `EINVAL`):
  - `process_shared`

Executable helpers:
- `condvar_attr_is_supported`
- `condvar_attr_support_errno`

## Errno Contract

- `EINVAL`: uninitialized/destroyed condvar, null pointers, invalid timespec, mutex mismatch, unsupported attributes, invalid clock
- `EBUSY`: destroy while waiters exist, re-init while initialized
- `EPERM`: wait/timedwait without owning the mutex (ERRORCHECK/RECURSIVE only)
- `ETIMEDOUT`: timedwait deadline expired
- `0`: success

## Contention/Futex Notes

Futex-based condvar uses:
- Sequence counter for signal/broadcast ordering.
- `futex_wait` on sequence counter for blocking.
- `futex_wake(1)` for signal, `futex_wake(INT_MAX)` for broadcast.
- Wait path: unlock mutex -> futex_wait(seq) -> relock mutex.
- No strict FIFO ordering for signal; wake ordering is kernel-scheduled.
- Broadcast uses requeue optimization when possible: `futex_cmp_requeue` to move waiters from condvar futex to mutex futex, avoiding thundering herd.

## Mutex Association Invariant

All concurrent `wait`/`timedwait` calls on the same condvar MUST use the same mutex. Per POSIX, using different mutexes is undefined behavior. Our implementation:
- **strict mode**: tracks the associated mutex; returns `EINVAL` on mismatch.
- **hardened mode**: same behavior.

The association is set by the first waiter and cleared when the last waiter departs.
