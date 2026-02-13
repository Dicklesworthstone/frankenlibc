use frankenlibc_membrane::{SafetyState, ValidationOutcome, ValidationPipeline};

#[derive(Clone, Copy, Debug)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn gen_range_usize(&mut self, low: usize, high_inclusive: usize) -> usize {
        assert!(low <= high_inclusive);
        let span = high_inclusive - low + 1;
        low + (self.next_u64() as usize % span)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    Empty,
    Live,
    Freed,
}

#[test]
fn deterministic_allocator_membrane_sequences_hold_core_invariants() {
    // Deterministic, bounded, and intentionally simple: this is invariant pressure,
    // not a fuzz campaign (those live in frankenlibc-fuzz).
    const SEEDS: [u64; 4] = [1, 2, 3, 4];
    const STEPS: usize = 2_000;
    const SLOTS: usize = 32;

    for seed in SEEDS {
        let pipeline = ValidationPipeline::new();
        let mut rng = XorShift64::new(seed);

        let mut ptrs = [std::ptr::null_mut::<u8>(); SLOTS];
        let mut sizes = [0_usize; SLOTS];
        let mut states = [SlotState::Empty; SLOTS];

        // Foreign pointers should remain allowed but Unknown/unbounded.
        let foreign_addr = 0xDEAD_BEEF_usize;
        let foreign_outcome = pipeline.validate(foreign_addr);
        assert!(
            matches!(foreign_outcome, ValidationOutcome::Foreign(_)),
            "seed={seed}: expected Foreign for foreign_addr"
        );
        assert!(foreign_outcome.can_read(), "seed={seed}: foreign can_read");
        assert!(foreign_outcome.can_write(), "seed={seed}: foreign can_write");
        let foreign_abs = foreign_outcome.abstraction().expect("foreign abstraction");
        assert_eq!(
            foreign_abs.state,
            SafetyState::Unknown,
            "seed={seed}: foreign abstraction must be Unknown"
        );
        assert!(
            foreign_abs.remaining.is_none(),
            "seed={seed}: foreign abstraction must not claim bounds"
        );

        for step in 0..STEPS {
            let op = rng.gen_range_usize(0, 99);
            let idx = rng.gen_range_usize(0, SLOTS - 1);

            match op {
                // allocate (biased)
                0..=44 => {
                    if states[idx] != SlotState::Empty {
                        continue;
                    }
                    let size = rng.gen_range_usize(1, 2048);
                    let ptr = pipeline.allocate(size).expect("alloc");
                    ptrs[idx] = ptr;
                    sizes[idx] = size;
                    states[idx] = SlotState::Live;
                }
                // validate
                45..=84 => match states[idx] {
                    SlotState::Empty => {
                        let out = pipeline.validate(foreign_addr);
                        assert!(
                            matches!(out, ValidationOutcome::Foreign(_)),
                            "seed={seed} step={step}: foreign validate must be Foreign"
                        );
                    }
                    SlotState::Live => {
                        let addr = ptrs[idx] as usize;
                        let out = pipeline.validate(addr);
                        assert!(
                            matches!(
                                out,
                                ValidationOutcome::CachedValid(_) | ValidationOutcome::Validated(_)
                            ),
                            "seed={seed} step={step}: live validate must be CachedValid/Validated (got {out:?})"
                        );
                        assert!(
                            out.can_read() && out.can_write(),
                            "seed={seed} step={step}: live pointer must be readable+writable"
                        );
                        let abs = out.abstraction().expect("live abstraction");
                        assert_eq!(
                            abs.state,
                            SafetyState::Valid,
                            "seed={seed} step={step}: live abstraction must be Valid"
                        );
                        assert_eq!(
                            abs.remaining,
                            Some(sizes[idx]),
                            "seed={seed} step={step}: remaining must match allocation size"
                        );
                    }
                    SlotState::Freed => {
                        let addr = ptrs[idx] as usize;
                        let out = pipeline.validate(addr);
                        assert!(
                            matches!(out, ValidationOutcome::TemporalViolation(_)),
                            "seed={seed} step={step}: freed validate must be TemporalViolation (got {out:?})"
                        );
                        assert!(
                            !out.can_read() && !out.can_write(),
                            "seed={seed} step={step}: freed pointer must not be readable/writable"
                        );
                        assert!(
                            !matches!(out, ValidationOutcome::CachedValid(_)),
                            "seed={seed} step={step}: freed validate must never be CachedValid"
                        );
                    }
                },
                // free live
                85..=94 => {
                    if states[idx] != SlotState::Live {
                        continue;
                    }
                    let ptr = ptrs[idx];
                    let result = pipeline.free(ptr);
                    assert!(
                        matches!(result, frankenlibc_membrane::arena::FreeResult::Freed),
                        "seed={seed} step={step}: expected Freed on first free (got {result:?})"
                    );
                    states[idx] = SlotState::Freed;
                }
                // double-free attempt
                _ => {
                    if states[idx] != SlotState::Freed {
                        continue;
                    }
                    let ptr = ptrs[idx];
                    let result = pipeline.free(ptr);
                    assert!(
                        matches!(result, frankenlibc_membrane::arena::FreeResult::DoubleFree),
                        "seed={seed} step={step}: expected DoubleFree on second free (got {result:?})"
                    );
                }
            }
        }
    }
}

