//! Sorting and searching functions.

/// Slices at or below this length are finished with insertion sort. Matches
/// the pattern-defeating quicksort (pdqsort) reference threshold.
const MAX_INSERTION: usize = 20;
const INSERTION_STACK_SCRATCH: usize = 64;
const I32_FAST_LANE_MIN: usize = 64;
const I32_FAST_LANE_MAX: usize = 2048;
const I64_FAST_LANE_MIN: usize = 64;
const I64_FAST_LANE_MAX: usize = 2048;
/// Above this element count, 4-/8-byte integer keys take an LSD radix lane
/// instead of the comparison-sort fast lane. The crossover sits just past the
/// comparison-lane window: radix's fixed per-pass overhead (256-bucket
/// histogram + a full ping-pong scatter) only amortizes once N is large.
const INTEGER_RADIX_LANE_MIN: usize = 2048;
/// 2-byte integer keys take the radix lane at a far lower threshold: they have
/// no comparison fast lane and a 2-pass radix has negligible fixed cost, so it
/// overtakes pdqsort early.
const NARROW_RADIX_LANE_MIN: usize = 256;
/// 1-byte keys take the dedicated counting-sort lane above this count.
const U8_COUNTING_LANE_MIN: usize = 256;

/// Generic qsort implementation: a pattern-defeating quicksort (pdqsort,
/// Orson Peters 2014) ported to operate on raw byte chunks through a
/// comparison callback, in 100% safe Rust.
///
/// `base`: the entire array as bytes.
/// `width`: size of each element in bytes.
/// `compare`: comparison function returning <0, 0, >0.
///
/// Over the median-of-three introsort it replaces, pdqsort delivers a
/// fundamentally different complexity profile rather than a constant-factor
/// tweak:
///   * O(n) on already-sorted, reverse-sorted, and constant inputs (sorted-run
///     detection + an equal-element partition that skips duplicate blocks),
///   * a guaranteed O(n·log n) worst case (heapsort fallback once the count of
///     imbalanced partitions exceeds ~log n), and
///   * adversarial-pattern resistance (deterministic shuffles break up median
///     killers that drive naive quicksort to O(n²)).
///
/// Behavior parity is absolute: like C `qsort`, the result is the input
/// multiset in non-decreasing comparator order; the relative order of
/// equal-comparing elements is unspecified (this sort is unstable), exactly
/// as glibc `qsort` leaves it.
pub fn qsort<F>(base: &mut [u8], width: usize, compare: F)
where
    F: Fn(&[u8], &[u8]) -> i32 + Copy,
{
    if width == 0 || base.len() < width {
        return;
    }
    let num = base.len() / width;
    if num < 2 {
        return;
    }

    if try_integer_unstable_lanes(base, width, num, &compare) {
        return;
    }

    // Number of imbalanced partitions tolerated before falling back to
    // heapsort. floor(log2(num)) + 1 keeps the bad-case bound at O(n·log n).
    let limit = usize::BITS - num.leading_zeros();
    pdqsort_recurse(base, width, &compare, 0, num, None, limit);
}

/// Try the verify-then-commit integer sort lanes shared by the two unstable
/// entry points (`qsort` and `heapsort`). Returns `true` iff a lane produced a
/// result that is genuinely non-decreasing under the caller's comparator (so it
/// has been committed in place); `false` leaves `base` holding the original
/// bytes for the caller's generic sort to handle.
///
/// Every lane is parity-safe by construction: the natural integer arrangement
/// is committed only after an O(n) verify against the actual comparator, so a
/// non-natural comparator (unsigned, descending, float, struct key, …) falls
/// back with zero behavioral difference. Because equal integer keys are
/// byte-identical, a committed result is byte-identical to any correct sort.
/// Both callers are unstable, so the lanes' tie order is conformant for both.
fn try_integer_unstable_lanes<F>(base: &mut [u8], width: usize, num: usize, compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    // 4-/8-byte comparison fast lanes (sort raw keys via the stdlib sort with no
    // per-comparison FFI callback) for the mid-size window.
    if width == 4 && (I32_FAST_LANE_MIN..=I32_FAST_LANE_MAX).contains(&num) {
        if try_qsort_i32_natural_fast_lane(base, num, compare) {
            return true;
        }
    }
    if width == 8 && (I64_FAST_LANE_MIN..=I64_FAST_LANE_MAX).contains(&num) {
        if try_qsort_i64_natural_fast_lane(base, num, compare) {
            return true;
        }
    }

    // 1-byte keys: a dedicated counting sort (O(n + 256)) — one histogram pass
    // plus one memset run per value, no key widening. Beats both pdqsort and the
    // generic u64-widening radix (which regresses on bytes).
    if width == 1 && num > U8_COUNTING_LANE_MIN {
        if try_qsort_u8_counting_lane(base, num, compare) {
            return true;
        }
    }

    // 2-/4-/8-byte keys above the radix threshold: an LSD radix sort, a
    // different complexity class (O(n · key_bytes) linear passes, no per-element
    // comparison) that wins decisively once N is large. 2-byte keys have no
    // comparison fast lane and a 2-pass radix is cheap, so they take the lane at
    // a much lower threshold than 4-/8-byte keys.
    let radix_min = if width == 2 {
        NARROW_RADIX_LANE_MIN
    } else {
        INTEGER_RADIX_LANE_MIN
    };
    if (width == 2 || width == 4 || width == 8) && num > radix_min {
        if try_qsort_integer_radix_lane(base, num, width, compare) {
            return true;
        }
    }

    false
}

/// Element index helper: borrows the `i`-th element as a byte slice.
#[inline]
fn elem(buf: &[u8], width: usize, i: usize) -> &[u8] {
    &buf[i * width..(i + 1) * width]
}

fn try_qsort_i32_natural_fast_lane<F>(base: &mut [u8], num: usize, compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let active_len = num * 4;
    let active = &mut base[..active_len];
    let mut original = Vec::with_capacity(num);
    let mut values = Vec::with_capacity(num);
    for chunk in active.chunks_exact(4) {
        let bytes = [chunk[0], chunk[1], chunk[2], chunk[3]];
        original.push(bytes);
        values.push(i32::from_ne_bytes(bytes));
    }

    values.sort_unstable();
    for (chunk, value) in active.chunks_exact_mut(4).zip(&values) {
        chunk.copy_from_slice(&value.to_ne_bytes());
    }

    if qsort_i32_candidate_is_ordered(active, compare) {
        return true;
    }

    for (chunk, bytes) in active.chunks_exact_mut(4).zip(original) {
        chunk.copy_from_slice(&bytes);
    }
    false
}

fn qsort_i32_candidate_is_ordered<F>(active: &[u8], compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let mut prev = &active[..4];
    for current in active[4..].chunks_exact(4) {
        if compare(prev, current) > 0 {
            return false;
        }
        prev = current;
    }
    true
}

/// 8-byte analog of [`try_qsort_i32_natural_fast_lane`]. The vast majority of
/// `qsort` calls with `width == 8` sort native machine words (`int64_t`,
/// pointers, indices) under a comparator that is equivalent to natural signed
/// 64-bit order. Sorting the raw `i64` values with the standard-library sort
/// (no per-comparison FFI callback) and then verifying the result against the
/// caller's comparator in a single linear pass is dramatically faster than
/// driving `pdqsort_recurse` through `O(n log n)` indirect comparator calls.
///
/// Safety of the optimization rests entirely on the verify step: the natural
/// `i64` arrangement is committed only if it is genuinely non-decreasing under
/// the caller's own comparator. For any comparator where that holds, the output
/// is a valid `qsort` result — and because equal-comparing `i64` keys are also
/// byte-identical, the emitted bytes are independent of tie order, so the output
/// is bit-identical to what the generic path would produce. Comparators that do
/// not match natural order (unsigned, floating-point, struct keys, descending)
/// fail the verify, the original bytes are restored, and we fall back to the
/// generic pdqsort with zero behavioral difference.
fn try_qsort_i64_natural_fast_lane<F>(base: &mut [u8], num: usize, compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let active_len = num * 8;
    let active = &mut base[..active_len];
    let mut original = Vec::with_capacity(num);
    let mut values = Vec::with_capacity(num);
    for chunk in active.chunks_exact(8) {
        let bytes = [
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ];
        original.push(bytes);
        values.push(i64::from_ne_bytes(bytes));
    }

    values.sort_unstable();
    for (chunk, value) in active.chunks_exact_mut(8).zip(&values) {
        chunk.copy_from_slice(&value.to_ne_bytes());
    }

    if qsort_i64_candidate_is_ordered(active, compare) {
        return true;
    }

    for (chunk, bytes) in active.chunks_exact_mut(8).zip(original) {
        chunk.copy_from_slice(&bytes);
    }
    false
}

fn qsort_i64_candidate_is_ordered<F>(active: &[u8], compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let mut prev = &active[..8];
    for current in active[8..].chunks_exact(8) {
        if compare(prev, current) > 0 {
            return false;
        }
        prev = current;
    }
    true
}

/// Counting-sort lane for 1-byte keys.
///
/// Builds a 256-bucket histogram in one linear pass, then materialises the
/// sorted array by filling one contiguous run per distinct byte value (a
/// memset per bucket) — `O(n + 256)`, with no key widening and no per-element
/// comparison. Because every element in a bucket is the identical byte, the
/// emitted bytes are independent of tie order, so a committed result is
/// byte-identical to any correct sort (including glibc's).
///
/// A byte comparator is almost always either unsigned (`u8`/`unsigned char`,
/// ascending byte order) or signed (`i8`/`signed char`, ascending value order =
/// bytes `0x80..=0xFF` then `0x00..=0x7F`). We materialise the unsigned order
/// first and verify it against the caller's comparator; on failure we re-emit
/// the signed order and verify that; if neither is non-decreasing the original
/// bytes are restored and the caller falls back to the generic pdqsort, exactly
/// like the other integer lanes. Parity is therefore absolute.
fn try_qsort_u8_counting_lane<F>(base: &mut [u8], num: usize, compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let active = &mut base[..num];

    let mut count = [0usize; 256];
    for &b in active.iter() {
        count[b as usize] += 1;
    }

    // Preserve the original byte order so a comparator that neither natural
    // order satisfies can fall back to pdqsort over the exact original input —
    // keeping the fallback's (unspecified) tie order byte-identical to glibc.
    let original = active.to_vec();

    // Materialise the buckets in `order`, one run (memset) per value, then
    // verify the result is non-decreasing under `compare`.
    fn emit_and_check<F, I>(active: &mut [u8], count: &[usize; 256], order: I, compare: &F) -> bool
    where
        F: Fn(&[u8], &[u8]) -> i32,
        I: Iterator<Item = usize>,
    {
        let mut pos = 0usize;
        for v in order {
            let c = count[v];
            if c != 0 {
                active[pos..pos + c].fill(v as u8);
                pos += c;
            }
        }
        // Runs are internally uniform, so a comparator mismatch can only occur
        // at a run boundary; checking every adjacent pair is still linear.
        let mut prev = &active[..1];
        for cur in active[1..].chunks_exact(1) {
            if compare(prev, cur) > 0 {
                return false;
            }
            prev = cur;
        }
        true
    }

    // Unsigned-ascending (the dominant `unsigned char` case).
    if emit_and_check(active, &count, 0usize..256, compare) {
        return true;
    }
    // Signed-ascending (`signed char`): negative bytes 0x80..=0xFF first.
    if emit_and_check(active, &count, (128usize..256).chain(0..128), compare) {
        return true;
    }

    // Neither natural order satisfies the comparator: restore the exact
    // original bytes and let the caller's pdqsort handle it.
    active.copy_from_slice(&original);
    false
}

/// LSD radix lane for large 2-/4-/8-byte integer arrays. Width 2 runs two 8-bit
/// passes; width 4 four; width 8 eight.
///
/// Reinterprets each element as its native-endian integer, maps it to an
/// order-preserving unsigned "rank" by flipping the sign bit (so two's
/// complement order coincides with unsigned byte order), and sorts the ranks
/// with a least-significant-digit radix sort (8-bit digits, `width` linear
/// passes). The sorted ranks are written back as the original integer bytes.
///
/// Parity is preserved by the same verify-then-commit contract as the
/// comparison fast lanes: the radix arrangement is committed only if it is
/// genuinely non-decreasing under the caller's own comparator. Natural signed
/// integer comparators pass and yield output bit-identical to glibc (equal keys
/// are byte-identical, so tie order is immaterial). Any other comparator
/// (unsigned, descending, float, struct field, …) fails the single linear
/// verify pass; the saved original bytes are restored and the caller falls back
/// to the generic pdqsort with zero behavioral difference.
fn try_qsort_integer_radix_lane<F>(
    base: &mut [u8],
    num: usize,
    width: usize,
    compare: &F,
) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    debug_assert!(width == 2 || width == 4 || width == 8);
    let active_len = num * width;
    let active = &mut base[..active_len];
    let sign_mask: u64 = 1u64 << (width as u64 * 8 - 1);

    // Extract sign-flipped unsigned rank keys.
    let mut keys: Vec<u64> = Vec::with_capacity(num);
    for chunk in active.chunks_exact(width) {
        let mut raw = [0u8; 8];
        raw[..width].copy_from_slice(chunk);
        keys.push(u64::from_ne_bytes(raw) ^ sign_mask);
    }

    // Preserve the original bytes so a non-natural comparator can fall back.
    let original = active.to_vec();

    radix_sort_u64_lsd(&mut keys, width);

    // Write sorted keys back as their original integer byte representation.
    for (chunk, &k) in active.chunks_exact_mut(width).zip(&keys) {
        let restored = (k ^ sign_mask).to_ne_bytes();
        chunk.copy_from_slice(&restored[..width]);
    }

    // Verify the radix arrangement satisfies the caller's comparator.
    let mut ordered = true;
    let mut prev = &active[..width];
    for current in active[width..].chunks_exact(width) {
        if compare(prev, current) > 0 {
            ordered = false;
            break;
        }
        prev = current;
    }
    if ordered {
        return true;
    }

    active.copy_from_slice(&original);
    false
}

/// Stable least-significant-digit radix sort over 8-bit digits. Runs `passes`
/// counting passes (one per significant key byte) using a ping-pong auxiliary
/// buffer; a pass whose digit is constant across all keys is skipped. On return
/// `keys` holds the ascending-sorted values.
fn radix_sort_u64_lsd(keys: &mut Vec<u64>, passes: usize) {
    let n = keys.len();
    if n < 2 {
        return;
    }
    let mut aux: Vec<u64> = vec![0u64; n];
    for p in 0..passes {
        let shift = (p as u64) * 8;
        let mut count = [0usize; 256];
        for &k in keys.iter() {
            count[((k >> shift) & 0xff) as usize] += 1;
        }
        // Skip passes where every key shares the same digit (e.g. unused high
        // bytes of small-magnitude integers) — the order is already settled.
        if count.iter().any(|&c| c == n) {
            continue;
        }
        let mut sum = 0usize;
        for c in count.iter_mut() {
            let cur = *c;
            *c = sum;
            sum += cur;
        }
        for &k in keys.iter() {
            let d = ((k >> shift) & 0xff) as usize;
            aux[count[d]] = k;
            count[d] += 1;
        }
        core::mem::swap(keys, &mut aux);
    }
}

/// pdqsort core. Operates on the element-index range `[lo, hi)` of `buf`.
///
/// `pred`, when present, is the index of the pivot element immediately
/// preceding this range; it is already in its final sorted position and never
/// moves, so it is safe to keep as an index. The invariant `buf[pred] <= every
/// element in [lo, hi)` lets us detect and collapse runs of duplicate keys.
fn pdqsort_recurse<F>(
    buf: &mut [u8],
    width: usize,
    compare: &F,
    mut lo: usize,
    mut hi: usize,
    mut pred: Option<usize>,
    mut limit: u32,
) where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let mut was_balanced = true;
    let mut was_partitioned = true;

    loop {
        let len = hi - lo;

        // Small slices: insertion sort is the fastest finisher and keeps the
        // stable behavior the small-input conformance fixtures expect.
        if len <= MAX_INSERTION {
            if len >= 2 {
                insertion_sort(&mut buf[lo * width..hi * width], width, compare);
            }
            return;
        }

        // Too many imbalanced partitions: switch to heapsort for a hard
        // O(n·log n) guarantee on adversarial input.
        if limit == 0 {
            heapsort(&mut buf[lo * width..hi * width], width, compare);
            return;
        }

        // The previous partition was lopsided: shuffle a few elements to
        // destroy the pattern that caused it, then spend one limit token.
        if !was_balanced {
            break_patterns(buf, width, lo, hi);
            limit -= 1;
        }

        let (pivot, likely_sorted) = choose_pivot(buf, width, compare, lo, hi);

        // If the slice looks nearly sorted and the last partition was clean,
        // try a bounded insertion sort; if it finishes the slice, we are done
        // in O(n) instead of O(n·log n).
        if was_balanced
            && was_partitioned
            && likely_sorted
            && partial_insertion_sort(buf, width, compare, lo, hi)
        {
            return;
        }

        // If the predecessor pivot equals this pivot then every element in the
        // range is >= pred == pivot. Collapse the equal block in one pass and
        // recurse only on the strictly-greater tail — O(n) on low-cardinality
        // keys instead of the repeated full scans of a naive partition.
        if let Some(p) = pred
            && compare(elem(buf, width, p), elem(buf, width, pivot)) >= 0
        {
            lo = partition_equal(buf, width, compare, lo, hi, pivot);
            continue;
        }

        let (mid, partitioned) = pdq_partition(buf, width, compare, lo, hi, pivot);
        was_partitioned = partitioned;

        let left_len = mid - lo;
        let right_len = hi - (mid + 1);
        was_balanced = left_len.min(right_len) >= len / 8;

        // Recurse into the smaller side and loop on the larger to bound stack
        // depth to O(log n). The pivot at `mid` is now final and becomes the
        // predecessor of whichever side sits to its right.
        if left_len < right_len {
            pdqsort_recurse(buf, width, compare, lo, mid, pred, limit);
            lo = mid + 1;
            pred = Some(mid);
        } else {
            pdqsort_recurse(buf, width, compare, mid + 1, hi, Some(mid), limit);
            hi = mid;
        }
    }
}

/// Order two index variables so that `buf[*x] <= buf[*y]`, counting reorders.
#[inline]
fn sort2_idx<F>(
    buf: &[u8],
    width: usize,
    compare: &F,
    x: &mut usize,
    y: &mut usize,
    swaps: &mut usize,
) where
    F: Fn(&[u8], &[u8]) -> i32,
{
    if compare(elem(buf, width, *y), elem(buf, width, *x)) < 0 {
        core::mem::swap(x, y);
        *swaps += 1;
    }
}

/// Order three index variables so that `buf[*a] <= buf[*b] <= buf[*c]`.
#[inline]
fn sort3_idx<F>(
    buf: &[u8],
    width: usize,
    compare: &F,
    a: &mut usize,
    b: &mut usize,
    c: &mut usize,
    swaps: &mut usize,
) where
    F: Fn(&[u8], &[u8]) -> i32,
{
    sort2_idx(buf, width, compare, a, b, swaps);
    sort2_idx(buf, width, compare, b, c, swaps);
    sort2_idx(buf, width, compare, a, b, swaps);
}

/// Replace `*a` with the index of the median of `{*a-1, *a, *a+1}`.
#[inline]
fn sort_adjacent_idx<F>(buf: &[u8], width: usize, compare: &F, a: &mut usize, swaps: &mut usize)
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let tmp = *a;
    let mut p = tmp - 1;
    let mut r = tmp + 1;
    sort3_idx(buf, width, compare, &mut p, a, &mut r, swaps);
}

/// Choose a pivot for `[lo, hi)` using a median-of-three (median-of-medians for
/// large slices). Returns the pivot's element index and `true` when the slice
/// is likely already sorted. If it looks reverse-sorted, the range is reversed
/// in place so the caller can treat it as ascending.
fn choose_pivot<F>(buf: &mut [u8], width: usize, compare: &F, lo: usize, hi: usize) -> (usize, bool)
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    const SHORTEST_MEDIAN_OF_MEDIANS: usize = 50;
    const MAX_SWAPS: usize = 4 * 3;

    let len = hi - lo;
    let quarter = len / 4;
    let mut a = lo + quarter;
    let mut b = lo + quarter * 2;
    let mut c = lo + quarter * 3;
    let mut swaps = 0usize;

    if len >= 8 {
        if len >= SHORTEST_MEDIAN_OF_MEDIANS {
            sort_adjacent_idx(buf, width, compare, &mut a, &mut swaps);
            sort_adjacent_idx(buf, width, compare, &mut b, &mut swaps);
            sort_adjacent_idx(buf, width, compare, &mut c, &mut swaps);
        }
        sort3_idx(buf, width, compare, &mut a, &mut b, &mut c, &mut swaps);
    }

    if swaps < MAX_SWAPS {
        (b, swaps == 0)
    } else {
        // The candidates were maximally out of order — the slice is likely
        // descending. Reverse it so downstream logic sees ascending data.
        reverse_range(buf, width, lo, hi);
        let rel_b = b - lo;
        (lo + (len - 1 - rel_b), true)
    }
}

/// Reverse the element range `[lo, hi)` in place.
fn reverse_range(buf: &mut [u8], width: usize, lo: usize, hi: usize) {
    let mut i = lo;
    let mut j = hi;
    while i < j {
        j -= 1;
        swap_chunks(buf, i, j, width);
        i += 1;
    }
}

/// Forward (Lomuto-style) partition of `[lo, hi)` around the pivot at index
/// `pivot`. Returns the pivot's final element index and whether the range was
/// already partitioned. A single forward scan keeps one cache stream and good
/// hardware prefetch, which measures faster here than a bidirectional Hoare
/// scan despite Hoare's lower swap count. Elements equal to the pivot are sent
/// right; runs of them are collapsed separately via `partition_equal`.
fn pdq_partition<F>(
    buf: &mut [u8],
    width: usize,
    compare: &F,
    lo: usize,
    hi: usize,
    pivot: usize,
) -> (usize, bool)
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    // Stash the pivot value at the front so comparisons reference a fixed slot.
    swap_chunks(buf, lo, pivot, width);

    let mut store = lo + 1;
    let mut was_partitioned = true;
    let mut j = lo + 1;
    while j < hi {
        if compare(elem(buf, width, j), elem(buf, width, lo)) < 0 {
            if j != store {
                swap_chunks(buf, store, j, width);
                was_partitioned = false;
            }
            store += 1;
        }
        j += 1;
    }

    // Elements [lo+1, store) are < pivot; move the pivot to the boundary so it
    // sits in its final sorted position.
    let mid = store - 1;
    swap_chunks(buf, lo, mid, width);
    (mid, was_partitioned)
}

/// Partition `[lo, hi)` into the block of elements equal to the pivot (at
/// `pivot`) followed by the strictly-greater elements. Returns the index of the
/// first strictly-greater element. Used when the predecessor pivot equals this
/// pivot, collapsing duplicate runs in a single linear pass.
fn partition_equal<F>(
    buf: &mut [u8],
    width: usize,
    compare: &F,
    lo: usize,
    hi: usize,
    pivot: usize,
) -> usize
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    swap_chunks(buf, lo, pivot, width);

    let mut l = lo + 1;
    let mut r = hi;
    loop {
        // Advance over elements equal to the pivot (all are >= pivot here, so
        // `pivot >= elem` means equal).
        while l < r && compare(elem(buf, width, lo), elem(buf, width, l)) >= 0 {
            l += 1;
        }
        while l < r && compare(elem(buf, width, lo), elem(buf, width, r - 1)) < 0 {
            r -= 1;
        }
        if l >= r {
            break;
        }
        r -= 1;
        swap_chunks(buf, l, r, width);
        l += 1;
    }
    l
}

/// Bounded insertion sort used as the nearly-sorted shortcut. Performs at most
/// `MAX_STEPS` corrective insertions; returns `true` only if the whole range
/// `[lo, hi)` ends up fully sorted. A `false` return may leave the range
/// partially reordered, which is harmless: the caller proceeds to partition it.
fn partial_insertion_sort<F>(
    buf: &mut [u8],
    width: usize,
    compare: &F,
    lo: usize,
    hi: usize,
) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    const MAX_STEPS: usize = 5;
    const SHORTEST_SHIFTING: usize = 50;

    let len = hi - lo;
    let mut i = lo + 1;
    for _ in 0..MAX_STEPS {
        // Skip the in-order prefix.
        while i < hi && compare(elem(buf, width, i), elem(buf, width, i - 1)) >= 0 {
            i += 1;
        }
        if i == hi {
            return true;
        }
        if len < SHORTEST_SHIFTING {
            return false;
        }
        // Insert the out-of-order element at `i` into the sorted prefix.
        let mut j = i;
        while j > lo && compare(elem(buf, width, j - 1), elem(buf, width, j)) > 0 {
            swap_chunks(buf, j - 1, j, width);
            j -= 1;
        }
        i += 1;
    }
    false
}

/// Deterministically shuffle a few elements of `[lo, hi)` to break up patterns
/// (e.g. median-of-three killers) that cause repeated imbalanced partitions.
/// Seeded solely by `len`, so the result is reproducible and the final sort
/// order is unaffected.
fn break_patterns(buf: &mut [u8], width: usize, lo: usize, hi: usize) {
    let len = hi - lo;
    if len < 8 {
        return;
    }
    let mut seed = len as u64;
    let modulus = len.next_power_of_two();
    let pos = (len / 4) * 2;
    for i in 0..3 {
        // xorshift64 — cheap, deterministic pseudo-random index.
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let mut other = (seed as usize) & (modulus - 1);
        if other >= len {
            other -= len;
        }
        swap_chunks(buf, lo + pos - 1 + i, lo + other, width);
    }
}

fn swap_chunks(buffer: &mut [u8], i: usize, j: usize, width: usize) {
    if i == j {
        return;
    }
    let (head, tail) = if i < j {
        buffer.split_at_mut(j * width)
    } else {
        buffer.split_at_mut(i * width)
    };

    let first = if i < j {
        &mut head[i * width..(i + 1) * width]
    } else {
        &mut head[j * width..(j + 1) * width]
    };

    first.swap_with_slice(&mut tail[0..width]);
}

/// Insertion sort fallback for small or deeply-recursed subarrays.
fn insertion_sort<F>(buffer: &mut [u8], width: usize, compare: &F)
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    if width <= INSERTION_STACK_SCRATCH {
        insertion_sort_block_move(buffer, width, compare);
        return;
    }
    insertion_sort_adjacent_swaps(buffer, width, compare);
}

fn insertion_sort_adjacent_swaps<F>(buffer: &mut [u8], width: usize, compare: &F)
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let count = buffer.len() / width;
    for i in 1..count {
        let mut j = i;
        while j > 0 {
            let cmp = compare(
                &buffer[(j - 1) * width..j * width],
                &buffer[j * width..(j + 1) * width],
            );
            if cmp <= 0 {
                break;
            }
            swap_chunks(buffer, j - 1, j, width);
            j -= 1;
        }
    }
}

fn insertion_sort_block_move<F>(buffer: &mut [u8], width: usize, compare: &F)
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    debug_assert!(width <= INSERTION_STACK_SCRATCH);
    let count = buffer.len() / width;
    let mut scratch = [0u8; INSERTION_STACK_SCRATCH];
    for i in 1..count {
        let item_start = i * width;
        let item_end = item_start + width;
        let mut insert = i;
        while insert > 0 {
            let prev_start = (insert - 1) * width;
            let prev_end = insert * width;
            if compare(&buffer[prev_start..prev_end], &buffer[item_start..item_end]) <= 0 {
                break;
            }
            insert -= 1;
        }

        if insert == i {
            continue;
        }

        scratch[..width].copy_from_slice(&buffer[item_start..item_end]);
        let dest_start = insert * width;
        buffer.copy_within(dest_start..item_start, dest_start + width);
        buffer[dest_start..dest_start + width].copy_from_slice(&scratch[..width]);
    }
}

/// Generic bsearch implementation.
pub fn bsearch<'a, K, F>(key: &K, base: &'a [u8], width: usize, compare: F) -> Option<&'a [u8]>
where
    K: ?Sized,
    F: Fn(&K, &[u8]) -> i32,
{
    if width == 0 || base.len() < width {
        return None;
    }

    let count = base.len() / width;
    let mut low = 0;
    let mut high = count;

    while low < high {
        let mid = low + (high - low) / 2;
        let mid_elem = &base[mid * width..(mid + 1) * width];
        let cmp = compare(key, mid_elem);

        if cmp == 0 {
            return Some(mid_elem);
        } else if cmp < 0 {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// mergesort / heapsort — BSD libc sort variants
// ---------------------------------------------------------------------------

/// Stable BSD `mergesort`: same signature as `qsort` but preserves
/// input order for elements that compare equal. Uses Rust's
/// `Vec::sort_by` (timsort) on a copied-out element table, then
/// writes the sorted elements back. This matches libbsd's contract
/// of allocating temporary storage proportional to the input.
pub fn mergesort<F>(base: &mut [u8], width: usize, compare: F)
where
    F: Fn(&[u8], &[u8]) -> i32 + Copy,
{
    if width == 0 || base.len() < width {
        return;
    }
    let num = base.len() / width;
    if num < 2 {
        return;
    }

    // Stable sort via an index permutation, NOT a `Vec<Vec<u8>>`. The previous
    // implementation heap-allocated one `Vec<u8>` per element (n allocations) —
    // catastrophic for large n (measured ~200 ms / 3.2x slower than a reference
    // qsort at n=262144). Instead, stably sort a single index array by the
    // comparator and gather the result through one scratch buffer: O(n) extra
    // memory and zero per-element allocations.
    //
    // Behavior is byte-identical to the old code: `[_]::sort_by` is stable and
    // the index array starts in ascending (i.e. original) order, so equal-
    // comparing elements keep their input order exactly as the old element-copy
    // stable sort did.
    if num <= u32::MAX as usize {
        let mut idx: Vec<u32> = (0..num as u32).collect();
        idx.sort_by(|&a, &b| {
            let ea = &base[a as usize * width..a as usize * width + width];
            let eb = &base[b as usize * width..b as usize * width + width];
            compare(ea, eb).cmp(&0)
        });
        let mut scratch = vec![0u8; num * width];
        for (dst, &src) in idx.iter().enumerate() {
            let s = src as usize * width;
            scratch[dst * width..dst * width + width].copy_from_slice(&base[s..s + width]);
        }
        base[..num * width].copy_from_slice(&scratch);
    } else {
        let mut idx: Vec<usize> = (0..num).collect();
        idx.sort_by(|&a, &b| {
            let ea = &base[a * width..a * width + width];
            let eb = &base[b * width..b * width + width];
            compare(ea, eb).cmp(&0)
        });
        let mut scratch = vec![0u8; num * width];
        for (dst, &src) in idx.iter().enumerate() {
            scratch[dst * width..dst * width + width]
                .copy_from_slice(&base[src * width..src * width + width]);
        }
        base[..num * width].copy_from_slice(&scratch);
    }
}

/// In-place BSD `heapsort`: builds a max-heap on the byte buffer
/// itself (via index manipulation + element swaps) then repeatedly
/// extracts the maximum. NOT stable. Uses no auxiliary storage
/// proportional to `nmemb`.
pub fn heapsort<F>(base: &mut [u8], width: usize, compare: F)
where
    F: Fn(&[u8], &[u8]) -> i32 + Copy,
{
    if width == 0 || base.len() < width {
        return;
    }
    let num = base.len() / width;
    if num < 2 {
        return;
    }

    // `heapsort` is unstable, so the same verify-then-commit integer lanes that
    // accelerate `qsort` apply unchanged. For integer keys these turn the
    // cache-unfriendly O(n log n) sift-down (with a comparator callback per
    // comparison) into an O(n) radix/counting pass; non-integer or non-natural
    // comparators fall back to the in-place heap sort below with no behavioral
    // difference.
    if try_integer_unstable_lanes(base, width, num, &compare) {
        return;
    }

    // Build heap (heapify — sift down from the last non-leaf).
    let mut start = num / 2;
    while start > 0 {
        start -= 1;
        sift_down(base, width, &compare, start, num);
    }

    // Repeatedly swap the root (max) with the last element of the
    // active region, then sift down from 0 in the shrunk region.
    let mut end = num;
    while end > 1 {
        end -= 1;
        swap_elements(base, width, 0, end);
        sift_down(base, width, &compare, 0, end);
    }
}

fn swap_elements(base: &mut [u8], width: usize, a: usize, b: usize) {
    if a == b {
        return;
    }
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let (left, right) = base.split_at_mut(hi * width);
    let lo_slice = &mut left[lo * width..(lo + 1) * width];
    let hi_slice = &mut right[..width];
    for i in 0..width {
        core::mem::swap(&mut lo_slice[i], &mut hi_slice[i]);
    }
}

fn sift_down<F>(base: &mut [u8], width: usize, compare: &F, mut root: usize, end: usize)
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    loop {
        let left = 2 * root + 1;
        if left >= end {
            return;
        }
        let right = left + 1;
        // Pick the larger child.
        let mut largest = left;
        if right < end {
            let l_slice = &base[left * width..(left + 1) * width];
            let r_slice = &base[right * width..(right + 1) * width];
            if compare(l_slice, r_slice) < 0 {
                largest = right;
            }
        }
        // Compare against root.
        let root_slice = &base[root * width..(root + 1) * width];
        let largest_slice = &base[largest * width..(largest + 1) * width];
        if compare(root_slice, largest_slice) >= 0 {
            return;
        }
        swap_elements(base, width, root, largest);
        root = largest;
    }
}

// ---------------------------------------------------------------------------
// radixsort / sradixsort (NetBSD libutil radix sort family)
// ---------------------------------------------------------------------------

/// Sort `items` by translated-byte order and return the permutation
/// that would produce sorted output: `out[i]` is the index in
/// `items` of the i-th sorted element.
///
/// `table`, when supplied, maps each input byte to a sort key. When
/// `None`, byte values are compared directly. The comparison reads
/// items position by position; the shorter slice sorts before a
/// longer slice that agrees on every byte of the shorter prefix.
///
/// `stable` controls whether equal-key items retain their input
/// order. Set this to `true` to mirror NetBSD `sradixsort` and
/// `false` for `radixsort` (which makes no stability promise — but
/// since stable is a strict superset of unstable behavior, callers
/// of `radixsort` cannot observe any regression from a stable
/// implementation).
pub fn radix_sort(items: &[&[u8]], table: Option<&[u8; 256]>, stable: bool) -> Vec<usize> {
    let mut order: Vec<usize> = (0..items.len()).collect();
    if stable {
        order.sort_by(|&a, &b| compare_translated(items[a], items[b], table));
    } else {
        order.sort_unstable_by(|&a, &b| compare_translated(items[a], items[b], table));
    }
    order
}

fn compare_translated(a: &[u8], b: &[u8], table: Option<&[u8; 256]>) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    let n = a.len().min(b.len());
    for i in 0..n {
        let ak = table.map_or(a[i], |t| t[a[i] as usize]);
        let bk = table.map_or(b[i], |t| t[b[i] as usize]);
        match ak.cmp(&bk) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    a.len().cmp(&b.len())
}

#[cfg(test)]
mod sort_variant_tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn cmp_u32_le(a: &[u8], b: &[u8]) -> i32 {
        let av = u32::from_le_bytes(a[..4].try_into().unwrap());
        let bv = u32::from_le_bytes(b[..4].try_into().unwrap());
        av.cmp(&bv) as i32
    }

    fn flatten_u32(values: &[u32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(values.len() * 4);
        for &v in values {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    }

    fn cmp_i32_ne(a: &[u8], b: &[u8]) -> i32 {
        let av = i32::from_ne_bytes(a[..4].try_into().unwrap());
        let bv = i32::from_ne_bytes(b[..4].try_into().unwrap());
        av.cmp(&bv) as i32
    }

    fn flatten_i32_ne(values: &[i32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(values.len() * 4);
        for &v in values {
            out.extend_from_slice(&v.to_ne_bytes());
        }
        out
    }

    fn unflatten_i32_ne(bytes: &[u8]) -> Vec<i32> {
        bytes
            .chunks_exact(4)
            .map(|c| i32::from_ne_bytes(c.try_into().unwrap()))
            .collect()
    }

    fn unflatten_u32(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect()
    }

    fn cmp_key_u32(key: &u32, elem: &[u8]) -> i32 {
        let ev = u32::from_le_bytes(elem[..4].try_into().unwrap());
        key.cmp(&ev) as i32
    }

    // ---- cross-sort/search metamorphic invariants ----

    #[test]
    fn qsort_permutation_invariance_matches_reversed_input() {
        let values = [42, 7, 19, 7, 0, 255, 3, 19, 88, 1, 144, 2];
        let reversed: Vec<u32> = values.iter().copied().rev().collect();

        let mut original_buf = flatten_u32(&values);
        let mut reversed_buf = flatten_u32(&reversed);
        qsort(&mut original_buf, 4, cmp_u32_le);
        qsort(&mut reversed_buf, 4, cmp_u32_le);

        assert_eq!(unflatten_u32(&original_buf), unflatten_u32(&reversed_buf));
    }

    #[test]
    fn qsort_small_partition_cutoff_preserves_sorted_multiset() {
        let values = [11, 7, 3, 7, 0, 19, 2, 2, 5, 13, 17, 1, 11, 23, 5, 29];
        let mut expected = values.to_vec();
        expected.sort_unstable();

        let mut buf = flatten_u32(&values);
        qsort(&mut buf, 4, cmp_u32_le);

        assert_eq!(unflatten_u32(&buf), expected);
    }

    #[test]
    fn qsort_small_partition_block_move_preserves_equal_order() {
        let values = [(3_u32, 0_u32), (1, 1), (3, 2), (2, 3), (1, 4), (2, 5)];
        let mut buf = Vec::with_capacity(values.len() * 8);
        for &(key, position) in &values {
            buf.extend_from_slice(&key.to_le_bytes());
            buf.extend_from_slice(&position.to_le_bytes());
        }

        qsort(&mut buf, 8, |a, b| cmp_u32_le(&a[..4], &b[..4]));
        let sorted: Vec<(u32, u32)> = buf
            .chunks_exact(8)
            .map(|chunk| {
                (
                    u32::from_le_bytes(chunk[..4].try_into().unwrap()),
                    u32::from_le_bytes(chunk[4..].try_into().unwrap()),
                )
            })
            .collect();

        assert_eq!(sorted, [(1, 1), (1, 4), (2, 3), (2, 5), (3, 0), (3, 2)]);
    }

    #[test]
    fn sort_variants_agree_under_total_order() {
        let values = [13, 5, 8, 5, 21, 3, 34, 2, 1, 1, 55, 0, 89];
        let mut qsort_buf = flatten_u32(&values);
        let mut mergesort_buf = flatten_u32(&values);
        let mut heapsort_buf = flatten_u32(&values);

        qsort(&mut qsort_buf, 4, cmp_u32_le);
        mergesort(&mut mergesort_buf, 4, cmp_u32_le);
        heapsort(&mut heapsort_buf, 4, cmp_u32_le);

        assert_eq!(qsort_buf, mergesort_buf);
        assert_eq!(qsort_buf, heapsort_buf);
    }

    #[test]
    fn bsearch_finds_each_distinct_key_after_qsort() {
        let mut buf = flatten_u32(&[12, 4, 12, 9, 1, 0, 4, 16, 25, 9]);
        qsort(&mut buf, 4, cmp_u32_le);

        for key in [0, 1, 4, 9, 12, 16, 25] {
            let found = bsearch(&key, &buf, 4, cmp_key_u32).expect("key should be present");
            assert_eq!(u32::from_le_bytes(found.try_into().unwrap()), key);
        }
        assert!(bsearch(&11, &buf, 4, cmp_key_u32).is_none());
    }

    #[test]
    fn radix_sort_identity_table_matches_untranslated_order() {
        let mut identity = [0u8; 256];
        for (i, slot) in identity.iter_mut().enumerate() {
            *slot = i as u8;
        }
        let items: Vec<&[u8]> = vec![b"beta", b"alpha", b"alphabet", b"gamma", b""];

        assert_eq!(
            radix_sort(&items, Some(&identity), true),
            radix_sort(&items, None, true)
        );
        assert_eq!(
            radix_sort(&items, Some(&identity), false),
            radix_sort(&items, None, false)
        );
    }

    // ---- mergesort (stable) ----

    #[test]
    fn mergesort_handles_sorted_input() {
        let mut buf = flatten_u32(&[1, 2, 3, 4, 5]);
        mergesort(&mut buf, 4, cmp_u32_le);
        assert_eq!(unflatten_u32(&buf), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn mergesort_handles_reverse_input() {
        let mut buf = flatten_u32(&[5, 4, 3, 2, 1]);
        mergesort(&mut buf, 4, cmp_u32_le);
        assert_eq!(unflatten_u32(&buf), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn mergesort_handles_random_input() {
        let mut buf = flatten_u32(&[3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5]);
        mergesort(&mut buf, 4, cmp_u32_le);
        assert_eq!(unflatten_u32(&buf), vec![1, 1, 2, 3, 3, 4, 5, 5, 5, 6, 9]);
    }

    #[test]
    fn mergesort_is_stable() {
        // Encode (key, original_index) as 8 bytes: low 4 = key, high 4 = idx.
        // Compare on key only; verify that equal-key elements preserve
        // their original index ordering.
        let pairs = [(5u32, 0u32), (3, 1), (5, 2), (1, 3), (3, 4), (5, 5), (1, 6)];
        let mut buf = Vec::with_capacity(pairs.len() * 8);
        for &(k, i) in &pairs {
            buf.extend_from_slice(&k.to_le_bytes());
            buf.extend_from_slice(&i.to_le_bytes());
        }
        mergesort(&mut buf, 8, |a, b| cmp_u32_le(&a[..4], &b[..4]));
        let sorted: Vec<(u32, u32)> = buf
            .chunks_exact(8)
            .map(|c| {
                (
                    u32::from_le_bytes(c[0..4].try_into().unwrap()),
                    u32::from_le_bytes(c[4..8].try_into().unwrap()),
                )
            })
            .collect();
        // For each key group, the indices must be in their original
        // ascending order — that's the stability guarantee.
        let mut expected = pairs.to_vec();
        expected.sort_by_key(|a| a.0);
        assert_eq!(sorted, expected);
    }

    #[test]
    fn mergesort_single_element_no_op() {
        let mut buf = flatten_u32(&[42]);
        mergesort(&mut buf, 4, cmp_u32_le);
        assert_eq!(unflatten_u32(&buf), vec![42]);
    }

    #[test]
    fn mergesort_empty_no_op() {
        let mut buf: Vec<u8> = Vec::new();
        mergesort(&mut buf, 4, cmp_u32_le);
        assert!(buf.is_empty());
    }

    #[test]
    fn mergesort_zero_width_no_op() {
        let mut buf = flatten_u32(&[3, 1, 2]);
        mergesort(&mut buf, 0, cmp_u32_le);
        // Untouched.
        assert_eq!(unflatten_u32(&buf), vec![3, 1, 2]);
    }

    // ---- heapsort (in-place, not stable) ----

    #[test]
    fn heapsort_handles_sorted_input() {
        let mut buf = flatten_u32(&[1, 2, 3, 4, 5]);
        heapsort(&mut buf, 4, cmp_u32_le);
        assert_eq!(unflatten_u32(&buf), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn heapsort_handles_reverse_input() {
        let mut buf = flatten_u32(&[5, 4, 3, 2, 1]);
        heapsort(&mut buf, 4, cmp_u32_le);
        assert_eq!(unflatten_u32(&buf), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn heapsort_handles_random_input() {
        let mut buf = flatten_u32(&[3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5]);
        heapsort(&mut buf, 4, cmp_u32_le);
        assert_eq!(unflatten_u32(&buf), vec![1, 1, 2, 3, 3, 4, 5, 5, 5, 6, 9]);
    }

    #[test]
    fn heapsort_handles_all_equal() {
        let mut buf = flatten_u32(&[7, 7, 7, 7, 7]);
        heapsort(&mut buf, 4, cmp_u32_le);
        assert_eq!(unflatten_u32(&buf), vec![7, 7, 7, 7, 7]);
    }

    #[test]
    fn heapsort_single_element_no_op() {
        let mut buf = flatten_u32(&[42]);
        heapsort(&mut buf, 4, cmp_u32_le);
        assert_eq!(unflatten_u32(&buf), vec![42]);
    }

    #[test]
    fn heapsort_large_random() {
        // 100 elements pseudorandom to exercise heap depth. Use u64
        // arithmetic to avoid overflow, then narrow.
        let mut values: Vec<u32> = (0..100u64)
            .map(|i| ((i.wrapping_mul(1103515245).wrapping_add(12345)) % 256) as u32)
            .collect();
        let mut buf = flatten_u32(&values);
        heapsort(&mut buf, 4, cmp_u32_le);
        values.sort();
        assert_eq!(unflatten_u32(&buf), values);
    }

    #[test]
    fn radix_sort_default_table_is_byte_order() {
        let items: Vec<&[u8]> = vec![b"banana", b"apple", b"cherry"];
        let order = radix_sort(&items, None, true);
        assert_eq!(order, vec![1, 0, 2]);
    }

    #[test]
    fn radix_sort_shorter_string_sorts_first() {
        // Both prefixes match; the shorter slice ("ab") wins.
        let items: Vec<&[u8]> = vec![b"abc", b"ab", b"abcd"];
        let order = radix_sort(&items, None, true);
        assert_eq!(order, vec![1, 0, 2]);
    }

    #[test]
    fn radix_sort_table_can_invert_order() {
        // Inverse table: each byte maps to 255 - byte.
        let mut table = [0u8; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            *slot = 255 - i as u8;
        }
        let items: Vec<&[u8]> = vec![b"a", b"c", b"b"];
        let order = radix_sort(&items, Some(&table), true);
        // 'c' (0x63) translates to 0x9c, smallest under inverse → first.
        assert_eq!(order, vec![1, 2, 0]);
    }

    #[test]
    fn radix_sort_collapses_keys_via_table() {
        // Map all letters to the same key — every comparison ties on
        // every position, so output ordering is decided by length.
        // Stable sort then preserves input order among equal-length
        // items.
        let table = [0u8; 256];
        let items: Vec<&[u8]> = vec![b"abc", b"x", b"yz", b"d"];
        let order = radix_sort(&items, Some(&table), true);
        // Lengths: 3, 1, 2, 1 → sorted by length then input order:
        // (idx 1, len 1), (idx 3, len 1), (idx 2, len 2), (idx 0, len 3).
        assert_eq!(order, vec![1, 3, 2, 0]);
    }

    #[test]
    fn radix_sort_stable_preserves_input_order_for_equal_keys() {
        // Three identical strings — stable sort keeps them in the
        // input order 0, 1, 2.
        let items: Vec<&[u8]> = vec![b"x", b"x", b"x"];
        let order = radix_sort(&items, None, true);
        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn radix_sort_empty_input_returns_empty() {
        let items: Vec<&[u8]> = vec![];
        let order = radix_sort(&items, None, true);
        assert!(order.is_empty());
    }

    #[test]
    fn radix_sort_single_element() {
        let items: Vec<&[u8]> = vec![b"only"];
        let order = radix_sort(&items, None, true);
        assert_eq!(order, vec![0]);
    }

    // ---- pdqsort isomorphism + golden-output proof ----
    //
    // Behavior parity for an *unstable* sort means: the output is a permutation
    // of the input (multiset preserved) that is non-decreasing under the
    // comparator. We verify both invariants against `slice::sort_unstable` (the
    // trusted reference) across an adversarial corpus that specifically targets
    // the cases pdqsort changes complexity class on: sorted, reverse-sorted,
    // all-equal, low-cardinality, sawtooth, organ-pipe, and a median-of-three
    // killer — at sizes that exercise the deep recursion / heapsort fallback.

    /// Deterministic LCG so the corpus is fixed (no `rand`, no clock).
    fn lcg(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state
    }

    fn adversarial_corpus() -> Vec<Vec<u32>> {
        let sizes = [21usize, 50, 97, 128, 257, 1000, 5000];
        let mut corpus = Vec::new();
        for &n in &sizes {
            // sorted ascending
            corpus.push((0..n as u32).collect());
            // sorted descending
            corpus.push((0..n as u32).rev().collect());
            // all equal
            corpus.push(vec![7u32; n]);
            // low cardinality (mod 4) — drives the equal-partition path
            corpus.push((0..n as u32).map(|i| i % 4).collect());
            // low cardinality (mod 16)
            corpus.push((0..n as u32).map(|i| (i * 7) % 16).collect());
            // sawtooth
            corpus.push((0..n as u32).map(|i| i % 50).collect());
            // organ pipe: 0..n/2 then n/2..0
            corpus.push(
                (0..n)
                    .map(|i| if i < n / 2 { i } else { n - i } as u32)
                    .collect(),
            );
            // median-of-three killer-ish: the bench template generalized
            corpus.push((0..n as u32).rev().map(|v| (v * 17) % 97).collect());
            // pseudo-random
            let mut s = 0x1234_5678_9abc_def0u64 ^ (n as u64);
            corpus.push((0..n).map(|_| (lcg(&mut s) % 1000) as u32).collect());
        }
        corpus
    }

    #[test]
    fn qsort_isomorphic_to_reference_over_adversarial_corpus() {
        for input in adversarial_corpus() {
            let mut reference = input.clone();
            reference.sort_unstable();

            let mut buf = flatten_u32(&input);
            qsort(&mut buf, 4, cmp_u32_le);
            let got = unflatten_u32(&buf);

            // Output equals the trusted reference (this simultaneously proves
            // sorted order AND multiset preservation, since both are the same
            // total order applied to the same elements).
            assert_eq!(got, reference, "qsort diverged on n={}", input.len());
        }
    }

    /// FNV-1a over the byte stream of every sorted output in the corpus. A
    /// stable golden value pins the exact bytes pdqsort produces; any future
    /// change to ordering or element handling trips this.
    #[test]
    fn qsort_golden_corpus_hash_is_stable() {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for input in adversarial_corpus() {
            let mut buf = flatten_u32(&input);
            qsort(&mut buf, 4, cmp_u32_le);
            for &b in &buf {
                h ^= b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        assert_eq!(
            h, GOLDEN_QSORT_CORPUS_FNV1A,
            "qsort golden corpus hash changed: 0x{h:016x}"
        );
    }

    // Pinned from a run that also passed the isomorphism check above (so the
    // bytes are known-correct, not merely self-consistent).
    const GOLDEN_QSORT_CORPUS_FNV1A: u64 = 0x9a03_8cb3_bfb2_d40e;

    fn i32_fast_lane_corpus() -> Vec<Vec<i32>> {
        let sizes = [1usize, 2, 7, 20, 21, 50, 97, 128, 257];
        let mut corpus = Vec::new();
        for &n in &sizes {
            corpus.push((0..n as i32).map(|v| v - 64).collect());
            corpus.push((0..n as i32).rev().map(|v| v - 64).collect());
            corpus.push(vec![0; n]);
            corpus.push((0..n as i32).rev().map(|v| (v * 17) % 97 - 48).collect());
            let mut s = 0x9e37_79b9_7f4a_7c15u64 ^ (n as u64);
            corpus.push((0..n).map(|_| (lcg(&mut s) % 2001) as i32 - 1000).collect());
        }
        corpus
    }

    #[test]
    fn qsort_i32_fast_lane_preserves_sorted_sha256() {
        let mut hash = Sha256::new();
        for input in i32_fast_lane_corpus() {
            let mut reference = input.clone();
            reference.sort_unstable();

            let mut buf = flatten_i32_ne(&input);
            qsort(&mut buf, 4, cmp_i32_ne);
            let got = unflatten_i32_ne(&buf);

            assert_eq!(got, reference, "i32 qsort diverged on n={}", input.len());
            hash.update(&buf);
        }

        #[cfg(target_endian = "little")]
        let expected = [
            0xde, 0xea, 0x99, 0x6e, 0x63, 0x1c, 0xd5, 0x92, 0xe8, 0xbc, 0x3d, 0x2b, 0x05, 0xf8,
            0xc6, 0x8d, 0x6c, 0x08, 0xae, 0x89, 0x42, 0x52, 0x50, 0x79, 0xbe, 0xba, 0x77, 0x3c,
            0x0d, 0x24, 0x1a, 0x75,
        ];
        #[cfg(target_endian = "big")]
        let expected = [
            0xe5, 0x91, 0xad, 0x2b, 0xcd, 0x8c, 0x5a, 0x7f, 0x6b, 0xfb, 0x20, 0xdb, 0x38, 0x69,
            0x7d, 0x93, 0xef, 0x8a, 0x55, 0x57, 0x7b, 0xc0, 0xe0, 0x7c, 0x57, 0x39, 0x20, 0xd7,
            0x55, 0x77, 0xa5, 0xd7,
        ];
        let digest: [u8; 32] = hash.finalize().into();
        assert_eq!(digest, expected);
    }

    #[test]
    fn qsort_i32_fast_lane_restores_and_falls_back_for_non_i32_order() {
        let input: Vec<i32> = (0..128).map(|v| v - 64).collect();
        let mut expected = input.clone();
        expected.sort_unstable_by(|a, b| b.cmp(a));

        let mut buf = flatten_i32_ne(&input);
        qsort(&mut buf, 4, |a, b| -cmp_i32_ne(a, b));

        assert_eq!(unflatten_i32_ne(&buf), expected);
    }

    #[test]
    fn qsort_handles_wide_elements_isomorphically() {
        // 24-byte records keyed on the first u32; exercises the swap/move paths
        // for widths above the stack-scratch threshold.
        let mut s = 0xdead_beef_0000_0001u64;
        let n = 2000usize;
        let width = 24usize;
        let mut buf = vec![0u8; n * width];
        let mut keys = Vec::with_capacity(n);
        for i in 0..n {
            let k = (lcg(&mut s) % 50) as u32; // low cardinality, wide records
            keys.push(k);
            buf[i * width..i * width + 4].copy_from_slice(&k.to_le_bytes());
        }
        qsort(&mut buf, width, |a, b| {
            let av = u32::from_le_bytes(a[..4].try_into().unwrap());
            let bv = u32::from_le_bytes(b[..4].try_into().unwrap());
            av.cmp(&bv) as i32
        });
        keys.sort_unstable();
        let got: Vec<u32> = buf
            .chunks_exact(width)
            .map(|c| u32::from_le_bytes(c[..4].try_into().unwrap()))
            .collect();
        assert_eq!(got, keys, "wide-element qsort diverged");
    }
}
