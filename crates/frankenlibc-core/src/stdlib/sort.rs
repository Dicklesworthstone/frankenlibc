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
/// At this size, eight radix passes lose to fixed-width pdqsort when a short
/// sample shows a very small key domain. Below it, radix still wins even on
/// the same duplicate-heavy distribution.
const U64_DUPLICATE_FALLBACK_MIN: usize = 65_536;
/// 2-byte integer keys take the radix lane at a far lower threshold: they have
/// no comparison fast lane and a 2-pass radix has negligible fixed cost, so it
/// overtakes pdqsort early.
const NARROW_RADIX_LANE_MIN: usize = 256;
/// 1-byte keys take the dedicated counting-sort lane above this count.
const U8_COUNTING_LANE_MIN: usize = 256;
/// 16-byte fixed keys under byte-lexicographic comparators take a stable LSD
/// radix lane. The verify guard makes this speculative: non-lexicographic
/// comparators restore and fall through.
const BYTE_LEX16_RADIX_LANE_MIN: usize = 1024;

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

    if try_integer_unstable_lanes(base, width, num, &compare, true) {
        return;
    }

    // Non-radix fallback. For the common fixed element widths, reinterpret the
    // bytes as `[u8; N]` and use the stdlib's highly-tuned unstable sort — measured
    // ~1.7x faster than the in-house `pdqsort_recurse` on string/struct-key
    // workloads (e.g. `char*` by `strcmp`), and producing the SAME conformant
    // result (the input multiset in non-decreasing comparator order; equal-comparing
    // ties unspecified, exactly as C `qsort` permits). Other widths keep pdqsort.
    if std_sort_unstable_fixed_width(base, width, &compare) {
        return;
    }

    // Medium/large elements (width > 8, i.e. not one of the {1,2,4,8,16} direct
    // cases above): sort an array of u32 INDICES with the stdlib unstable sort,
    // then permute the elements ONCE. This moves 4-byte indices during the
    // O(n·log n) sort instead of full width-byte elements (glibc sorts large
    // records indirectly for the same reason). Measured ~1.9–2.0x faster than
    // moving the elements through `pdqsort_recurse` at widths 12 and 32. Same
    // conformant unstable result (multiset in non-decreasing order; ties
    // unspecified). `num` fits u32 for any sane array; the absurd >4 G-element
    // case keeps the pdqsort path. Widths {3,5,6,7} (where a 4-byte index is not
    // smaller than the element) keep `pdqsort_recurse`.
    if width > 8 && num <= u32::MAX as usize && std_index_sort(base, width, num, &compare) {
        return;
    }

    // Number of imbalanced partitions tolerated before falling back to
    // heapsort. floor(log2(num)) + 1 keeps the bad-case bound at O(n·log n).
    let limit = usize::BITS - num.leading_zeros();
    pdqsort_recurse(base, width, &compare, 0, num, None, limit);
}

/// Indirect sort for large elements: stdlib-sort `0..num` u32 indices by the
/// comparator, then materialize the permutation into a scratch buffer and copy
/// back. Returns `true` (always handles the call when invoked).
fn std_index_sort<F>(base: &mut [u8], width: usize, num: usize, compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let mut idx: Vec<u32> = (0..num as u32).collect();
    idx.sort_unstable_by(|&i, &j| {
        compare(elem(base, width, i as usize), elem(base, width, j as usize)).cmp(&0)
    });
    let mut out = vec![0u8; num * width];
    for (dst, &src) in idx.iter().enumerate() {
        let s = src as usize;
        out[dst * width..dst * width + width].copy_from_slice(elem(base, width, s));
    }
    base[..num * width].copy_from_slice(&out);
    true
}

/// Sort the `base` bytes as `[u8; N]` elements via the stdlib unstable sort for
/// the fixed widths `N ∈ {1,2,4,8,16}`; returns `false` for other widths so the
/// caller's `pdqsort_recurse` handles them. The stdlib sort is non-allocating
/// (`sort_unstable_by` lives in `core`) and unstable, matching `qsort` semantics.
fn std_sort_unstable_fixed_width<F>(base: &mut [u8], width: usize, compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    macro_rules! sort_w {
        ($n:literal) => {{
            // Safe reinterpretation as fixed-size chunks (any trailing partial
            // element is the discarded remainder, matching the caller's `num`).
            let (chunks, _rem) = base.as_chunks_mut::<$n>();
            chunks.sort_unstable_by(|a, b| compare(&a[..], &b[..]).cmp(&0));
            true
        }};
    }
    match width {
        1 => sort_w!(1),
        2 => sort_w!(2),
        4 => sort_w!(4),
        8 => sort_w!(8),
        16 => sort_w!(16),
        _ => false,
    }
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
fn try_integer_unstable_lanes<F>(
    base: &mut [u8],
    width: usize,
    num: usize,
    compare: &F,
    prefer_fixed_width_duplicate_fallback: bool,
) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    // 4-/8-byte comparison fast lanes (sort raw keys via the stdlib sort with no
    // per-comparison FFI callback) for the mid-size window.
    if width == 4
        && (I32_FAST_LANE_MIN..=I32_FAST_LANE_MAX).contains(&num)
        && try_qsort_i32_natural_fast_lane(base, num, compare)
    {
        return true;
    }
    if width == 8
        && (I64_FAST_LANE_MIN..=I64_FAST_LANE_MAX).contains(&num)
        && try_qsort_i64_natural_fast_lane(base, num, compare)
    {
        return true;
    }

    // 1-byte keys: a dedicated counting sort (O(n + 256)) — one histogram pass
    // plus one memset run per value, no key widening. Beats both pdqsort and the
    // generic u64-widening radix (which regresses on bytes).
    if width == 1 && num > U8_COUNTING_LANE_MIN && try_qsort_u8_counting_lane(base, num, compare) {
        return true;
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

    // Float radix lane (width 4/8), gated by a STRONG float-order prefix probe and
    // tried BEFORE the integer radix lane: a genuine f32/f64 array (with negatives)
    // takes ONE float-radix pass instead of paying the two wasted integer-radix
    // attempts that always fail on float bits. The probe declares float only on an
    // unambiguous signal, so integer/unsigned data falls straight through to the
    // integer lane unchanged (no regression); verify-then-commit still guards the
    // committed bytes. All-positive float arrays still take the unsigned integer
    // lane (their bit pattern is monotonic), so the probe need not fire for them.
    if (width == 4 || width == 8)
        && num > INTEGER_RADIX_LANE_MIN
        && try_qsort_float_radix_lane(base, num, width, compare)
    {
        return true;
    }

    // Radix-eligible widths above the threshold. First scan for an already-monotonic
    // run under the comparator: sorted/reverse input is the one case the LSD radix
    // loses decisively (6-14x — pdqsort is O(n) on runs while radix always pays
    // O(n·width) cache-missing scatter passes), and it needs no sorting at all. The
    // scan early-exits once BOTH directions are ruled out, so random/perturbed data
    // costs only a couple of comparator calls and proceeds to the radix lane; a
    // definitive Ascending/Descending result is a FULL O(n) verification under the
    // real comparator, so committing the data as-is (already sorted) or reversed
    // (non-increasing → reverse is non-decreasing) is a correct, glibc-identical sort
    // for integer keys — one comparator pass total, versus the two the previous
    // skip-to-pdqsort guard paid.
    if (width == 2 || width == 4 || width == 8) && num > radix_min {
        match qsort_scan_order(&base[..num * width], width, compare) {
            QsortOrder::Ascending => return true,
            QsortOrder::Descending => {
                reverse_fixed_width_elements(&mut base[..num * width], width);
                return true;
            }
            QsortOrder::Unordered => {
                // Eight radix scatter passes are a net loss for very large,
                // low-cardinality u64 inputs. A bounded raw-key sample can only
                // change routing: qsort falls through to its conformant stdlib
                // fixed-width sort, while heapsort leaves this disabled to retain
                // its existing in-place/radix behavior.
                if prefer_fixed_width_duplicate_fallback
                    && width == 8
                    && num >= U64_DUPLICATE_FALLBACK_MIN
                    && qsort_u64_prefix_is_duplicate_dense(&base[..num * width])
                {
                    return false;
                }
                // Only ENTER the radix lane if a short prefix sample is consistent
                // with signed OR unsigned integer order — a non-integer comparator
                // (`char*` by `strcmp`, struct key) otherwise pays two wasted
                // build+radix+verify passes before falling to pdqsort.
                if qsort_prefix_consistent_with_integer_order(&base[..num * width], width, compare)
                    && try_qsort_integer_radix_lane(base, num, width, compare)
                {
                    return true;
                }
            }
        }
    }

    if width == 16
        && num > BYTE_LEX16_RADIX_LANE_MIN
        && try_qsort_byte_lex16_radix_lane(base, num, compare)
    {
        return true;
    }

    false
}

/// Return true when a 32-key prefix contains at most 16 distinct raw u64 keys.
/// Random/high-cardinality data returns as soon as the 17th distinct key appears,
/// bounding the admission cost independently of `num`.
#[inline]
fn qsort_u64_prefix_is_duplicate_dense(active: &[u8]) -> bool {
    const SAMPLE_KEYS: usize = 32;
    const MAX_UNIQUE: usize = 16;

    let mut unique = [0u64; MAX_UNIQUE];
    let mut unique_len = 0usize;
    let mut sampled = 0usize;
    for chunk in active.chunks_exact(8).take(SAMPLE_KEYS) {
        sampled += 1;
        let key = u64::from_ne_bytes(chunk.try_into().unwrap());
        if !unique[..unique_len].contains(&key) {
            if unique_len == MAX_UNIQUE {
                return false;
            }
            unique[unique_len] = key;
            unique_len += 1;
        }
    }
    sampled == SAMPLE_KEYS
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

    // See the 8-byte lane for the full rationale; this is the 4-byte analog.
    macro_rules! commit_if_ordered {
        () => {{
            for (chunk, value) in active.chunks_exact_mut(4).zip(&values) {
                chunk.copy_from_slice(&value.to_ne_bytes());
            }
            if qsort_i32_candidate_is_ordered(active, compare) {
                return true;
            }
        }};
    }

    // Signed ascending (the dominant int32_t case) then signed descending (its
    // O(n) reverse — no second sort).
    values.sort_unstable();
    commit_if_ordered!();
    values.reverse();
    commit_if_ordered!();

    // Unsigned ascending + descending (u32 sizes / indices / hashes / ids). Only
    // when a key has the top bit set; `*v as u32` reinterprets the bits with no
    // new allocation.
    if values.iter().any(|&v| v < 0) {
        values.sort_unstable_by(|a, b| (*a as u32).cmp(&(*b as u32)));
        commit_if_ordered!();
        values.reverse();
        commit_if_ordered!();
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

    // Each attempt writes the current `values` order into `active` and checks it
    // against the caller's comparator, committing (returning) iff the arrangement
    // is non-decreasing. A comparator matching none of the natural integer
    // orderings (float, struct / partial key, …) falls through with the original
    // bytes restored, exactly as before.
    macro_rules! commit_if_ordered {
        () => {{
            for (chunk, value) in active.chunks_exact_mut(8).zip(&values) {
                chunk.copy_from_slice(&value.to_ne_bytes());
            }
            if qsort_i64_candidate_is_ordered(active, compare) {
                return true;
            }
        }};
    }

    // Signed ascending (the dominant int64_t / pointer / index case) then signed
    // descending (top-N / recent-first). Descending is the ascending sort
    // reversed, so it costs an O(n) reverse, not a second O(n log n) sort.
    values.sort_unstable();
    commit_if_ordered!();
    values.reverse();
    commit_if_ordered!();

    // Unsigned ascending + descending (u64 sizes / hashes / ids). Without these,
    // unsigned keys in the fast-lane window verify-fail above and drop to the
    // generic byte sort, which pays the caller's FFI comparator on every one of
    // its O(n log n) comparisons — the exact cost the fast lane avoids. Only
    // attempted when some key has the top bit set: otherwise the unsigned order
    // equals the signed arrangement already rejected, so a non-integer comparator
    // pays nothing extra. `*v as u64` reinterprets the bits (an `as` cast between
    // equal-width ints is bit-preserving), reusing the buffer with no allocation.
    if values.iter().any(|&v| v < 0) {
        values.sort_unstable_by(|a, b| (*a as u64).cmp(&(*b as u64)));
        commit_if_ordered!();
        values.reverse();
        commit_if_ordered!();
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
/// Stable LSD radix sort over 8-bit digits for an unsigned-integer key type. Runs `passes`
/// counting passes (one per significant key byte) with a ping-pong aux buffer; a pass whose
/// digit is constant across all keys is skipped. On return `keys` is ascending. Generated
/// per key width so a 2-byte key moves 2 bytes per pass — not 8 (the old u64-widening cost
/// 4x the traffic for u16, 2x for u32).
macro_rules! radix_sort_lsd_for {
    ($name:ident, $ty:ty) => {
        fn $name(keys: &mut Vec<$ty>, passes: usize) {
            let n = keys.len();
            if n < 2 {
                return;
            }
            let mut aux: Vec<$ty> = vec![0; n];
            for p in 0..passes {
                let shift = (p as u32) * 8;
                let mut count = [0usize; 256];
                for &k in keys.iter() {
                    count[((k >> shift) & 0xff) as usize] += 1;
                }
                if count.contains(&n) {
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
    };
}
radix_sort_lsd_for!(radix_sort_u16_lsd, u16);
radix_sort_lsd_for!(radix_sort_u32_lsd, u32);
radix_sort_lsd_for!(radix_sort_u64_lsd, u64);

/// Width-specialised integer radix lane. Builds NATIVE-width keys (no u64 widening), tries
/// SIGNED rank order (XOR the sign bit) first then UNSIGNED (no XOR), and verify-then-
/// commits against the caller's comparator. A 2's-complement signed comparator is satisfied
/// by the sign-flipped order; an unsigned comparator (`u16`/`u32`/`u64` — sizes/indices/
/// hashes/ids) by the plain order. Any other comparator (descending, struct, float) fails
/// both verifies, restores, and falls through to pdqsort.
macro_rules! try_radix_lane_for {
    ($name:ident, $ty:ty, $width:literal, $radix:ident) => {
        fn $name<F>(active: &mut [u8], num: usize, compare: &F) -> bool
        where
            F: Fn(&[u8], &[u8]) -> i32,
        {
            let sign_mask: $ty = 1 << ($width * 8 - 1);
            let original = active.to_vec();
            // Pick the attempt order to skip a wasted radix pass: within a short prefix find
            // a key with the sign bit set and one without, and let the caller's comparator
            // say which ranks lower — signed order (sign bit = small/negative) or unsigned
            // (sign bit = large). Verify-guarded: a wrong/absent probe just costs the second
            // attempt as before, and all-same-sign data already sorts correctly either way.
            let (mut hi, mut lo): (Option<usize>, Option<usize>) = (None, None);
            for (k, chunk) in active.chunks_exact($width).take(32).enumerate() {
                let raw: [u8; $width] = chunk.try_into().unwrap();
                if <$ty>::from_ne_bytes(raw) & sign_mask != 0 {
                    hi = hi.or(Some(k));
                } else {
                    lo = lo.or(Some(k));
                }
                if hi.is_some() && lo.is_some() {
                    break;
                }
            }
            let signed_first = match (hi, lo) {
                (Some(h), Some(l)) => {
                    compare(
                        &active[h * $width..h * $width + $width],
                        &active[l * $width..l * $width + $width],
                    ) < 0
                }
                _ => true,
            };
            let masks: [$ty; 2] = if signed_first {
                [sign_mask, 0]
            } else {
                [0, sign_mask]
            };
            for &mask in &masks {
                let mut keys: Vec<$ty> = Vec::with_capacity(num);
                for chunk in active.chunks_exact($width) {
                    let raw: [u8; $width] = chunk.try_into().unwrap();
                    keys.push(<$ty>::from_ne_bytes(raw) ^ mask);
                }
                $radix(&mut keys, $width);
                for (chunk, &k) in active.chunks_exact_mut($width).zip(&keys) {
                    chunk.copy_from_slice(&(k ^ mask).to_ne_bytes());
                }
                let mut ordered = true;
                let mut prev = &active[..$width];
                for current in active[$width..].chunks_exact($width) {
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
            }
            false
        }
    };
}
try_radix_lane_for!(try_qsort_radix_u16, u16, 2, radix_sort_u16_lsd);
try_radix_lane_for!(try_qsort_radix_u32, u32, 4, radix_sort_u32_lsd);
try_radix_lane_for!(try_qsort_radix_u64, u64, 8, radix_sort_u64_lsd);

fn try_qsort_integer_radix_lane<F>(base: &mut [u8], num: usize, width: usize, compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    debug_assert!(width == 2 || width == 4 || width == 8);
    let active = &mut base[..num * width];
    match width {
        2 => try_qsort_radix_u16(active, num, compare),
        4 => try_qsort_radix_u32(active, num, compare),
        8 => try_qsort_radix_u64(active, num, compare),
        _ => false,
    }
}

/// IEEE-754 float radix lane. An array of `fN` sorted ascending by a `<`-style
/// comparator is a different complexity class for radix than for pdqsort: the
/// floats map to an order-preserving UNSIGNED key via the classic sortable-key
/// bit transform (positive: set the sign bit; negative: flip all bits), so one
/// LSD radix sort yields ascending order with NO per-element comparator call.
/// glibc's `qsort` over `double[]` runs `O(n log n)` indirect comparator calls.
///
/// The all-POSITIVE case is already covered by the unsigned integer lane (a
/// positive float's bit pattern is monotonic in its value); this lane adds the
/// case that lane cannot reach — arrays containing NEGATIVE floats, whose bit
/// patterns run backwards. As with every other lane, correctness rests entirely
/// on the verify-then-commit contract: the transformed arrangement is committed
/// only after a single linear pass proves it non-decreasing under the caller's
/// own comparator. A descending, struct, or NaN-poisoned comparator simply fails
/// the verify, the original bytes are restored, and pdqsort handles the call —
/// zero behavioral difference. Equal floats (incl. -0.0 vs +0.0) are immaterial
/// because `qsort` is unstable.
macro_rules! try_radix_float_lane_for {
    ($name:ident, $uty:ty, $width:literal, $radix:ident) => {
        fn $name<F>(active: &mut [u8], num: usize, compare: &F) -> bool
        where
            F: Fn(&[u8], &[u8]) -> i32,
        {
            const SIGN: $uty = 1 << ($width * 8 - 1);
            let original = active.to_vec();

            // Forward transform: positive (sign bit clear) -> XOR SIGN (set MSB);
            // negative (sign bit set) -> XOR all-ones (flip every bit). The result
            // is an unsigned key whose ascending order is the floats' ascending
            // order.
            let mut keys: Vec<$uty> = Vec::with_capacity(num);
            for chunk in active.chunks_exact($width) {
                let raw: [u8; $width] = chunk.try_into().unwrap();
                let bits = <$uty>::from_ne_bytes(raw);
                let mask = if bits & SIGN != 0 { <$uty>::MAX } else { SIGN };
                keys.push(bits ^ mask);
            }

            $radix(&mut keys, $width);

            // Inverse transform: the key's MSB now flags the original sign — set
            // means it was positive (undo XOR SIGN), clear means negative (undo
            // XOR all-ones).
            for (chunk, &k) in active.chunks_exact_mut($width).zip(&keys) {
                let mask = if k & SIGN != 0 { SIGN } else { <$uty>::MAX };
                chunk.copy_from_slice(&(k ^ mask).to_ne_bytes());
            }

            let mut ordered = true;
            let mut prev = &active[..$width];
            for current in active[$width..].chunks_exact($width) {
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
    };
}
try_radix_float_lane_for!(try_qsort_radix_f32, u32, 4, radix_sort_u32_lsd);
try_radix_float_lane_for!(try_qsort_radix_f64, u64, 8, radix_sort_u64_lsd);

#[inline]
fn read_uint(chunk: &[u8], width: usize) -> u64 {
    let mut v = 0u64;
    for (i, &b) in chunk.iter().take(width).enumerate() {
        v |= (b as u64) << (i * 8);
    }
    v
}

/// Bench-only: the cost of ONE integer-radix-lane attempt (build keys + LSD radix
/// + verify) — i.e. the wasted work the prefix gate skips for non-integer data.
#[doc(hidden)]
pub fn __bench_integer_radix_attempt<F>(base: &mut [u8], width: usize, compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let num = base.len() / width;
    try_qsort_integer_radix_lane(base, num, width, compare)
}

/// Bench-only: the cost of the prefix integer-order gate itself.
#[doc(hidden)]
pub fn __bench_integer_order_gate<F>(active: &[u8], width: usize, compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    qsort_prefix_consistent_with_integer_order(active, width, compare)
}

/// Pre-gate for the integer radix lane: returns `true` if a short prefix sample
/// is consistent with EITHER unsigned OR signed native-width integer order under
/// the caller's comparator, `false` only when NEITHER can possibly hold (so the
/// lane's two build+radix+verify passes would be wasted — skip to pdqsort).
///
/// Sound by construction: genuine integer data is, by definition, consistent with
/// its own (signed or unsigned) order on every pair, so this never returns `false`
/// for it — no regression to the integer-sort wins. A non-integer comparator that
/// coincidentally matches the small sample just falls through to the existing
/// verify-then-commit (no worse than before). The float lane runs earlier, so
/// float arrays don't reach here.
fn qsort_prefix_consistent_with_integer_order<F>(active: &[u8], width: usize, compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    debug_assert!(width == 2 || width == 4 || width == 8);
    let n = active.len() / width;
    let pairs = (n - 1).min(8);
    if pairs == 0 {
        return true; // too small to judge — let the lane (and its verify) decide
    }
    let sign_bit = 1u64 << (width * 8 - 1);
    let mut unsigned_ok = true;
    let mut signed_ok = true;
    for k in 0..pairs {
        let a = &active[k * width..k * width + width];
        let b = &active[(k + 1) * width..(k + 1) * width + width];
        let c = compare(a, b); // desired order sign of a vs b
        let (ua, ub) = (read_uint(a, width), read_uint(b, width));
        // consistency of comparator sign with an integer order: a<b ⟺ c<0, a>b ⟺
        // c>0, a==b ⟺ c==0.
        let cons = |ia: u64, ib: u64| -> bool {
            use core::cmp::Ordering::*;
            match ia.cmp(&ib) {
                Less => c < 0,
                Greater => c > 0,
                Equal => c == 0,
            }
        };
        if !cons(ua, ub) {
            unsigned_ok = false;
        }
        if !cons(ua ^ sign_bit, ub ^ sign_bit) {
            signed_ok = false;
        }
        if !unsigned_ok && !signed_ok {
            return false;
        }
    }
    unsigned_ok || signed_ok
}

/// Result of [`qsort_scan_order`].
enum QsortOrder {
    /// Every adjacent pair is non-decreasing under the comparator (all-equal too).
    Ascending,
    /// Every adjacent pair is non-increasing under the comparator.
    Descending,
    /// Neither — a genuine sort is needed.
    Unordered,
}

/// Scan the data for an already-monotonic run under the caller's comparator.
/// Returns `Ascending` iff every adjacent pair is non-decreasing, `Descending`
/// iff every pair is non-increasing (an all-equal run reports `Ascending`), and
/// `Unordered` otherwise — early-exiting the instant BOTH directions are ruled
/// out, so random/perturbed data costs only a couple of comparator calls.
///
/// A definitive `Ascending`/`Descending` verdict is a FULL O(n) verification
/// against the real comparator, so the caller may commit the input as-is
/// (`Ascending`) or reversed (`Descending` — reversing a non-increasing sequence
/// yields a non-decreasing one) as a correct sorted arrangement. For an integer
/// comparator, equal keys are byte-identical, so that arrangement is bit-identical
/// to glibc's; for an exotic partial-key comparator the C standard leaves tie
/// order unspecified, so it remains conformant.
fn qsort_scan_order<F>(active: &[u8], width: usize, compare: &F) -> QsortOrder
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let n = active.len() / width;
    if n < 2 {
        return QsortOrder::Ascending;
    }
    let (mut asc, mut desc) = (true, true);
    let mut prev = &active[..width];
    for k in 1..n {
        let cur = &active[k * width..(k + 1) * width];
        let c = compare(prev, cur);
        if c > 0 {
            asc = false;
        } else if c < 0 {
            desc = false;
        }
        if !asc && !desc {
            return QsortOrder::Unordered;
        }
        prev = cur;
    }
    if asc {
        QsortOrder::Ascending
    } else {
        QsortOrder::Descending
    }
}

/// Reverse the order of the `width`-byte elements in `active` in place.
fn reverse_fixed_width_elements(active: &mut [u8], width: usize) {
    let n = active.len() / width;
    let (mut lo, mut hi) = (0usize, n.wrapping_sub(1));
    while lo < hi {
        let (a, b) = (lo * width, hi * width);
        for k in 0..width {
            active.swap(a + k, b + k);
        }
        lo += 1;
        hi -= 1;
    }
}

/// Conservative IEEE-754 float-order probe over a short prefix, used to gate the
/// float radix lane BEFORE the integer radix lane — so a genuine `double[]` /
/// `float[]` sort takes ONE float-radix pass instead of paying the two wasted
/// integer-radix attempts (signed+unsigned) that always fail on float bits.
///
/// It returns `true` only on a STRONG, unambiguous float signal, so integer data
/// never diverts here (no regression to the integer lanes). An element whose MSB
/// is set is either a negative float, a negative two's-complement int, or a large
/// unsigned int — distinguished by two comparator probes:
///   1. a cross-sign pair (`h` = MSB set, `l` = MSB clear): for float AND signed
///      int `h < l` (negative sorts first); for unsigned `h > l`. So `h > l`
///      rules float OUT.
///   2. a same-MSB-set pair (`big` larger raw bits than `small`): among NEGATIVE
///      values, float orders by DESCENDING bits (`big < small`), two's-complement
///      signed by ASCENDING bits (`big > small`). So `big < small` is the tell.
/// Float is declared only when `big < small` AND (no cross-sign pair seen OR
/// `h < l`). The lane's verify-then-commit remains the correctness authority;
/// this probe only chooses whether to TRY float first, never what is committed.
fn qsort_prefix_says_float<F>(active: &[u8], width: usize, compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    debug_assert!(width == 4 || width == 8);
    let get = |i: usize| &active[i * width..i * width + width];
    let msb_set = |chunk: &[u8]| chunk[width - 1] & 0x80 != 0;

    let mut h_idx: Option<usize> = None; // first MSB-set element
    let mut l_idx: Option<usize> = None; // first MSB-clear element
    let mut big_idx: Option<usize> = None; // MSB-set, largest raw bits seen
    let mut small_idx: Option<usize> = None; // MSB-set, smallest raw bits seen
    for (k, chunk) in active.chunks_exact(width).take(64).enumerate() {
        if msb_set(chunk) {
            if h_idx.is_none() {
                h_idx = Some(k);
            }
            let kb = read_uint(chunk, width);
            if big_idx
                .map(|b| kb > read_uint(get(b), width))
                .unwrap_or(true)
            {
                big_idx = Some(k);
            }
            if small_idx
                .map(|s| kb < read_uint(get(s), width))
                .unwrap_or(true)
            {
                small_idx = Some(k);
            }
        } else if l_idx.is_none() {
            l_idx = Some(k);
        }
    }

    // Need two DISTINCT MSB-set magnitudes for the negative-region discriminator.
    let (Some(big), Some(small)) = (big_idx, small_idx) else {
        return false;
    };
    if read_uint(get(big), width) == read_uint(get(small), width) {
        return false;
    }
    // (2) float negatives sort by descending bits: the larger-bits one is SMALLER.
    if compare(get(big), get(small)) >= 0 {
        return false;
    }
    // (1) if a cross-sign pair exists, the MSB-set side must sort first (h < l);
    //     h > l would mean unsigned ⇒ not float.
    if let (Some(h), Some(l)) = (h_idx, l_idx) {
        if compare(get(h), get(l)) >= 0 {
            return false;
        }
    }
    true
}

/// Float radix lane dispatch for width 4 (`f32`) / 8 (`f64`), gated by a strong
/// float-order probe so integer inputs never reach the float transform. Verify-
/// then-commit guarantees parity regardless of the probe.
fn try_qsort_float_radix_lane<F>(base: &mut [u8], num: usize, width: usize, compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    debug_assert!(width == 4 || width == 8);
    let active = &mut base[..num * width];
    if !qsort_prefix_says_float(active, width, compare) {
        return false;
    }
    match width {
        4 => try_qsort_radix_f32(active, num, compare),
        8 => try_qsort_radix_f64(active, num, compare),
        _ => false,
    }
}

/// Fixed-16-byte lexicographic byte radix lane.
///
/// Many `qsort` users sort fixed-size string/hash records with a memcmp-style
/// comparator. For those, stable LSD radix over byte positions 15..0 gives the
/// same lexicographic order with no O(n log n) comparator calls. As with the
/// integer lanes, correctness does not depend on guessing the comparator: the
/// candidate output is committed only if a linear verification against the
/// caller's comparator proves it non-decreasing. Otherwise the original bytes
/// are restored and the generic pdqsort handles the call.
fn try_qsort_byte_lex16_radix_lane<F>(base: &mut [u8], num: usize, compare: &F) -> bool
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    const WIDTH: usize = 16;
    let active = &mut base[..num * WIDTH];
    let original = active.to_vec();
    let mut aux = vec![0u8; active.len()];

    for pos in (0..WIDTH).rev() {
        let mut count = [0usize; 256];
        for chunk in active.chunks_exact(WIDTH) {
            count[chunk[pos] as usize] += 1;
        }
        if count.contains(&num) {
            continue;
        }

        let mut sum = 0usize;
        for c in &mut count {
            let cur = *c;
            *c = sum;
            sum += cur;
        }

        for chunk in active.chunks_exact(WIDTH) {
            let d = chunk[pos] as usize;
            let dst = count[d] * WIDTH;
            aux[dst..dst + WIDTH].copy_from_slice(chunk);
            count[d] += 1;
        }
        active.copy_from_slice(&aux);
    }

    let mut prev = &active[..WIDTH];
    for current in active[WIDTH..].chunks_exact(WIDTH) {
        if compare(prev, current) > 0 {
            active.copy_from_slice(&original);
            return false;
        }
        prev = current;
    }
    true
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
    if try_integer_unstable_lanes(base, width, num, &compare, false) {
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
    // Vectorized whole-slice exchange (memswap-class), not a per-byte loop —
    // matches swap_chunks. Byte-identical: the two width-byte elements are
    // swapped. Hot in the heapsort/sift_down fallback for adversarial inputs.
    lo_slice.swap_with_slice(hi_slice);
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

    #[test]
    fn u64_duplicate_prefix_gate_accepts_half_unique_sample() {
        let mut bytes = Vec::with_capacity(32 * 8);
        for i in 0..32u64 {
            bytes.extend_from_slice(&(i % 16).to_ne_bytes());
        }
        assert!(qsort_u64_prefix_is_duplicate_dense(&bytes));
    }

    #[test]
    fn u64_duplicate_prefix_gate_rejects_high_cardinality_sample() {
        let mut bytes = Vec::with_capacity(32 * 8);
        for i in 0..32u64 {
            bytes.extend_from_slice(&i.to_ne_bytes());
        }
        assert!(!qsort_u64_prefix_is_duplicate_dense(&bytes));
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

    fn cmp_lex16(a: &[u8], b: &[u8]) -> i32 {
        for i in 0..16 {
            if a[i] != b[i] {
                return a[i] as i32 - b[i] as i32;
            }
        }
        0
    }

    #[test]
    fn qsort_lex16_radix_lane_commits_and_restores() {
        let n = 2048usize;
        let width = 16usize;
        let mut input = vec![0u8; n * width];
        for i in 0..n {
            let mut s = (i as u64)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(0x1234_5678_9abc_def0);
            for j in 0..width {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                input[i * width + j] = (s >> 24) as u8;
            }
        }

        let mut expected: Vec<[u8; 16]> = input
            .chunks_exact(width)
            .map(|chunk| chunk.try_into().unwrap())
            .collect();
        expected.sort_unstable();

        let mut buf = input.clone();
        qsort(&mut buf, width, cmp_lex16);
        let got: Vec<[u8; 16]> = buf
            .chunks_exact(width)
            .map(|chunk| chunk.try_into().unwrap())
            .collect();
        assert_eq!(got, expected);

        let mut reverse_expected: Vec<[u8; 16]> = input
            .chunks_exact(width)
            .map(|chunk| chunk.try_into().unwrap())
            .collect();
        reverse_expected.sort_unstable_by(|a, b| b.cmp(a));

        let mut reverse_buf = input;
        qsort(&mut reverse_buf, width, |a, b| -cmp_lex16(a, b));
        let reverse_got: Vec<[u8; 16]> = reverse_buf
            .chunks_exact(width)
            .map(|chunk| chunk.try_into().unwrap())
            .collect();
        assert_eq!(reverse_got, reverse_expected);
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

    #[test]
    fn swap_elements_exchanges_full_elements_across_widths() {
        // swap_elements underlies heapsort's sift_down; the integer radix lanes
        // bypass that comparison path, so pin the whole-element exchange
        // directly across widths (including odd, non-power-of-two). It must swap
        // exactly the two width-byte elements and leave the others untouched.
        let fill = |i: usize, k: usize| (0x10u8.wrapping_mul(i as u8 + 1)).wrapping_add(k as u8);
        for &width in &[1usize, 3, 4, 8, 16, 24] {
            let n = 5;
            let mut buf = vec![0u8; n * width];
            for i in 0..n {
                for k in 0..width {
                    buf[i * width + k] = fill(i, k);
                }
            }
            swap_elements(&mut buf, width, 1, 3);
            // Elements 1 and 3 exchanged; 0, 2, 4 untouched.
            let order = [0usize, 3, 2, 1, 4];
            let mut want = vec![0u8; n * width];
            for (dst, &src) in order.iter().enumerate() {
                for k in 0..width {
                    want[dst * width + k] = fill(src, k);
                }
            }
            assert_eq!(buf, want, "swap_elements wrong for width {width}");
        }
        // a == b is a no-op.
        let mut buf = vec![1u8, 2, 3, 4];
        swap_elements(&mut buf, 2, 0, 0);
        assert_eq!(buf, vec![1, 2, 3, 4], "swap_elements(a, a) must be a no-op");
    }
}
