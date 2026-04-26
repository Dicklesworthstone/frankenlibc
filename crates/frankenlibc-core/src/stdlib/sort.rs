//! Sorting and searching functions.

/// Generic qsort implementation.
/// `base`: the entire array as bytes.
/// `width`: size of each element in bytes.
/// `compare`: comparison function returning <0, 0, >0.
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

    // Depth limit: 2 * floor(log2(num)). Prevents O(n^2) stack depth.
    let depth_limit = 2 * (usize::BITS - num.leading_zeros()) as usize;
    quicksort_safe(base, width, &compare, depth_limit);
}

fn quicksort_safe<F>(buffer: &mut [u8], width: usize, compare: &F, depth_limit: usize)
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let len = buffer.len();
    let count = len / width;
    if count < 2 {
        return;
    }

    // Fall back to insertion sort when recursion is too deep.
    if depth_limit == 0 {
        insertion_sort(buffer, width, compare);
        return;
    }

    // Partition
    let pivot_index = partition(buffer, width, compare);

    // Split at pivot.
    // Left is [0..pivot_index], right is [pivot_index..end].
    // Pivot element is at right[0..width].
    // Recurse on left and right[width..].
    let (left, right) = buffer.split_at_mut(pivot_index * width);

    quicksort_safe(left, width, compare, depth_limit - 1);
    if right.len() > width {
        quicksort_safe(&mut right[width..], width, compare, depth_limit - 1);
    }
}

fn partition<F>(buffer: &mut [u8], width: usize, compare: &F) -> usize
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let count = buffer.len() / width;
    let last = count - 1;

    // Median-of-three pivot selection: compare first, middle, and last
    // elements, then swap the median into the last position as pivot.
    if count >= 3 {
        let mid = count / 2;
        // Sort the three candidates so the median ends up in position `mid`.
        if compare(&buffer[0..width], &buffer[mid * width..(mid + 1) * width]) > 0 {
            swap_chunks(buffer, 0, mid, width);
        }
        if compare(&buffer[0..width], &buffer[last * width..(last + 1) * width]) > 0 {
            swap_chunks(buffer, 0, last, width);
        }
        if compare(
            &buffer[mid * width..(mid + 1) * width],
            &buffer[last * width..(last + 1) * width],
        ) > 0
        {
            swap_chunks(buffer, mid, last, width);
        }
        // Now first <= mid <= last. Swap median (mid) into pivot position (last).
        swap_chunks(buffer, mid, last, width);
    }

    let pivot_idx = last;

    let mut i = 0;
    for j in 0..pivot_idx {
        let cmp = {
            let (head, tail) = buffer.split_at(pivot_idx * width);
            let val_j = &head[j * width..(j + 1) * width];
            let pivot = &tail[0..width];
            compare(val_j, pivot)
        };

        if cmp <= 0 {
            swap_chunks(buffer, i, j, width);
            i += 1;
        }
    }
    swap_chunks(buffer, i, pivot_idx, width);
    i
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

    // Copy the elements out so Rust's stable timsort can reorder
    // them by value (instead of permuting an index array, which
    // becomes hairy for non-trivial widths).
    let mut elems: Vec<Vec<u8>> = (0..num)
        .map(|i| base[i * width..(i + 1) * width].to_vec())
        .collect();
    elems.sort_by(|a, b| match compare(a, b).cmp(&0) {
        core::cmp::Ordering::Less => core::cmp::Ordering::Less,
        core::cmp::Ordering::Equal => core::cmp::Ordering::Equal,
        core::cmp::Ordering::Greater => core::cmp::Ordering::Greater,
    });
    for (i, e) in elems.iter().enumerate() {
        base[i * width..(i + 1) * width].copy_from_slice(e);
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

    fn unflatten_u32(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect()
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
}
