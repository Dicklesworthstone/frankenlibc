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

    quicksort_safe(base, width, &compare);
}

fn quicksort_safe<F>(buffer: &mut [u8], width: usize, compare: &F)
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let len = buffer.len();
    let count = len / width;
    if count < 2 {
        return;
    }

    // Partition
    let pivot_index = partition(buffer, width, compare);

    // Split at pivot
    let (left, right) = buffer.split_at_mut(pivot_index * width);

    // Right part includes pivot at index 0?
    // partition returns index of pivot.
    // We split at pivot_index * width.
    // Left is [0..pivot]. Right is [pivot..end].
    // Pivot element is at right[0].
    // We want to sort left and right[width..].

    quicksort_safe(left, width, compare);
    if right.len() > width {
        quicksort_safe(&mut right[width..], width, compare);
    }
}

fn partition<F>(buffer: &mut [u8], width: usize, compare: &F) -> usize
where
    F: Fn(&[u8], &[u8]) -> i32,
{
    let count = buffer.len() / width;
    let pivot_idx = count - 1;

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
