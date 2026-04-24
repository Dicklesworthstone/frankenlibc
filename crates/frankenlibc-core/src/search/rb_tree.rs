//! Left-leaning red-black tree (Sedgewick 2008) — guaranteed O(log n)
//! insert/find/delete, generic over the key type with caller-supplied
//! comparator on each operation.
//!
//! The LLRB invariants:
//!   1. Every node is either RED or BLACK.
//!   2. The root is BLACK.
//!   3. RED edges only lean left (right children are never RED).
//!   4. No node has two RED children.
//!   5. Every root-to-leaf path has the same number of BLACK edges
//!      (the "black-height").
//!
//! These guarantee tree height ≤ 2 * log2(n+1).

use core::cmp::Ordering;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Color {
    Red,
    Black,
}

#[derive(Debug)]
struct Node<K> {
    key: K,
    color: Color,
    left: Option<Box<Node<K>>>,
    right: Option<Box<Node<K>>>,
}

impl<K> Node<K> {
    fn new_red(key: K) -> Box<Self> {
        Box::new(Self {
            key,
            color: Color::Red,
            left: None,
            right: None,
        })
    }
}

/// Order in which `walk` visits nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RbWalkOrder {
    /// Visit in sorted order (left, self, right).
    InOrder,
    /// Visit root before subtrees (self, left, right).
    PreOrder,
    /// Visit subtrees before root (left, right, self).
    PostOrder,
}

/// Balanced binary search tree with LLRB invariants.
#[derive(Debug)]
pub struct RbTree<K> {
    root: Option<Box<Node<K>>>,
    len: usize,
}

impl<K> Default for RbTree<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K> RbTree<K> {
    /// Empty tree.
    pub const fn new() -> Self {
        Self { root: None, len: 0 }
    }

    /// Number of keys in the tree.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Insert `key` if not already present.
    ///
    /// Returns `true` if a new node was inserted, `false` if a node with
    /// an equal key already existed (in which case the existing key is
    /// retained, matching POSIX `tsearch` semantics).
    pub fn insert<F: Fn(&K, &K) -> Ordering>(&mut self, key: K, cmp: &F) -> bool {
        let prev_len = self.len;
        let new_root = Self::insert_rec(self.root.take(), key, cmp, &mut self.len);
        let mut root = new_root;
        // Root invariant: always black.
        if let Some(ref mut r) = root {
            r.color = Color::Black;
        }
        self.root = root;
        self.len > prev_len
    }

    fn insert_rec<F: Fn(&K, &K) -> Ordering>(
        node: Option<Box<Node<K>>>,
        key: K,
        cmp: &F,
        len: &mut usize,
    ) -> Option<Box<Node<K>>> {
        let mut h = match node {
            None => {
                *len += 1;
                return Some(Node::new_red(key));
            }
            Some(h) => h,
        };
        match cmp(&key, &h.key) {
            Ordering::Less => h.left = Self::insert_rec(h.left.take(), key, cmp, len),
            Ordering::Greater => h.right = Self::insert_rec(h.right.take(), key, cmp, len),
            Ordering::Equal => {
                // Key already present; retain existing.
            }
        }
        h = Self::fix_up(h);
        Some(h)
    }

    /// Read-only lookup. Returns a reference to the stored key matching
    /// `needle` per the comparator, or `None`.
    pub fn find<F: Fn(&K, &K) -> Ordering>(&self, needle: &K, cmp: &F) -> Option<&K> {
        let mut cur = self.root.as_deref();
        while let Some(n) = cur {
            cur = match cmp(needle, &n.key) {
                Ordering::Less => n.left.as_deref(),
                Ordering::Greater => n.right.as_deref(),
                Ordering::Equal => return Some(&n.key),
            };
        }
        None
    }

    /// Delete the key matching `needle`. Returns the removed key on
    /// success; returns `None` if the key was not present.
    pub fn delete<F: Fn(&K, &K) -> Ordering>(&mut self, needle: &K, cmp: &F) -> Option<K> {
        if self.find(needle, cmp).is_none() {
            return None;
        }
        let prev_len = self.len;
        let (new_root, removed) = Self::delete_rec(self.root.take(), needle, cmp, &mut self.len);
        self.root = new_root;
        if let Some(ref mut r) = self.root {
            r.color = Color::Black;
        }
        debug_assert_eq!(self.len, prev_len - 1);
        removed
    }

    fn delete_rec<F: Fn(&K, &K) -> Ordering>(
        node: Option<Box<Node<K>>>,
        needle: &K,
        cmp: &F,
        len: &mut usize,
    ) -> (Option<Box<Node<K>>>, Option<K>) {
        let mut h = match node {
            None => return (None, None),
            Some(h) => h,
        };
        let removed;
        if cmp(needle, &h.key) == Ordering::Less {
            if !Self::is_red(h.left.as_deref())
                && !Self::is_red(h.left.as_deref().and_then(|l| l.left.as_deref()))
            {
                h = Self::move_red_left(h);
            }
            let (new_left, r) = Self::delete_rec(h.left.take(), needle, cmp, len);
            h.left = new_left;
            removed = r;
        } else {
            if Self::is_red(h.left.as_deref()) {
                h = Self::rotate_right(h);
            }
            if cmp(needle, &h.key) == Ordering::Equal && h.right.is_none() {
                *len -= 1;
                return (None, Some(h.key));
            }
            if !Self::is_red(h.right.as_deref())
                && !Self::is_red(h.right.as_deref().and_then(|r| r.left.as_deref()))
            {
                h = Self::move_red_right(h);
            }
            if cmp(needle, &h.key) == Ordering::Equal {
                // Replace h.key with successor (min of right subtree),
                // then delete successor.
                let (new_right, succ_key) = Self::delete_min_rec(h.right.take());
                let succ = succ_key.expect("right subtree nonempty");
                let old_key = core::mem::replace(&mut h.key, succ);
                h.right = new_right;
                *len -= 1;
                removed = Some(old_key);
            } else {
                let (new_right, r) = Self::delete_rec(h.right.take(), needle, cmp, len);
                h.right = new_right;
                removed = r;
            }
        }
        h = Self::fix_up(h);
        (Some(h), removed)
    }

    fn delete_min_rec(node: Option<Box<Node<K>>>) -> (Option<Box<Node<K>>>, Option<K>) {
        let mut h = match node {
            None => return (None, None),
            Some(h) => h,
        };
        if h.left.is_none() {
            return (None, Some(h.key));
        }
        if !Self::is_red(h.left.as_deref())
            && !Self::is_red(h.left.as_deref().and_then(|l| l.left.as_deref()))
        {
            h = Self::move_red_left(h);
        }
        let (new_left, k) = Self::delete_min_rec(h.left.take());
        h.left = new_left;
        h = Self::fix_up(h);
        (Some(h), k)
    }

    fn is_red(n: Option<&Node<K>>) -> bool {
        matches!(n, Some(n) if n.color == Color::Red)
    }

    fn rotate_left(mut h: Box<Node<K>>) -> Box<Node<K>> {
        let mut x = h.right.take().expect("rotate_left: right is None");
        h.right = x.left.take();
        x.color = h.color;
        h.color = Color::Red;
        x.left = Some(h);
        x
    }

    fn rotate_right(mut h: Box<Node<K>>) -> Box<Node<K>> {
        let mut x = h.left.take().expect("rotate_right: left is None");
        h.left = x.right.take();
        x.color = h.color;
        h.color = Color::Red;
        x.right = Some(h);
        x
    }

    fn flip_colors(h: &mut Node<K>) {
        h.color = match h.color {
            Color::Red => Color::Black,
            Color::Black => Color::Red,
        };
        if let Some(l) = h.left.as_deref_mut() {
            l.color = match l.color {
                Color::Red => Color::Black,
                Color::Black => Color::Red,
            };
        }
        if let Some(r) = h.right.as_deref_mut() {
            r.color = match r.color {
                Color::Red => Color::Black,
                Color::Black => Color::Red,
            };
        }
    }

    fn fix_up(mut h: Box<Node<K>>) -> Box<Node<K>> {
        if Self::is_red(h.right.as_deref()) && !Self::is_red(h.left.as_deref()) {
            h = Self::rotate_left(h);
        }
        if Self::is_red(h.left.as_deref())
            && Self::is_red(h.left.as_deref().and_then(|l| l.left.as_deref()))
        {
            h = Self::rotate_right(h);
        }
        if Self::is_red(h.left.as_deref()) && Self::is_red(h.right.as_deref()) {
            Self::flip_colors(&mut h);
        }
        h
    }

    fn move_red_left(mut h: Box<Node<K>>) -> Box<Node<K>> {
        Self::flip_colors(&mut h);
        if Self::is_red(h.right.as_deref().and_then(|r| r.left.as_deref())) {
            let r = h.right.take().expect("right exists");
            h.right = Some(Self::rotate_right(r));
            h = Self::rotate_left(h);
            Self::flip_colors(&mut h);
        }
        h
    }

    fn move_red_right(mut h: Box<Node<K>>) -> Box<Node<K>> {
        Self::flip_colors(&mut h);
        if Self::is_red(h.left.as_deref().and_then(|l| l.left.as_deref())) {
            h = Self::rotate_right(h);
            Self::flip_colors(&mut h);
        }
        h
    }

    /// Walk the tree in the requested order, calling `visit(key, depth)`
    /// for each node. Depth of root is 0.
    pub fn walk<V: FnMut(&K, usize)>(&self, order: RbWalkOrder, mut visit: V) {
        Self::walk_rec(self.root.as_deref(), order, 0, &mut visit);
    }

    fn walk_rec<V: FnMut(&K, usize)>(
        node: Option<&Node<K>>,
        order: RbWalkOrder,
        depth: usize,
        visit: &mut V,
    ) {
        let n = match node {
            None => return,
            Some(n) => n,
        };
        match order {
            RbWalkOrder::PreOrder => {
                visit(&n.key, depth);
                Self::walk_rec(n.left.as_deref(), order, depth + 1, visit);
                Self::walk_rec(n.right.as_deref(), order, depth + 1, visit);
            }
            RbWalkOrder::InOrder => {
                Self::walk_rec(n.left.as_deref(), order, depth + 1, visit);
                visit(&n.key, depth);
                Self::walk_rec(n.right.as_deref(), order, depth + 1, visit);
            }
            RbWalkOrder::PostOrder => {
                Self::walk_rec(n.left.as_deref(), order, depth + 1, visit);
                Self::walk_rec(n.right.as_deref(), order, depth + 1, visit);
                visit(&n.key, depth);
            }
        }
    }

    /// Walk the tree post-order, consuming each key via `take(key)` as
    /// the corresponding node is freed. Used by POSIX `tdestroy`.
    pub fn destroy_with<F: FnMut(K)>(mut self, mut take: F) {
        let root = self.root.take();
        Self::destroy_rec(root, &mut take);
        self.len = 0;
    }

    fn destroy_rec<F: FnMut(K)>(node: Option<Box<Node<K>>>, take: &mut F) {
        if let Some(n) = node {
            let n = *n;
            Self::destroy_rec(n.left, take);
            Self::destroy_rec(n.right, take);
            take(n.key);
        }
    }

    /// Maximum depth in the tree (for tests / invariant checks).
    pub fn max_depth(&self) -> usize {
        Self::depth_rec(self.root.as_deref())
    }

    fn depth_rec(node: Option<&Node<K>>) -> usize {
        match node {
            None => 0,
            Some(n) => {
                1 + core::cmp::max(
                    Self::depth_rec(n.left.as_deref()),
                    Self::depth_rec(n.right.as_deref()),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp_i32(a: &i32, b: &i32) -> Ordering {
        a.cmp(b)
    }

    #[test]
    fn empty_tree_basics() {
        let t: RbTree<i32> = RbTree::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert_eq!(t.find(&42, &cmp_i32), None);
    }

    #[test]
    fn single_insert_then_find() {
        let mut t = RbTree::new();
        assert!(t.insert(7i32, &cmp_i32));
        assert_eq!(t.len(), 1);
        assert_eq!(t.find(&7, &cmp_i32), Some(&7));
        assert_eq!(t.find(&8, &cmp_i32), None);
    }

    #[test]
    fn duplicate_insert_returns_false() {
        let mut t = RbTree::new();
        assert!(t.insert(1i32, &cmp_i32));
        assert!(!t.insert(1i32, &cmp_i32));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn ascending_inserts_stay_balanced() {
        let mut t = RbTree::new();
        for k in 0i32..1024 {
            t.insert(k, &cmp_i32);
        }
        assert_eq!(t.len(), 1024);
        // LLRB guarantees height <= 2 * log2(n+1) ≈ 2 * 10 = 20.
        assert!(
            t.max_depth() <= 22,
            "ascending-1024 depth={} exceeds 2*log2(n+1)+slack",
            t.max_depth()
        );
    }

    #[test]
    fn random_order_inserts_stay_balanced() {
        let mut t = RbTree::new();
        // Deterministic xorshift seeds
        let mut state = 0xCAFEBABEu64;
        for _ in 0..2048 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let k = (state & 0xFFFF) as i32;
            t.insert(k, &cmp_i32);
        }
        // Even with duplicates len <= 2048
        assert!(t.len() <= 2048);
        assert!(
            t.max_depth() <= 32,
            "depth={} for {} keys exceeds RB-tree bound",
            t.max_depth(),
            t.len()
        );
    }

    #[test]
    fn inorder_walk_yields_sorted() {
        let mut t = RbTree::new();
        for k in [5i32, 2, 8, 1, 3, 7, 9, 4, 6] {
            t.insert(k, &cmp_i32);
        }
        let mut seen: Vec<i32> = Vec::new();
        t.walk(RbWalkOrder::InOrder, |k, _d| seen.push(*k));
        assert_eq!(seen, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn delete_existing_returns_key() {
        let mut t = RbTree::new();
        for k in [5i32, 2, 8, 1, 3, 7, 9] {
            t.insert(k, &cmp_i32);
        }
        assert_eq!(t.delete(&3, &cmp_i32), Some(3));
        assert_eq!(t.find(&3, &cmp_i32), None);
        assert_eq!(t.len(), 6);
    }

    #[test]
    fn delete_missing_returns_none() {
        let mut t = RbTree::new();
        for k in [5i32, 2, 8] {
            t.insert(k, &cmp_i32);
        }
        assert_eq!(t.delete(&99, &cmp_i32), None);
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn delete_all_keeps_balance() {
        let mut t = RbTree::new();
        let keys: Vec<i32> = (0..256).collect();
        for k in &keys {
            t.insert(*k, &cmp_i32);
        }
        assert_eq!(t.len(), 256);
        for k in &keys {
            assert_eq!(t.delete(k, &cmp_i32), Some(*k));
        }
        assert!(t.is_empty());
        assert!(t.find(&0, &cmp_i32).is_none());
    }

    #[test]
    fn destroy_with_callback_visits_all() {
        let mut t = RbTree::new();
        for k in 1i32..=10 {
            t.insert(k, &cmp_i32);
        }
        let mut visited: Vec<i32> = Vec::new();
        t.destroy_with(|k| visited.push(k));
        visited.sort();
        assert_eq!(visited, (1..=10).collect::<Vec<_>>());
    }

    #[test]
    fn destroy_empty_safe() {
        let t: RbTree<i32> = RbTree::new();
        let mut count = 0;
        t.destroy_with(|_| count += 1);
        assert_eq!(count, 0);
    }
}
