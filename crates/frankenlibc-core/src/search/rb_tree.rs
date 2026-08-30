//! Red-black tree — guaranteed O(log n) insert/find/delete, generic over the
//! key type with caller-supplied comparator on each operation.
//!
//! The red-black invariants:
//!   1. Every node is either RED or BLACK.
//!   2. The root is BLACK.
//!   3. No RED node has a RED child.
//!   4. Every root-to-leaf path has the same number of BLACK edges
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

/// POSIX `VISIT` kind for `<search.h>`-style `twalk`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PosixVisit {
    PreOrder = 0,
    PostOrder = 1,
    EndOrder = 2,
    Leaf = 3,
}

/// Balanced binary search tree with red-black invariants.
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

    /// Insert `key` if absent, and return a stable pointer to the key stored in
    /// the matching node (the newly inserted one, or the pre-existing equal key
    /// that was retained). A single tree walk — unlike `insert` followed by a
    /// separate `find`, this halves the comparator calls, which matters when the
    /// comparator is an indirect C callback (POSIX `tsearch`).
    ///
    /// The returned pointer stays valid across the rebalancing rotations: LLRB
    /// rotations only move the `Box` owners (the heap `Node` allocations never
    /// move), so the address of a node's `key` field is stable for the node's
    /// lifetime in the tree. The caller must not outlive the node (i.e. must not
    /// use the pointer after the key is deleted), exactly as POSIX requires.
    pub fn insert_find<F: Fn(&K, &K) -> Ordering>(&mut self, key: K, cmp: &F) -> *const K {
        let mut found: *const K = core::ptr::null();
        let new_root = Self::insert_find_rec(self.root.take(), key, cmp, &mut self.len, &mut found);
        let mut root = new_root;
        if let Some(ref mut r) = root {
            r.color = Color::Black;
        }
        self.root = root;
        found
    }

    fn insert_find_rec<F: Fn(&K, &K) -> Ordering>(
        node: Option<Box<Node<K>>>,
        key: K,
        cmp: &F,
        len: &mut usize,
        found: &mut *const K,
    ) -> Option<Box<Node<K>>> {
        let mut h = match node {
            None => {
                *len += 1;
                let n = Node::new_red(key);
                *found = &n.key as *const K;
                return Some(n);
            }
            Some(h) => h,
        };
        match cmp(&key, &h.key) {
            Ordering::Less => h.left = Self::insert_find_rec(h.left.take(), key, cmp, len, found),
            Ordering::Greater => {
                h.right = Self::insert_find_rec(h.right.take(), key, cmp, len, found)
            }
            Ordering::Equal => {
                // Key already present; retain existing and report its stable address.
                *found = &h.key as *const K;
            }
        }
        h = Self::fix_up(h);
        Some(h)
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
    ///
    /// A missing key is an ordinary no-op. Unlike Sedgewick's LLRB deletion,
    /// this plain red-black deletion does not need a separate membership walk:
    /// a recursive result records whether a black-height deficit needs repair.
    /// The `None` descent therefore returns without mutation, while a present
    /// key uses exactly one comparator descent. bd-z4k8bh.
    pub fn delete<F: Fn(&K, &K) -> Ordering>(&mut self, needle: &K, cmp: &F) -> Option<K> {
        let prev_len = self.len;
        let (new_root, removed, _shortened) = Self::delete_rec(self.root.take(), needle, cmp);
        self.root = new_root;
        if let Some(ref mut r) = self.root {
            r.color = Color::Black;
        }
        self.len -= usize::from(removed.is_some());
        debug_assert_eq!(self.len + usize::from(removed.is_some()), prev_len);
        removed
    }

    fn delete_rec<F: Fn(&K, &K) -> Ordering>(
        node: Option<Box<Node<K>>>,
        needle: &K,
        cmp: &F,
    ) -> (Option<Box<Node<K>>>, Option<K>, bool) {
        let mut h = match node {
            None => return (None, None, false),
            Some(h) => h,
        };
        match cmp(needle, &h.key) {
            Ordering::Less => {
                let (left, removed, shortened) = Self::delete_rec(h.left.take(), needle, cmp);
                h.left = left;
                if shortened {
                    let (fixed, still_shortened) = Self::repair_left_shortened(h);
                    (Some(fixed), removed, still_shortened)
                } else {
                    (Some(h), removed, false)
                }
            }
            Ordering::Greater => {
                let (right, removed, shortened) = Self::delete_rec(h.right.take(), needle, cmp);
                h.right = right;
                if shortened {
                    let (fixed, still_shortened) = Self::repair_right_shortened(h);
                    (Some(fixed), removed, still_shortened)
                } else {
                    (Some(h), removed, false)
                }
            }
            Ordering::Equal if h.left.is_some() && h.right.is_some() => {
                let (right, successor, shortened) = Self::delete_min_rec(h.right.take());
                h.right = right;
                let old_key = core::mem::replace(
                    &mut h.key,
                    successor.expect("nonempty right subtree has a minimum"),
                );
                if shortened {
                    let (fixed, still_shortened) = Self::repair_right_shortened(h);
                    (Some(fixed), Some(old_key), still_shortened)
                } else {
                    (Some(h), Some(old_key), false)
                }
            }
            Ordering::Equal => {
                let old_color = h.color;
                let child = h.left.take().or(h.right.take());
                let mut child = child;
                if let Some(ref mut child) = child {
                    child.color = Color::Black;
                }
                let shortened = old_color == Color::Black && child.is_none();
                (child, Some(h.key), shortened)
            }
        }
    }

    fn delete_min_rec(node: Option<Box<Node<K>>>) -> (Option<Box<Node<K>>>, Option<K>, bool) {
        let mut h = match node {
            None => return (None, None, false),
            Some(h) => h,
        };
        if h.left.is_none() {
            let old_color = h.color;
            let mut child = h.right.take();
            if let Some(ref mut child) = child {
                child.color = Color::Black;
            }
            let shortened = old_color == Color::Black && child.is_none();
            return (child, Some(h.key), shortened);
        }
        let (left, key, shortened) = Self::delete_min_rec(h.left.take());
        h.left = left;
        if shortened {
            let (fixed, still_shortened) = Self::repair_left_shortened(h);
            (Some(fixed), key, still_shortened)
        } else {
            (Some(h), key, false)
        }
    }

    /// Repair a one-black deficit in `h.left`. The boolean reports whether a
    /// black parent with an all-black sibling must propagate that deficit upward.
    fn repair_left_shortened(mut h: Box<Node<K>>) -> (Box<Node<K>>, bool) {
        if Self::is_red(h.right.as_deref()) {
            let mut root = Self::rotate_left(h);
            let left = root.left.take().expect("rotate_left supplies old parent");
            let (fixed_left, shortened) = Self::repair_left_shortened(left);
            debug_assert!(!shortened, "red sibling must absorb left deficit");
            root.left = Some(fixed_left);
            return (root, false);
        }

        // A nil sibling is black with black children. This case occurs while a
        // prior repair is propagating its deficit upward; it follows the same
        // recolor/propagate rule as a present all-black sibling.
        let Some(sibling) = h.right.as_deref_mut() else {
            return if h.color == Color::Red {
                h.color = Color::Black;
                (h, false)
            } else {
                (h, true)
            };
        };
        let sibling_left_red = Self::is_red(sibling.left.as_deref());
        let sibling_right_red = Self::is_red(sibling.right.as_deref());
        if !sibling_left_red && !sibling_right_red {
            sibling.color = Color::Red;
            return if h.color == Color::Red {
                h.color = Color::Black;
                (h, false)
            } else {
                (h, true)
            };
        }

        if !sibling_right_red {
            let sibling = h.right.take().expect("sibling exists");
            let mut near = Self::rotate_right(sibling);
            near.color = Color::Black;
            near.right
                .as_deref_mut()
                .expect("near rotation has right child")
                .color = Color::Red;
            h.right = Some(near);
        }
        let parent_color = h.color;
        let mut root = Self::rotate_left(h);
        root.color = parent_color;
        root.left
            .as_deref_mut()
            .expect("left rotation has old parent")
            .color = Color::Black;
        root.right
            .as_deref_mut()
            .expect("far red child exists")
            .color = Color::Black;
        (root, false)
    }

    /// Mirror of [`Self::repair_left_shortened`] for a deficit in `h.right`.
    fn repair_right_shortened(mut h: Box<Node<K>>) -> (Box<Node<K>>, bool) {
        if Self::is_red(h.left.as_deref()) {
            let mut root = Self::rotate_right(h);
            let right = root.right.take().expect("rotate_right supplies old parent");
            let (fixed_right, shortened) = Self::repair_right_shortened(right);
            debug_assert!(!shortened, "red sibling must absorb right deficit");
            root.right = Some(fixed_right);
            return (root, false);
        }

        // See the mirror case in `repair_left_shortened`: nil is an all-black
        // sibling and therefore only passes the deficit on when the parent is
        // black.
        let Some(sibling) = h.left.as_deref_mut() else {
            return if h.color == Color::Red {
                h.color = Color::Black;
                (h, false)
            } else {
                (h, true)
            };
        };
        let sibling_left_red = Self::is_red(sibling.left.as_deref());
        let sibling_right_red = Self::is_red(sibling.right.as_deref());
        if !sibling_left_red && !sibling_right_red {
            sibling.color = Color::Red;
            return if h.color == Color::Red {
                h.color = Color::Black;
                (h, false)
            } else {
                (h, true)
            };
        }

        if !sibling_left_red {
            let sibling = h.left.take().expect("sibling exists");
            let mut near = Self::rotate_left(sibling);
            near.color = Color::Black;
            near.left
                .as_deref_mut()
                .expect("near rotation has left child")
                .color = Color::Red;
            h.left = Some(near);
        }
        let parent_color = h.color;
        let mut root = Self::rotate_right(h);
        root.color = parent_color;
        root.right
            .as_deref_mut()
            .expect("right rotation has old parent")
            .color = Color::Black;
        root.left
            .as_deref_mut()
            .expect("far red child exists")
            .color = Color::Black;
        (root, false)
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

    /// POSIX `<search.h>`-style `twalk` visit kind.
    ///
    /// For every non-leaf node the walker calls `visit` three times in
    /// the order: PreOrder (before any descendant), PostOrder (after
    /// left subtree, before right), EndOrder (after right subtree).
    /// Leaf nodes get a single Leaf visit.
    pub fn walk_posix<V: FnMut(&K, PosixVisit, usize)>(&self, mut visit: V) {
        Self::walk_posix_rec(self.root.as_deref(), 0, &mut visit);
    }

    fn walk_posix_rec<V: FnMut(&K, PosixVisit, usize)>(
        node: Option<&Node<K>>,
        depth: usize,
        visit: &mut V,
    ) {
        let n = match node {
            None => return,
            Some(n) => n,
        };
        if n.left.is_none() && n.right.is_none() {
            visit(&n.key, PosixVisit::Leaf, depth);
        } else {
            visit(&n.key, PosixVisit::PreOrder, depth);
            Self::walk_posix_rec(n.left.as_deref(), depth + 1, visit);
            visit(&n.key, PosixVisit::PostOrder, depth);
            Self::walk_posix_rec(n.right.as_deref(), depth + 1, visit);
            visit(&n.key, PosixVisit::EndOrder, depth);
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
    use std::cell::Cell;

    use super::*;

    fn cmp_i32(a: &i32, b: &i32) -> Ordering {
        a.cmp(b)
    }

    /// Recursively verify the red-black structural invariants and return the
    /// black-height of `node` (counting the black null sentinel as 1).
    fn black_height(node: Option<&Node<i32>>) -> usize {
        match node {
            None => 1,
            Some(n) => {
                // A red node cannot have a red child.
                if n.color == Color::Red {
                    assert!(
                        !matches!(n.left.as_deref(), Some(l) if l.color == Color::Red),
                        "red left child below red key {}",
                        n.key
                    );
                    assert!(
                        !matches!(n.right.as_deref(), Some(r) if r.color == Color::Red),
                        "red right child below red key {}",
                        n.key
                    );
                }
                let lh = black_height(n.left.as_deref());
                let rh = black_height(n.right.as_deref());
                // Invariant 5: perfect black balance.
                assert_eq!(
                    lh, rh,
                    "black-height mismatch at key {}: left={lh} right={rh}",
                    n.key
                );
                lh + usize::from(n.color == Color::Black)
            }
        }
    }

    /// Assert every plain red-black invariant plus in-order sortedness.
    fn assert_rb_invariants(t: &RbTree<i32>) {
        if let Some(r) = t.root.as_deref() {
            // Invariant 2: the root is BLACK.
            assert_eq!(r.color, Color::Black, "root must be black");
        }
        black_height(t.root.as_deref());
        let mut seen: Vec<i32> = Vec::new();
        t.walk(RbWalkOrder::InOrder, |k, _| seen.push(*k));
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        assert_eq!(seen, sorted, "in-order traversal is not sorted");
        assert_eq!(seen.len(), t.len(), "node count disagrees with len()");
    }

    fn assert_left_leaning(node: Option<&Node<i32>>) {
        if let Some(n) = node {
            assert!(
                !matches!(n.right.as_deref(), Some(r) if r.color == Color::Red),
                "right-leaning red link at key {}",
                n.key
            );
            assert_left_leaning(n.left.as_deref());
            assert_left_leaning(n.right.as_deref());
        }
    }

    /// Insertion retains the stricter LLRB shape even though deletion only
    /// promises the ordinary red-black invariants.
    fn assert_llrb_invariants(t: &RbTree<i32>) {
        assert_rb_invariants(t);
        assert_left_leaning(t.root.as_deref());
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
    fn delete_existing_uses_one_comparator_descent() {
        // The old LLRB deletion first called `find`, then walked the same path
        // again in `delete_rec`, for four comparisons here. A seemingly safe
        // implementation that restores that membership precheck regresses the
        // exact hot path this bead targets.
        let mut t = RbTree::new();
        for k in [2i32, 1, 3] {
            t.insert(k, &cmp_i32);
        }
        let comparisons = Cell::new(0usize);
        let counted_cmp = |a: &i32, b: &i32| {
            comparisons.set(comparisons.get() + 1);
            a.cmp(b)
        };

        assert_eq!(t.delete(&1, &counted_cmp), Some(1));
        assert_eq!(
            comparisons.get(),
            2,
            "delete of a leaf must follow its search path once, not precheck then delete"
        );
        assert_rb_invariants(&t);
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
    fn missing_deletes_preserve_set_and_llrb_invariants() {
        let mut t = RbTree::new();
        let expected: Vec<i32> = (0..512).step_by(2).collect();
        for &k in &expected {
            t.insert(k, &cmp_i32);
        }

        for missing in [-1, 1, 127, 255, 511, 512, 513] {
            assert_eq!(t.delete(&missing, &cmp_i32), None);
            assert_eq!(t.len(), expected.len());
            let mut seen = Vec::new();
            t.walk(RbWalkOrder::InOrder, |k, _| seen.push(*k));
            assert_eq!(seen, expected);
            assert_rb_invariants(&t);
        }
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

    /// Deleting a key that is NOT present must be a total no-op — including on
    /// a tree that has already had real deletions applied to it.
    ///
    /// `delete_rec` is Sedgewick's LLRB deletion, whose stated precondition is
    /// that the key EXISTS: it manufactures a red node to remove on the way
    /// down via `move_red_left`/`move_red_right`, and discards a whole node at
    /// `needle == h.key && h.right.is_none()`. Driven at an absent key those
    /// steps restructure a tree that had nothing to remove, and nodes are
    /// dropped. `conformance_diff_tsearch` caught it as an in-order walk
    /// missing the band 87, 89, 103, 111, 123 that glibc's tdelete still had.
    ///
    /// RELATIONSHIP TO `missing_deletes_preserve_set_and_llrb_invariants`: that
    /// arm builds its tree with inserts only and was ALSO red at HEAD — the
    /// mutation run that removed the guard again failed both. So core's own
    /// unit tests had caught this and were simply not being run either; the abi
    /// sweep that found `conformance_diff_tsearch` had not covered core. This
    /// arm adds the post-deletion shape, which is what the tsearch corpus
    /// actually exercises, so the two cover different tree states. bd-0v1jdb.
    #[test]
    fn delete_missing_key_is_a_no_op_after_prior_deletions() {
        let snapshot = |t: &RbTree<i32>| {
            let mut v = Vec::new();
            t.walk(RbWalkOrder::InOrder, |k, _| v.push(*k));
            v
        };

        // Interleave inserts and deletions of PRESENT keys first, so the tree
        // reaches a post-deletion shape, then probe absent keys at every gap.
        let mut t = RbTree::new();
        for k in 0i32..64 {
            t.insert(k * 2, &cmp_i32);
        }
        for k in [0i32, 2, 30, 62, 64, 66, 90, 120, 126, 14, 46, 78, 110] {
            t.delete(&k, &cmp_i32);
        }

        let before = snapshot(&t);
        let len_before = t.len();
        assert_eq!(before.len(), len_before, "walk and len disagree up front");
        assert!(
            len_before > 0,
            "tree must be non-empty for this to mean anything"
        );

        // Every odd value is absent by construction; so are the evens deleted
        // above and values outside the range.
        for missing in [
            -3i32, -1, 1, 15, 31, 47, 63, 79, 95, 111, 127, 129, 1000, 0, 30, 90,
        ] {
            assert_eq!(
                t.delete(&missing, &cmp_i32),
                None,
                "delete({missing}) of an absent key must report nothing removed"
            );
            assert_eq!(t.len(), len_before, "delete({missing}) changed len");
            assert_eq!(
                snapshot(&t),
                before,
                "delete({missing}) changed the tree contents"
            );
            // Structure too: a restructure that happened to keep every key
            // would still be a bug worth catching.
            assert_rb_invariants(&t);
        }

        // And the tree is still fully functional afterwards.
        for k in &before {
            assert_eq!(t.find(k, &cmp_i32), Some(k));
        }
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
    fn walk_posix_emits_three_visits_per_internal_one_per_leaf() {
        let mut t = RbTree::new();
        for k in [2i32, 1, 3] {
            t.insert(k, &cmp_i32);
        }
        // Tree should be: 2 (root, internal) -> {1 (leaf), 3 (leaf)}
        let mut log: Vec<(i32, PosixVisit)> = Vec::new();
        t.walk_posix(|k, v, _depth| log.push((*k, v)));
        // Expected (PreOrder, PostOrder, EndOrder) for 2; Leaf for 1 and 3.
        let twos: Vec<&(i32, PosixVisit)> = log.iter().filter(|(k, _)| *k == 2).collect();
        assert_eq!(twos.len(), 3, "internal node visited 3 times: {twos:?}");
        let leaves_one: Vec<&(i32, PosixVisit)> = log.iter().filter(|(k, _)| *k == 1).collect();
        let leaves_three: Vec<&(i32, PosixVisit)> = log.iter().filter(|(k, _)| *k == 3).collect();
        assert_eq!(leaves_one.len(), 1);
        assert_eq!(leaves_three.len(), 1);
        assert_eq!(leaves_one[0].1, PosixVisit::Leaf);
        assert_eq!(leaves_three[0].1, PosixVisit::Leaf);
    }

    #[test]
    fn destroy_empty_safe() {
        let t: RbTree<i32> = RbTree::new();
        let mut count = 0;
        t.destroy_with(|_| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn insert_only_preserves_llrb_invariants() {
        let mut t = RbTree::new();
        for k in 0i32..512 {
            t.insert(k, &cmp_i32);
            assert_llrb_invariants(&t);
        }
    }

    #[test]
    fn ascending_delete_preserves_red_black_invariants() {
        let mut t = RbTree::new();
        for k in 0i32..256 {
            t.insert(k, &cmp_i32);
        }
        assert_rb_invariants(&t);
        for k in 0i32..256 {
            assert_eq!(t.delete(&k, &cmp_i32), Some(k));
            assert_rb_invariants(&t);
        }
        assert!(t.is_empty());
    }

    #[test]
    fn descending_delete_preserves_red_black_invariants() {
        let mut t = RbTree::new();
        for k in 0i32..256 {
            t.insert(k, &cmp_i32);
        }
        for k in (0i32..256).rev() {
            assert_eq!(t.delete(&k, &cmp_i32), Some(k));
            assert_rb_invariants(&t);
        }
        assert!(t.is_empty());
    }

    #[test]
    fn randomized_delete_preserves_red_black_invariants() {
        let mut t = RbTree::new();
        let n = 400i32;
        for k in 0..n {
            t.insert(k, &cmp_i32);
        }
        assert_rb_invariants(&t);
        // Deterministic xorshift removal order; check invariants after each.
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut remaining: Vec<i32> = (0..n).collect();
        while !remaining.is_empty() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let idx = (state % remaining.len() as u64) as usize;
            let k = remaining.swap_remove(idx);
            assert_eq!(t.delete(&k, &cmp_i32), Some(k));
            assert_eq!(t.len(), remaining.len());
            assert_rb_invariants(&t);
        }
        assert!(t.is_empty());
    }
}
