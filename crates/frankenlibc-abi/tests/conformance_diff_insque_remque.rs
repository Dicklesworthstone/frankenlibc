#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc insque/remque oracle + raw list pointers

//! Differential + metamorphic harness for `<search.h>` intrusive-list helpers
//! `insque` / `remque` (bd-zaod5s). Existing coverage exercised local behavior,
//! but did not compare against host glibc for the exact pointer mutations.
//!
//! These functions operate on the first two pointer-sized fields of an arbitrary
//! user node. The contract details that matter here are neighbor rewiring and
//! glibc's removed-node behavior: `remque` updates adjacent nodes but leaves the
//! removed element's own `next`/`prev` fields untouched. No mocks.

use std::ffi::c_void;

mod g {
    use super::*;

    unsafe extern "C" {
        pub fn insque(elem: *mut c_void, pred: *mut c_void);
        pub fn remque(elem: *mut c_void);
    }
}

use frankenlibc_abi::search_abi as fl;

#[repr(C)]
#[derive(Debug)]
struct Node {
    next: *mut Node,
    prev: *mut Node,
    value: i32,
}

impl Node {
    fn new(value: i32) -> Self {
        Self {
            next: std::ptr::null_mut(),
            prev: std::ptr::null_mut(),
            value,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Insert { elem: usize, pred: Option<usize> },
    Remove { elem: usize },
}

#[derive(Debug, PartialEq, Eq)]
struct NodeSnapshot {
    next: isize,
    prev: isize,
    value: i32,
}

fn ptr_index(nodes: &[Node], ptr: *mut Node) -> isize {
    if ptr.is_null() {
        return -1;
    }
    nodes
        .iter()
        .position(|node| std::ptr::eq(node as *const Node, ptr.cast_const()))
        .map(|idx| idx as isize)
        .unwrap_or(-2)
}

fn snapshot(nodes: &[Node]) -> Vec<NodeSnapshot> {
    nodes
        .iter()
        .map(|node| NodeSnapshot {
            next: ptr_index(nodes, node.next),
            prev: ptr_index(nodes, node.prev),
            value: node.value,
        })
        .collect()
}

unsafe fn run_script(count: usize, script: &[Op], glibc: bool) -> Vec<NodeSnapshot> {
    let mut nodes: Vec<Node> = (0..count).map(|idx| Node::new(idx as i32)).collect();

    for op in script {
        match *op {
            Op::Insert { elem, pred } => {
                let elem_ptr = (&mut nodes[elem] as *mut Node).cast::<c_void>();
                let pred_ptr = pred
                    .map(|idx| (&mut nodes[idx] as *mut Node).cast::<c_void>())
                    .unwrap_or(std::ptr::null_mut());
                unsafe {
                    if glibc {
                        g::insque(elem_ptr, pred_ptr);
                    } else {
                        fl::insque(elem_ptr, pred_ptr);
                    }
                }
            }
            Op::Remove { elem } => {
                let elem_ptr = (&mut nodes[elem] as *mut Node).cast::<c_void>();
                unsafe {
                    if glibc {
                        g::remque(elem_ptr);
                    } else {
                        fl::remque(elem_ptr);
                    }
                }
            }
        }
    }

    snapshot(&nodes)
}

fn assert_no_foreign_links(snap: &[NodeSnapshot]) {
    let max = snap.len() as isize;
    for (idx, node) in snap.iter().enumerate() {
        assert!(
            (-1..max).contains(&node.next),
            "node {idx} next points outside fixture: {node:?}"
        );
        assert!(
            (-1..max).contains(&node.prev),
            "node {idx} prev points outside fixture: {node:?}"
        );
    }
}

#[test]
fn hand_scripts_match_glibc() {
    let scripts: &[&[Op]] = &[
        &[
            Op::Insert {
                elem: 0,
                pred: None,
            },
            Op::Insert {
                elem: 1,
                pred: Some(0),
            },
            Op::Insert {
                elem: 2,
                pred: Some(1),
            },
            Op::Insert {
                elem: 3,
                pred: Some(1),
            },
        ],
        &[
            Op::Insert {
                elem: 0,
                pred: None,
            },
            Op::Insert {
                elem: 1,
                pred: Some(0),
            },
            Op::Insert {
                elem: 2,
                pred: Some(1),
            },
            Op::Insert {
                elem: 3,
                pred: Some(2),
            },
            Op::Remove { elem: 1 },
        ],
        &[
            Op::Insert {
                elem: 0,
                pred: None,
            },
            Op::Insert {
                elem: 1,
                pred: Some(0),
            },
            Op::Insert {
                elem: 2,
                pred: Some(1),
            },
            Op::Remove { elem: 0 },
            Op::Remove { elem: 2 },
        ],
        &[
            Op::Insert {
                elem: 0,
                pred: None,
            },
            Op::Insert {
                elem: 1,
                pred: Some(0),
            },
            Op::Remove { elem: 1 },
            Op::Insert {
                elem: 1,
                pred: Some(0),
            },
            Op::Insert {
                elem: 2,
                pred: Some(1),
            },
            Op::Remove { elem: 1 },
        ],
    ];

    for script in scripts {
        let gs = unsafe { run_script(5, script, true) };
        let fs = unsafe { run_script(5, script, false) };
        assert_no_foreign_links(&fs);
        assert_eq!(fs, gs, "insque/remque script mismatch: {script:?}");
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
}

fn pick(rng: &mut Rng, flags: &[bool], want: bool) -> Option<usize> {
    let matching: Vec<usize> = flags
        .iter()
        .enumerate()
        .filter_map(|(idx, &flag)| (flag == want).then_some(idx))
        .collect();
    (!matching.is_empty()).then(|| matching[rng.below(matching.len())])
}

fn random_scripts() -> Vec<Vec<Op>> {
    let mut rng = Rng(0x5151_5545_5245_4d51);
    let mut scripts = Vec::new();

    for _ in 0..256 {
        let count = 8;
        let mut active = vec![false; count];
        let mut next = vec![None; count];
        let mut prev = vec![None; count];
        let first = rng.below(count);
        active[first] = true;
        let mut script = vec![Op::Insert {
            elem: first,
            pred: None,
        }];

        for _ in 0..28 {
            let can_insert = active.iter().any(|&x| x) && active.iter().any(|&x| !x);
            let can_remove = active.iter().filter(|&&x| x).count() > 1;
            let do_remove = can_remove && (!can_insert || rng.below(3) == 0);

            if do_remove {
                let elem = pick(&mut rng, &active, true).expect("active node");
                let old_prev = prev[elem];
                let old_next = next[elem];
                if let Some(p) = old_prev {
                    next[p] = old_next;
                }
                if let Some(n) = old_next {
                    prev[n] = old_prev;
                }
                active[elem] = false;
                script.push(Op::Remove { elem });
            } else if can_insert {
                let elem = pick(&mut rng, &active, false).expect("inactive node");
                let pred = pick(&mut rng, &active, true).expect("active predecessor");
                let old_next = next[pred];
                next[elem] = old_next;
                prev[elem] = Some(pred);
                if let Some(n) = old_next {
                    prev[n] = Some(elem);
                }
                next[pred] = Some(elem);
                active[elem] = true;
                script.push(Op::Insert {
                    elem,
                    pred: Some(pred),
                });
            }
        }

        scripts.push(script);
    }

    scripts
}

#[test]
fn generated_scripts_match_glibc() {
    for script in random_scripts() {
        let gs = unsafe { run_script(8, &script, true) };
        let fs = unsafe { run_script(8, &script, false) };
        assert_no_foreign_links(&fs);
        assert_eq!(fs, gs, "insque/remque generated mismatch: {script:?}");
    }
}
