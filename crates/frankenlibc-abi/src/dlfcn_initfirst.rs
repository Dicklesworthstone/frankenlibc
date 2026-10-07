//! Native constructor scheduling, including GNU DF_1_INITFIRST.
//!
//! Callback order and dependency lifetime are separate. INITFIRST may execute
//! a consumer before its dependencies, but must not invert their FINI order.
//! Reserve dependency-order finalization ranks before calling that initializer.
//! Other loads retain the existing completion-order ranks. All callers hold
//! OPERATIONS; no registry guard crosses arbitrary constructor code.

use super::{InitState, NativeDso, ResidentPin, lifecycle, registry};

/// Preserve the existing dependency-first traversal, including deterministic
/// cycle handling. Snapshot IDs, not references: constructors may grow the
/// registry or initialize another part of the graph recursively.
fn plan(dsos: &[NativeDso], root: usize) -> Option<Vec<usize>> {
    let mut stack = vec![(root, false)];
    let mut seen = Vec::new();
    let mut order = Vec::new();
    while let Some((id, ready)) = stack.pop() {
        let dso = dsos.iter().find(|dso| dso.id == id)?;
        if dso.state != InitState::Pending {
            continue;
        }
        if ready {
            order.push(id);
        } else if !seen.contains(&id) {
            seen.push(id);
            stack.push((id, true));
            stack.extend(dso.needed.iter().rev().map(|&id| (id, false)));
        }
    }
    Some(order)
}

/// Consume INITFIRST once per publication group. GNU chooses the last newly
/// mapped marked object, not every marked object and not an already-resident
/// dependency. `pending` is in the loader's breadth-first mapping order.
pub(super) fn select(pending: &mut [NativeDso]) {
    let first = pending.iter().rposition(|dso| dso.initialize_first);
    for (index, dso) in pending.iter_mut().enumerate() {
        dso.initialize_first = Some(index) == first;
    }
}

fn call(id: usize) -> Option<()> {
    let callbacks = {
        let mut dsos = registry().lock().ok()?;
        let dso = dsos.iter_mut().find(|dso| dso.id == id)?;
        // Reentry may already have initialized this planned object. Mark it
        // before user code so reopening it cannot repeat its constructors.
        if dso.state != InitState::Pending {
            return Some(());
        }
        dso.initialize_first = false;
        dso.state = InitState::Running;
        dso.callbacks.init.clone()
    };
    for address in callbacks {
        // SAFETY: the complete group's callbacks and executable providers were
        // validated before publication. The operation's root pin retains the
        // whole graph even when INITFIRST's root is already marked Live.
        unsafe { lifecycle::call_init(address) };
    }
    let mut dsos = registry().lock().ok()?;
    let index = dsos.iter().position(|dso| dso.id == id)?;
    if dsos[index].initialized_at == 0 {
        let sequence = dsos.iter().map(|dso| dso.initialized_at)
            .max().unwrap_or(0).checked_add(1)?;
        dsos[index].initialized_at = sequence;
    }
    dsos[index].state = InitState::Live;
    Some(())
}

pub(super) fn initialize(root: usize) -> Option<()> {
    let (order, first, _pin) = {
        let mut dsos = registry().lock().ok()?;
        let order = plan(&dsos, root)?;
        if order.is_empty() {
            return Some(());
        }
        let first = dsos.iter().rev().find(|dso| {
            dso.initialize_first && order.contains(&dso.id)
        }).map(|dso| dso.id);
        let root_index = dsos.iter().position(|dso| dso.id == root)?;
        let pins = dsos[root_index].load_pins.checked_add(1)?;
        if first.is_some() {
            let base = dsos.iter().map(|dso| dso.initialized_at).max().unwrap_or(0);
            // Preflight all arithmetic before changing any rank or pin.
            base.checked_add(order.len())?;
            for (ordinal, id) in order.iter().enumerate() {
                // Every ID was resolved by plan under this same lock.
                let dso = dsos.iter_mut().find(|dso| dso.id == *id)?;
                if dso.initialized_at == 0 {
                    dso.initialized_at = base + ordinal + 1;
                }
            }
        }
        dsos[root_index].load_pins = pins;
        (order, first, ResidentPin { id: root })
    };
    if let Some(first) = first {
        call(first)?;
    }
    // Do not restart traversal from a now-Live INITFIRST root: that would skip
    // its still-Pending dependencies. Execute the complete pre-callback plan.
    for id in order {
        call(id)?;
    }
    Some(())
}
