use crate::LedgerType;
use std::collections::HashSet;
use std::hash::Hash;

/// Unordered set of `T` on the ledger.
///
/// Maps to `StateValue::Map<AlignedValue<T>, StateValue::Null>` at the VM
/// level — Set reuses the Map StateValue with a `Null` placeholder for the
/// value, so `Member`/`Ins`/`Rem` all work the same as for `Map<T, _>`. The
/// only on-chain difference vs. `Map::insert(k, v)` is that the value Push
/// emits `StateValue::Null` (encoded as `[0x11, 0]`) instead of
/// `StateValue::Cell(...)`.
#[derive(Debug, Clone)]
pub struct Set<T: Eq + Hash> {
    inner: HashSet<T>,
}

impl<T: Eq + Hash + Clone> Set<T> {
    pub fn empty() -> Self {
        Self {
            inner: HashSet::new(),
        }
    }

    pub fn contains(&self, key: &T) -> bool {
        self.inner.contains(key)
    }

    /// HashSet-style `insert`. Returns `true` if the element was newly
    /// added, `false` if it was already present.
    pub fn insert(&mut self, key: T) -> bool {
        self.inner.insert(key)
    }

    /// Remove an element. Returns `true` if it was present.
    pub fn remove(&mut self, key: &T) -> bool {
        self.inner.remove(key)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<T: Eq + Hash + Clone> LedgerType for Set<T> {
    fn requires_init() -> bool {
        false
    }
}
