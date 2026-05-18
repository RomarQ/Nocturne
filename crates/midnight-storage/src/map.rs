use crate::LedgerType;
use std::collections::HashMap;
use std::hash::Hash;

/// Key-value storage on the ledger.
///
/// Maps to `StateValue::Map(HashMap)` at the VM level.
#[derive(Debug, Clone)]
pub struct Map<K: Eq + Hash, V> {
    inner: HashMap<K, V>,
}

impl<K: Eq + Hash + Clone, V: Clone> Map<K, V> {
    pub fn empty() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.inner.get(key).cloned()
    }

    pub fn set(&mut self, key: K, value: V) {
        self.inner.insert(key, value);
    }

    /// HashMap-style alias for `set`. Returns the previous value, if any.
    /// The eDSL exposes this name because the on-chain VM verb is `Ins`
    /// (insert) and compact's surface API uses `insert(k, v)`.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key, value)
    }

    /// Remove a key, returning the value that was stored (if any). Mirrors
    /// the on-chain `Rem` opcode.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.remove(key)
    }

    pub fn contains(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<K: Eq + Hash + Clone, V: Clone> LedgerType for Map<K, V> {
    fn requires_init() -> bool {
        false
    }
}
