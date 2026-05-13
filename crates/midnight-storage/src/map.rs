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
