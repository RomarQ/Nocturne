use crate::LedgerType;

/// A single mutable value on the ledger.
///
/// Maps to `StateValue::Cell(AlignedValue)` at the VM level.
#[derive(Debug, Clone)]
pub struct Cell<T> {
    value: T,
}

impl<T: Clone> Cell<T> {
    pub fn new(value: T) -> Self {
        Self { value }
    }

    pub fn get(&self) -> T {
        self.value.clone()
    }

    pub fn set(&mut self, value: T) {
        self.value = value;
    }
}

impl<T: Clone> LedgerType for Cell<T> {
    fn requires_init() -> bool {
        true
    }
}
