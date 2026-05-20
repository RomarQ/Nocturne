use crate::LedgerType;

/// Increment-only integer. Privacy-friendly because a ZK proof can
/// demonstrate increment without revealing the current value.
///
/// Maps to `StateValue::Cell(AlignedValue)` at the VM level.
#[derive(Debug, Clone)]
pub struct Counter(u64);

impl Counter {
    pub fn zero() -> Self {
        Self(0)
    }

    pub fn increment(&mut self) {
        self.0 += 1;
    }

    /// Bump the counter by `n`. The macro emits the on-chain `Addi`
    /// with this immediate, so `n` must be a const literal in circuit
    /// bodies; here at the storage level we accept any `u32`.
    pub fn increment_by(&mut self, n: u32) {
        self.0 += n as u64;
    }

    /// Overwrite the counter with `n`. On-chain this lowers to the same
    /// Push + Ins shape `Cell<u64>::set` uses (Counter and Cell<u64>
    /// share their StateValue::Cell encoding), so the value can be a
    /// witness read — there's no const restriction like increment_by.
    pub fn set(&mut self, n: u64) {
        self.0 = n;
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

impl LedgerType for Counter {
    fn requires_init() -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_basics() {
        let mut c = Counter::zero();
        assert_eq!(c.value(), 0);
        c.increment();
        c.increment();
        assert_eq!(c.value(), 2);
    }
}
