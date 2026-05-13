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
