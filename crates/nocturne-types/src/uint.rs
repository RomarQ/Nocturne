use crate::ZkType;
use std::fmt;
use std::ops::{Add, Mul, Sub};

/// N-bit unsigned integer for ZK circuits.
///
/// Represented as a field element with a `ConstrainBits(N)` constraint.
/// Supported bit widths: 8, 16, 32, 64, 128. The backing store is a
/// `u128`, so widths above 128 are not representable.
///
/// Test-mode arithmetic (`+`, `-`, `*`) panics on overflow/underflow
/// past `2^N` instead of wrapping: the circuit lowers these operators to
/// unconstrained field arithmetic, so a silent off-chain wrap would mask
/// a divergence the proof never catches. Note this panic is conservative
/// for intermediates: `(max + b) - b` is circuit-valid (field elements
/// don't wrap at `2^N`) but panics off-chain on the `max + b` step —
/// reorder the expression or widen the type. `ConstrainBits(N)` only
/// applies where a `Uint<N>` ENTERS the circuit (witness/public-input
/// declaration), never to arithmetic results, so in-circuit
/// `Uint<8>: 255 + 1` is the field element 256 and a proof over it
/// verifies. This is a deliberate divergence from Compact's checked
/// in-circuit arithmetic; emitting per-op range constraints is an open
/// decision.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uint<const N: u32>(u128);

impl<const N: u32> Uint<N> {
    pub fn new(value: u128) -> Self {
        // Compile-time width bound: the backing store is a u128, so a
        // Uint<200> would otherwise silently behave as Uint<128>
        // (max_value saturates). Every value-producing path goes through
        // new()/zero(), so asserting here catches the bad width at
        // monomorphization.
        const { assert!(N >= 1 && N <= 128, "Uint<N> requires 1 <= N <= 128") }
        debug_assert!(
            N >= 128 || value <= Self::max_value(),
            "value {value} exceeds Uint<{N}> max"
        );
        Self(value & Self::max_value())
    }

    pub fn zero() -> Self {
        const { assert!(N >= 1 && N <= 128, "Uint<N> requires 1 <= N <= 128") }
        Self(0)
    }

    pub fn value(&self) -> u128 {
        self.0
    }

    fn max_value() -> u128 {
        if N >= 128 {
            u128::MAX
        } else {
            (1u128 << N) - 1
        }
    }
}

impl<const N: u32> From<u64> for Uint<N> {
    fn from(v: u64) -> Self {
        Self::new(v as u128)
    }
}

impl<const N: u32> From<u128> for Uint<N> {
    fn from(v: u128) -> Self {
        Self::new(v)
    }
}

impl<const N: u32> Default for Uint<N> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<const N: u32> Add for Uint<N> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        match self
            .0
            .checked_add(rhs.0)
            .filter(|v| *v <= Self::max_value())
        {
            Some(v) => Self(v),
            None => {
                panic!("Uint<{N}> overflow; the circuit would not constrain this — restructure")
            }
        }
    }
}

impl<const N: u32> Sub for Uint<N> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        match self.0.checked_sub(rhs.0) {
            Some(v) => Self(v),
            None => {
                panic!("Uint<{N}> underflow; the circuit would not constrain this — restructure")
            }
        }
    }
}

impl<const N: u32> Mul for Uint<N> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        match self
            .0
            .checked_mul(rhs.0)
            .filter(|v| *v <= Self::max_value())
        {
            Some(v) => Self(v),
            None => {
                panic!("Uint<{N}> overflow; the circuit would not constrain this — restructure")
            }
        }
    }
}

impl<const N: u32> Ord for Uint<N> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<const N: u32> PartialOrd for Uint<N> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: u32> fmt::Debug for Uint<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uint<{N}>({})", self.0)
    }
}

impl<const N: u32> fmt::Display for Uint<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<const N: u32> ZkType for Uint<N> {
    fn field_count() -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint64_arithmetic() {
        let a = Uint::<64>::from(100u64);
        let b = Uint::<64>::from(200u64);
        assert_eq!((a + b).value(), 300);
        assert_eq!((b - a).value(), 100);
        assert!(a < b);
    }

    #[test]
    #[should_panic(expected = "Uint<8> overflow")]
    fn uint8_add_overflow_panics() {
        let a = Uint::<8>::new(255);
        let b = Uint::<8>::new(1);
        let _ = a + b;
    }

    #[test]
    #[should_panic(expected = "Uint<8> underflow")]
    fn uint8_sub_underflow_panics() {
        let a = Uint::<8>::new(0);
        let b = Uint::<8>::new(1);
        let _ = a - b;
    }

    #[test]
    #[should_panic(expected = "Uint<8> overflow")]
    fn uint8_mul_overflow_panics() {
        let a = Uint::<8>::new(16);
        let b = Uint::<8>::new(16);
        let _ = a * b;
    }

    #[test]
    fn arithmetic_at_the_boundary_does_not_panic() {
        let max = Uint::<8>::new(255);
        let zero = Uint::<8>::zero();
        assert_eq!((max + zero).value(), 255);
        assert_eq!((max - max).value(), 0);
        assert_eq!((Uint::<8>::new(15) * Uint::<8>::new(17)).value(), 255);
    }

    #[test]
    fn uint128_full_width_works() {
        let max = Uint::<128>::new(u128::MAX);
        assert_eq!(max.value(), u128::MAX);
        assert_eq!((max - Uint::<128>::new(1)).value(), u128::MAX - 1);
    }

    #[test]
    #[should_panic(expected = "Uint<128> overflow")]
    fn uint128_add_overflow_panics() {
        let max = Uint::<128>::new(u128::MAX);
        let _ = max + Uint::<128>::new(1);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "exceeds Uint<8> max")]
    fn new_rejects_out_of_range_value_in_debug() {
        let _ = Uint::<8>::new(256);
    }
}
