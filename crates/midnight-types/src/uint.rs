use crate::ZkType;
use std::fmt;
use std::ops::{Add, Mul, Sub};

/// N-bit unsigned integer for ZK circuits.
///
/// Represented as a field element with a `ConstrainBits(N)` constraint.
/// Supported bit widths: 8, 16, 32, 64, 128, 256.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uint<const N: u32>(u128);

impl<const N: u32> Uint<N> {
    pub fn new(value: u128) -> Self {
        debug_assert!(
            N <= 128 || value <= Self::max_value(),
            "value {value} exceeds Uint<{N}> max"
        );
        Self(value & Self::max_value())
    }

    pub fn zero() -> Self {
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

impl<const N: u32> Add for Uint<N> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self::new(self.0.wrapping_add(rhs.0))
    }
}

impl<const N: u32> Sub for Uint<N> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self::new(self.0.wrapping_sub(rhs.0))
    }
}

impl<const N: u32> Mul for Uint<N> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self::new(self.0.wrapping_mul(rhs.0))
    }
}

impl<const N: u32> PartialOrd for Uint<N> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl<const N: u32> Ord for Uint<N> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
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
    fn uint8_wrapping() {
        let a = Uint::<8>::new(255);
        let b = Uint::<8>::new(1);
        assert_eq!((a + b).value(), 0); // wraps at 256
    }
}
