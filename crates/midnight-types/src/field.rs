use crate::ZkType;
use std::fmt;
use std::ops::{Add, Mul, Neg, Sub};

/// A field element in the BLS12-381 scalar field.
///
/// In test mode this wraps a `u128` for simplicity.
/// The real field modulus is ~2^254, but u128 suffices for testing.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Field(u128);

impl Field {
    pub fn zero() -> Self {
        Self(0)
    }

    pub fn one() -> Self {
        Self(1)
    }

    pub fn value(&self) -> u128 {
        self.0
    }
}

impl From<u64> for Field {
    fn from(v: u64) -> Self {
        Self(v as u128)
    }
}

impl From<u128> for Field {
    fn from(v: u128) -> Self {
        Self(v)
    }
}

impl Add for Field {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Sub for Field {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0.wrapping_sub(rhs.0))
    }
}

impl Mul for Field {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self(self.0.wrapping_mul(rhs.0))
    }
}

impl Neg for Field {
    type Output = Self;
    fn neg(self) -> Self {
        Self(self.0.wrapping_neg())
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Field({})", self.0)
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ZkType for Field {
    fn field_count() -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_arithmetic() {
        let a = Field::from(10u64);
        let b = Field::from(20u64);
        assert_eq!((a + b).value(), 30);
        assert_eq!((b - a).value(), 10);
        assert_eq!((a * b).value(), 200);
        assert_eq!((-Field::one()).value(), u128::MAX); // wrapping neg
    }
}
