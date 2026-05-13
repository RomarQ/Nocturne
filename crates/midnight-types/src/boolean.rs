use crate::ZkType;
use std::fmt;

/// A ZK-native boolean (field element constrained to 0 or 1).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Boolean(bool);

impl Boolean {
    pub fn true_val() -> Self {
        Self(true)
    }

    pub fn false_val() -> Self {
        Self(false)
    }

    pub fn value(&self) -> bool {
        self.0
    }
}

impl From<bool> for Boolean {
    fn from(v: bool) -> Self {
        Self(v)
    }
}

impl From<Boolean> for bool {
    fn from(v: Boolean) -> bool {
        v.0
    }
}

impl std::ops::Not for Boolean {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl fmt::Debug for Boolean {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Boolean({})", self.0)
    }
}

impl ZkType for Boolean {
    fn field_count() -> usize {
        1
    }
}
