use crate::ZkType;
use std::fmt;

/// Fixed-size byte array for ZK circuits.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Bytes<const N: usize>([u8; N]);

impl<const N: usize> Bytes<N> {
    pub fn new(data: [u8; N]) -> Self {
        Self(data)
    }

    pub fn zeroed() -> Self {
        Self([0u8; N])
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        let mut data = [0u8; N];
        let len = slice.len().min(N);
        data[..len].copy_from_slice(&slice[..len]);
        Self(data)
    }
}

impl<const N: usize> From<[u8; N]> for Bytes<N> {
    fn from(data: [u8; N]) -> Self {
        Self(data)
    }
}

impl<const N: usize> fmt::Debug for Bytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bytes<{N}>(0x")?;
        for byte in &self.0[..N.min(8)] {
            write!(f, "{byte:02x}")?;
        }
        if N > 8 {
            write!(f, "...")?;
        }
        write!(f, ")")
    }
}

impl<const N: usize> ZkType for Bytes<N> {
    fn field_count() -> usize {
        // Each field element can hold ~31 bytes.
        (N + 30) / 31
    }
}
