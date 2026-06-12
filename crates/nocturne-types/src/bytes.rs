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

    /// Construct from a slice of exactly `N` bytes.
    ///
    /// Debug builds assert the length matches; release builds truncate a
    /// longer slice and zero-pad a shorter one (the historical lenient
    /// behavior). Prefer [`try_from_slice`](Self::try_from_slice) when
    /// the slice length isn't statically known.
    pub fn from_slice(slice: &[u8]) -> Self {
        debug_assert_eq!(
            slice.len(),
            N,
            "Bytes<{N}>::from_slice requires exactly {N} bytes, got {}",
            slice.len()
        );
        let mut data = [0u8; N];
        let len = slice.len().min(N);
        data[..len].copy_from_slice(&slice[..len]);
        Self(data)
    }

    /// Construct from a slice, returning `None` unless it is exactly `N`
    /// bytes long.
    pub fn try_from_slice(slice: &[u8]) -> Option<Self> {
        let data: [u8; N] = slice.try_into().ok()?;
        Some(Self(data))
    }
}

impl<const N: usize> Default for Bytes<N> {
    fn default() -> Self {
        Self::zeroed()
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
        N.div_ceil(31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_slice_exact_length_round_trips() {
        let b = Bytes::<4>::from_slice(&[1, 2, 3, 4]);
        assert_eq!(b.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Bytes<4>::from_slice")]
    fn from_slice_short_slice_panics_in_debug() {
        let _ = Bytes::<4>::from_slice(&[1, 2]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Bytes<4>::from_slice")]
    fn from_slice_long_slice_panics_in_debug() {
        let _ = Bytes::<4>::from_slice(&[1, 2, 3, 4, 5]);
    }

    #[test]
    fn try_from_slice_checks_length() {
        assert_eq!(
            Bytes::<4>::try_from_slice(&[1, 2, 3, 4]),
            Some(Bytes::new([1, 2, 3, 4]))
        );
        assert_eq!(Bytes::<4>::try_from_slice(&[1, 2]), None);
        assert_eq!(Bytes::<4>::try_from_slice(&[1, 2, 3, 4, 5]), None);
    }
}
