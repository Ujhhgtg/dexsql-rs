use std::fmt;
use std::ops::{Deref, Range};
use std::ptr::NonNull;
use std::sync::Arc;

use memmap2::Mmap;

enum Backing {
    Owned(Vec<u8>),
    Mapped(Mmap),
    External {
        address: NonNull<u8>,
        length: usize,
        _owner: Arc<dyn Send + Sync>,
    },
}

unsafe impl Send for Backing {}
unsafe impl Sync for Backing {}

/// Shared, immutable original DEX bytes. Cloning and slicing retain the backing allocation.
#[derive(Clone)]
pub struct DexBytes {
    backing: Arc<Backing>,
    range: Range<usize>,
}

impl DexBytes {
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        Self {
            backing: Arc::new(Backing::Owned(bytes)),
            range: 0..len,
        }
    }

    /// Take ownership of a read-only mapping.
    ///
    /// # Safety
    /// The mapped contents must remain immutable and readable until all views are dropped.
    pub unsafe fn from_mmap(mapping: Mmap) -> Self {
        let len = mapping.len();
        Self {
            backing: Arc::new(Backing::Mapped(mapping)),
            range: 0..len,
        }
    }

    /// Create a read-only view over bytes retained by an external owner.
    ///
    /// # Safety
    /// The range must be initialized, belong to one live allocation, and remain readable and
    /// immutable until `owner` is released. Its length must not exceed `isize::MAX`.
    pub unsafe fn from_raw_parts_with_owner(
        address: NonNull<u8>,
        length: usize,
        owner: Arc<dyn Send + Sync>,
    ) -> Self {
        assert!(length <= isize::MAX as usize);
        Self {
            backing: Arc::new(Backing::External {
                address,
                length,
                _owner: owner,
            }),
            range: 0..length,
        }
    }

    pub fn slice(&self, range: Range<usize>) -> Option<Self> {
        if range.start > range.end || range.end > self.len() {
            return None;
        }
        Some(Self {
            backing: Arc::clone(&self.backing),
            range: self.range.start + range.start..self.range.start + range.end,
        })
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        if self.range.start != 0 {
            return self.to_vec();
        }
        match Arc::try_unwrap(self.backing) {
            Ok(Backing::Owned(mut bytes)) => {
                bytes.truncate(self.range.end);
                bytes
            }
            Ok(backing) => Self {
                backing: Arc::new(backing),
                range: self.range,
            }
            .to_vec(),
            Err(backing) => Self {
                backing,
                range: self.range,
            }
            .to_vec(),
        }
    }

    #[cfg(unix)]
    pub(crate) fn discard_mapped_pages(&self, range: Range<usize>) {
        if let Backing::Mapped(mapping) = self.backing.as_ref() {
            let _ = unsafe {
                mapping.unchecked_advise_range(
                    memmap2::UncheckedAdvice::DontNeed,
                    self.range.start + range.start,
                    range.len(),
                )
            };
        }
    }
}

impl Deref for DexBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        let bytes: &[u8] = match self.backing.as_ref() {
            Backing::Owned(bytes) => bytes,
            Backing::Mapped(mapping) => mapping,
            Backing::External {
                address, length, ..
            } => unsafe { std::slice::from_raw_parts(address.as_ptr(), *length) },
        };
        &bytes[self.range.clone()]
    }
}

impl AsRef<[u8]> for DexBytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl fmt::Debug for DexBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DexBytes")
            .field(&self.range)
            .finish()
    }
}
