//! Packed immutable string IDs: one UTF-8 arena and one end offset per ID.
//!
//! Empty strings have repeated offsets and embedded NUL is an ordinary UTF-8
//! byte. Offsets refer to decoded UTF-8, not the DEX's UTF-16 length prefix.

use std::cmp::Ordering;
use std::ops::Index;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StringPool {
    bytes: Vec<u8>,
    ends: Vec<u32>,
}

impl StringPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve the ID array without allocating a separate buffer per string.
    pub fn with_capacity(strings: usize) -> Self {
        Self {
            bytes: Vec::new(),
            ends: Vec::with_capacity(strings),
        }
    }

    pub fn len(&self) -> usize {
        self.ends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&str> {
        let end = *self.ends.get(index)? as usize;
        let start = index
            .checked_sub(1)
            .map_or(0, |previous| self.ends[previous] as usize);
        // SAFETY: only append_utf8 mutates the arena. It accepts valid UTF-8
        // and records its exact endpoint, so every ID spans whole characters.
        Some(unsafe { std::str::from_utf8_unchecked(&self.bytes[start..end]) })
    }

    pub fn iter(&self) -> Iter<'_> {
        Iter {
            pool: self,
            front: 0,
            back: self.len(),
            front_start: 0,
        }
    }

    /// IDs of the strings that contain `needle` (which must be non-empty).
    ///
    /// One pass over the packed arena is far cheaper than slicing every string
    /// for a substring predicate: the search is a SIMD byte scan, and matches
    /// are mapped back to their owning ID through the end offsets. A match
    /// crossing two adjacent IDs is rejected because it is not a substring of
    /// either one.
    pub fn indices_containing(&self, needle: &str) -> Vec<u32> {
        debug_assert!(!needle.is_empty());
        let mut indices = Vec::new();
        let mut previous = None;
        for position in memchr::memmem::find_iter(&self.bytes, needle.as_bytes()) {
            let index = self.ends.partition_point(|&end| end as usize <= position);
            let Some(&end) = self.ends.get(index) else {
                continue;
            };
            if position + needle.len() > end as usize {
                continue;
            }
            let index = index as u32;
            if previous != Some(index) {
                indices.push(index);
                previous = Some(index);
            }
        }
        indices
    }

    /// Match slice binary-search behavior, retaining the caller's ordering.
    pub fn binary_search_by<F>(&self, mut compare: F) -> Result<usize, usize>
    where
        F: FnMut(&str) -> Ordering,
    {
        let mut start = 0;
        let mut end = self.len();
        while start < end {
            let middle = start + (end - start) / 2;
            match compare(&self[middle]) {
                Ordering::Less => start = middle + 1,
                Ordering::Greater => end = middle,
                Ordering::Equal => return Ok(middle),
            }
        }
        Err(start)
    }

    /// Append an already-decoded value, preserving embedded NUL verbatim.
    pub fn push(&mut self, value: impl AsRef<str>) {
        self.append_utf8(value.as_ref());
    }

    fn append_utf8(&mut self, value: &str) {
        let end = self
            .bytes
            .len()
            .checked_add(value.len())
            .and_then(|end| u32::try_from(end).ok())
            .expect("decoded DEX string arena exceeds u32 offsets");
        self.bytes.extend_from_slice(value.as_bytes());
        self.ends.push(end);
    }

    /// Decode one DEX string, avoiding the temporary String for ASCII IDs.
    /// All other inputs use the existing MUTF-8 decoder, including its
    /// terminator, encoded NUL, surrogate replacement, and error behavior.
    pub(crate) fn push_mutf8(&mut self, value: &[u8]) -> Result<(), crate::mutf8::DecodeError> {
        if value.iter().all(|byte| byte.is_ascii() && *byte != 0) {
            // SAFETY: every byte was checked to be nonzero ASCII.
            self.append_utf8(unsafe { std::str::from_utf8_unchecked(value) });
        } else {
            self.append_utf8(&crate::mutf8::decode(value)?);
        }
        Ok(())
    }
}

impl From<Vec<String>> for StringPool {
    fn from(strings: Vec<String>) -> Self {
        let mut pool = Self::with_capacity(strings.len());
        let bytes = strings.iter().map(String::len).sum();
        pool.bytes.reserve_exact(bytes);
        for string in strings {
            pool.push(string);
        }
        pool
    }
}

impl FromIterator<String> for StringPool {
    fn from_iter<T: IntoIterator<Item = String>>(strings: T) -> Self {
        let strings = strings.into_iter();
        let mut pool = Self::with_capacity(strings.size_hint().0);
        for string in strings {
            pool.push(string);
        }
        pool
    }
}

impl Index<usize> for StringPool {
    type Output = str;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("string pool index out of bounds")
    }
}

#[derive(Clone, Debug)]
pub struct Iter<'a> {
    pool: &'a StringPool,
    front: usize,
    back: usize,
    /// Start byte of the next front item; tracked so forward iteration reads
    /// one offset per item instead of reloading the previous end.
    front_start: usize,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        let end = self.pool.ends[self.front] as usize;
        let item = &self.pool.bytes[self.front_start..end];
        self.front_start = end;
        self.front += 1;
        Some(unsafe { std::str::from_utf8_unchecked(item) })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.back - self.front;
        (remaining, Some(remaining))
    }
}

impl DoubleEndedIterator for Iter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        self.back -= 1;
        self.pool.get(self.back)
    }
}

impl ExactSizeIterator for Iter<'_> {}
impl std::iter::FusedIterator for Iter<'_> {}

impl<'a> IntoIterator for &'a StringPool {
    type Item = &'a str;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_ids_preserve_empty_nul_unicode_and_iteration() {
        let values = vec!["", "ascii", "", "a\0b", "你好", "😀", "�"];
        let pool = StringPool::from(
            values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        );
        assert_eq!(pool.len(), values.len());
        assert!(!pool.is_empty());
        assert_eq!(pool.iter().collect::<Vec<_>>(), values);
        assert_eq!(
            pool.iter().rev().collect::<Vec<_>>(),
            values.iter().rev().copied().collect::<Vec<_>>()
        );
        assert_eq!(&pool[3], "a\0b");
        assert_eq!(pool.get(values.len()), None);
        assert_eq!(
            pool.bytes.len(),
            values.iter().map(|value| value.len()).sum::<usize>()
        );
        assert_eq!(
            pool.ends.len() * std::mem::size_of::<u32>(),
            values.len() * 4
        );
    }

    #[test]
    fn mutf8_path_matches_existing_decoder_including_errors() {
        for value in [
            b"".as_slice(),
            b"abc",
            b"abc\0ignored",
            b"a\xc0\x80b",
            b"\xe4\xbd\xa0\xe5\xa5\xbd",
            b"\xed\xa0\xbd\xed\xb8\x80",
            b"\xed\xa0\x80",
            b"\xed\xb0\x80",
            b"\xed\xa0\x80x",
            b"\xc0",
            b"\xe0\x80",
            b"\xf0\x9f\x98\x80",
            b"\xc0x",
        ] {
            let mut pool = StringPool::new();
            match crate::mutf8::decode(value) {
                Ok(expected) => {
                    pool.push_mutf8(value).unwrap();
                    assert_eq!(pool.get(0), Some(expected.as_str()), "{value:?}");
                }
                Err(expected) => {
                    assert_eq!(pool.push_mutf8(value), Err(expected), "{value:?}");
                    assert!(pool.is_empty());
                }
            }
        }
    }

    #[test]
    fn binary_search_and_clone_keep_string_ids() {
        let pool = StringPool::from(vec!["".into(), "".into(), "a".into(), "c".into()]);
        assert_eq!(pool.binary_search_by(|value| value.cmp("a")), Ok(2));
        assert_eq!(pool.binary_search_by(|value| value.cmp("b")), Err(3));
        assert_eq!(pool.binary_search_by(|value| value.cmp("z")), Err(4));
        assert!(pool.binary_search_by(|value| value.cmp("")).is_ok());
        assert_eq!(pool.clone(), pool);
    }

    #[test]
    fn decoded_supplementary_and_replacement_values_keep_utf16_order() {
        let mut pool = StringPool::new();
        pool.push_mutf8(b"\xed\xa0\x80\xed\xb0\x80").unwrap();
        pool.push("\u{e000}");
        pool.push_mutf8(b"\xed\xa0\x80").unwrap();
        assert_eq!(
            pool.iter().collect::<Vec<_>>(),
            vec!["\u{10000}", "\u{e000}", "�"]
        );
        assert_eq!(crate::dex::utf16_cmp(&pool[0], &pool[1]), Ordering::Less);
        assert_eq!(crate::dex::utf16_cmp(&pool[1], &pool[2]), Ordering::Less);
        assert_eq!(pool[0].cmp(&pool[1]), Ordering::Greater);
    }

    #[test]
    fn indices_containing_reports_substrings_without_crossing_ids() {
        let pool = StringPool::from(
            vec!["abc", "", "bcde", "xxbcxx", "b", "c", "你好世界"]
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        );
        assert_eq!(pool.indices_containing("bc"), vec![0, 2, 3]);
        assert_eq!(pool.indices_containing("c"), vec![0, 2, 3, 5]);
        assert_eq!(pool.indices_containing("你好"), vec![6]);

        // The needle's bytes occur at the junction between two adjacent IDs,
        // where it is not a substring of either one.
        let pool = StringPool::from(vec!["ab".to_owned(), "cd".to_owned()]);
        assert_eq!(pool.indices_containing("bc"), Vec::<u32>::new());
        assert_eq!(pool.indices_containing("b"), vec![0]);
        assert_eq!(pool.indices_containing("cd"), vec![1]);

        // A short needle may match many times inside one ID but is reported once.
        let pool = StringPool::from(vec!["aaaa".to_owned()]);
        assert_eq!(pool.indices_containing("aa"), vec![0]);
    }
}
