#[cfg(feature = "image")]
use color_eyre::eyre::Result;
use sha2::Digest as _;
use std::convert::TryInto;
use std::fmt::{self, Debug};
use std::ops::Add;
#[cfg(feature = "image")]
use std::path::Path;

#[derive(Clone, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Counters {
    counter: Vec<u32>,
}

#[allow(clippy::len_without_is_empty)]
impl Counters {
    pub fn new(len: usize, init: u32) -> Self {
        Self {
            counter: vec![init; len],
        }
    }

    /// Discard the counter values which appear in `pattern`
    ///
    /// Each counter which is `!= 0` in `pattern` will be set to `0` in `self.`
    /// This allows discarding all the values which appear in [`Counters`].
    ///
    /// # Panics
    ///
    /// The function panics if the length of the [`Counters`] is different.
    pub fn discard_counters_by_pattern(&mut self, pattern: &Self) {
        assert_eq!(
            self.len(),
            pattern.len(),
            "Both Counters need to be of equal length but self {} and pattern {} differ",
            self.len(),
            pattern.len()
        );

        self.counter
            .iter_mut()
            .zip(pattern.counter.iter().copied())
            .for_each(|(counter, pattern)| {
                if pattern > 0 {
                    *counter = 0;
                }
            });
    }

    pub fn min_pairwise(&mut self, other: &Self) {
        self.counter
            .iter_mut()
            .zip(other.counter.iter())
            .for_each(|(s, &o)| *s = (*s).min(o));
    }

    pub fn max_pairwise(&mut self, other: &Self) {
        self.counter
            .iter_mut()
            .zip(other.counter.iter())
            .for_each(|(s, &o)| *s = (*s).max(o));
    }

    /// Return `true` if any of the counter values is larger 0.
    pub fn has_counters_set(&self) -> bool {
        self.counter.iter().any(|&x| x > 0)
    }

    #[cfg(feature = "image")]
    pub fn save_as_image<'a>(
        &self,
        img_file: impl AsRef<Path>,
        highest_value: impl Into<ImageMax<'a>>,
    ) -> Result<()> {
        use image::{GrayImage, Luma};

        // // Ensure the value is at least 1, otherwise divide by 0 errors
        // let highest = highest_value
        //     .unwrap_or_else(|| self.counter.iter().copied().max().unwrap_or(0))
        //     .max(1);
        let max_values = match highest_value.into() {
            ImageMax::None => itertools::Either::Left(std::iter::repeat(
                self.counter.iter().copied().max().unwrap_or(1),
            )),
            ImageMax::Single(max) => itertools::Either::Left(std::iter::repeat(max)),
            ImageMax::Multiple(max) => itertools::Either::Right(max.iter()),
        };
        // if let ImageMax::Multiple(max) = highest_value.into() {
        //     assert_eq!(
        //         self.len(),
        //         max.len(),
        //         "Both Counters need to be of equal length but self {} and max {} differ",
        //         self.len(),
        //         max.len()
        //     );
        // };

        // Draw the counters into a greyscale image
        let img_size = ((self.counter.len() as f64).sqrt().floor() + 1.) as u32;
        let mut image = GrayImage::new(img_size, img_size);
        for (idx, (&value, max_value)) in self.counter.iter().zip(max_values).enumerate() {
            let idx = idx as u32;
            image.put_pixel(
                idx / img_size,
                idx % img_size,
                Luma([(u64::from(value) * 255 / u64::from(max_value)) as u8]),
            );
        }
        image.save(img_file.as_ref())?;
        Ok(())
    }

    /// Return the number of counters included
    pub fn len(&self) -> usize {
        self.counter.len()
    }
    /// Return the number of counters larger 0
    pub fn count(&self) -> usize {
        self.counter.iter().filter(|&&x| x > 0).count()
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        for val in &self.counter {
            hasher.update(val.to_le_bytes());
        }
        let res = hasher.finalize();
        res.to_vec().try_into().unwrap()
    }

    pub fn as_slice(&self) -> &[u32] {
        &self.counter
    }

    pub fn iter(&'_ self) -> impl Iterator<Item = u32> + '_ {
        self.counter.iter().cloned()
    }

    /// Discard the counter values which do not appear in `pattern`
    ///
    /// Each counter which is `!= 0` in `pattern` will be kept.
    /// This returns a new `Counter` with only those values.
    ///
    /// This can be used to shrink the original counter to only the relevant places.
    ///
    /// # Panics
    ///
    /// The function panics if the length of the [`Counters`] is different.
    #[must_use]
    pub fn shrink_by_pattern(&self, pattern: &Self) -> Self {
        assert_eq!(
            self.len(),
            pattern.len(),
            "Both Counters need to be of equal length but self {} and pattern {} differ",
            self.len(),
            pattern.len()
        );

        let counter = self
            .counter
            .iter()
            .cloned()
            .zip(pattern.counter.iter())
            // Only keep the entries with a != 0 pattern
            .filter(|(_, &p)| p > 0)
            .map(|(c, _)| c)
            .collect();
        Self { counter }
    }

    /// Map all counts to a binary representation
    ///
    /// All values `>0` will be mapped to `1` and `0` stays `0`.
    pub fn convert_to_binary(&mut self) {
        self.counter.iter_mut().for_each(|val| {
            *val = match val {
                0 => 0,
                _ => 1,
            }
        });
    }
}

#[cfg(feature = "image")]
#[derive(Debug)]
pub enum ImageMax<'a> {
    None,
    Single(u32),
    Multiple(&'a Counters),
}

#[cfg(feature = "image")]
impl Default for ImageMax<'_> {
    fn default() -> Self {
        ImageMax::None
    }
}

#[cfg(feature = "image")]
impl From<u32> for ImageMax<'_> {
    fn from(max: u32) -> Self {
        ImageMax::Single(max)
    }
}

#[cfg(feature = "image")]
impl<'a> From<&'a Counters> for ImageMax<'a> {
    fn from(max: &'a Counters) -> Self {
        ImageMax::Multiple(max)
    }
}

#[cfg(feature = "image")]
impl From<Option<u32>> for ImageMax<'_> {
    fn from(max: Option<u32>) -> Self {
        match max {
            None => ImageMax::None,
            Some(max) => ImageMax::Single(max),
        }
    }
}

impl Debug for Counters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let non_null_values = self.counter.iter().filter(|&&x| x != 0).count();
        let total_hit_count: u64 = self.counter.iter().copied().map(u64::from).sum();
        let highest = self.counter.iter().copied().max().unwrap_or(0);
        f.debug_struct("Counters")
            .field("num", &self.len())
            .field("hits", &total_hit_count)
            .field("non_0", &non_null_values)
            .field("highest", &highest)
            .finish()
    }
}

impl Add for Counters {
    type Output = Counters;

    fn add(mut self, rhs: Self) -> Self::Output {
        assert_eq!(
            self.len(),
            rhs.len(),
            "Both Counters need to be of equal length but Left {} and Right {} differ",
            self.len(),
            rhs.len()
        );
        self.counter
            .iter_mut()
            .zip(rhs.counter.into_iter())
            .for_each(|(left, right)| *left = left.saturating_add(right));
        self
    }
}

impl From<Vec<u32>> for Counters {
    fn from(values: Vec<u32>) -> Self {
        Self { counter: values }
    }
}
