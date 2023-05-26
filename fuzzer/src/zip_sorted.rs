use std::collections::BTreeMap;
use std::iter::FusedIterator;

/// Merge sort two sorted iterators
///
/// This produces a new sorted iterator.
/// Keys for which both inputs have a key will be merged together, producing two `Some` values.
/// A key should never be present multiple times.
pub(crate) fn zip_sorted<'a, K, VLeft, VRight>(
    left: &'a BTreeMap<K, VLeft>,
    right: &'a BTreeMap<K, VRight>,
) -> impl Iterator<Item = (&'a K, Option<&'a VLeft>, Option<&'a VRight>)>
where
    K: Ord,
{
    ZipSortedIterator {
        iter_left: left.iter(),
        iter_right: right.iter(),
        curr: None,
    }
}

enum Either<Left, Right> {
    Left(Left),
    Right(Right),
}

struct ZipSortedIterator<ILeft, IRight, K, VLeft, VRight> {
    iter_left: ILeft,
    iter_right: IRight,
    curr: Option<(K, Either<VLeft, VRight>)>,
}

impl<ILeft, IRight, K, VLeft, VRight> Iterator
    for ZipSortedIterator<ILeft, IRight, K, VLeft, VRight>
where
    ILeft: Iterator<Item = (K, VLeft)>,
    IRight: Iterator<Item = (K, VRight)>,
    K: Ord,
{
    type Item = (K, Option<VLeft>, Option<VRight>);

    fn next(&mut self) -> Option<Self::Item> {
        let left;
        let right;
        match self.curr.take() {
            None => {
                left = self.iter_left.next();
                right = self.iter_right.next();
            }
            Some((k, Either::Left(v))) => {
                left = Some((k, v));
                right = self.iter_right.next();
            }
            Some((k, Either::Right(v))) => {
                left = self.iter_left.next();
                right = Some((k, v));
            }
        };

        match (left, right) {
            // Only one side set
            (None, None) => None,
            (None, Some((k, v))) => Some((k, None, Some(v))),
            (Some((k, v)), None) => Some((k, Some(v), None)),

            // Both sides available, determine which is earlier
            (Some((k_left, v_left)), Some((k_right, v_right))) => {
                match Ord::cmp(&k_left, &k_right) {
                    std::cmp::Ordering::Equal => Some((k_left, Some(v_left), Some(v_right))),

                    std::cmp::Ordering::Less => {
                        self.curr = Some((k_right, Either::Right(v_right)));
                        Some((k_left, Some(v_left), None))
                    }
                    std::cmp::Ordering::Greater => {
                        self.curr = Some((k_left, Either::Left(v_left)));
                        Some((k_right, None, Some(v_right)))
                    }
                }
            }
        }
    }
}

// BTreeMap iterators are fused
impl<ILeft, IRight, K, VLeft, VRight> FusedIterator
    for ZipSortedIterator<ILeft, IRight, K, VLeft, VRight>
where
    ILeft: Iterator<Item = (K, VLeft)>,
    IRight: Iterator<Item = (K, VRight)>,
    K: Ord,
{
}

#[cfg(test)]
mod tests {
    use super::zip_sorted;
    use pretty_assertions::assert_eq;
    use std::collections::BTreeMap;

    type Joined<'a> = (&'a i32, Option<&'a i32>, Option<&'a i32>);

    #[test]
    fn empty_iters() {
        let left: BTreeMap<i32, i32> = BTreeMap::new();
        let right: BTreeMap<i32, i32> = BTreeMap::new();
        let merged: Vec<Joined<'_>> = zip_sorted(&left, &right).collect::<Vec<_>>();
        let expected: Vec<Joined<'_>> = [].to_vec();
        assert_eq!(expected, merged);
    }

    #[test]
    fn only_left() {
        let left: BTreeMap<i32, i32> = BTreeMap::from([(0, 0), (1, 11), (2, 22), (5, 55), (9, 99)]);
        let right: BTreeMap<i32, i32> = BTreeMap::new();
        let merged: Vec<Joined<'_>> = zip_sorted(&left, &right).collect::<Vec<_>>();
        let expected: Vec<Joined<'_>> = [
            (&0, Some(&0), None),
            (&1, Some(&11), None),
            (&2, Some(&22), None),
            (&5, Some(&55), None),
            (&9, Some(&99), None),
        ]
        .to_vec();
        assert_eq!(expected, merged);
    }

    #[test]
    fn only_right() {
        let left: BTreeMap<i32, i32> = BTreeMap::new();
        let right: BTreeMap<i32, i32> = BTreeMap::from([
            (0, 0),
            (2, 222),
            (3, 333),
            (5, 555),
            (7, 777),
            (9, 999),
            (10, 0),
        ]);
        let merged: Vec<Joined<'_>> = zip_sorted(&left, &right).collect::<Vec<_>>();
        let expected: Vec<Joined<'_>> = [
            (&0, None, Some(&0)),
            (&2, None, Some(&222)),
            (&3, None, Some(&333)),
            (&5, None, Some(&555)),
            (&7, None, Some(&777)),
            (&9, None, Some(&999)),
            (&10, None, Some(&0)),
        ]
        .to_vec();
        assert_eq!(expected, merged);
    }

    #[test]
    fn merge_simple_right_longer() {
        let left: BTreeMap<i32, i32> = BTreeMap::from([(0, 0), (1, 11), (2, 22), (5, 55), (9, 99)]);
        let right: BTreeMap<i32, i32> = BTreeMap::from([
            (0, 0),
            (2, 222),
            (3, 333),
            (5, 555),
            (7, 777),
            (9, 999),
            (10, 0),
        ]);
        let merged: Vec<Joined<'_>> = zip_sorted(&left, &right).collect();
        let expected: Vec<Joined<'_>> = [
            (&0, Some(&0), Some(&0)),
            (&1, Some(&11), None),
            (&2, Some(&22), Some(&222)),
            (&3, None, Some(&333)),
            (&5, Some(&55), Some(&555)),
            (&7, None, Some(&777)),
            (&9, Some(&99), Some(&999)),
            (&10, None, Some(&0)),
        ]
        .to_vec();
        assert_eq!(expected, merged);
    }

    #[test]
    fn merge_simple_left_longer() {
        let left: BTreeMap<i32, i32> = BTreeMap::from([(0, 0), (1, 11), (2, 22), (5, 55), (9, 99)]);
        let right: BTreeMap<i32, i32> = BTreeMap::from([(0, 0), (2, 222), (3, 333)]);
        let merged: Vec<Joined<'_>> = zip_sorted(&left, &right).collect();
        let expected: Vec<Joined<'_>> = [
            (&0, Some(&0), Some(&0)),
            (&1, Some(&11), None),
            (&2, Some(&22), Some(&222)),
            (&3, None, Some(&333)),
            (&5, Some(&55), None),
            (&9, Some(&99), None),
        ]
        .to_vec();
        assert_eq!(expected, merged);
    }
}
