use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

const DECAY_FACTOR: f64 = 0.91;

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
pub(crate) struct OrdF64(f64);

impl OrdF64 {
    pub(crate) fn into_inner(self) -> f64 {
        self.0
    }
}

impl Ord for OrdF64 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        f64::total_cmp(&self.0, &other.0)
    }
}

impl PartialOrd for OrdF64 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for OrdF64 {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for OrdF64 {}

#[derive(PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
struct PriorityQueueEntry<T> {
    priority: OrdF64,
    value: T,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct PriorityQueue<T> {
    #[serde(bound(deserialize = "T: Ord"))]
    queue: BinaryHeap<PriorityQueueEntry<T>>,
    original_priorities: BTreeMap<T, OrdF64>,
    /// Store penalties for each item.
    ///
    /// The values are in multiple of the `DECAY_FACTOR`.
    /// We cannot directly update the queue since that would require rebuilding the heap, so instead we store the adjustments in a sidetable and update the priorities in the queue whenever we get the chance, because we are handling the item anyway.
    penalties: BTreeMap<T, u32>,
}

impl<T> PriorityQueue<T>
where
    T: Ord,
{
    pub(crate) fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
            original_priorities: BTreeMap::new(),
            penalties: BTreeMap::new(),
        }
    }

    pub(crate) fn push(&mut self, priority: f64, value: T)
    where
        T: Clone,
    {
        self.queue.push(PriorityQueueEntry {
            priority: OrdF64(priority),
            value: value.clone(),
        });
        self.original_priorities.insert(value, OrdF64(priority));
    }

    /// Get the n-top priority item and requeue it with a new (lower) priority.
    ///
    /// This function pops the n-top priority item from the queue and requeues them.
    /// Using the top n items ensures that the mutation source has some diversity, since the same item can only be picked once.
    ///
    /// During the processing the function will also apply all the penalties to the items, which have not yet been applied.
    pub(crate) fn get_and_requeue_n(&mut self, n: usize) -> Vec<T>
    where
        T: Clone,
    {
        let mut res = Vec::with_capacity(n);
        let mut buffer = Vec::with_capacity(n);

        while res.len() < n {
            if let Some(mut item) = self.queue.pop() {
                // Remove the penalty for this item.
                if let Some(stored_penalty) = self.penalties.remove(&item.value) {
                    item.priority.0 *= DECAY_FACTOR.powi(stored_penalty as i32);
                    // We just modified the priority of the item, so we do not know if it is still the top item.
                    // We need to put it back into the queue and pop again.
                    self.queue.push(item);
                } else {
                    // Apply a single decay to the item.
                    item.priority.0 *= DECAY_FACTOR;
                    // No penalty, we can just use the item.
                    res.push(item.value.clone());
                    buffer.push(item);
                }
            } else {
                // Queue is empty, return what we have.
                break;
            }
        }

        // Refill the queue with the items we have popped but not put back yet.
        for item in buffer {
            self.queue.push(item);
        }

        res
    }

    /// Return the original priority of the given item.
    pub(crate) fn original_priority(&self, value: &T) -> Option<f64>
    where
        T: PartialEq,
    {
        self.original_priorities.get(value).map(|OrdF64(p)| *p)
    }

    pub(crate) fn decay(&mut self, ids: &BTreeSet<T>)
    where
        T: Clone,
    {
        ids.iter().for_each(|id| {
            // Apply the decay to the original priorities directly.
            if let Some(OrdF64(p)) = self.original_priorities.get_mut(id) {
                *p *= DECAY_FACTOR;
            }

            *self.penalties.entry(id.clone()).or_insert(0) += 1;
        });
    }

    // // Prune the queue to the given size.
    // // Apply an s-shaped probability function to each element, keeping more elements with higher priority.
    // pub(crate) fn prune(&mut self, size: usize) {
    //     if self.0.len() <= size {
    //         return;
    //     }

    //     let mut new_queue = BinaryHeap::with_capacity(size);
    //     let mut rng = rand::thread_rng();
    //     let mut i = 0;
    //     for (priority, value) in self.0.drain() {
    //         let prob = (i as f64) / (size as f64);
    //         let prob = prob * prob;
    //         if rng.gen_bool(prob) {
    //             new_queue.push((priority, value));
    //         }
    //         i += 1;
    //     }
    //     self.0 = new_queue;
    // }

    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }

    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub(crate) fn iter_priorities(&self) -> impl Iterator<Item = OrdF64> + '_ {
        self.queue
            .iter()
            .map(|PriorityQueueEntry { priority, .. }| *priority)
    }
}
