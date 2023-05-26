//! Cache which runs the computation in batches

// This needs to apply to the whole file, because the derived code also triggers this warning
#![allow(clippy::type_complexity)]

use crate::utils::ok;
use crate::FuzzingState;
use color_eyre::eyre::Result;
use dnsauth::definitions::{FuzzCaseId, FuzzResultSet, FuzzSuite, FuzzSuiteId, ResolverName};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, RwLock};

#[derive(Clone)]
pub(crate) struct AsyncBatchCache(Arc<AsyncBatchCacheImpl>);

struct AsyncBatchCacheImpl {
    computed_values: RwLock<BTreeMap<(FuzzCaseId, ResolverName), Arc<FuzzResultSet>>>,
    /// FuzzCaseIds which need re-execution
    ///
    /// The value contains two parts.
    /// The set is all the outstanding FuzzCaseIds which need to be computed.
    /// They can either be on standby or be actively running right now.
    /// The Vec only contains the Ids not yet run.
    ///
    /// The last `usize` is the batch_size
    to_be_computed: Mutex<(BTreeSet<FuzzCaseId>, Vec<FuzzCaseId>, usize)>,
    updates: broadcast::Sender<()>,
}

fn make_update_channel() -> broadcast::Sender<()> {
    broadcast::channel(16).0
}
impl AsyncBatchCacheImpl {
    fn new(batch_size: usize) -> Self {
        let updates = make_update_channel();

        Self {
            computed_values: Default::default(),
            to_be_computed: Mutex::new((
                BTreeSet::default(),
                Vec::with_capacity(batch_size),
                batch_size,
            )),

            updates,
        }
    }
}

impl AsyncBatchCache {
    pub(crate) fn new(batch_size: usize) -> Self {
        Self(Arc::new(AsyncBatchCacheImpl::new(batch_size)))
    }

    // The epoch allows for removing outdated values from the cache.
    pub(crate) async fn get(
        &self,
        fc_id: FuzzCaseId,
        mut resolver: ResolverName,
        state: &Arc<FuzzingState>,
    ) -> Result<Arc<FuzzResultSet>> {
        loop {
            // Access cache to see if we have the result already
            let cache = self.0.computed_values.read().await;
            let key = (fc_id, resolver);
            if let Some(result) = cache.get(&key) {
                // Happy path, we found a value in the cache
                // Directly return the value, thus dropping all locks.
                return Ok(result.clone());
            }
            resolver = key.1;
            log::trace!(
                "{resolver}/{fc_id}: No value found in cache, registering for computation..."
            );

            // No value found in the cache.
            // We need to register the fc_id value for computation.
            // This might have already happened by another thread.
            // In this case, we will already have the id in the BTreeSet.
            // If the value is not in the set, we also need to add it to the vector.
            // The important invariant is that the BTreeSet contains entries for all currently running fc_ids and those waiting for a batch.
            // The vector contains all the fc_ids which are waiting for a full batch.
            // Thus we always need to add to both.
            // If adding to the vector pushes it over the batch size, we need to send the batch to the executor.
            //
            // As long as we hold a lock on either the `computed_values` or the `to_be_computed` we can be sure that new results will not be added to the cache.
            // We use that time window to subscribe to the updates channel.
            // This ensures that we will be notified when new results are added to the cache.
            // The new results might not be for the value we are waiting for, but that is fine, since the code will just loop again.
            // During the next iteration, we will notice the fc_id already being in the set, so we only need to listen for updates again.
            let mut tbc = self.0.to_be_computed.lock().await;
            drop(cache);

            // Register for updates before scheduling the computation
            // This ensures that we will not miss any updates
            let mut rx = self.0.updates.subscribe();
            if tbc.0.insert(fc_id) {
                // The value was not yet in the set of outstanding values
                // Add it to the vector
                tbc.1.push(fc_id);
                if tbc.1.len() >= tbc.2 {
                    // We have enough values to compute
                    // Send the values to the executor
                    let batch_size = tbc.2;
                    let ids = std::mem::replace(&mut tbc.1, Vec::with_capacity(batch_size));
                    // Drop the guard to allow other threads to access the cache
                    drop(tbc);

                    self.spawn_computation_for_ids(state, ids).await;
                } else {
                    // Drop the guard to allow other threads to access the cache
                    drop(tbc);
                }
            } else {
                // Drop the guard to allow other threads to access the cache
                drop(tbc);
            }
            // Wait until the cache got updated
            rx.recv().await?;
            log::trace!("{resolver}/{fc_id}: Received update info");
        }
    }

    /// Given a list of IDs, create a [`FuzzSuite`] and spawn a computation for it.
    async fn spawn_computation_for_ids(&self, state: &Arc<FuzzingState>, ids: Vec<FuzzCaseId>) {
        let fuzz_cases = state.fuzz_cases.lock().await;
        let fuzz_case_batch = ids
            .iter()
            .map(|id| fuzz_cases[id].fuzz_case.clone())
            .collect::<Vec<_>>();
        let fuzz_suite = FuzzSuite {
            id: FuzzSuiteId::new(),
            test_cases: fuzz_case_batch,
        };

        tokio::spawn(
            self.clone()
                .compute_and_update_cache(fuzz_suite, state.clone()),
        );
    }

    /// Given a [`FuzzSuite`] run it against all executors and update the cache.
    async fn compute_and_update_cache(
        self,
        fuzz_suite: FuzzSuite,
        state: Arc<FuzzingState>,
    ) -> Result<()> {
        // Run the exact same batch against all executors
        // See GitLab #26 for more information
        let this = self.clone();
        state
            .foreach_executor(move |executor| {
                let fuzz_suite = fuzz_suite.clone();
                let this = this.clone();

                async move {
                    // Do the computation
                    let result = Arc::new(executor.run_new_test_cases(&fuzz_suite).await?);

                    // Update the values in the cache
                    // ALWAYS hold both locks while doing this. This means that holding the `to_be_computed` lock is enough to prevent insertions.
                    let mut cache = this.0.computed_values.write().await;
                    let _tbc = this.0.to_be_computed.lock().await;
                    for id in fuzz_suite.test_cases.iter().map(|tc| tc.id) {
                        cache.insert((id, executor.fuzzee.clone()), result.clone());
                    }
                    ok(())
                }
            })
            .await?;

        // Send the update
        // Sending can only fail if there are no active receivers.
        // That can happen if a previous update woke them all up, but they haven't requeued.
        let _ = self.0.updates.send(());
        log::trace!("Sent update for batch computation");
        ok(())
    }

    /// Take
    pub(crate) async fn finish_computation(&self, state: &Arc<FuzzingState>) {
        log::debug!("Finishing computation of queued values...");
        let _cache = self.0.computed_values.read().await;
        let mut tbc = self.0.to_be_computed.lock().await;
        // Set batch size to 1 to ensure that any further queued computations are sent to the executor immediately
        tbc.2 = 1;
        // Get all queued IDs
        let ids = std::mem::replace(&mut tbc.1, Vec::with_capacity(1));
        if ids.is_empty() {
            // No computations are queued, fast exit
            return;
        }
        drop(tbc);
        // Spawn a computation for the queued IDs
        self.spawn_computation_for_ids(state, ids).await;
    }
}
