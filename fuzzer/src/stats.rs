use crate::diff_matcher::{DifferenceKind, DifferenceKindCategory};
use color_eyre::eyre::Result;
use dnsauth::definitions::ResolverName;
use misc_utils::fs;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::Instant;

#[serde_with::serde_as]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(remote = "Self")]
pub(crate) struct FuzzingStats {
    // TODO what to gather here??
    /// Time when fuzzing started
    #[serde(with = "instant_as_duration")]
    pub(crate) start_time: Instant,
    /// Number of test cases which have been explored.
    pub(crate) fuzz_case_count: u64,
    /// Number of difference fingerprints founds
    pub(crate) fingerprints: u64,
    /// Number of fuzz cases in the popluation pool
    #[serde(default)]
    pub(crate) population_size: u64,
    /// Top n priorities in the population pool
    #[serde(default)]
    pub(crate) top_n_priorities: Vec<f64>,
    /// Statistics about the coverage per executor.
    pub(crate) coverage: BTreeMap<ResolverName, CoverageStats>,
    /// Statistics about the container spawning behavior
    pub(crate) executor: BTreeMap<ResolverName, ExecutorStats>,
    /// Statistics about what the oracles found for each resolver.
    #[serde(default)]
    pub(crate) oracles: BTreeMap<ResolverName, OracleStats>,
    /// Statistics about results differences per executor pair.
    #[serde_as(as = "Vec<(_, _)>")]
    pub(crate) differences: BTreeMap<(ResolverName, ResolverName), DifferenceStats>,
    #[serde(skip)]
    pub(crate) timeline: Option<(Vec<PathBuf>, usize)>,
}

impl serde::Serialize for FuzzingStats {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Self::serialize(self, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for FuzzingStats {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut this = Self::deserialize(deserializer)?;

        // Fixup missing oracle values
        if this.oracles.is_empty() {
            for resolver in this.coverage.keys() {
                this.oracles.insert(resolver.clone(), Default::default());
            }
        }

        if this.top_n_priorities.is_empty() {
            this.top_n_priorities = vec![];
        }

        Ok(this)
    }
}

mod instant_as_duration {
    use super::*;
    use std::time::Duration;

    pub(crate) fn serialize<S: serde::Serializer>(
        value: &Instant,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let duration: Duration = value.elapsed();
        serde::Serialize::serialize(&duration, serializer)
    }

    pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Instant, D::Error> {
        let duration: Duration = serde::Deserialize::deserialize(deserializer)?;
        Ok(Instant::now() - duration)
    }
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct CoverageStats {
    /// Total number of edges in the Fuzzee
    pub(crate) edges: u64,
    /// Number of edges which have been covered by the test cases.
    pub(crate) explored_edges: u64,
    /// Number of fuzz cases increasing the coverage.
    pub(crate) progress_fuzz_case_count: u64,
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(crate) struct DifferenceStats {
    /// Total number of compared [`FuzzResult`]s
    pub(crate) total: u64,
    /// Total number of compared [`FuzzResult`]s which were identical
    pub(crate) no_diff: u64,
    /// Total number of compared [`FuzzResult`]s with differences that could be fully explained by the diff-matching
    pub(crate) insignificant: u64,
    /// Total number of compared [`FuzzResult`]s with differences new (unexplained) differences
    pub(crate) significant: u64,
    /// Verification runs which resulted in no difference
    pub(crate) repro_no_diff: u64,
    /// Verification runs which resulted in a difference that could be fully explained by the diff-matching
    pub(crate) repro_insignificant: u64,
    /// Verification runs which resulted in a difference new (unexplained) differences, but the difference is different than the original one
    pub(crate) repro_significant_other: u64,
    /// Verification runs which resulted in a difference new (unexplained) differences, and the difference reproduces the original one
    pub(crate) repro_significant: u64,

    pub(crate) per_diff_kind: BTreeMap<DifferenceKind, u64>,
    pub(crate) per_diff_category: BTreeMap<DifferenceKindCategory, u64>,
}

impl FuzzingStats {
    pub(crate) fn new(executors: &[ResolverName]) -> Self {
        Self {
            start_time: Instant::now(),
            fuzz_case_count: 0,
            fingerprints: 0,
            population_size: 0,
            top_n_priorities: Vec::new(),
            coverage: {
                executors
                    .iter()
                    .map(|exec| (exec.clone(), CoverageStats::default()))
                    .collect()
            },
            executor: {
                executors
                    .iter()
                    .map(|exec| (exec.clone(), ExecutorStats::default()))
                    .collect()
            },
            differences: {
                executors
                    .iter()
                    .enumerate()
                    .flat_map(|(idx, exec_a)| {
                        executors[idx + 1..].iter().map(move |exec_b| {
                            // Sort the executor names to avoid duplicates
                            let execs = if exec_a < exec_b {
                                (exec_a.clone(), exec_b.clone())
                            } else {
                                (exec_b.clone(), exec_a.clone())
                            };
                            (execs, DifferenceStats::default())
                        })
                    })
                    .collect()
            },
            oracles: {
                executors
                    .iter()
                    .map(|exec| (exec.clone(), OracleStats::default()))
                    .collect()
            },
            timeline: None,
        }
    }

    pub(crate) fn from_timeline(files: Vec<PathBuf>, idx: usize) -> Result<Self> {
        let idx = idx.clamp(0, files.len() - 1);
        let mut stats: Self = serde_json::from_slice(&fs::read(&files[idx])?)?;
        stats.timeline = Some((files, idx));
        Ok(stats)
    }
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct ExecutorStats {
    pub(crate) queue_capacity: u64,
    pub(crate) queue_len: u64,

    pub(crate) total_spawned: u64,
    pub(crate) total_errors: u64,
    pub(crate) curr_errors: u64,
    pub(crate) min_timeout: Duration,
    pub(crate) spawn_timeout: Duration,
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct OracleStats {
    pub(crate) crashed_resolver_count: u64,
    pub(crate) excessive_queries_count: u64,
    pub(crate) excessive_answer_records_count: u64,
    pub(crate) duplicate_records_count: u64,
    pub(crate) fake_data_count: u64,
    #[serde(default)]
    pub(crate) responds_to_response_count: u64,
}
