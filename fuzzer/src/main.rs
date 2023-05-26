#![warn(
    clippy::future_not_send,
    clippy::semicolon_if_nothing_returned,
    missing_copy_implementations,
    missing_debug_implementations,
    noop_method_call,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unused_extern_crates,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications,
    variant_size_differences
)]

mod async_batch_cache;
mod atom;
mod diff_matcher;
mod executor;
mod key_values;
mod mutations;
mod prio_queue;
mod serialize;
mod stats;
mod ui;
mod utils;
mod zip_sorted;

use self::stats::OracleStats;
use crate::async_batch_cache::AsyncBatchCache;
use crate::diff_matcher::DiffFingerprint;
use crate::executor::Executor;
use crate::prio_queue::PriorityQueue;
use crate::stats::FuzzingStats;
use crate::utils::{ok, stream_assert_send, task_spawn_named, JoinSetExt};
use color_eyre::eyre::{bail, Context as _, Result};
use dnsauth::definitions::{
    FuzzCase, FuzzCaseId, FuzzResultSet, FuzzSuite, FuzzSuiteId, OracleResults, ResolverName,
};
use futures::stream::{self, StreamExt as _};
use misc_utils::fs;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::iter;
use std::os::unix::prelude::OsStrExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

static SHOULD_TERMINATE: AtomicBool = AtomicBool::new(false);

#[derive(clap::Parser)]
struct CliArgs {
    /// Ignore any existing fuzzing state and start from scratch.
    #[arg(long = "reset-state")]
    reset_state: bool,
    /// Dump any found differences into this directory.
    #[arg(long = "dump-diffs")]
    dump_diffs: Option<PathBuf>,

    #[arg(long = "resolvers", num_args = 1..)]
    resolvers: Vec<ResolverName>,

    /// Execute further special case operations
    #[clap(subcommand)]
    subcommand: Option<Subcommand>,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    Single(SubcommandSingle),
    Spawn(SubcommandSpawn),
    ShowStats(SubcommandShowStats),
}

/// Execute a single FuzzSuite
#[derive(clap::Parser)]
struct SubcommandSingle {
    /// Keep the directory with all output files
    #[clap(long = "keep")]
    keep_output: bool,
    /// Path to the FuzzSuite file
    suite: PathBuf,
    /// List of fuzzees to run
    #[arg(required = true, num_args = 1..)]
    fuzzees: Vec<ResolverName>,
}

/// Show statistics about the fuzzing
#[derive(clap::Parser)]
struct SubcommandShowStats {
    /// Path to the statistics file
    stats: PathBuf,
}

/// Spawn a container running the resolver and all static AuthNS
#[derive(clap::Parser)]
struct SubcommandSpawn {
    /// Keep the directory with all output files
    #[clap(long = "keep")]
    keep_output: bool,
    /// Path to the FuzzSuite file
    suite: PathBuf,
    /// Fuzzee container to spawn
    fuzzee: ResolverName,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    #[cfg(tokio_unstable)]
    console_subscriber::init();

    // Truncate the log file before using it
    let _ = tokio::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open("fuzzer.log")
        .await;

    tokio::spawn(async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut interrupts = signal(SignalKind::interrupt())?;
        let mut terminates = signal(SignalKind::terminate())?;
        loop {
            tokio::select! {
                _ = interrupts.recv() => {
                    log::info!("Will terminate soon...");
                    let prev_state = SHOULD_TERMINATE.swap(true, Ordering::SeqCst);
                    if prev_state {
                        log::warn!("Double Ctrl-C detected, exiting immediately");
                        tui_logger::move_events();
                        eprintln!("Double Ctrl-C detected, exiting immediately");
                        std::process::exit(60);
                    }
                }
                _ = terminates.recv() => {
                    log::info!("Will terminate soon...");
                    let prev_state = SHOULD_TERMINATE.swap(true, Ordering::SeqCst);
                    if prev_state {
                        log::warn!("Double Ctrl-C detected, exiting immediately");
                        tui_logger::move_events();
                        eprintln!("Double Ctrl-C detected, exiting immediately");
                        std::process::exit(60);
                    }
                }
            }
            tui_logger::move_events();
        }
        // To allow the ? operator
        #[allow(unreachable_code)]
        ok(())
    });

    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            tui_logger::move_events();
        }
    }
    let _guard = Guard;

    let cli_args: CliArgs = clap::Parser::parse();

    // TODO add some cleanup code of tempdir files and podman containers
    // tempdir files can already accumulate if fuzzer is killed (double Ctrl-C)
    // podman containers not yet, but might also accumulate
    // TODO use a label when spawning podman containers to distinguish them from other containers

    // Ensure the tmp dir exists
    let _ = tokio::fs::remove_dir_all("/tmp/fuzzing-dns/").await;
    tokio::fs::create_dir_all("/tmp/fuzzing-dns/").await?;

    match cli_args.subcommand {
        None => run_fuzzing(cli_args).await,
        Some(Subcommand::Single(single)) => run_single(single).await,
        Some(Subcommand::Spawn(spawn)) => run_spawn(spawn).await,
        Some(Subcommand::ShowStats(stats)) => run_show_stats(stats).await,
    }
}

async fn run_single(cli_args: SubcommandSingle) -> Result<()> {
    env_logger::init();

    let output_dir = tempfile::Builder::new()
        .prefix("fuzzer-single-")
        .tempdir()?;
    let mut fuzz_suite: FuzzSuite = postcard::from_bytes(&fs::read(cli_args.suite)?)?;
    for fuzz_case in &mut fuzz_suite.test_cases {
        fuzz_case.update_check_cache();
    }
    let fuzz_suite = Arc::new(fuzz_suite);

    let executors: Vec<Arc<Executor>> = cli_args
        .fuzzees
        .iter()
        .map(|fuzzee| {
            // Use a queue of 0 to prevent any pre-spawning possible
            Arc::new(Executor::new(fuzzee.clone(), 0, true))
        })
        .collect();
    let fuzz_results: Vec<FuzzResultSet> = foreach_executor(executors.into_iter(), |exec| {
        let fuzz_suite = fuzz_suite.clone();
        async move { exec.run_new_test_cases(&fuzz_suite).await }
    })
    .await?;

    let mut fuzz_case_metas = BTreeMap::new();
    for fuzz_case in fuzz_suite.test_cases.iter() {
        let fuzz_case_meta = FuzzCaseMeta {
            fuzz_case: fuzz_case.clone(),
            label_set: Vec::new(),
            derived_from: None,
        };
        fuzz_case_metas.insert(fuzz_case.id, fuzz_case_meta);
    }

    let diffs = diff_matcher::process_differences(&fuzz_results, &fuzz_case_metas).await?;
    // Mark the process as terminating.
    // This should prevent some errors which otherwise might occur.
    SHOULD_TERMINATE.store(true, Ordering::SeqCst);

    for (fuzz_case_id, fuzz_case_diff) in diffs {
        for ((r1, r2), (diff, left_oracle, right_oracle)) in fuzz_case_diff {
            match diff {
                diff_matcher::DifferenceResult::NoDifference => {
                    println!("No difference for {fuzz_case_id} between {r1} and {r2}");
                }
                diff_matcher::DifferenceResult::KnownDifference(known_diff) => {
                    println!("Known difference for {fuzz_case_id} between {r1} and {r2}");
                    for kind in known_diff {
                        println!(" - {}", kind.as_ref());
                    }
                }
                diff_matcher::DifferenceResult::NewDifference((fingerprint, known_diffs)) => {
                    let first_result = fuzz_results.iter().find(|frs| frs.fuzzee == r1).unwrap();
                    let second_result = fuzz_results.iter().find(|frs| frs.fuzzee == r2).unwrap();
                    let first_meta = first_result.meta.clone();
                    let second_meta = second_result.meta.clone();
                    let first_result = first_result
                        .results
                        .iter()
                        .find(|r| r.id == fuzz_case_id)
                        .unwrap();
                    let second_result = second_result
                        .results
                        .iter()
                        .find(|r| r.id == fuzz_case_id)
                        .unwrap();

                    // Write the difference results, if desired
                    diff_matcher::dump_difference_information(
                        output_dir.path().to_owned(),
                        fuzz_case_metas[&fuzz_case_id].fuzz_case.clone(),
                        fuzz_suite.clone(),
                        r1.clone(),
                        r2.clone(),
                        first_result.clone(),
                        second_result.clone(),
                        first_meta,
                        second_meta,
                        *fingerprint.clone(),
                        known_diffs,
                    )
                    .await?;

                    println!("New difference for {fuzz_case_id} between {r1} and {r2}");
                    for kind in fingerprint.key_diffs {
                        println!(" - {}", kind.as_ref());
                    }
                    let fulldiff = output_dir
                        .path()
                        .join(fuzz_case_id.to_string())
                        .join(format!("{r1}-{r2}"))
                        .join("fulldiff.txt");
                    let fulldiff = tokio::fs::read_to_string(fulldiff).await?;
                    println!("\n\nFulldiff:\n{fulldiff}");
                }
            }
            if left_oracle.has_any_set() || right_oracle.has_any_set() {
                println!("Oracles for {fuzz_case_id} between {r1} and {r2}");
                println!("Left {left_oracle:#?}\nRight {right_oracle:#?}");
            }
        }
    }

    if cli_args.keep_output {
        // Prevent execution of cleanup code
        let output_dir = output_dir.into_path();
        println!("Output directory: {}", output_dir.display());
    }
    Ok(())
}

async fn run_spawn(cli_args: SubcommandSpawn) -> Result<()> {
    env_logger::init();

    let output_dir = tempfile::Builder::new().prefix("fuzzer-spawn-").tempdir()?;

    let container = cli_args.fuzzee.to_string();
    let tag = "latest";
    let tempdir_folder = output_dir.path().to_owned();
    let ignore_background_activity = true;
    {
        let workdir = tokio::task::spawn_blocking({
            let container = container.clone();
            move || {
                tempfile::Builder::new()
                    .prefix(&container)
                    .tempdir_in(tempdir_folder)
                    .context("Failed to create tempdir")
            }
        })
        .await??;
        log::debug!(
            "[{container}:{tag}] Created tempdir: {}",
            workdir.path().display()
        );
        let mnt_volume = format!("{}:/config:Z", workdir.path().display());

        // Write all the support files into the workdir
        tokio::fs::write(
            workdir.path().join("config.toml"),
            include_bytes!("../../dnsauth/config.toml"),
        )
        .await
        .context("Failed to write config.toml")?;

        let mut cmd = Command::new("podman");
        cmd.arg("run")
            // Cleanup after execution
            .arg("--rm")
            .arg("--interactive")
            .arg("--label")
            .arg("dns-fuzzer=fuzzee")
            .arg("--replace")
            // enables tcpdump
            .arg("--cap-add=NET_RAW")
            // Missing in newer podman settings, but used by multiple resolvers
            .arg("--cap-add=SYS_CHROOT")
            // Prevent the container from lingering into all eternity
            .arg("--timeout=1800")
            .arg("--volume")
            .arg(mnt_volume)
            .arg("--name")
            .arg(format!("{container}-{tag}",))
            .arg(&format!("{container}:{tag}"))
            // Arguments for the dnsauth process inside the container
            .arg("--config=/config/config.toml")
            .arg("--fuzz-suite=/config/fuzz-suite.postcard")
            .arg("--no-run");
        if ignore_background_activity {
            cmd.arg("--ignore-background-activity");
        }
        cmd.kill_on_drop(true)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        tokio::fs::copy(&cli_args.suite, workdir.path().join("fuzz-suite.postcard")).await?;
        let mut proc = cmd.spawn()?;
        while !SHOULD_TERMINATE.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // Container exited, so we can exit as well
            if proc.try_wait()?.is_some() {
                SHOULD_TERMINATE.store(true, Ordering::SeqCst);
                break;
            }
        }
        let _ = proc.kill().await;
        dbg!(proc.wait().await?);

        if cli_args.keep_output {
            // Prevent execution of cleanup code
            let _ = workdir.into_path();
        }
    }

    if cli_args.keep_output {
        // Prevent execution of cleanup code
        let output_dir = output_dir.into_path();
        println!("Output directory: {}", output_dir.display());
    }

    // Mark the process as terminating.
    // This should prevent some errors which otherwise might occur.
    SHOULD_TERMINATE.store(true, Ordering::SeqCst);
    Ok(())
}

async fn run_show_stats(cli_args: SubcommandShowStats) -> Result<()> {
    tui_logger::init_logger(log::LevelFilter::Trace)?;
    tui_logger::set_default_level(log::LevelFilter::Info);

    let path = std::path::Path::new(&cli_args.stats);
    let meta = tokio::fs::metadata(path).await?;

    let mut files = if meta.is_file() {
        // Assume the path is to a single stats file
        vec![path.to_owned()]
    } else if meta.is_dir() && path.file_name() == Some("stats".as_ref()) {
        // We are directly in the stats directory
        find_all_stats_files(path)?
    } else if meta.is_dir() {
        // Assume we are in the output directory
        find_all_stats_files(path.join("stats").as_path())?
    } else {
        bail!("Invalid stats path");
    };

    fn find_all_stats_files(path: &std::path::Path) -> Result<Vec<PathBuf>, color_eyre::Report> {
        tokio::task::block_in_place(|| {
            let rd = std::fs::read_dir(path.join("."))?;
            ok(rd
                .into_iter()
                .filter_map(|entry| {
                    let entry = entry.ok()?;
                    let path = entry.path();
                    if path.is_file()
                        && path
                            .file_name()
                            .unwrap_or("".as_ref())
                            .as_bytes()
                            .starts_with(b"stats-")
                    {
                        Some(path)
                    } else {
                        None
                    }
                })
                .collect())
        })
    }

    files.sort();
    let statistics: FuzzingStats = tokio::task::block_in_place(|| {
        if files.is_empty() {
            bail!("No stats files found");
        }
        let idx = files.len() - 1;
        FuzzingStats::from_timeline(files, idx)
    })?;

    log::info!("Start UI thread");
    ui::App::run(Arc::new(Mutex::new(statistics))).await?;
    ok(())
}

async fn run_fuzzing(cli_args: CliArgs) -> Result<()> {
    tui_logger::init_logger(log::LevelFilter::Trace)?;
    tui_logger::set_default_level(log::LevelFilter::Info);
    // tui_logger::set_level_for_target(std::env!("CARGO_PKG_NAME"), log::LevelFilter::Trace);
    tui_logger::set_log_file("fuzzer.log")?;
    // Ensure that logs messages are always processed, also if the UI is not running
    std::thread::spawn(|| loop {
        tui_logger::move_events();
        std::thread::sleep(std::time::Duration::from_millis(1000));
    });

    let mut fuzzing_state: Option<FuzzingState> = None;

    if !cli_args.reset_state {
        // Try restoring the previous state
        fuzzing_state = FuzzingState::load_from_disk()
            .await
            .map_err(|err| {
                log::info!("Failed to deserialize existing fuzzing state: {}", err);
            })
            .ok();
    }
    let fuzzing_state = match fuzzing_state {
        Some(mut state) => {
            log::info!("Continue fuzzing from previous state");
            state.dump_diffs = cli_args.dump_diffs;
            state
        }
        None => {
            log::info!("Start fuzzing from scratch");

            // Resolvername, queue_length, ignore_background_activity
            let executors_full_config = Vec::from([
                ("bind9", 3, false),
                ("bind9_11", 3, false),
                ("unbound", 3, false),
                ("maradns", 3, false),
                ("pdns-recursor", 3, false),
                ("knot-resolver", 3, false),
                ("trust-dns", 3, false),
                ("resolved", 3, false),
            ]);
            // Use all available resolvers/executors if nothing else is specified.
            // But only use those provided on the command line if they are specified.
            let executors_simple = if cli_args.resolvers.is_empty() {
                executors_full_config
            } else {
                executors_full_config
                    .into_iter()
                    .filter(|cfg| {
                        cli_args
                            .resolvers
                            .contains(&ResolverName::new(cfg.0.to_string()))
                    })
                    .collect()
            };
            if executors_simple.len() < 2 {
                bail!("At least two executors are required");
            }
            let executor_names: Vec<ResolverName> = executors_simple
                .iter()
                .map(|(e, _, _)| ResolverName::new(e.to_string()))
                .collect();
            let executors: BTreeMap<_, _> = executors_simple
                .into_iter()
                .map(|(e, q, i)| -> (ResolverName, Arc<Executor>) {
                    (
                        ResolverName::new(e.to_string()),
                        Arc::new(Executor::new(ResolverName::new(e.to_string()), q, i)),
                    )
                })
                .collect();

            FuzzingState {
                rng: Mutex::new(ChaCha20Rng::from_entropy()),
                dump_diffs: cli_args.dump_diffs,

                fuzz_suite_size: 30,
                fuzz_suite_min_random: 4,
                reproduction_batch_size: 5,

                mutateable_test_cases: Mutex::new(PriorityQueue::new()),
                executors,

                fuzz_cases: Mutex::new(BTreeMap::new()),

                statistics: Arc::new(Mutex::new(FuzzingStats::new(&executor_names))),
                fingerprints: Mutex::new(BTreeMap::new()),
            }
        }
    };
    log::info!("Start UI thread");
    tokio::task::spawn(ui::App::run(fuzzing_state.statistics.clone()));

    let fuzzing_state = Arc::new(fuzzing_state);
    fuzzing_state
        .foreach_executor(|exec| async move {
            log::info!("Load background activity profile for {}", exec.fuzzee);
            exec.load_background_activity().await?;
            Ok(())
        })
        .await?;

    // Run fuzzing until `SHOULD_TERMINATE` is set to true
    let mut tasks = JoinSet::new();
    for epoch in 0.. {
        while tasks.len() >= 4 {
            tasks.join_next().await;
        }
        if SHOULD_TERMINATE.load(Ordering::SeqCst) {
            break;
        }
        log::warn!("Start fuzzing epoch {}", epoch);
        tasks.spawn_named(&format!("Fuzzing Loop Iterations {epoch}"), {
            let fuzzing_state = fuzzing_state.clone();
            async move {
                if let Err(err) = fuzz_single_round(fuzzing_state.clone(), epoch).await {
                    log::error!("Fuzzing loop {} failed: {}", epoch, err);
                }
            }
        });
    }
    // Drain the JoinSet
    while (tasks.join_next().await).is_some() {}

    // Save the state
    fuzzing_state.serialize_to_disk(true).await?;

    Ok(())
}

async fn fuzz_single_round(fuzzing_state: Arc<FuzzingState>, epoch: usize) -> Result<()> {
    // Generate a new fuzz suite
    let (fuzz_suite, meta_cases) = mutate(&fuzzing_state).await;
    let fuzz_suite = Arc::new(fuzz_suite);
    let suite_id = fuzz_suite.id;
    // Update stats
    {
        fuzzing_state.statistics.lock().await.fuzz_case_count += fuzz_suite.test_cases.len() as u64;
    }

    // Make all the FuzzCases available, such that other parts can re-run then (verification) or use the meta information for the parents
    {
        let mut fuzz_case = fuzzing_state.fuzz_cases.lock().await;
        for (&id, mc) in &meta_cases {
            fuzz_case.insert(id, mc.clone());
        }
    }

    let test_results: Vec<FuzzResultSet> = fuzzing_state
        .foreach_executor(|exec| {
            let fuzz_suite = fuzz_suite.clone();
            async move { exec.run_new_test_cases(&fuzz_suite).await }
        })
        .await?;

    let meta_cases = Arc::new(meta_cases);
    process_test_results(fuzzing_state.clone(), fuzz_suite, meta_cases, test_results)
        .await
        .with_context(|| format!("Failed to process FuzzResults {suite_id}"))?;

    // Gather values from the population pool
    let test_cases: u64;
    let highest_priorities: Vec<f64>;
    {
        // Get some stats about the global pool of test cases
        let mutateable_test_cases = fuzzing_state.mutateable_test_cases.lock().await;
        test_cases = mutateable_test_cases.len() as _;
        let mut prios: Vec<_> = mutateable_test_cases.iter_priorities().collect();
        prios.sort_by_key(|&k| Reverse(k));
        highest_priorities = prios.into_iter().map(|p| p.into_inner()).collect();
    }
    // Update the executor stats
    {
        let exec_stats = fuzzing_state
            .foreach_executor(
                |exec| async move { Ok((exec.fuzzee.clone(), exec.get_stats().await)) },
            )
            .await?;
        let mut stats = fuzzing_state.statistics.lock().await;
        for (fuzzee, executor_stat) in exec_stats {
            *stats
                .executor
                .get_mut(&fuzzee)
                .expect("The executor entry always exists") = executor_stat;
        }

        stats.population_size = test_cases;
        stats.top_n_priorities = highest_priorities;
    }

    // Save the state
    fuzzing_state.serialize_stats_to_disk().await?;
    if epoch % 10 == 0 {
        fuzzing_state.serialize_to_disk(false).await?;
    }

    // Cleanup some old podman containers
    if epoch % 3 == 0 {
        // The executor spawns the containers with 800 seconds lifetime, so 900 seconds should be enought to
        let _child = Command::new("podman")
            .args([
                "container",
                "prune",
                "--force",
                "--filter",
                "until=900s",
                // Only prune the fuzzee containers
                "--filter",
                "label=dns-fuzzer=fuzzee",
            ])
            .spawn()
            .context("Failed to run podman container prune")?;
    }

    Ok(())
}

#[serde_with::serde_as]
#[derive(serde::Serialize, serde::Deserialize)]
struct FuzzingState {
    /// The RNG used to generate test cases.
    ///
    /// This ensures deterministic progression.
    #[serde_as(as = "serialize::SerializableMutex<_>")]
    rng: Mutex<ChaCha20Rng>,
    /// Folder to store
    dump_diffs: Option<PathBuf>,

    // Some constants used later on
    /// Number of [`FuzzCase`]s to generate for each [`FuzzSuite`].
    fuzz_suite_size: usize,
    /// Include at least this many new randomly generated [`FuzzCase`]s
    /// This keeps some amount of randomness in the fuzzing process.
    fuzz_suite_min_random: usize,
    /// Batch size for the verification cache.
    reproduction_batch_size: usize,

    /// Test cases which should be explored further by adding mutations.
    #[serde_as(as = "serialize::SerializableMutex<_>")]
    mutateable_test_cases: Mutex<PriorityQueue<FuzzCaseId>>,
    /// [`Executor`]s and their storage.
    ///
    /// An executor is runs the [`FuzzSuite`]s and stores the results.
    #[serde_as(as = "BTreeMap<_, Arc<_>>")]
    executors: BTreeMap<ResolverName, Arc<Executor>>,

    /// All test cases which have been explored.
    #[serde_as(as = "serialize::SerializableMutex<_>")]
    fuzz_cases: Mutex<BTreeMap<FuzzCaseId, FuzzCaseMeta>>,

    /// Statistics about the progress and the fuzzing results.
    #[serde_as(as = "Arc<serialize::SerializableMutex<_>>")]
    statistics: Arc<Mutex<FuzzingStats>>,

    #[serde_as(as = "serialize::SerializableMutex<Vec<(_, _)>>")]
    fingerprints: Mutex<BTreeMap<DiffFingerprint, BTreeSet<FuzzCaseId>>>,
}

impl FuzzingState {
    async fn load_from_disk() -> Result<FuzzingState> {
        let bytes = tokio::fs::read("fuzzing_state.postcard").await?;
        Ok(postcard::from_bytes(&bytes)?)
    }

    async fn serialize_stats_to_disk(&self) -> Result<()> {
        if let Some(dump_dir) = &self.dump_diffs {
            let stats_dir = dump_dir.join("stats");
            let stats_fname = chrono::Utc::now()
                .format("stats-%Y-%m-%dT%H-%M-%S.json")
                .to_string();
            let stats_path = stats_dir.join(stats_fname);
            let stats = self.statistics.lock().await;
            let stats_bytes = tokio::task::block_in_place(|| {
                serde_json::to_vec(&*stats).context("Failed to serialize stats")
            })?;

            tokio::task::spawn_blocking(move || {
                //Ensure stats dir exists. Allow is fine, since we are in blocking context.
                #[allow(clippy::disallowed_methods)]
                std::fs::create_dir_all(stats_path.parent().unwrap())
                    .context("Failed to create stats dir")?;
                let mut file = NamedTempFile::new_in(stats_path.parent().unwrap())?;
                std::io::Write::write_all(&mut file, &stats_bytes)
                    .context("Failed to write temporary stats file")?;
                file.persist(stats_path)
                    .context("Failed to persist stats file")?;
                ok(())
            });
        };

        Ok(())
    }

    async fn serialize_to_disk(&self, wait_for_finish: bool) -> Result<()> {
        let state_bytes = tokio::task::block_in_place(|| {
            postcard::to_allocvec(&self).context("Failed to serialize FuzzingState")
        })?;

        let write_file = tokio::task::spawn_blocking(move || {
            // Write the data to a temporary file first and then atomically rename it to the final file.
            let mut file = NamedTempFile::new_in("./")?;
            std::io::Write::write_all(&mut file, &state_bytes)
                .context("Failed to write temporary fuzzing_state.postcard")?;
            file.persist("fuzzing_state.postcard")
                .context("Failed to persist fuzzing_state.postcard")?;
            ok(())
        });
        if wait_for_finish {
            write_file.await?
        } else {
            task_spawn_named("Serialize FuzzingState to disk", async {
                write_file.await.map_err(|err| {
                    log::error!("Failed to write fuzzing_state.postcard: {:#}", err);
                })
            });

            Ok(())
        }
    }

    /// Run function for each executor in parallel providing mutable access to the [`Executor`].
    async fn foreach_executor<F, FUT, T>(&self, f: F) -> Result<Vec<T>>
    where
        F: Fn(Arc<Executor>) -> FUT + Send,
        FUT: Future<Output = Result<T>> + Send + Sync + 'static,
        T: Send + 'static,
    {
        foreach_executor(self.executors.values().cloned(), f).await
    }
}

/// Run function for each executor in parallel providing mutable access to the [`Executor`].
async fn foreach_executor<E, F, FUT, T>(executors: E, f: F) -> Result<Vec<T>>
where
    F: Fn(Arc<Executor>) -> FUT + Send,
    FUT: Future<Output = Result<T>> + Send + Sync + 'static,
    T: Send + 'static,
    E: Iterator<Item = Arc<Executor>> + ExactSizeIterator + Send,
{
    let mut set = JoinSet::new();
    let mut results = Vec::with_capacity(executors.len());
    for exec in executors {
        set.spawn_named(
            &format!("Foreach Executor: {}", exec.fuzzee),
            f(exec.clone()),
        );
    }
    while let Some(res) = set.join_next().await {
        results.push(res??);
    }
    Ok(results)
}

/// Information about a [`FuzzCase`] with additional metadata
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct FuzzCaseMeta {
    fuzz_case: FuzzCase,
    /// A limited set of labels to be used in domain name generations
    ///
    /// This ensures that randomly generating a domain name (e.g., by using a subdomain) has a high chance
    /// of producing the same name as a previous attempt. Thus we get the same name in the query and response sections.
    label_set: Vec<String>,

    /// If the [`FuzzCase`] is a mutation of another [`FuzzCase`], this is the ID of the original.
    derived_from: Option<FuzzCaseId>,
}

/// Run mutations on the current list of [`FuzzCase`]s to generate new ones
async fn mutate(state: &FuzzingState) -> (FuzzSuite, BTreeMap<FuzzCaseId, FuzzCaseMeta>) {
    // Get access rights to all the shared state
    let fuzz_cases = state.fuzz_cases.lock().await;
    let mut mutateable_test_cases = state.mutateable_test_cases.lock().await;
    let mut rng = state.rng.lock().await;

    let suitid = FuzzSuiteId::new();
    let mut test_cases = Vec::new();
    let mut meta_cases = BTreeMap::new();
    for id in
        mutateable_test_cases.get_and_requeue_n(state.fuzz_suite_size - state.fuzz_suite_min_random)
    {
        let fc_meta = crate::mutations::mutate_fuzz_case(fuzz_cases[&id].clone(), &mut *rng);
        meta_cases.insert(fc_meta.fuzz_case.id, fc_meta.clone());
        test_cases.push(fc_meta.fuzz_case.clone());
    }
    drop(fuzz_cases);

    while test_cases.len() < state.fuzz_suite_size {
        let fc_meta = crate::mutations::new_fuzz_case(&mut *rng);
        meta_cases.insert(fc_meta.fuzz_case.id, fc_meta.clone());
        test_cases.push(fc_meta.fuzz_case.clone());
    }

    log::info!(
        "Created new FuzzSuite ({suitid}) with {} entries",
        test_cases.len()
    );
    (
        FuzzSuite {
            id: suitid,
            test_cases,
        },
        meta_cases,
    )
}

/// Process the list of new [`FuzzResultSet`]s determining new and improved states
async fn process_test_results(
    state: Arc<FuzzingState>,
    fuzz_suite: Arc<FuzzSuite>,
    meta_cases: Arc<BTreeMap<FuzzCaseId, FuzzCaseMeta>>,
    fuzz_results: Vec<FuzzResultSet>,
) -> Result<()> {
    let ids_with_new_coverage = process_result_coverage(&state, &fuzz_results).await?;

    // Per resolver check how often we find each oracle
    let oracle_counts: BTreeMap<ResolverName, OracleStats> = fuzz_results
        .iter()
        .map(|fuzz_result_set| {
            let mut os = OracleStats::default();
            for fr in &fuzz_result_set.results {
                let OracleResults {
                    crashed_resolver,
                    excessive_queries,
                    excessive_answer_records,
                    duplicate_records,
                    fake_data,
                    responds_to_response,
                } = fr.oracles;
                os.crashed_resolver_count += crashed_resolver as u64;
                os.excessive_queries_count += excessive_queries as u64;
                os.excessive_answer_records_count += excessive_answer_records as u64;
                os.duplicate_records_count += duplicate_records as u64;
                os.fake_data_count += fake_data as u64;
                os.responds_to_response_count += responds_to_response as u64;
            }
            (fuzz_result_set.fuzzee.clone(), os)
        })
        .collect();

    let diff_results = diff_matcher::process_differences(&fuzz_results, &meta_cases).await?;

    let mut case_score = BTreeMap::new();
    for id in ids_with_new_coverage {
        case_score.insert(id, 10.0);
    }
    let verification_cache = AsyncBatchCache::new(state.reproduction_batch_size);
    let mut verification_tasks = JoinSet::new();
    // Act on the difference results
    {
        let statistics = &mut state.statistics.lock().await;

        // Store the oracle stats
        for (resolver, os) in oracle_counts {
            let OracleStats {
                crashed_resolver_count,
                excessive_queries_count,
                excessive_answer_records_count,
                duplicate_records_count,
                fake_data_count,
                responds_to_response_count,
            } = os;
            let oracle_stats = statistics.oracles.entry(resolver).or_default();
            oracle_stats.crashed_resolver_count += crashed_resolver_count;
            oracle_stats.excessive_queries_count += excessive_queries_count;
            oracle_stats.excessive_answer_records_count += excessive_answer_records_count;
            oracle_stats.duplicate_records_count += duplicate_records_count;
            oracle_stats.fake_data_count += fake_data_count;
            oracle_stats.responds_to_response_count += responds_to_response_count;
        }

        for (id, pair_score) in diff_results {
            for (pair, (result, _left_oracle, _right_oracle)) in pair_score {
                // TODO maybe do something with the oracle results here
                assert!(
                    pair.0 <= pair.1,
                    "Resolver pair is not sorted: {} vs {}",
                    pair.0,
                    pair.1
                );
                let diff_stat = statistics
                    .differences
                    .get_mut(&pair)
                    .expect("Could not find diff stats for resolver pair");
                diff_stat.total += 1;
                let score = match result {
                    diff_matcher::DifferenceResult::NoDifference => {
                        diff_stat.no_diff += 1;
                        1.0
                    }
                    diff_matcher::DifferenceResult::KnownDifference(diff_kinds) => {
                        diff_stat.insignificant += 1;
                        // Update DiffKind statistics
                        for dk in &diff_kinds {
                            *diff_stat.per_diff_kind.entry(*dk).or_default() += 1;
                        }
                        // Update DiffKindCategory statistics
                        // First aggregate the values for each category
                        let diff_kind_categories: BTreeSet<_> =
                            diff_kinds.iter().map(|x| x.categorize()).collect();
                        for dk_cat in diff_kind_categories {
                            *diff_stat.per_diff_category.entry(dk_cat).or_default() += 1;
                        }
                        diff_kinds
                            .iter()
                            .map(|dk| dk.interest_level() as f64)
                            .product()
                    }
                    diff_matcher::DifferenceResult::NewDifference((fingerprint, _)) => {
                        diff_stat.significant += 1;
                        // Verify the original fingerprint, by re-running the same FuzzCase in a different configuration.
                        // This is to ensure that the fingerprint is not a false positive.
                        //
                        // Spawn this into a separate task, so that we can continue processing the results.
                        // And do not have to keep the mutexes locked.
                        verification_tasks.spawn_named(
                            &format!("Verify FP for ID {id} and {}-{}", pair.0, pair.1),
                            verify_fingerprint(
                                state.clone(),
                                id,
                                pair,
                                fingerprint,
                                meta_cases.clone(),
                                // only for dumping
                                fuzz_suite.clone(),
                                verification_cache.clone(),
                            ),
                        );

                        1.0
                    }
                };
                *case_score.entry(id).or_insert(1.0) *= score;
            }
        }
    }

    // All verification tasks are spawned, now wait for them to complete.
    // Some tasks might be stuck waiting for a batch to fill up.
    // Send an update signal indicating that everything is full and to run any incomplete batches.
    //
    // The spawning above is slow enough that calling `finish_computation` here will run first.
    // This is a problem, because then we will not get any batching benefits.
    // To avoid this, we wait a bit before calling `finish_computation`.
    //
    // A too short sleep means `finish_computation` sets the batch size to 1, and we run more batches than necessary.
    // A too long sleep means loose speed while fuzzing.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    verification_cache.finish_computation(&state).await;

    // Run the verification tasks until completion
    while let Some((id, score)) = verification_tasks
        .join_next()
        .await
        .transpose()?
        .transpose()?
    {
        *case_score.entry(id).or_insert(1.0) *= score;
    }

    // Normalize all the scores. They can grow extremely large, since they also depend on the number of resolver pairs.
    let max_score = case_score.values().cloned().fold(0.0, f64::max);
    for score in case_score.values_mut() {
        *score = *score * 100. / max_score;
    }

    // Make all FuzzCases available for mutation with the calculated scores.
    {
        let mut mutateable_test_cases = state.mutateable_test_cases.lock().await;
        case_score.into_iter().for_each(|(id, mut score)| {
            // The parent score will be 1/3 of the final score.
            // Take the parent score if available
            let parent_score = meta_cases
                .get(&id)
                .and_then(|meta| meta.derived_from.as_ref())
                .and_then(|parent_case_id| mutateable_test_cases.original_priority(parent_case_id));

            if let Some(parent_score) = parent_score {
                score = (score * 2.0 + parent_score) / 3.0;
            }

            mutateable_test_cases.push(score, id);
        });
    }

    Ok(())
}

/// Return the ID and the score associated with it
async fn verify_fingerprint(
    state: Arc<FuzzingState>,
    id: FuzzCaseId,
    resolvers: (ResolverName, ResolverName),
    fingerprint: Box<DiffFingerprint>,
    meta_cases: Arc<BTreeMap<FuzzCaseId, FuzzCaseMeta>>,
    // Only for dumping diff data
    fuzz_suite: Arc<FuzzSuite>,
    epoch_cache: AsyncBatchCache,
) -> Result<(FuzzCaseId, f64)> {
    assert!(
        resolvers.0 <= resolvers.1,
        "Resolver pair is not sorted: {} vs {}",
        resolvers.0,
        resolvers.1
    );

    let result_sets = tokio::try_join!(
        epoch_cache.get(id, resolvers.0.clone(), &state),
        epoch_cache.get(id, resolvers.1.clone(), &state),
    )
    .context("Failed to get rerun results")?;
    let first_result = result_sets.0.results.iter().find(|r| r.id == id).unwrap();
    let second_result = result_sets.1.results.iter().find(|r| r.id == id).unwrap();
    let fuzz_case = &meta_cases[&id].fuzz_case;

    let diff_result = diff_matcher::diff_two_resolvers(
        fuzz_case,
        &resolvers.0,
        &resolvers.1,
        first_result,
        second_result,
    )
    .await?;

    let score = match diff_result {
        diff_matcher::DifferenceResult::NewDifference((new_fp, known_diffs))
            if new_fp == fingerprint =>
        {
            // We successfully reproduced the difference.
            // Update the fingerprint list, the scoring, and the statistics

            let score;
            // IMPORTANT: Keep the order of aquired locks alphabetical, to avoid deadlocks.
            // This is important for the entries later on, such as mutateable_test_cases and statistics.
            {
                let mut fingerprints = state.fingerprints.lock().await;

                let fp_entry = fingerprints.entry(*fingerprint.clone()).or_default();
                fp_entry.insert(id);

                score = match fp_entry.len() {
                    0..=9 => 50.0,
                    10..=14 => 20.0,
                    15..=19 => 10.0,
                    20..=29 => 5.0,
                    30..=49 => 1.0,
                    50..=59 => 0.1,
                    _ => 0.001,
                };
                // Add a group penalty to all the FuzzCases belonging to this fingerprint
                if fp_entry.len() > 20 {
                    state.mutateable_test_cases.lock().await.decay(fp_entry);
                }
                let mut statistics = state.statistics.lock().await;
                statistics.fingerprints = fingerprints.len() as u64;
                statistics
                    .differences
                    .get_mut(&resolvers)
                    .expect("Difference statistics is created during construction")
                    .repro_significant += 1;
            }

            // Write the difference results, if desired
            if let Some(diff_dir) = &state.dump_diffs {
                diff_matcher::dump_difference_information(
                    diff_dir.clone(),
                    fuzz_case.clone(),
                    fuzz_suite,
                    resolvers.0,
                    resolvers.1,
                    first_result.clone(),
                    second_result.clone(),
                    result_sets.0.meta.clone(),
                    result_sets.1.meta.clone(),
                    *fingerprint,
                    known_diffs,
                )
                .await?;
            }

            score
        }
        diff_matcher::DifferenceResult::NewDifference(_) => {
            state
                .statistics
                .lock()
                .await
                .differences
                .get_mut(&resolvers)
                .expect("Difference statistics is created during construction")
                .repro_significant_other += 1;
            2.0
        }

        // Difference does not reproduce, ignore results
        diff_matcher::DifferenceResult::NoDifference => {
            state
                .statistics
                .lock()
                .await
                .differences
                .get_mut(&resolvers)
                .expect("Difference statistics is created during construction")
                .repro_no_diff += 1;
            1.0
        }
        diff_matcher::DifferenceResult::KnownDifference(_) => {
            state
                .statistics
                .lock()
                .await
                .differences
                .get_mut(&resolvers)
                .expect("Difference statistics is created during construction")
                .repro_insignificant += 1;
            1.0
        }
    };

    Ok((id, score))
}

enum CoverageStatus {
    Unchanged,
    NewBranches,
}

/// Process the coverage for all fuzz results, returning the new coverage [`FuzzCaseId`]s
async fn process_result_coverage(
    state: &FuzzingState,
    fuzz_results: &[FuzzResultSet],
) -> Result<BTreeSet<FuzzCaseId>> {
    let results = stream_assert_send(stream::iter(fuzz_results).map(|fuzz_result| {
        async {
            // Get the matching executor
            let exec = state.executors[&fuzz_result.fuzzee].clone();
            let (coverage_statusses, mut new_coverage_stats) =
                exec.update_coverage(fuzz_result).await;

            new_coverage_stats.progress_fuzz_case_count = coverage_statusses
                .iter()
                .filter(|x| matches!(x, CoverageStatus::NewBranches))
                .count() as u64;

            let ids_with_new_coverage = iter::zip(coverage_statusses, &fuzz_result.results)
                .filter_map(|(cs, fr)| {
                    if matches!(cs, CoverageStatus::NewBranches) {
                        Some(fr.id)
                    } else {
                        None
                    }
                });

            (
                fuzz_result.fuzzee.clone(),
                new_coverage_stats,
                ids_with_new_coverage,
            )
        }
    }))
    .buffer_unordered(fuzz_results.len())
    .collect::<Vec<_>>()
    .await;

    let mut improved_coverage = BTreeSet::new();
    let mut statistics = state.statistics.lock().await;
    for r in results {
        let (fuzzee, new_coverage_stats, ids_with_new_coverage) = r;
        let old_stats = statistics
            .coverage
            .get_mut(&fuzzee)
            .expect("Stats are filled during construction");
        old_stats.edges = new_coverage_stats.edges;
        old_stats.explored_edges = new_coverage_stats.explored_edges;
        old_stats.progress_fuzz_case_count += new_coverage_stats.progress_fuzz_case_count;
        improved_coverage.extend(ids_with_new_coverage);
    }

    Ok(improved_coverage)
}
