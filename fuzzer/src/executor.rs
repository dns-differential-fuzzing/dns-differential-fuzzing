use crate::serialize::SerializableMutex;
use crate::stats::{CoverageStats, ExecutorStats};
use crate::utils::ok;
use crate::CoverageStatus;
use color_eyre::eyre::{bail, eyre, Context as _, Result};
use dnsauth::definitions::{FuzzResultSet, FuzzSuite, FuzzSuiteId, ResolverName};
use fuzzer_protocol::Counters;
use misc_utils::fs;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::Mutex;

#[serde_with::serde_as]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(from = "ExecutorSerializable")]
pub(crate) struct Executor {
    pub(crate) fuzzee: ResolverName,
    #[serde_as(as = "SerializableMutex<_>")]
    background_activity: Mutex<Option<Counters>>,

    /// Observed coverages
    #[serde_as(as = "SerializableMutex<_>")]
    pub(crate) coverage: Mutex<Counters>,

    /// Spawns new preloaded `dnsauth` processes.
    #[serde(skip)]
    spawner: spawner::Spawner,
    /// How many containers to pre-spawn
    queue_length: usize,
    /// If set the fuzzee controller will not spend time to generate a background activity profile.
    ignore_background_activity: bool,
}

impl Executor {
    /// Creates a new `Executor` instance.
    ///
    /// The `fuzzee` determines which container to spawn.
    /// The `queue_length` determines how many container instances can be pre-spawned.
    pub(crate) fn new(
        fuzzee: ResolverName,
        queue_length: usize,
        ignore_background_activity: bool,
    ) -> Self {
        Self {
            fuzzee: fuzzee.clone(),
            // TODO If this becomes dynamic the value in the
            background_activity: Mutex::new(None),
            coverage: Mutex::new(Counters::default()),
            spawner: spawner::Spawner::new(
                fuzzee.to_string(),
                None,
                queue_length,
                ignore_background_activity,
            ),
            queue_length,
            ignore_background_activity,
        }
    }

    /// Execute an empty [`FuzzSuite`] to determine the background activity of the fuzzee.
    pub(crate) async fn load_background_activity(&self) -> Result<()> {
        if self.background_activity.lock().await.is_some() {
            return Ok(());
        }

        log::info!("Generate background activity profile for {}", self.fuzzee);
        let empty_fuzz_suite = FuzzSuite {
            id: FuzzSuiteId::new(),
            test_cases: Vec::new(),
        };
        let fuzz_result_set = self.run_new_test_cases(&empty_fuzz_suite).await?;
        {
            let mut background_activity = self.background_activity.lock().await;
            let mut coverage = self.coverage.lock().await;

            *background_activity = fuzz_result_set.background_activity;
            if background_activity.is_none() {
                bail!("Failed to load background activity");
            }
            if coverage.len() == 0 {
                *coverage = Counters::new(background_activity.as_ref().unwrap().len(), 0);
            }
        }
        log::info!(
            "Done generating background activity profile for {}",
            self.fuzzee
        );

        Ok(())
    }

    pub(crate) async fn run_new_test_cases(&self, fuzz_suite: &FuzzSuite) -> Result<FuzzResultSet> {
        let (mut fuzzer, workdir) = self.spawner.get_prespawned_container().await?;
        let fuzzer_id = fuzzer.id().unwrap_or(0);

        // Write all the support files into the workdir
        // TODO: The background activity is static after initial determination. Maybe this should be moved into the spawner, which also writes the config.
        // TODO: The postcard data could also be stored pre-serialized.
        if let Some(background_activity) = &*self.background_activity.lock().await {
            tokio::task::block_in_place(|| {
                let bytes = postcard::to_allocvec(background_activity)?;
                fs::file_write(workdir.path().join("background_activity_profile.postcard"))
                    .truncate()?
                    .write_all(&bytes)?;
                ok(())
            })?;
        }

        tokio::task::block_in_place(|| {
            let bytes = postcard::to_allocvec(&fuzz_suite)?;
            fs::file_write(workdir.path().join("fuzz-suite.postcard"))
                .truncate()?
                .write_all(&bytes)?;
            ok(())
        })?;

        let output = {
            let stdin = fuzzer.stdin.as_mut().expect("stdin is set to piped");
            stdin.write_all(b"ready\n").await?;
            stdin.flush().await?;

            fuzzer
                .wait_with_output()
                .await
                .context("Failed to wait for fuzzer")?
        };

        if !output.status.success() {
            log::error!("Output\n{}", String::from_utf8_lossy(&output.stdout));
            log::error!("Error\n{}", String::from_utf8_lossy(&output.stderr));
            bail!("Fuzzer exited with non-zero status: {}", output.status);
        }
        log::trace!("Podman terminated (pid {fuzzer_id})");

        // Read multiple output files in parallel
        let results = tokio::try_join!(
            tokio::task::spawn_blocking({
                let file = workdir.path().join("fuzz-result-set.postcard");
                || {
                    let data = fs::read(file)?;
                    ok(postcard::from_bytes(&data)?)
                }
            }),
            tokio::task::spawn_blocking({
                let file = workdir.path().join("tcpdump.pcap");
                || {
                    // Try to capture the tcpdump output
                    if let Ok(pcap) = fs::read(file) {
                        let pcap = Arc::<Box<[u8]>>::from(pcap.into_boxed_slice());
                        ok(Some(pcap))
                    } else {
                        ok(None)
                    }
                }
            }),
        )?;
        // Check for errors
        let mut frs: FuzzResultSet = results.0?;
        let pcap = results.1?;
        // Store extra data in the meta field
        if let Some(pcap) = pcap {
            frs.meta.insert("tcpdump.pcap".to_string(), pcap);
        }

        // Check with oracles for problems in each `FuzzResult` for each `FuzzResultSet`
        const EXCESSIVE_QUERIES_COUNT: usize = 15;
        const EXCESSIVE_ANSWER_RECORDS_COUNT: u16 = 10;
        frs.results.iter_mut().for_each(|fr| {
            // TODO: check for fake data
            if let Some(resp) = &mut fr.fuzzee_response {
                if resp.answer_count() + resp.name_server_count() + resp.additional_count()
                    > EXCESSIVE_ANSWER_RECORDS_COUNT
                {
                    fr.oracles.excessive_answer_records = true;
                }

                // Check for duplicate records within each section
                for section_records in [resp.answers(), resp.name_servers(), resp.additionals()] {
                    if section_records.len() != BTreeSet::from_iter(section_records).len() {
                        fr.oracles.duplicate_records = true;
                    }
                }

                // Check if the original query had QR=1, i.e., it was a response
                if fuzz_suite
                    .test_cases
                    .iter()
                    .find(|tc| tc.id == fr.id)
                    .expect("Each FuzzResult must have a matching TestCase")
                    .client_query
                    .header()
                    .message_type()
                    == trust_dns_proto::op::MessageType::Response
                {
                    fr.oracles.responds_to_response = true;
                }
            }
            if fr.fuzzee_queries.len() > EXCESSIVE_QUERIES_COUNT {
                fr.oracles.excessive_queries = true;
            }
        });

        Ok(frs)
    }

    /// Update coverage information from a [`FuzzResultSet`].
    pub(crate) async fn update_coverage(
        &self,
        fuzz_results: &FuzzResultSet,
    ) -> (Vec<CoverageStatus>, CoverageStats) {
        let background_activity = self.background_activity.lock().await;
        let mut coverage = self.coverage.lock().await;

        let statusses = fuzz_results
            .results
            .iter()
            .map(|result| {
                let mut new_coverage = result.counters.clone().unwrap();
                new_coverage.discard_counters_by_pattern(background_activity.as_ref().unwrap());
                // Such that we can see if the coverage increased
                new_coverage.discard_counters_by_pattern(&coverage);
                coverage.max_pairwise(&new_coverage);
                if new_coverage.has_counters_set() {
                    CoverageStatus::NewBranches
                } else {
                    CoverageStatus::Unchanged
                }
            })
            .collect();

        let stats = CoverageStats {
            edges: coverage.len() as u64,
            explored_edges: coverage.count() as u64,
            progress_fuzz_case_count: 0,
        };

        (statusses, stats)
    }

    pub(crate) async fn get_stats(&self) -> ExecutorStats {
        let mut queue_capacity = 0;
        let mut queue_len = 0;
        if let Some(sender) = self.spawner.sender.upgrade() {
            queue_capacity = sender.max_capacity() as u64;
            queue_len = queue_capacity - sender.capacity() as u64;
        }
        let spawner_state = self.spawner.state.lock().await;
        ExecutorStats {
            queue_capacity,
            queue_len,
            total_errors: spawner_state.total_errors,
            total_spawned: spawner_state.total_spawned,
            curr_errors: spawner_state.curr_errors,
            min_timeout: spawner_state.min_timeout,
            spawn_timeout: spawner_state.spawn_timeout,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ExecutorSerializable {
    fuzzee: ResolverName,
    background_activity: Option<Counters>,
    coverage: Counters,
    queue_length: usize,
    ignore_background_activity: bool,
}

impl From<ExecutorSerializable> for Executor {
    fn from(executor: ExecutorSerializable) -> Self {
        Self {
            fuzzee: executor.fuzzee.clone(),
            background_activity: Mutex::new(executor.background_activity),
            coverage: Mutex::new(executor.coverage),
            spawner: spawner::Spawner::new(
                executor.fuzzee.to_string(),
                None,
                executor.queue_length,
                executor.ignore_background_activity,
            ),
            queue_length: executor.queue_length,
            ignore_background_activity: executor.ignore_background_activity,
        }
    }
}

mod spawner {
    use super::*;
    use crate::utils::task_spawn_named;
    use crate::SHOULD_TERMINATE;
    use futures::Future;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::Stdio;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt as _, BufReader};
    use tokio::process::{Child, Command};
    use tokio::sync::mpsc;

    pub(super) struct Spawner {
        container: String,
        tag: String,
        pub(super) sender: mpsc::WeakSender<(Child, TempDir)>,
        // TODO: Maybe better use a mpmc channel?
        // https://github.com/tokio-rs/tokio/discussions/3891
        receiver: Mutex<mpsc::Receiver<(Child, TempDir)>>,
        pub(super) state: Arc<Mutex<SpawnerState>>,
    }

    pub(super) struct SpawnerState {
        pub(super) total_errors: u64,
        pub(super) total_spawned: u64,
        pub(super) curr_errors: u64,
        pub(super) min_timeout: Duration,
        pub(super) spawn_timeout: Duration,
    }

    impl Spawner {
        // TODO: Consider multiple spawners, when the containers are consumed too quickly
        pub(super) fn new(
            container: String,
            tag: Option<String>,
            mut queue_length: usize,
            ignore_background_activity: bool,
        ) -> Self {
            // Prevent a 0 value to be passed to queue lenght, since that causes a panic
            if queue_length == 0 {
                queue_length = 1;
            }
            let tag = tag.unwrap_or_else(|| String::from("latest"));
            let (send, recv) = mpsc::channel(queue_length);
            let state = Arc::new(Mutex::new(SpawnerState {
                total_errors: 0,
                total_spawned: 0,
                curr_errors: 0,
                min_timeout: Duration::from_secs(10),
                spawn_timeout: Duration::from_secs(120),
            }));
            let weak_send = send.downgrade();

            task_spawn_named(&(format!("Container spawner for {container}:{tag}")), {
                let container = container.clone();
                let tag = tag.clone();
                let state = state.clone();
                async move {
                    loop {
                        let (min_timeout, spawn_timeout) = {
                            let state = state.lock().await;
                            (state.min_timeout, state.spawn_timeout)
                        };
                        log::debug!("Spawn Timeout {container}:{tag} {spawn_timeout:?}");
                        let spawner = spawn_container(
                            container.clone(),
                            tag.clone(),
                            ignore_background_activity,
                        );
                        // Always allow more time for spawning the container than strictly needed
                        // Also use a minimal timeout value
                        let (status, duration) = measure_duration(tokio::time::timeout(
                            min_timeout.max(spawn_timeout * 2),
                            spawner,
                        ))
                        .await;
                        match status {
                            Ok(Ok(msg)) => {
                                let mut state = state.lock().await;
                                // Average spawn time over the last couple attempts
                                state.spawn_timeout *= 5;
                                state.spawn_timeout += duration;
                                state.spawn_timeout /= 6;

                                state.total_spawned += 1;
                                state.curr_errors = 0;

                                match send.send(msg).await {
                                    Ok(()) => {}
                                    Err(mpsc::error::SendError(_)) => {
                                        if SHOULD_TERMINATE
                                            .load(std::sync::atomic::Ordering::SeqCst)
                                        {
                                            break;
                                        }
                                        log::error!("Channel for {container}:{tag} disconnected");
                                        break;
                                    }
                                }
                            }
                            Ok(Err(err)) => {
                                log::warn!(
                                    "Failed to spawn container {container}:{tag}: {:?}",
                                    err
                                );
                                let mut state = state.lock().await;
                                state.total_errors += 1;
                                state.curr_errors += 1;

                                if state.curr_errors > 10 {
                                    log::error!("Aborting spawner due to too many errors");
                                    break;
                                }
                            }
                            Err(/* timeout */ _) => {
                                log::warn!("Spawning container {container}:{tag} timed out");
                                let mut state = state.lock().await;
                                // Maybe spawning a container is just slow at the moment, so we extend the timeout
                                // 6/5 == 1.2, i.e., 20% more time
                                // With up to 10 errors which yields up to 1.2**10 ~= 6.2 times the original timeout
                                state.spawn_timeout *= 6;
                                state.spawn_timeout /= 5;

                                state.total_errors += 1;
                                state.curr_errors += 1;

                                if state.curr_errors > 10 {
                                    log::error!("Aborting spawner due to too many errors");
                                    break;
                                }
                            }
                        }
                    }
                }
            });

            Self {
                container,
                tag,
                receiver: Mutex::new(recv),
                sender: weak_send,
                state,
            }
        }

        pub(super) async fn get_prespawned_container(&self) -> Result<(Child, TempDir)> {
            self.receiver.lock().await.recv().await.ok_or_else(|| {
                eyre!(
                    "Channel closed unexpectedly for {}:{}",
                    self.container,
                    self.tag
                )
            })
        }
    }

    async fn spawn_container(
        container: String,
        tag: String,
        ignore_background_activity: bool,
    ) -> Result<(Child, TempDir)> {
        let workdir = tokio::task::spawn_blocking({
            let container = container.clone();
            move || {
                tempfile::Builder::new()
                    .prefix(&container)
                    .tempdir_in("/tmp/fuzzing-dns/")
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
            // The containers do not need internet access.
            // Loopback is always available
            .arg("--network=none")
            // enables tcpdump
            .arg("--cap-add=NET_RAW")
            // Missing in newer podman settings, but used by multiple resolvers
            .arg("--cap-add=SYS_CHROOT")
            // Prevent the container from lingering into all eternity
            .arg("--timeout=800")
            .arg("--volume")
            .arg(mnt_volume)
            .arg("--name")
            .arg(format!(
                "{container}-{tag}-{}",
                crate::utils::rand_string(10)
            ))
            .arg(&format!("{container}:{tag}"))
            // Arguments for the dnsauth process inside the container
            .arg("--config=/config/config.toml")
            .arg("--fuzz-suite=/config/fuzz-suite.postcard")
            .arg("--delayed-startup")
            .arg("--ntests=50");
        if ignore_background_activity {
            cmd.arg("--ignore-background-activity");
        }
        cmd.kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            // Put the processes into their own process group
            // This separates them from receiving CTRL+C signals
            //
            // SAFETY: `setpgid(2)` is guaranteed to be a async-signal-safe function.
            // https://man7.org/linux/man-pages/man7/signal-safety.7.html
            //
            // If pid is zero, then the process ID of the calling process is used. If
            // pgid is zero, then the PGID of the process specified by pid is made the
            // same as its process ID.
            cmd.pre_exec(|| {
                Ok(nix::unistd::setpgid(
                    nix::unistd::Pid::from_raw(0),
                    nix::unistd::Pid::from_raw(0),
                )?)
            });
        }
        let mut fuzzer = cmd.spawn().context("Failed to run podman for fuzzing")?;
        let fuzzer_id = fuzzer.id().unwrap_or(0);
        log::trace!("Started podman (pid {fuzzer_id})");
        log::debug!("Waiting for fuzzer to be ready after delayed startup");
        let mut fuzzer_out =
            BufReader::new(fuzzer.stdout.as_mut().expect("stdout is set to piped")).lines();
        let mut fuzzer_err =
            BufReader::new(fuzzer.stderr.as_mut().expect("stderr is set to piped")).lines();

        let mut stdout = String::new();
        let mut stderr = String::new();

        loop {
            tokio::select!(
                line = fuzzer_out.next_line() => {
                    let line = line.context("Failed to read stdout from fuzzer")?;
                    log::trace!("{container}: Read Line {:?}", line);
                    if let Some(line) = line {
                        stdout.push_str(&line);
                        if line.starts_with("Ready to load the FuzzSuite") {
                            return Ok((fuzzer, workdir));
                        }
                    } else {
                        break;
                    }
                }
                line = fuzzer_err.next_line() => {
                    if let Some(line) = line.context("Failed to read stderr from fuzzer")? {
                        stderr.push_str(&line);
                    }
                }
            );
        }

        fuzzer
            .kill()
            .await
            .with_context(|| format!("Killing podman (pid {fuzzer_id}) failed."))?;
        let output = fuzzer.wait_with_output().await?;
        if output.status.success() {
            log::warn!("Fuzzer executed successfully, but never reached the pre-start state.");
            bail!("Fuzzer executed successfully, but never reached the pre-start state.");
        } else if output.status.signal() == Some(/* kill */ 9) {
            log::warn!("Fuzzer killed because it never reached the pre-start state.");
            bail!(
                "Fuzzer killed because it never reached the pre-start state.\n{}\n{}",
                stdout,
                stderr,
            );
        } else {
            log::warn!("Fuzzer exited with non-zero status: {}", output.status,);
            bail!(
                "Fuzzer exited with non-zero status: {}\n{}",
                output.status,
                stderr,
            );
        }
    }

    /// Measure the time it took for the future to resolve.
    async fn measure_duration<T>(future: impl Future<Output = T> + Send) -> (T, Duration) {
        let now = tokio::time::Instant::now();
        let res = future.await;
        let duration = now.elapsed();
        (res, duration)
    }
}
