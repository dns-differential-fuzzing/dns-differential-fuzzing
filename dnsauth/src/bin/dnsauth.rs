#![warn(
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
// The lint is being downgraded
// https://github.com/rust-lang/rust-clippy/pull/8544
#![allow(clippy::try_err)]

use chrono::Utc;
use color_eyre::eyre::{bail, eyre, Result, WrapErr as _};
use dnsauth::authns::dynamic::{DynamicDnsAuthServer, DynamicDnsAuthServerHandle};
use dnsauth::authns::fixed::DnsAuthServer;
use dnsauth::config::{Config, LogLevel, Record, ResouceRecord};
use dnsauth::definitions::{
    CacheKey, CachePresent, CacheState, FuzzCase, FuzzResult, FuzzResultSet, FuzzSuite,
    OracleResults, ResolverName,
};
use dnsauth::fuzzee::Fuzzee;
use futures::{future, FutureExt as _};
use fuzzer_protocol::Counters;
use log::{info, warn};
use misc_utils::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use tokio::process::{Child, Command};
use trust_dns_client::rr::LowerName;
use trust_dns_proto::op::{Message, ResponseCode};
use trust_dns_proto::rr::{DNSClass, Name};
use trust_dns_server::proto::rr::RecordType;

// #[global_allocator]
// static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod eyre {
    use super::Result;

    #[allow(non_snake_case)]
    pub(crate) fn Ok<T>(t: T) -> Result<T> {
        Result::Ok(t)
    }
}

#[derive(clap::Parser)]
struct CliArgs {
    /// Path to the config file
    #[clap(long = "config", default_value = "./config.toml")]
    config: PathBuf,
    /// Path to the FuzzSuite file
    #[clap(long = "fuzz-suite")]
    fuzz_suite: PathBuf,
    /// Maximum number of tests which are executed later on
    #[clap(long = "ntests", default_value_t = 100)]
    ntests: u16,
    /// Only perform startup initialization and then sleep infinitely
    #[clap(long = "no-run")]
    no_run: bool,
    /// More aggressive variant of `no-run`, which also skips the resolver functionality test
    #[clap(long = "no-run-early")]
    no_run_early: bool,
    /// Delay reading the FuzzSuite file until the server is ready
    ///
    /// This allows to startup the container in a half-ready state, with the fuzzee up and running,
    /// and allows for fast usage of the container.
    #[clap(long = "delayed-startup", requires = "ntests")]
    delayed_startup: bool,
    #[clap(long = "ignore-background-activity")]
    ignore_background_activity: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::builder()
        .filter(Some(std::env!("CARGO_PKG_NAME")), log::LevelFilter::Debug)
        .parse_default_env()
        .try_init()?;
    let mut cli_args: CliArgs = clap::Parser::parse();

    let mut config: Config = tokio::task::block_in_place(|| {
        eyre::Ok(
            toml::from_str(&fs::read_to_string(cli_args.config).context("Failed to read config.")?)
                .context("Failed to parse config.")?,
        )
    })?;
    // Initialize FuzzSuite already if present, because then the correct number of zones can be setup
    // Otherwise do that later and to support pre-startup of fuzzees
    let fuzz_suite = if !cli_args.delayed_startup {
        let fuzz_suite_path = cli_args.fuzz_suite.clone();
        let fuzz_suite = tokio::task::spawn_blocking(move || {
            eyre::Ok(load_fuzz_suite(&fuzz_suite_path).context("Failed to load the FuzzSuite.")?)
        })
        .await??;
        cli_args.ntests = fuzz_suite.test_cases.len() as u16;
        Some(fuzz_suite)
    } else {
        log::debug!("Preparing delayed startup");
        None
    };

    match config.common.log_level {
        Some(LogLevel::Warn) | None => log::set_max_level(log::LevelFilter::Warn),
        Some(LogLevel::Info) => log::set_max_level(log::LevelFilter::Info),
        Some(LogLevel::Debug) => log::set_max_level(log::LevelFilter::Debug),
        Some(LogLevel::Trace) => log::set_max_level(log::LevelFilter::Trace),
    };
    let initial_ip = Ipv4Addr::new(127, 250, 0, 1);

    // Use spawn to run all code in parallel
    // This results in a nested `Result`, the outer for the `spawn` and the inner because of the normal return code.
    let tcpdump = spawn_tcpdump()?;
    let (mut fuzzer_handle, mut fuzzee, ()) = tokio::try_join!(
        tokio::spawn(DynamicDnsAuthServer::spawn_n(initial_ip, cli_args.ntests)).map(|res| res?),
        tokio::spawn(Fuzzee::new()).map(|res| res?),
        startup_fixed_authns(&mut config, initial_ip, cli_args.ntests),
    )?;

    if cli_args.no_run_early {
        info!("Skipping running fuzzee functionality test and fuzzer");
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    // Wait for the resolver to be ready, with timeout
    tokio::time::timeout(Duration::from_secs(30), async {
        while fuzzee
            .query_by_name(Name::from_ascii(".")?, RecordType::NS)
            .await?
            .is_none()
        {
            // Give the resolver some time to start up
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        eyre::Ok(())
    })
    .await
    .context("The resolver did not became ready in time")?
    .context("Querying the resolver failed")?;

    // Prime server
    info!("Prefetch and reset counters");
    for qname in ["ns.", "ns-ns.ns.", "fuzz.", "ns-fuzz.ns."] {
        let qname = Name::from_ascii(qname)?;
        for &rtype in &[
            RecordType::AAAA,
            RecordType::CNAME,
            RecordType::SOA,
            RecordType::NS,
            RecordType::A,
        ] {
            if fuzzee.query_by_name(qname.clone(), rtype).await?.is_none() {
                // Slow down primeing if it does not yield a response
                // We already ensured that the root priming query is working,
                // but that one is also in the root hints, and these could fail separately
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    // Record what the default background noise is such that it can be ignored in the future
    // This does not need to be done every time. Instead we can load a saved profile to speed up the process.
    let background_activity = if !cli_args.ignore_background_activity && !cli_args.delayed_startup {
        let background_activity = load_or_measure_background_activity(&mut fuzzee)
            .await
            .wrap_err_with(|| {
                eyre!("Could not load or measure the background_activity of the fuzzee")
            })?;
        Some(background_activity)
    } else {
        None
    };

    // Initialize FuzzSuite if not already done so earlier
    let fuzz_suite: FuzzSuite = if let Some(fuzz_suite) = fuzz_suite {
        fuzz_suite
    } else {
        log::info!("Ready for delayed startup");
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        writeln!(stdout, "Ready to load the FuzzSuite")?;
        stdout.flush()?;
        drop(stdout);
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        if !line.starts_with("ready") {
            bail!("Expected `ready` to start fuzzing, but got {line:?}");
        }

        let fuzz_suite_path = cli_args.fuzz_suite.clone();
        let fuzz_suite: FuzzSuite = tokio::task::spawn_blocking(move || {
            eyre::Ok(load_fuzz_suite(&fuzz_suite_path).context("Failed to load the FuzzSuite.")?)
        })
        .await??;
        // Ensure that enough listening sockets were spawned for all the tests
        if fuzz_suite.test_cases.len() > cli_args.ntests as usize {
            bail!(
                "The number of test cases in the fuzz suite ({}) is larger than the number of \
                 prepared sockets/zones ({})",
                fuzz_suite.test_cases.len(),
                cli_args.ntests
            );
        }
        fuzz_suite
    };

    let background_activity = match background_activity {
        Some(background_activity) => background_activity,
        None if cli_args.ignore_background_activity => {
            // Initialize a dummy Counters of the correct size but filled with 0s
            let counter_len = fuzzee.controller.get_and_reset().await?.len();
            Counters::new(counter_len, 0)
        }
        None => load_or_measure_background_activity(&mut fuzzee)
            .await
            .wrap_err_with(|| {
                eyre!("Could not load or measure the background_activity of the fuzzee")
            })?,
    };
    info!("Background Activity: {background_activity:?}");

    if cli_args.no_run {
        info!("Skipping running fuzzing");
        if let Some(fuzz_case) = fuzz_suite.test_cases.get(0) {
            info!("Load the fuzzing responses for the first fuzz case");
            *fuzzer_handle.state.fuzzing_response.lock().await = fuzz_case.server_responses.clone();
        }
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    // Start the actual fuzzing procedure
    let time_start = Utc::now();

    let mut fuzzing_results = Vec::new();
    for fuzz_case in &fuzz_suite.test_cases {
        let fuzz_result = fuzz_single_case(fuzz_case, &mut fuzzer_handle, &mut fuzzee).await;
        if let Ok(res) = fuzz_result {
            fuzzing_results.push(res);
        } else {
            warn!("Fuzzing failed for case {:?}", fuzz_case.id);
        }
        if let Ok(Some(exit)) = fuzzee.try_wait() {
            warn!("Fuzzee exited with {:?}", exit);
            break;
        }
    }
    let time_end = Utc::now();

    // Path in the container which stores the fuzzee name
    let fuzzee_name = ResolverName::new(
        fs::read_to_string("/fuzzee")
            .context("Fuzzee name not found in container")?
            .trim()
            .to_string(),
    );
    let output = postcard::to_allocvec(&FuzzResultSet {
        id: fuzz_suite.id,
        fuzzee: fuzzee_name,
        results: fuzzing_results,
        background_activity: Some(background_activity),
        time_start,
        time_end,
        meta: Default::default(),
    })?;
    fs::write("./fuzz-result-set.postcard", output)?;

    if let Some(tcpdump) = &tcpdump {
        if let Some(pid) = tcpdump.id() {
            // If the child hasn't already completed, send a SIGTERM.
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid.try_into().expect("Invalid PID")),
                nix::sys::signal::Signal::SIGTERM,
            );
        }
    }
    fuzzee.terminate().await;
    if let Some(mut tcpdump) = tcpdump {
        let _ = tokio::time::timeout(Duration::from_secs(5), tcpdump.wait()).await;
    }

    Ok(())
}

/// Startup the fixed AuthNSs hosting the support zones.
///
/// The function creates `ntests` zones under `fuzz.` each with a unique nameserver.
/// The nameserver IPs are allocated sequentually starting from `initial_ip`.
async fn startup_fixed_authns(
    config: &mut Config,
    initial_ip: Ipv4Addr,
    ntests: u16,
) -> Result<()> {
    {
        let mut fuzz_zone = None;
        let mut ns_zone = None;
        config.auth.iter_mut().for_each(|a| {
            if a.zone == LowerName::from_str("fuzz.").unwrap() {
                fuzz_zone = Some(&mut a.data);
            } else if a.zone == LowerName::from_str("ns.").unwrap() {
                ns_zone = Some(&mut a.data);
            }
        });
        let fuzz_zone = fuzz_zone.unwrap();
        let ns_zone = ns_zone.unwrap();

        let mut ipaddr = initial_ip;
        for id in 0..ntests {
            let ns_name = Name::from_ascii(format!("ns-{id:04}.ns.").as_str()).unwrap();
            let ip = ipaddr;
            ipaddr = dnsauth::utils::next_ipv4(ipaddr);
            let zone_name = Name::from_ascii(format!("{id:04}.fuzz.").as_str()).unwrap();

            let ns_record = ResouceRecord {
                name: LowerName::from(zone_name),
                record: Record::NS {
                    rdata: ns_name.clone(),
                },
            };
            let a_record = ResouceRecord {
                name: LowerName::from(ns_name),
                record: Record::A { rdata: ip },
            };

            fuzz_zone.push(ns_record);
            ns_zone.push(a_record);
        }
    }

    for auth_config in &config.auth {
        let addr = &auth_config.listen_addresses;
        let mut server =
            trust_dns_server::ServerFuture::new(DnsAuthServer::with_config(auth_config.clone())?);

        for listen_addr in addr {
            let socket = tokio::net::UdpSocket::bind(listen_addr)
                .await
                .wrap_err_with(|| format!("Could not bind listen socket on UDP {listen_addr}"))?;
            server.register_socket(socket);
            let socket = tokio::net::TcpListener::bind(listen_addr)
                .await
                .wrap_err_with(|| format!("Could not bind listen socket on TCP {listen_addr}"))?;
            server.register_listener(socket, Duration::new(30, 0));
        }

        tokio::spawn(server.block_until_done());
    }
    Ok(())
}

async fn load_or_measure_background_activity(fuzzee: &mut Fuzzee) -> Result<Counters> {
    // TODO move constant or make it configurable on the CLI
    const BACKGROUND_ACTIVITY_FILE: &str = "./background_activity_profile.postcard";

    fn load_from_file(file_path: &Path) -> Result<Counters> {
        let content = fs::read(file_path)?;
        Ok(postcard::from_bytes(&content)?)
    }
    if let Ok(values) = load_from_file(Path::new(BACKGROUND_ACTIVITY_FILE)) {
        let expected_counter_length = fuzzee.controller.get_and_reset().await?.len();
        if values.len() == expected_counter_length {
            info!(
                "Could use stored background activity profile from {}",
                BACKGROUND_ACTIVITY_FILE
            );
            return Ok(values);
        }
    }
    info!("Need to generate new background activity profile");

    let mut background_activity: Option<_> = None;
    for i in 0..3 {
        // Reset fuzzee to initial conditions
        fuzzee.controller.get_and_reset().await?;
        info!("Measure background activity Round {i}");
        let qname = Name::from_utf8(format!("www{i}.shortlived.test."))?;
        let dns_resp = fuzzee
            .query_no_recurse(qname.clone(), RecordType::A, DNSClass::IN)
            .await;
        info!("Fetched {}: {}", qname, dns_resp.is_ok());
        fuzzee.controller.get_and_reset().await?;
        // Ignore errors from checking, limit to fixed time
        let _ = tokio::time::timeout(Duration::from_secs(60), async {
            // Wait for the background activity to run once
            while !fuzzee.controller.get().await?.has_counters_set() {
                tokio::time::sleep(Duration::new(0, 500_000_000)).await;
            }
            // Sleep a tiny bit to ensure the background activity has passed
            tokio::time::sleep(Duration::new(1, 0)).await;
            eyre::Ok(())
        })
        .await;
        let new_background_activity = fuzzee.controller.get_and_reset().await?;
        background_activity = if let Some(background_activity) = background_activity {
            Some(background_activity + new_background_activity)
        } else {
            Some(new_background_activity)
        };
    }
    let background_activity =
        background_activity.expect("background_activity needs to be set in the above loop");
    let background_activity_profile = postcard::to_allocvec(&background_activity)?;
    fs::write(BACKGROUND_ACTIVITY_FILE, background_activity_profile)?;

    Ok(background_activity)
}

async fn fuzz_single_case(
    FuzzCase {
        id,
        client_query,
        server_responses,
        check_cache,
    }: &FuzzCase,
    fuzz_server: &mut DynamicDnsAuthServerHandle,
    fuzzee: &mut Fuzzee,
) -> Result<FuzzResult> {
    info!("Running: {id}");
    // Set the fuzzing responses
    *fuzz_server.state.fuzzing_response.lock().await = server_responses.clone();
    // Ensure that all values are 0
    fuzzee.controller.get_and_reset().await?;
    // Reset potentially old entries
    fuzz_server.get_query_list().await?;

    let fuzzee_response = fuzzee
        .query(client_query.clone())
        .await
        .context("Error while waiting for client response.")?
        .map(Message::from);

    tokio::time::sleep(Duration::new(0, 10_000_000)).await;
    let fuzzee_state = fuzzee.try_wait()?;
    let counters = fuzzee.controller.get_and_reset().await?;
    let (fuzzee_queries, response_idxs) = fuzz_server.get_query_list().await?;

    let cache_state = future::join_all(
        check_cache
            .iter()
            .cloned()
            .map(|CacheKey(qname, qtype, qclass)| fuzzee.query_no_recurse(qname, qtype, qclass)),
    )
    .await;
    let cache_state = CacheState {
        values: cache_state
            .into_iter()
            .zip(check_cache.iter().cloned())
            .map(|(response, key)| {
                let value = match response {
                    Ok(Some(response)) => {
                        if response.contains_answer() {
                            return (key, CachePresent::Present);
                        }
                        let msg = Message::from(response);
                        match msg.response_code() {
                            ResponseCode::NoError => CachePresent::Absent,
                            _ => CachePresent::Error,
                        }
                    }
                    Ok(None) | Err(_) => CachePresent::Error,
                };
                (key, value)
            })
            .collect(),
    };

    let oracles = OracleResults {
        crashed_resolver: fuzzee_state.is_some(),
        ..Default::default()
    };
    let fuzzresult = FuzzResult {
        id: *id,
        counters: Some(counters),
        cache_state,
        fuzzee_response,
        fuzzee_queries,
        response_idxs,
        oracles,
    };
    info!("{fuzzresult}");
    Ok(fuzzresult)
}

/// Load a [`FuzzSuite`] and ensure each test uses a unique zone.
fn load_fuzz_suite(path: &Path) -> Result<FuzzSuite> {
    let data = fs::read(path)?;
    let mut fsb: dnsauth::definitions::FuzzSuiteBytes =
        postcard::from_bytes(&data).context("Could not parse FuzzSuite")?;
    for (i, fc) in fsb.test_cases.iter_mut().enumerate() {
        fc.replace_label(b"\x04test", &format!("\x04{i:04}").into_bytes())
            .context("Replacing the placeholder label with a unique zone label failed.")?;
    }
    let data = postcard::to_allocvec(&fsb).context("Re-serializing the FuzzSuite failed.")?;
    Ok(postcard::from_bytes(&data)?)
}

fn spawn_tcpdump() -> Result<Option<Child>> {
    match Command::new("tcpdump")
        // Write each packet to file
        .arg("--packet-buffered")
        .arg("--immediate-mode")
        .arg("-w")
        .arg("/config/tcpdump.pcap")
        .arg("--interface=lo")
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => Ok(Some(child)),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(err).context("Could not spawn tcpdump")
            }
        }
    }
}
