//! Communication protocol between fuzzing helper and fuzzee.
//!
//! This crate implements a TCP based communication protocol between the fuzzing helper and the fuzzee.

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

// The libcoverage part needs to be minimal, so check that nothing is enabled when the "server" feature is used.
// The server feature is the only thing needed by libcoverage.
#[cfg(all(
    PREVENT_CONFLICTING_FEATURES,
    feature = "server",
    any(feature = "client", feature = "image")
))]
compile_error!("The server feature cannot be used together with other features");

pub use crate::counters::Counters;

#[cfg(feature = "client")]
use {
    color_eyre::eyre::eyre,
    std::fmt,
    tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufStream},
    tokio::net::TcpStream as TokioTcpStream,
};

#[cfg(feature = "server")]
use {
    log::{debug, error, warn},
    std::io::prelude::*,
    std::io::BufReader,
    std::net::{Shutdown, TcpListener, TcpStream},
    std::sync::atomic::{AtomicU32, Ordering},
};

#[cfg(any(feature = "client", feature = "server"))]
use {
    crate::cmds::{CommandResponses, Commands},
    color_eyre::eyre::{bail, Context, Result},
    std::net::SocketAddrV4,
};

#[cfg(any(feature = "client", feature = "server"))]
pub mod cmds;
mod counters;

/// Number of guard counters
#[cfg(feature = "server")]
const NUM_GUARDS: usize = 1 << 20;
/// Store the counter values for a program
#[cfg(feature = "server")]
pub static COVERAGE_COUNTERS: CoverageCounters = CoverageCounters::new();

/// Store the counter values for a program
///
/// The counters are one large array of atomic values.
/// Each guard (i.e., location of interest) is assigned a unique ID.
/// The ID is the index into the array.
#[cfg(feature = "server")]
#[derive(Debug)]
pub struct CoverageCounters {
    arr: [AtomicU32; NUM_GUARDS],
    size: AtomicU32,
}

#[cfg(feature = "server")]
impl CoverageCounters {
    /// Create a new `CoverageCounters` with the given number of counters.
    const fn new() -> Self {
        // A const item is necessary to initialize the array, since the type is not `Copy`.
        #[allow(clippy::declare_interior_mutable_const)]
        const ZERO: AtomicU32 = AtomicU32::new(0);
        CoverageCounters {
            arr: [ZERO; NUM_GUARDS],
            size: ZERO,
        }
    }

    /// Set the size of the counters.
    ///
    /// Counters beyond the `size` should not be used.
    /// This function fails if the new size is larger than the static backing array.
    pub fn set_size(&self, size: u32) -> Result<()> {
        if size as usize > self.arr.len() {
            bail!(
                "CoverageCounters only supports {} counters, but at least {} are needed.",
                self.arr.len(),
                size
            );
        } else {
            self.size.store(size, Ordering::Relaxed);
            Ok(())
        }
    }

    /// Increment the counter at the given index.
    ///
    /// Returns the previous value
    #[cfg(feature = "server")]
    pub fn inc(&self, id: u32) -> u32 {
        self.arr
            .get(id as usize)
            .map(|counter| counter.fetch_add(1, Ordering::SeqCst))
            .unwrap_or(0)
    }

    /// Convert into a slice of atomic counters
    #[cfg(feature = "server")]
    fn as_slice(&self) -> &[AtomicU32] {
        &self.arr[..self.size() as usize]
    }

    /// Return the number of counters
    fn size(&self) -> u32 {
        self.size.load(Ordering::SeqCst)
    }

    /// Read all counter values
    ///
    /// This action is partially synchronized via `self.lock`, but concurrent modifications on the counters are possible.
    pub fn get_values(&self) -> Counters {
        self.as_slice()
            .iter()
            .map(|a| a.load(Ordering::SeqCst))
            .collect::<Vec<_>>()
            .into()
    }

    /// Reset all counters to 0
    ///
    /// This action is partially synchronized via `self.lock`, but concurrent modifications on the counters are possible.
    pub fn get_and_reset(&self) -> Counters {
        self.as_slice()
            .iter()
            .map(|a| a.swap(0, Ordering::SeqCst))
            .collect::<Vec<_>>()
            .into()
    }
}

/// Run the fuzzing control server waiting for client to connect.
#[cfg(feature = "server")]
pub fn run_server(addr: SocketAddrV4) {
    let listener = TcpListener::bind(addr)
        .unwrap_or_else(|_| panic!("Cannot bind to the fuzzer control point at {addr}"));
    eprintln!("Fuzzee listening on: {addr}");

    // accept connections and process them serially
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer = stream.peer_addr().ok();
                let res = run_server_client(stream);
                if let Err(err) = res {
                    error!(
                        "Connection to client {} failed with {}",
                        peer.map_or_else(|| "*unknown*".to_string(), |peer| peer.to_string()),
                        err
                    );
                }
            }
            Err(err) => warn!("Client connection error: {err}"),
        }
    }
}

/// Handle a single client using the fuzzing protocol.
#[cfg(feature = "server")]
fn run_server_client(stream: TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut stream = &stream;
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = line.wrap_err("Failed to read line from TCP")?;
        debug!("Received command: {line}");
        let cmd = serde_json::from_str(&line).wrap_err("Could not parse command")?;
        let resp = match cmd {
            Commands::GetAndReset { .. } => {
                let values = COVERAGE_COUNTERS.get_and_reset();
                CommandResponses::Counters { values }
            }
            Commands::Get { .. } => {
                let values = COVERAGE_COUNTERS.get_values();
                CommandResponses::Counters { values }
            }
            Commands::Terminate { .. } => {
                let mut resp_msg = serde_json::to_string(&CommandResponses::Ok)
                    .wrap_err("Failed to serialize response message")
                    .expect("Failed to serialize response message");
                resp_msg.push('\n');
                let _ = stream.write_all(resp_msg.as_bytes());
                let _ = stream.shutdown(Shutdown::Both);
                let _ = stream.flush();
                std::process::exit(55);
            }
            Commands::Unknown => CommandResponses::UnknownCommand,
        };

        let mut resp_msg =
            serde_json::to_string(&resp).wrap_err("Failed to serialize response message")?;
        resp_msg.push('\n');
        stream
            .write_all(resp_msg.as_bytes())
            .wrap_err("Could not send response message")?;
        stream.flush()?;
    }
    Ok(())
}

#[cfg(feature = "client")]
pub struct FuzzeeControl {
    addr: SocketAddrV4,
    sock: BufStream<TokioTcpStream>,
}

#[cfg(feature = "client")]
impl FuzzeeControl {
    pub async fn new(addr: SocketAddrV4) -> Result<Self> {
        let sock = TokioTcpStream::connect(addr)
            .await
            .wrap_err_with(|| eyre!("Cannot connect to fuzzee on {addr}"))?;
        Ok(Self {
            addr,
            sock: BufStream::new(sock),
        })
    }

    async fn send_recv(&mut self, cmd: &Commands) -> Result<CommandResponses> {
        let msg = serde_json::to_string(cmd)?;
        self.sock.write_all(msg.as_bytes()).await?;
        self.sock.write_all(b"\n").await?;
        self.sock.flush().await?;

        let mut response = String::new();
        self.sock.read_line(&mut response).await?;
        Ok(serde_json::from_str(&response)?)
    }

    pub async fn get(&mut self) -> Result<Counters> {
        let response = self.send_recv(&Commands::Get {}).await?;
        if let CommandResponses::Counters { values } = response {
            Ok(values)
        } else {
            bail!("Encountered wrong response to Get command\n{:?}", response);
        }
    }

    pub async fn get_and_reset(&mut self) -> Result<Counters> {
        let response = self.send_recv(&Commands::GetAndReset {}).await?;
        if let CommandResponses::Counters { values } = response {
            Ok(values)
        } else {
            bail!(
                "Encountered wrong response to GetAndReset command\n{:?}",
                response
            );
        }
    }

    pub async fn terminate(&mut self) -> Result<()> {
        let response = self.send_recv(&Commands::Terminate {}).await?;
        if response != CommandResponses::Ok {
            bail!(
                "Encountered wrong response to Terminate command\n{:?}",
                response
            );
        }

        Ok(())
    }
}

#[cfg(feature = "client")]
impl fmt::Debug for FuzzeeControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FuzzeeControl")
            .field("addr", &self.addr)
            .finish()
    }
}
