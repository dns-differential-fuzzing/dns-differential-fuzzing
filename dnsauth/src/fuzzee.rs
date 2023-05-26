//! The [`Fuzzee`] is a control handle to the fuzzed process.
//!
//! It provides functionality to send queries and terminate the process.
//! It also provides access to a [`FuzzeeControl`] which implements the client part of the fuzzer-protocol to fetch coverage information.

use color_eyre::eyre::{Context as _, Result};
use futures::StreamExt as _;
use fuzzer_protocol::FuzzeeControl;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::process::{Child, Command};
use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_client::error::ClientErrorKind;
use trust_dns_proto::error::ProtoErrorKind;
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::{DNSClass, Name, RecordType};
use trust_dns_proto::udp::UdpClientStream;
use trust_dns_proto::xfer::DnsResponse;

/// Control handle to the fuzzed process.
///
/// It allows sending queries, terminating the process.
/// Via the `controller` handle the fuzzer-protocol can be used to query and reset the coverage counters.
pub struct Fuzzee {
    process: Child,
    pub controller: FuzzeeControl,
    dns_client: AsyncClient,
    _dns_port: SocketAddrV4,
}

impl Fuzzee {
    pub async fn new() -> Result<Self> {
        let dns_port = 53;

        let control_port = SocketAddrV4::new(Ipv4Addr::new(127, 222, 0, 1), 20001);
        let dns_port = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), dns_port);

        // Start the instrumented process
        let process = Command::new("/usr/local/bin/fuzzee")
            .env("FUZZEE_LISTEN_ADDR", control_port.to_string())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .wrap_err("Could not spawn fuzzee")?;

        let (controller, dns_client): (Result<_>, Result<_>) = tokio::join!(
            async {
                let mut last_error = None;
                for _ in 0..20 {
                    // Open a communication channel with the fuzzee
                    match FuzzeeControl::new(control_port).await {
                        Ok(controller) => return Ok(controller),
                        Err(err) => {
                            last_error = Some(err);
                            // Wait a moment for the fuzzee to start the TCP socket
                            tokio::time::sleep(Duration::new(0, 100_000_000)).await;
                        }
                    }
                }
                Err(last_error.expect("Must be set if loop continued until here."))?
            },
            async {
                // Open DNS client for our fuzzee
                let stream = UdpClientStream::<UdpSocket>::with_timeout(
                    dns_port.into(),
                    Duration::new(0, 750_000_000),
                );
                let (dns_client, background_task) = AsyncClient::connect(stream).await?;
                tokio::spawn(background_task);
                Ok(dns_client)
            }
        );
        let (controller, dns_client) = (controller?, dns_client?);

        Ok(Self {
            process,
            controller,
            dns_client,
            _dns_port: dns_port,
        })
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        Ok(self.process.try_wait()?)
    }

    /// Terminate the fuzzee.
    pub async fn terminate(&mut self) -> ExitStatus {
        // Ask nicely to terminate the process
        let _ = tokio::time::timeout(Duration::from_secs(60), self.controller.terminate()).await;
        if let Ok(Some(exit)) = self.process.try_wait() {
            return exit;
        }
        // Kill the fuzzee if still running
        let _ = self.process.kill().await;
        self.process
            .wait()
            .await
            .expect("Process must be terminated by now.")
    }

    /// Send a full [`Message`] to the fuzzee and return its response.
    pub async fn query(&self, query: Message) -> Result<Option<DnsResponse>> {
        use trust_dns_proto::DnsHandle as _;
        match self.dns_client.clone().send(query).next().await {
            Some(Ok(msg)) => Ok(Some(msg)),
            Some(Err(err)) if matches!(err.kind(), ProtoErrorKind::Timeout) => Ok(None),
            Some(Err(err)) => Err(err)?,
            None => Ok(None),
        }
    }

    /// Send a simple pre-fetching query to the fuzzee and return its response.
    pub async fn query_by_name(
        &self,
        qname: Name,
        qtype: RecordType,
    ) -> Result<Option<DnsResponse>> {
        match self
            .dns_client
            .clone()
            .query(qname, DNSClass::IN, qtype)
            .await
        {
            Ok(resp) => Ok(Some(resp)),
            Err(err) if matches!(err.kind(), ClientErrorKind::Timeout) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Send a *non-recursive* query to the fuzzee and return its response.
    pub async fn query_no_recurse(
        &self,
        qname: Name,
        qtype: RecordType,
        qclass: DNSClass,
    ) -> Result<Option<DnsResponse>> {
        use trust_dns_proto::op::*;

        let mut query = Query::query(qname, qtype);
        query.set_query_class(qclass);
        let mut message: Message = Message::new();
        message
            .add_query(query)
            .set_id(0)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(false);
        message.edns_mut().set_max_payload(1232).set_version(0);
        self.query(message).await
    }
}

impl fmt::Debug for Fuzzee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fuzzee")
            .field("process", &self.process)
            .field("controller", &self.controller)
            .field("dns_client", &self._dns_port)
            .finish()
    }
}
