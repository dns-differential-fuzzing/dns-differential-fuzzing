//! This module contains a dumb AuthNS server for serving the fuzzing responses.
//!
//! The main goal of this AuthNS is being as simple as possible and only serving pre-defined answers.
//! The pre-defined answers are the fuzzing input.
//! The server is split into two parts, the [`DynamicDnsAuthServer`] which is the main server and [`DynamicDnsAuthServerHandle`] which shared some state and is used to control the server.

use super::*;
use crate::utils::next_ipv4;
use futures::future::{self, AbortHandle, Abortable};
use futures::lock::Mutex;
use std::iter;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_client::op::LowerQuery;

/// AuthNS used for fuzzing.
///
/// The implementations details should stay private to this type.
/// Some aspects can be controlled via [`DynamicDnsAuthServerHandle`].
#[derive(Debug)]
pub struct DynamicDnsAuthServer {
    /// State controlling the behavior of the DNS server
    state: Arc<DynamicDnsAuthServerState>,
}

/// A handle to control the [`DynamicDnsAuthServer`].
#[derive(Clone, Debug)]
pub struct DynamicDnsAuthServerHandle {
    pub abort_handle: AbortHandle,
    /// State controlling the behavior of the DNS server
    pub state: Arc<DynamicDnsAuthServerState>,
}

/// Shared state between a [`DynamicDnsAuthServer`] and a [`DynamicDnsAuthServerHandle`].
#[derive(Debug, Default)]
pub struct DynamicDnsAuthServerState {
    /// A list of responses to queries.
    ///
    /// The fuzzing AuthNS will search for the first response matching the query section of the query.
    /// If the list is empty a NODATA response will be served.
    pub fuzzing_response: Mutex<Vec<Message>>,
    /// Stores the list of all queries received by the AuthNS.
    pub query_list: Mutex<Vec<Message>>,
    /// Stores the index of the answer served.
    /// The entries match in the order to the `query_list`.
    /// `usize::MAX` means a `NODATA` answer was served.
    pub answer_index: Mutex<Vec<usize>>,
}

impl DynamicDnsAuthServer {
    /// Spawn a DNS server listening on the provided IP address
    ///
    /// The Server will listen on port 53 for both UDP and TCP.
    /// Responses are created by calling `DynamicDnsAuthServer::create_response`.
    pub async fn spawn(addr: Ipv4Addr) -> Result<DynamicDnsAuthServerHandle> {
        Self::spawn_n(addr, 1).await
    }

    /// Spawn one DNS server listening on `n` IP addresses.
    ///
    /// The server creates a socket for each IP address and both UDP and TCP.
    /// The IP addresses will be used sequentially, starting from the provided `addr`.
    pub async fn spawn_n(mut addr: Ipv4Addr, n: u16) -> Result<DynamicDnsAuthServerHandle> {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let state = Arc::default();
        let fuzz_server = Self {
            state: Arc::clone(&state),
        };
        let mut fuzz_server = ServerFuture::new(fuzz_server);

        let (udps, tcps): (Result<Vec<UdpSocket>>, Result<Vec<_>>) = tokio::join!(
            future::try_join_all(
                iter::from_fn(move || {
                    let res = addr;
                    addr = next_ipv4(addr);
                    Some(res)
                })
                .take(usize::from(n))
                .map(|addr| {
                    // Register Sockets
                    async move {
                        let socket_addr: (Ipv4Addr, u16) = (addr, 53);
                        UdpSocket::bind(socket_addr)
                            .await
                            .wrap_err_with(|| format!("Could not bind listen socket on UDP {addr}"))
                    }
                }),
            ),
            future::try_join_all(
                iter::from_fn(move || {
                    let res = addr;
                    addr = next_ipv4(addr);
                    Some(res)
                })
                .take(usize::from(n))
                .map(|addr| {
                    async move {
                        let socket_addr: (Ipv4Addr, u16) = (addr, 53);
                        TcpListener::bind(socket_addr)
                            .await
                            .wrap_err_with(|| format!("Could not bind listen socket on UDP {addr}"))
                    }
                }),
            )
        );

        udps?.into_iter().for_each(|udp| {
            fuzz_server.register_socket(udp);
        });
        tcps?.into_iter().for_each(|tcp| {
            fuzz_server.register_listener(tcp, Duration::new(3, 0));
        });

        tokio::spawn(Abortable::new(
            fuzz_server.block_until_done(),
            abort_registration,
        ));

        Ok(DynamicDnsAuthServerHandle {
            abort_handle,
            state,
        })
    }

    /// Create a response to the fuzzee's query.
    async fn create_response(&self, request: &MessageRequest) -> Message {
        log::trace!("Fuzzing DNS Auth: {}", request.query().name());
        // Add query to the query list
        if let Ok(msg) = trust_dns_proto::serialize::binary::BinEncodable::to_bytes(request)
            .and_then(|bytes| {
                <Message as trust_dns_proto::serialize::binary::BinDecodable>::from_bytes(&bytes)
            })
        {
            self.state.query_list.lock().await.push(msg);
        } else {
            warn!("Could not parse query and append it to the query list.");
        }

        // Search through the list of responses for an entry matching the query
        for (idx, resp) in self.state.fuzzing_response.lock().await.iter().enumerate() {
            for resp_query in resp.queries() {
                if LowerQuery::query(resp_query.clone()) == *request.query() {
                    let mut response = resp.clone();
                    response.set_id(request.id());
                    log::trace!("Fuzzing AuthNS prepared response {idx}");
                    self.state.answer_index.lock().await.push(idx);
                    return response;
                }
            }
        }

        // If we haven't responded yet treat it as a NODATA response
        log::trace!("Fuzzing AuthNS default NODATA response");
        self.state.answer_index.lock().await.push(usize::MAX);
        let mut resp = create_error_response(request, ResponseCode::NoError, "DNS Fuzzer");
        // We need to add a SOA record
        // https://www.rfc-editor.org/rfc/rfc2308.html#section-3
        // Take the last two labels, i.e., 0000.fuzz., as the zone
        let encompasing_zone = request.query().original().name().trim_to(2);
        // private.server. testing.test. 15337002 1800 900 604800 1800
        let soa = trust_dns_proto::rr::rdata::SOA::new(
            Name::from_str("private.server.").expect("Static string is valid name"),
            Name::from_str("testing.test.").expect("Static string is valid name"),
            15337002,
            1800,
            900,
            604800,
            1800,
        );
        let soa = Record::from_rdata(encompasing_zone, 300, trust_dns_proto::rr::RData::SOA(soa));
        resp.add_name_server(soa);
        resp
    }
}

impl DynamicDnsAuthServerHandle {
    /// Return a list of all queries received since the last time this function was called.
    ///
    /// The second tuple entries indicates the index of the answer served.
    /// Boths lists should be the same length and the entries match in the order.
    pub async fn get_query_list(&self) -> Result<(Vec<Message>, Vec<usize>)> {
        let mut query_list = Vec::new();
        let mut answer_index = Vec::new();
        let mut ql_lock = self.state.query_list.lock().await;
        let mut ans_lock = self.state.answer_index.lock().await;
        std::mem::swap(&mut query_list, &mut *ql_lock);
        std::mem::swap(&mut answer_index, &mut *ans_lock);
        Ok((query_list, answer_index))
    }
}

#[async_trait::async_trait]
impl trust_dns_server::server::RequestHandler for DynamicDnsAuthServer {
    async fn handle_request<R: trust_dns_server::server::ResponseHandler>(
        &self,
        request: &trust_dns_server::server::Request,
        mut response_handle: R,
    ) -> trust_dns_server::server::ResponseInfo {
        // TODO: Check if the correct zone for the current test is used.
        // Otherwise belayed queries might be mixed together
        let request_message = &**request;
        log::trace!("request: {:?}", request_message);
        let msg = self.create_response(request_message).await;
        let msg = MessageResponseBuilder::build_with_message(&msg);
        match response_handle.send_response(msg).await {
            Ok(response_info) => response_info,
            Err(err) => {
                warn!("Could not send response: {err}");
                let mut header = trust_dns_proto::op::Header::new();
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        }
    }
}
