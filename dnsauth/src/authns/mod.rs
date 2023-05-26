pub mod dynamic;
pub mod fixed;

use color_eyre::eyre::{bail, eyre, Context as _};
use color_eyre::Result;
use log::warn;
use std::net::Ipv4Addr;
use trust_dns_client::rr::{LowerName, RrKey};
use trust_dns_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use trust_dns_proto::rr::{Name, Record, RecordSet, RecordType};
use trust_dns_server::authority::{MessageRequest, MessageResponseBuilder};
use trust_dns_server::ServerFuture;

/// Create an empty [`Message`] as a response to the `request`.
fn create_empty_response_from_request(request: &MessageRequest, nsid: &str) -> Message {
    let mut response = Message::new();
    if let Some(req_edns) = request.edns() {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);

        if req_edns.option(EdnsCode::NSID).is_some() {
            edns.options_mut().insert(EdnsOption::Unknown(
                3, /* NSID */
                nsid.as_bytes().to_vec(),
            ));
        }

        response.set_edns(edns);
    }
    response.add_query(request.query().original().clone());
    response.set_authoritative(true);
    response.set_checking_disabled(request.checking_disabled());
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_recursion_desired(request.recursion_desired());
    response
}

/// Create an empty [`Message`] as a response to the `request` with the given `response_code`.
fn create_error_response(
    request: &MessageRequest,
    response_code: ResponseCode,
    nsid: &str,
) -> Message {
    let mut response = create_empty_response_from_request(request, nsid);
    response.set_response_code(response_code);
    if response_code.high() != 0 {
        response.edns_mut().set_rcode_high(response_code.high());
    }
    response
}
