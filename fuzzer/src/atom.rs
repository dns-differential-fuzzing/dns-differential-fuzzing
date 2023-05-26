#![allow(dead_code)]

pub(crate) use self::build_generated::Atom;
use self::build_generated::*;
use std::fmt::{self, Display};

#[macro_use]
mod build_generated {
    #![allow(
        dead_code,
        missing_copy_implementations,
        missing_debug_implementations,
        unreachable_pub
    )]
    include!(concat!(env!("OUT_DIR"), "/atom.rs"));
}

// for x in l:
// if x.startswith("."):
//     prefix = ""
//     name = x.upper().replace("#","").replace(".", "__").replace("-", "_").strip("_")
// else:
//     prefix = "VALUE_"
//     name = x.upper().replace("#", "").replace(".", "_").replace("-", "_").replace("::", "_").strip("_")
// print(f"""pub(crate) static {prefix}{name}: &Atom = &atom!("{x}");""")

pub(crate) static FUZZ_CASE__CHECK_CACHE__SIZE: &Atom = &atom!(".fuzz_case.check_cache.#size");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__ADDITIONALS__COUNT: &Atom =
    &atom!(".fuzz_case.client_query.additionals.#count");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__ANSWERS__COUNT: &Atom =
    &atom!(".fuzz_case.client_query.answers.#count");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__EDNS__DNSSEC_OK: &Atom =
    &atom!(".fuzz_case.client_query.edns.dnssec_ok");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__EDNS__MAX_PAYLOAD: &Atom =
    &atom!(".fuzz_case.client_query.edns.max_payload");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__EDNS__VERSION: &Atom =
    &atom!(".fuzz_case.client_query.edns.version");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__ADDITIONAL_COUNT: &Atom =
    &atom!(".fuzz_case.client_query.header.additional_count");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__ANSWER_COUNT: &Atom =
    &atom!(".fuzz_case.client_query.header.answer_count");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__AUTHENTIC_DATA: &Atom =
    &atom!(".fuzz_case.client_query.header.authentic_data");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__AUTHORITATIVE: &Atom =
    &atom!(".fuzz_case.client_query.header.authoritative");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__CHECKING_DISABLED: &Atom =
    &atom!(".fuzz_case.client_query.header.checking_disabled");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__ID: &Atom =
    &atom!(".fuzz_case.client_query.header.id");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__MESSAGE_TYPE: &Atom =
    &atom!(".fuzz_case.client_query.header.message_type");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__NAME_SERVER_COUNT: &Atom =
    &atom!(".fuzz_case.client_query.header.name_server_count");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__OP_CODE: &Atom =
    &atom!(".fuzz_case.client_query.header.op_code");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__QUERY_COUNT: &Atom =
    &atom!(".fuzz_case.client_query.header.query_count");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__RECURSION_AVAILABLE: &Atom =
    &atom!(".fuzz_case.client_query.header.recursion_available");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__RECURSION_DESIRED: &Atom =
    &atom!(".fuzz_case.client_query.header.recursion_desired");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__RESPONSE_CODE: &Atom =
    &atom!(".fuzz_case.client_query.header.response_code");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__HEADER__TRUNCATED: &Atom =
    &atom!(".fuzz_case.client_query.header.truncated");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__NAME_SERVERS__COUNT: &Atom =
    &atom!(".fuzz_case.client_query.name_servers.#count");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__QUERIES__COUNT: &Atom =
    &atom!(".fuzz_case.client_query.queries.#count");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__QUERIES__0__NAME: &Atom =
    &atom!(".fuzz_case.client_query.queries.0.name");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__QUERIES__0__QUERY_CLASS: &Atom =
    &atom!(".fuzz_case.client_query.queries.0.query_class");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__QUERIES__0__QUERY_TYPE: &Atom =
    &atom!(".fuzz_case.client_query.queries.0.query_type");
pub(crate) static FUZZ_CASE__CLIENT_QUERY__SIG0__COUNT: &Atom =
    &atom!(".fuzz_case.client_query.sig0.#count");
pub(crate) static FUZZ_CASE__ID: &Atom = &atom!(".fuzz_case.id");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ADDITIONALS__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.0.additionals.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ADDITIONALS__0__DNS_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.0.additionals.0.dns_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ADDITIONALS__0__NAME_LABELS: &Atom =
    &atom!(".fuzz_case.server_responses.0.additionals.0.name_labels");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ADDITIONALS__0__RDATA: &Atom =
    &atom!(".fuzz_case.server_responses.0.additionals.0.rdata");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ADDITIONALS__0__RR_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.0.additionals.0.rr_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ADDITIONALS__0__TTL: &Atom =
    &atom!(".fuzz_case.server_responses.0.additionals.0.ttl");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ANSWERS__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.0.answers.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ANSWERS__0__DNS_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.0.answers.0.dns_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ANSWERS__0__NAME_LABELS: &Atom =
    &atom!(".fuzz_case.server_responses.0.answers.0.name_labels");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ANSWERS__0__RDATA: &Atom =
    &atom!(".fuzz_case.server_responses.0.answers.0.rdata");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ANSWERS__0__RR_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.0.answers.0.rr_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ANSWERS__0__TTL: &Atom =
    &atom!(".fuzz_case.server_responses.0.answers.0.ttl");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ANSWERS__1__DNS_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.0.answers.1.dns_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ANSWERS__1__NAME_LABELS: &Atom =
    &atom!(".fuzz_case.server_responses.0.answers.1.name_labels");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ANSWERS__1__RDATA: &Atom =
    &atom!(".fuzz_case.server_responses.0.answers.1.rdata");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ANSWERS__1__RR_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.0.answers.1.rr_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__ANSWERS__1__TTL: &Atom =
    &atom!(".fuzz_case.server_responses.0.answers.1.ttl");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__EDNS__DNSSEC_OK: &Atom =
    &atom!(".fuzz_case.server_responses.0.edns.dnssec_ok");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__EDNS__MAX_PAYLOAD: &Atom =
    &atom!(".fuzz_case.server_responses.0.edns.max_payload");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__EDNS__VERSION: &Atom =
    &atom!(".fuzz_case.server_responses.0.edns.version");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__ADDITIONAL_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.additional_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__ANSWER_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.answer_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__AUTHENTIC_DATA: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.authentic_data");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__AUTHORITATIVE: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.authoritative");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__CHECKING_DISABLED: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.checking_disabled");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__ID: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.id");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__MESSAGE_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.message_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__NAME_SERVER_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.name_server_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__OP_CODE: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.op_code");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__QUERY_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.query_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__RECURSION_AVAILABLE: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.recursion_available");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__RECURSION_DESIRED: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.recursion_desired");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__RESPONSE_CODE: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.response_code");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__HEADER__TRUNCATED: &Atom =
    &atom!(".fuzz_case.server_responses.0.header.truncated");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__NAME_SERVERS__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.0.name_servers.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__NAME_SERVERS__0__DNS_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.0.name_servers.0.dns_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__NAME_SERVERS__0__NAME_LABELS: &Atom =
    &atom!(".fuzz_case.server_responses.0.name_servers.0.name_labels");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__NAME_SERVERS__0__RDATA: &Atom =
    &atom!(".fuzz_case.server_responses.0.name_servers.0.rdata");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__NAME_SERVERS__0__RR_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.0.name_servers.0.rr_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__NAME_SERVERS__0__TTL: &Atom =
    &atom!(".fuzz_case.server_responses.0.name_servers.0.ttl");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__QUERIES__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.0.queries.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__QUERIES__0__NAME: &Atom =
    &atom!(".fuzz_case.server_responses.0.queries.0.name");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__QUERIES__0__QUERY_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.0.queries.0.query_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__QUERIES__0__QUERY_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.0.queries.0.query_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__0__SIG0__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.0.sig0.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ADDITIONALS__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.1.additionals.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ADDITIONALS__0__DNS_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.1.additionals.0.dns_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ADDITIONALS__0__NAME_LABELS: &Atom =
    &atom!(".fuzz_case.server_responses.1.additionals.0.name_labels");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ADDITIONALS__0__RDATA: &Atom =
    &atom!(".fuzz_case.server_responses.1.additionals.0.rdata");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ADDITIONALS__0__RR_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.1.additionals.0.rr_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ADDITIONALS__0__TTL: &Atom =
    &atom!(".fuzz_case.server_responses.1.additionals.0.ttl");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ANSWERS__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.1.answers.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ANSWERS__0__DNS_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.1.answers.0.dns_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ANSWERS__0__NAME_LABELS: &Atom =
    &atom!(".fuzz_case.server_responses.1.answers.0.name_labels");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ANSWERS__0__RDATA: &Atom =
    &atom!(".fuzz_case.server_responses.1.answers.0.rdata");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ANSWERS__0__RR_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.1.answers.0.rr_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ANSWERS__0__TTL: &Atom =
    &atom!(".fuzz_case.server_responses.1.answers.0.ttl");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ANSWERS__1__DNS_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.1.answers.1.dns_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ANSWERS__1__NAME_LABELS: &Atom =
    &atom!(".fuzz_case.server_responses.1.answers.1.name_labels");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ANSWERS__1__RDATA: &Atom =
    &atom!(".fuzz_case.server_responses.1.answers.1.rdata");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ANSWERS__1__RR_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.1.answers.1.rr_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__ANSWERS__1__TTL: &Atom =
    &atom!(".fuzz_case.server_responses.1.answers.1.ttl");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__EDNS__DNSSEC_OK: &Atom =
    &atom!(".fuzz_case.server_responses.1.edns.dnssec_ok");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__EDNS__MAX_PAYLOAD: &Atom =
    &atom!(".fuzz_case.server_responses.1.edns.max_payload");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__EDNS__VERSION: &Atom =
    &atom!(".fuzz_case.server_responses.1.edns.version");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__ADDITIONAL_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.additional_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__ANSWER_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.answer_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__AUTHENTIC_DATA: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.authentic_data");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__AUTHORITATIVE: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.authoritative");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__CHECKING_DISABLED: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.checking_disabled");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__ID: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.id");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__MESSAGE_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.message_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__NAME_SERVER_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.name_server_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__OP_CODE: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.op_code");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__QUERY_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.query_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__RECURSION_AVAILABLE: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.recursion_available");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__RECURSION_DESIRED: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.recursion_desired");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__RESPONSE_CODE: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.response_code");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__HEADER__TRUNCATED: &Atom =
    &atom!(".fuzz_case.server_responses.1.header.truncated");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__NAME_SERVERS__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.1.name_servers.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__NAME_SERVERS__0__DNS_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.1.name_servers.0.dns_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__NAME_SERVERS__0__NAME_LABELS: &Atom =
    &atom!(".fuzz_case.server_responses.1.name_servers.0.name_labels");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__NAME_SERVERS__0__RDATA: &Atom =
    &atom!(".fuzz_case.server_responses.1.name_servers.0.rdata");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__NAME_SERVERS__0__RR_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.1.name_servers.0.rr_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__NAME_SERVERS__0__TTL: &Atom =
    &atom!(".fuzz_case.server_responses.1.name_servers.0.ttl");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__QUERIES__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.1.queries.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__QUERIES__0__NAME: &Atom =
    &atom!(".fuzz_case.server_responses.1.queries.0.name");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__QUERIES__0__QUERY_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.1.queries.0.query_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__QUERIES__0__QUERY_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.1.queries.0.query_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__1__SIG0__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.1.sig0.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ADDITIONALS__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.2.additionals.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ADDITIONALS__0__DNS_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.2.additionals.0.dns_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ADDITIONALS__0__NAME_LABELS: &Atom =
    &atom!(".fuzz_case.server_responses.2.additionals.0.name_labels");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ADDITIONALS__0__RDATA: &Atom =
    &atom!(".fuzz_case.server_responses.2.additionals.0.rdata");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ADDITIONALS__0__RR_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.2.additionals.0.rr_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ADDITIONALS__0__TTL: &Atom =
    &atom!(".fuzz_case.server_responses.2.additionals.0.ttl");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ANSWERS__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.2.answers.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ANSWERS__0__DNS_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.2.answers.0.dns_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ANSWERS__0__NAME_LABELS: &Atom =
    &atom!(".fuzz_case.server_responses.2.answers.0.name_labels");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ANSWERS__0__RDATA: &Atom =
    &atom!(".fuzz_case.server_responses.2.answers.0.rdata");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ANSWERS__0__RR_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.2.answers.0.rr_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ANSWERS__0__TTL: &Atom =
    &atom!(".fuzz_case.server_responses.2.answers.0.ttl");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ANSWERS__1__DNS_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.2.answers.1.dns_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ANSWERS__1__NAME_LABELS: &Atom =
    &atom!(".fuzz_case.server_responses.2.answers.1.name_labels");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ANSWERS__1__RDATA: &Atom =
    &atom!(".fuzz_case.server_responses.2.answers.1.rdata");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ANSWERS__1__RR_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.2.answers.1.rr_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__ANSWERS__1__TTL: &Atom =
    &atom!(".fuzz_case.server_responses.2.answers.1.ttl");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__EDNS__DNSSEC_OK: &Atom =
    &atom!(".fuzz_case.server_responses.2.edns.dnssec_ok");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__EDNS__MAX_PAYLOAD: &Atom =
    &atom!(".fuzz_case.server_responses.2.edns.max_payload");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__EDNS__VERSION: &Atom =
    &atom!(".fuzz_case.server_responses.2.edns.version");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__ADDITIONAL_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.additional_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__ANSWER_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.answer_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__AUTHENTIC_DATA: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.authentic_data");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__AUTHORITATIVE: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.authoritative");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__CHECKING_DISABLED: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.checking_disabled");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__ID: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.id");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__MESSAGE_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.message_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__NAME_SERVER_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.name_server_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__OP_CODE: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.op_code");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__QUERY_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.query_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__RECURSION_AVAILABLE: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.recursion_available");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__RECURSION_DESIRED: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.recursion_desired");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__RESPONSE_CODE: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.response_code");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__HEADER__TRUNCATED: &Atom =
    &atom!(".fuzz_case.server_responses.2.header.truncated");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__NAME_SERVERS__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.2.name_servers.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__QUERIES__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.2.queries.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__QUERIES__0__NAME: &Atom =
    &atom!(".fuzz_case.server_responses.2.queries.0.name");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__QUERIES__0__QUERY_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.2.queries.0.query_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__QUERIES__0__QUERY_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.2.queries.0.query_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__2__SIG0__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.2.sig0.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__ADDITIONALS__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.3.additionals.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__ANSWERS__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.3.answers.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__ANSWERS__0__DNS_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.3.answers.0.dns_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__ANSWERS__0__NAME_LABELS: &Atom =
    &atom!(".fuzz_case.server_responses.3.answers.0.name_labels");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__ANSWERS__0__RDATA: &Atom =
    &atom!(".fuzz_case.server_responses.3.answers.0.rdata");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__ANSWERS__0__RR_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.3.answers.0.rr_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__ANSWERS__0__TTL: &Atom =
    &atom!(".fuzz_case.server_responses.3.answers.0.ttl");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__EDNS__DNSSEC_OK: &Atom =
    &atom!(".fuzz_case.server_responses.3.edns.dnssec_ok");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__EDNS__MAX_PAYLOAD: &Atom =
    &atom!(".fuzz_case.server_responses.3.edns.max_payload");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__EDNS__VERSION: &Atom =
    &atom!(".fuzz_case.server_responses.3.edns.version");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__ADDITIONAL_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.additional_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__ANSWER_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.answer_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__AUTHENTIC_DATA: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.authentic_data");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__AUTHORITATIVE: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.authoritative");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__CHECKING_DISABLED: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.checking_disabled");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__ID: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.id");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__MESSAGE_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.message_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__NAME_SERVER_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.name_server_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__OP_CODE: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.op_code");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__QUERY_COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.query_count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__RECURSION_AVAILABLE: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.recursion_available");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__RECURSION_DESIRED: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.recursion_desired");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__RESPONSE_CODE: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.response_code");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__HEADER__TRUNCATED: &Atom =
    &atom!(".fuzz_case.server_responses.3.header.truncated");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__NAME_SERVERS__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.3.name_servers.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__QUERIES__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.3.queries.#count");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__QUERIES__0__NAME: &Atom =
    &atom!(".fuzz_case.server_responses.3.queries.0.name");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__QUERIES__0__QUERY_CLASS: &Atom =
    &atom!(".fuzz_case.server_responses.3.queries.0.query_class");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__QUERIES__0__QUERY_TYPE: &Atom =
    &atom!(".fuzz_case.server_responses.3.queries.0.query_type");
pub(crate) static FUZZ_CASE__SERVER_RESPONSES__3__SIG0__COUNT: &Atom =
    &atom!(".fuzz_case.server_responses.3.sig0.#count");
pub(crate) static FUZZ_RESULT__COUNTERS: &Atom = &atom!(".fuzz_result.counters");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__ADDITIONALS__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.additionals.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__ANSWERS__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.answers.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__EDNS__COOKIE__CODE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.edns.Cookie.code");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__EDNS__COOKIE__VALUE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.edns.Cookie.value");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__EDNS__DNSSEC_OK: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.edns.dnssec_ok");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__EDNS__MAX_PAYLOAD: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.edns.max_payload");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__EDNS__VERSION: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.edns.version");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__ADDITIONAL_COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.additional_count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__ANSWER_COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.answer_count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__AUTHENTIC_DATA: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.authentic_data");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__AUTHORITATIVE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.authoritative");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__CHECKING_DISABLED: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.checking_disabled");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__ID: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.id");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__MESSAGE_TYPE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.message_type");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__NAME_SERVER_COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.name_server_count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__OP_CODE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.op_code");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__QUERY_COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.query_count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__RECURSION_AVAILABLE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.recursion_available");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__RECURSION_DESIRED: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.recursion_desired");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__RESPONSE_CODE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.response_code");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__HEADER__TRUNCATED: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.header.truncated");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__NAME_SERVERS__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.name_servers.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__QUERIES__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.queries.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__QUERIES__0__NAME: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.queries.0.name");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__QUERIES__0__QUERY_CLASS: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.queries.0.query_class");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__QUERIES__0__QUERY_TYPE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.queries.0.query_type");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__0__SIG0__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.0.sig0.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__ADDITIONALS__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.additionals.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__ANSWERS__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.answers.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__EDNS__DNSSEC_OK: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.edns.dnssec_ok");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__EDNS__MAX_PAYLOAD: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.edns.max_payload");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__EDNS__VERSION: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.edns.version");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__ADDITIONAL_COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.additional_count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__ANSWER_COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.answer_count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__AUTHENTIC_DATA: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.authentic_data");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__AUTHORITATIVE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.authoritative");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__CHECKING_DISABLED: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.checking_disabled");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__ID: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.id");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__MESSAGE_TYPE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.message_type");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__NAME_SERVER_COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.name_server_count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__OP_CODE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.op_code");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__QUERY_COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.query_count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__RECURSION_AVAILABLE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.recursion_available");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__RECURSION_DESIRED: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.recursion_desired");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__RESPONSE_CODE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.response_code");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__HEADER__TRUNCATED: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.header.truncated");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__NAME_SERVERS__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.name_servers.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__QUERIES__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.queries.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__QUERIES__0__NAME: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.queries.0.name");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__QUERIES__0__QUERY_CLASS: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.queries.0.query_class");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__QUERIES__0__QUERY_TYPE: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.queries.0.query_type");
pub(crate) static FUZZ_RESULT__FUZZEE_QUERIES__1__SIG0__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_queries.1.sig0.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_response.additionals.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__DNS_CLASS: &Atom =
    &atom!(".fuzz_result.fuzzee_response.additionals.0.dns_class");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__NAME_LABELS: &Atom =
    &atom!(".fuzz_result.fuzzee_response.additionals.0.name_labels");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__RDATA: &Atom =
    &atom!(".fuzz_result.fuzzee_response.additionals.0.rdata");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__RR_TYPE: &Atom =
    &atom!(".fuzz_result.fuzzee_response.additionals.0.rr_type");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__TTL: &Atom =
    &atom!(".fuzz_result.fuzzee_response.additionals.0.ttl");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__ANSWERS__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_response.answers.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__CODE15__CODE: &Atom =
    &atom!(".fuzz_result.fuzzee_response.edns.Code15.code");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__CODE15__ERROR_CODE: &Atom =
    &atom!(".fuzz_result.fuzzee_response.edns.Code15.error_code");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__CODE15__ERROR_VALUE: &Atom =
    &atom!(".fuzz_result.fuzzee_response.edns.Code15.error_value");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__DNSSEC_OK: &Atom =
    &atom!(".fuzz_result.fuzzee_response.edns.dnssec_ok");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__MAX_PAYLOAD: &Atom =
    &atom!(".fuzz_result.fuzzee_response.edns.max_payload");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__VERSION: &Atom =
    &atom!(".fuzz_result.fuzzee_response.edns.version");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ADDITIONAL_COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.additional_count");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ANSWER_COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.answer_count");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__AUTHENTIC_DATA: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.authentic_data");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__AUTHORITATIVE: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.authoritative");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__CHECKING_DISABLED: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.checking_disabled");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ID: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.id");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__MESSAGE_TYPE: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.message_type");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__NAME_SERVER_COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.name_server_count");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__OP_CODE: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.op_code");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__QUERY_COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.query_count");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RECURSION_AVAILABLE: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.recursion_available");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RECURSION_DESIRED: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.recursion_desired");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.response_code");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__TRUNCATED: &Atom =
    &atom!(".fuzz_result.fuzzee_response.header.truncated");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_response.name_servers.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__DNS_CLASS: &Atom =
    &atom!(".fuzz_result.fuzzee_response.name_servers.0.dns_class");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__NAME_LABELS: &Atom =
    &atom!(".fuzz_result.fuzzee_response.name_servers.0.name_labels");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__RDATA: &Atom =
    &atom!(".fuzz_result.fuzzee_response.name_servers.0.rdata");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__RR_TYPE: &Atom =
    &atom!(".fuzz_result.fuzzee_response.name_servers.0.rr_type");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__TTL: &Atom =
    &atom!(".fuzz_result.fuzzee_response.name_servers.0.ttl");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__QUERIES__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_response.queries.#count");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__QUERIES__0__NAME: &Atom =
    &atom!(".fuzz_result.fuzzee_response.queries.0.name");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__QUERIES__0__QUERY_CLASS: &Atom =
    &atom!(".fuzz_result.fuzzee_response.queries.0.query_class");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__QUERIES__0__QUERY_TYPE: &Atom =
    &atom!(".fuzz_result.fuzzee_response.queries.0.query_type");
pub(crate) static FUZZ_RESULT__FUZZEE_RESPONSE__SIG0__COUNT: &Atom =
    &atom!(".fuzz_result.fuzzee_response.sig0.#count");
pub(crate) static FUZZ_RESULT__ID: &Atom = &atom!(".fuzz_result.id");
pub(crate) static FUZZ_RESULT__RESPONSE_IDXS__COUNT: &Atom =
    &atom!(".fuzz_result.response_idxs.#count");
pub(crate) static FUZZ_RESULT__RESPONSE_IDXS__0: &Atom = &atom!(".fuzz_result.response_idxs.0");
pub(crate) static FUZZ_RESULT__RESPONSE_IDXS__1: &Atom = &atom!(".fuzz_result.response_idxs.1");
pub(crate) static FUZZ_RESULT__RESPONSE_IDXS__2: &Atom = &atom!(".fuzz_result.response_idxs.2");
pub(crate) static FUZZ_RESULT__RESPONSE_IDXS__3: &Atom = &atom!(".fuzz_result.response_idxs.3");
pub(crate) static FUZZ_RESULT__RESPONSE_IDXS__4: &Atom = &atom!(".fuzz_result.response_idxs.4");
pub(crate) static FUZZ_RESULT__RESPONSE_IDXS__5: &Atom = &atom!(".fuzz_result.response_idxs.5");
pub(crate) static FUZZ_RESULT__RESPONSE_IDXS__6: &Atom = &atom!(".fuzz_result.response_idxs.6");
pub(crate) static FUZZ_RESULT__RESPONSE_IDXS__7: &Atom = &atom!(".fuzz_result.response_idxs.7");
pub(crate) static FUZZ_RESULT__RESPONSE_IDXS__8: &Atom = &atom!(".fuzz_result.response_idxs.8");
pub(crate) static FUZZ_RESULT__RESPONSE_IDXS__9: &Atom = &atom!(".fuzz_result.response_idxs.9");
pub(crate) static HEADER__ID: &Atom = &atom!(".header.id");
pub(crate) static RESOLVER_NAME: &Atom = &atom!(".resolver_name");
pub(crate) static VALUE_127_97_1_1: &Atom = &atom!("127.97.1.1");
pub(crate) static VALUE_A: &Atom = &atom!("A");
pub(crate) static VALUE_AAAA: &Atom = &atom!("AAAA");
pub(crate) static VALUE_ANY: &Atom = &atom!("ANY");
pub(crate) static VALUE_BIND9: &Atom = &atom!("bind9");
pub(crate) static VALUE_BIND9_11: &Atom = &atom!("bind9_11");
pub(crate) static VALUE_ERROR: &Atom = &atom!("error");
pub(crate) static VALUE_FORMERR: &Atom = &atom!("FormErr");
pub(crate) static VALUE_FUZZ: &Atom = &atom!("fuzz.");
pub(crate) static VALUE_IN: &Atom = &atom!("IN");
pub(crate) static VALUE_KNOT_RESOLVER: &Atom = &atom!("knot-resolver");
pub(crate) static VALUE_MARADNS: &Atom = &atom!("maradns");
pub(crate) static VALUE_NOERROR: &Atom = &atom!("NoError");
pub(crate) static VALUE_NONE: &Atom = &atom!("NONE");
pub(crate) static VALUE_NOTIMP: &Atom = &atom!("NotImp");
pub(crate) static VALUE_NS_FUZZ_NS: &Atom = &atom!("ns-fuzz.ns.");
pub(crate) static VALUE_NS: &Atom = &atom!("NS");
pub(crate) static VALUE_PDNS_RECURSOR: &Atom = &atom!("pdns-recursor");
pub(crate) static VALUE_QUERY: &Atom = &atom!("query");
pub(crate) static VALUE_REFUSED: &Atom = &atom!("Refused");
pub(crate) static VALUE_RESOLVED: &Atom = &atom!("resolved");
pub(crate) static VALUE_SERVFAIL: &Atom = &atom!("ServFail");
pub(crate) static VALUE_SOA: &Atom = &atom!("SOA");
pub(crate) static VALUE_TRUST_DNS: &Atom = &atom!("trust-dns");
pub(crate) static VALUE_UNBOUND: &Atom = &atom!("unbound");
pub(crate) static VALUE_USIZE_MAX: &Atom = &atom!("usize::MAX");

#[repr(transparent)]
pub(crate) struct Natsorted(pub(crate) Atom);

impl fmt::Debug for Natsorted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0.as_ref(), f)
    }
}

impl Clone for Natsorted {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialOrd for Natsorted {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Natsorted {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        natord::compare(self.0.as_ref(), other.0.as_ref())
    }
}

impl PartialEq for Natsorted {
    fn eq(&self, other: &Self) -> bool {
        matches!(self.cmp(other), std::cmp::Ordering::Equal)
    }
}

impl Eq for Natsorted {}

impl AsRef<str> for Natsorted {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl Display for Natsorted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0.as_ref(), f)
    }
}
