// Mutation List
// Add/Remove server response
//
// Modify server response
//  - Modify bitflags
//  - Modify qname
//  - Modify qtype
//  - Modify qclass
//
//  - Add/Remove Resouce Record (new or cloned)
//  - Modify Resource Record
//   - Modify owner
//   - Modify type + rdata
//   - Modify TTL
//   - Modify class
//
// Modify client request
//  - Modify bitflags
//  - Modify qname
//  - Modify qtype
//  - Modify qclass

use crate::FuzzCaseMeta;
use dnsauth::definitions::{FuzzCase, FuzzCaseId};
use rand::prelude::SliceRandom as _;
use rand::Rng;
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
// use std::ops::DerefMut;
use trust_dns_proto::op::{Edns, Header, Message, MessageType, OpCode, Query, ResponseCode};
use trust_dns_proto::rr::domain::Label;
use trust_dns_proto::rr::{rdata, DNSClass, Name, RData, Record, RecordType};
use trust_dns_proto::serialize::binary::BinEncodable;

///////////////////////////////////////////////////////////////////////////////////////////
// Public functions used as entrypoints for this module
// region: public functions
///////////////////////////////////////////////////////////////////////////////////////////

/// Generate a new [`FuzzCaseMeta`]
pub(crate) fn new_fuzz_case(mut rng: impl Rng) -> FuzzCaseMeta {
    fn impl_new_fuzz_case(mut rng: impl Rng, label_set: &[String]) -> FuzzCase {
        let id = FuzzCaseId::new();

        let mut edns = Edns::new();
        edns.set_dnssec_ok(false)
            .set_max_payload(1200)
            .set_version(0);
        let name = make_new_name(&mut rng, label_set);

        let qclass = *[DNSClass::IN /* DNSClass::CH, DNSClass::ANY */]
            .choose(&mut rng)
            .expect("Non-empty slice");

        let rclass = *[DNSClass::IN /* DNSClass::CH, DNSClass::ANY */]
            .choose(&mut rng)
            .expect("Non-empty slice");
        let rdata = {
            match [
                RecordType::A,
                RecordType::AAAA,
                RecordType::NULL,
                RecordType::TXT,
            ]
            .choose(&mut rng)
            .expect("Non-empty slice")
            {
                RecordType::A => RData::A(Ipv4Addr::from(rng.gen::<u32>())),
                RecordType::AAAA => RData::AAAA(Ipv6Addr::from(rng.gen::<u128>())),
                RecordType::NULL => RData::NULL(rdata::NULL::with(rng.gen::<[u8; 16]>().to_vec())),
                RecordType::TXT => {
                    RData::TXT(rdata::TXT::new(vec![
                        make_new_name(&mut rng, label_set).to_string()
                    ]))
                }
                _ => unreachable!("All RecordTypes are covered"),
            }
        };
        let mut record = Record::from_rdata(name.clone(), 300, rdata);
        record.set_dns_class(rclass);

        let mut query = Query::new();
        query
            .set_name(name)
            .set_query_type(RecordType::A)
            .set_query_class(qclass);
        let mut client_query = Message::new();
        client_query
            .set_edns(edns.clone())
            .set_id(0)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .add_query(query.clone());
        let mut server_response = Message::new();
        server_response
            .set_authoritative(true)
            .set_id(0)
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_recursion_available(false)
            .set_edns(edns)
            .set_recursion_desired(false)
            .add_query(query)
            .add_answer(record);

        FuzzCase {
            id,
            client_query,
            server_responses: vec![server_response],
            check_cache: BTreeSet::new(),
        }
    }

    let label_set = make_new_label_set(&mut rng);
    let mut fuzz_case = impl_new_fuzz_case(&mut rng, &label_set);
    // Populate the information about the cache queries
    fuzz_case.update_check_cache();
    FuzzCaseMeta {
        fuzz_case,
        label_set,
        derived_from: None,
    }
}

/// Mutate a whole [`FuzzCase`] including client query and server responses.
#[allow(dead_code)]
pub(crate) fn mutate_fuzz_case(mut fc: FuzzCaseMeta, mut rng: impl Rng) -> FuzzCaseMeta {
    #[derive(Clone, Copy)]
    enum FuzzCaseMutations {
        AddResponse { index: usize },
        RemoveResponse { index: usize },
        MutateResponse { index: usize },
        MutateClientQuery,
    }

    let mut fuzz_case = fc.fuzz_case.clone();
    fuzz_case.id = FuzzCaseId::new();

    let mut mutations = Vec::new();
    for index in 0..fuzz_case.server_responses.len() {
        mutations.push((FuzzCaseMutations::AddResponse { index }, 1));
        mutations.push((FuzzCaseMutations::RemoveResponse { index }, 2));
        mutations.push((FuzzCaseMutations::MutateResponse { index }, 2));
    }
    mutations.push((
        FuzzCaseMutations::AddResponse {
            index: fuzz_case.server_responses.len(),
        },
        1,
    ));
    mutations.push((FuzzCaseMutations::MutateClientQuery, 5));

    let chosen_mutation = mutations
        .choose_weighted(&mut rng, |(_, weight): &(_, i32)| *weight)
        .unwrap()
        .0;
    match chosen_mutation {
        FuzzCaseMutations::AddResponse { index } => fuzz_case.server_responses.insert(
            index,
            make_new_response(rng, &fc.label_set, &fuzz_case.client_query.queries()[0]),
        ),
        FuzzCaseMutations::RemoveResponse { index } => {
            fuzz_case.server_responses.remove(index);
        }
        FuzzCaseMutations::MutateResponse { index } => {
            mutate_response(
                rng,
                &mut fc.label_set,
                &mut fuzz_case.server_responses[index],
            );
        }
        FuzzCaseMutations::MutateClientQuery => {
            mutate_client_query(rng, &mut fc.label_set, &mut fuzz_case.client_query);
        }
    }

    // Populate the information about the cache queries
    fuzz_case.update_check_cache();
    FuzzCaseMeta {
        fuzz_case,
        label_set: fc.label_set.clone(),
        derived_from: Some(fc.fuzz_case.id),
    }
}

// endregion: public functions
///////////////////////////////////////////////////////////////////////////////////////////
// Helper implementations
// region: helper implementations
///////////////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy)]
enum Section {
    Answers,
    Authorities,
    Additional,
}

trait MessageExt {
    fn get_section_mut(&mut self, section: Section) -> &mut Vec<Record>;
}

impl MessageExt for Message {
    fn get_section_mut(&mut self, section: Section) -> &mut Vec<Record> {
        match section {
            Section::Answers => self.answers_mut(),
            Section::Authorities => self.name_servers_mut(),
            Section::Additional => self.additionals_mut(),
        }
    }
}

// endregion: helper implementations
///////////////////////////////////////////////////////////////////////////////////////////
// Functions for creating new things
// region: make_new functions
///////////////////////////////////////////////////////////////////////////////////////////

/// Create a new [`DNSClass`]
///
/// This creates a type which can be used for a query or a resource record.
/// More values are allowed for a query.
fn make_new_class(mut rng: impl Rng, allow_query_values: bool) -> DNSClass {
    // Unknown values are sadly not possible, since they cannot be represented in the DNSClass enum
    let classes: &[_] = if allow_query_values {
        &[
            (DNSClass::IN, 1),
            (DNSClass::CH, 1),
            (DNSClass::HS, 1),
            (DNSClass::NONE, 1),
            (DNSClass::ANY, 1),
        ]
    } else {
        &[(DNSClass::IN, 1), (DNSClass::CH, 1), (DNSClass::HS, 1)]
    };
    classes
        .choose_weighted(&mut rng, |(_, weight): &(_, i32)| *weight)
        .unwrap()
        .0
}

/// Create a  new [`Name`] based on the available labels
fn make_new_name(mut rng: impl Rng, label_set: &[String]) -> Name {
    let subdomain =
        Name::from_labels([
            Label::from_raw_bytes(label_set.choose(&mut rng).unwrap().as_bytes())
                .expect("Bytes should be a valid label"),
        ])
        .unwrap();
    let domain = Name::from_labels(["test", "fuzz"]).unwrap();
    subdomain.append_domain(&domain).unwrap()
}

/// Create a set of labels which can be used for creating [`Name`]s
fn make_new_label_set(mut rng: impl Rng) -> Vec<String> {
    static ASCII_LETTERS: &[char] = &[
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    ];

    [(); 5]
        .map(|()| {
            ASCII_LETTERS
                .choose_multiple(&mut rng, 5)
                .collect::<String>()
        })
        .to_vec()
}

/// Create a new [`Opcode`] for a DNS [`Header`]
fn make_new_opcode(mut rng: impl Rng) -> OpCode {
    [
        (OpCode::Query, 10),
        (OpCode::Status, 1),
        (OpCode::Notify, 1),
        (OpCode::Update, 1),
    ]
    .choose_weighted(&mut rng, |(_, weight): &(_, i32)| *weight)
    .unwrap()
    .0
}

/// Create a new [`RecordType`]
///
/// This creates a type which can be used for a query or a resource record.
/// More values are allowed for a query.
fn make_new_qtype(mut rng: impl Rng) -> RecordType {
    *[
        RecordType::A,
        RecordType::AAAA,
        RecordType::TXT,
        RecordType::CNAME,
        RecordType::NS,
        RecordType::SRV,
        RecordType::SOA,
        // DNAME
        RecordType::Unknown(39),
        // For CVE-2022-3736
        RecordType::RRSIG,
        // Query only values
        RecordType::ANY,
    ]
    .choose(&mut rng)
    .unwrap()
}

/// Create a new [`RData`] for a resource record
fn make_new_rdata(mut rng: impl Rng, label_set: &[String]) -> RData {
    let record_type = {
        let mut rng = &mut rng;

        [
            RecordType::A,
            RecordType::AAAA,
            RecordType::TXT,
            RecordType::CNAME,
            RecordType::NS,
            RecordType::SRV,
            // DNAME
            RecordType::Unknown(39),
        ]
        .choose(&mut rng)
        .unwrap()
    };
    match record_type {
        RecordType::A => RData::A(Ipv4Addr::from(rng.gen::<u32>())),
        RecordType::AAAA => RData::AAAA(Ipv6Addr::from(rng.gen::<u128>())),
        RecordType::TXT => RData::TXT(rdata::TXT::new(vec![
            make_new_name(rng, label_set).to_string()
        ])),
        RecordType::CNAME => RData::CNAME(make_new_name(rng, label_set)),
        RecordType::NS => RData::NS(make_new_name(rng, label_set)),
        RecordType::SRV => RData::SRV(rdata::SRV::new(1, 1, 53, make_new_name(rng, label_set))),
        // DNAME
        RecordType::Unknown(39) => RData::Unknown {
            code: 39,
            rdata: rdata::NULL::with(
                make_new_name(rng, label_set)
                    .to_bytes()
                    .expect("Encoding a valid Name should always work"),
            ),
        },
        rtype => unreachable!("unsupported record type: {:?}", rtype),
    }
}

/// Create a new [`Record`]
fn make_new_record(mut rng: impl Rng, label_set: &[String]) -> Record {
    let name = make_new_name(&mut rng, label_set);
    let class = make_new_class(&mut rng, false);
    let ttl = rng.gen_range(0..86400 * 7);
    let rdata = make_new_rdata(&mut rng, label_set);
    let mut rec = Record::from_rdata(name, ttl, rdata);
    rec.set_dns_class(class);
    rec
}

/// Create a minimal server response matching the available client query
fn make_new_response(rng: impl Rng, label_set: &[String], client_query: &Query) -> Message {
    let mut edns = trust_dns_proto::op::Edns::new();
    edns.set_dnssec_ok(false)
        .set_max_payload(1200)
        .set_version(0);
    let record = make_new_record(rng, label_set);
    let mut server_response = Message::new();
    server_response
        .set_authoritative(true)
        .set_id(0)
        .set_message_type(trust_dns_proto::op::MessageType::Response)
        .set_op_code(trust_dns_proto::op::OpCode::Query)
        .set_recursion_available(false)
        .set_edns(edns)
        .set_recursion_desired(false)
        .add_query(client_query.clone())
        .add_answer(record);
    server_response
}

/// Create a new [`ResponseCode`] for a DNS [`Header`]
///
/// This only creates the smaller codes, which do not require the `OPT` record for encoding.
fn make_new_response_code(mut rng: impl Rng) -> ResponseCode {
    [
        (ResponseCode::NoError, 10),
        (ResponseCode::FormErr, 1),
        (ResponseCode::ServFail, 1),
        (ResponseCode::NXDomain, 1),
        (ResponseCode::NotImp, 1),
        (ResponseCode::Refused, 1),
        (ResponseCode::YXDomain, 1),
        (ResponseCode::YXRRSet, 1),
        (ResponseCode::NXRRSet, 1),
        (ResponseCode::NotAuth, 1),
        (ResponseCode::NotZone, 1),
    ]
    .choose_weighted(&mut rng, |(_, weight): &(_, i32)| *weight)
    .unwrap()
    .0
}

/// Mutate the `TTL` of a [`Record`]
fn make_new_ttl(mut rng: impl Rng, ttl: &mut u32) {
    *ttl = rng.gen_range(0..86400 * 7);
}

// endregion: make_new functions
///////////////////////////////////////////////////////////////////////////////////////////
// Functions for mutating things
// region: mutation functions
///////////////////////////////////////////////////////////////////////////////////////////

/// Mutate the [`DNSClass`] of a [`Query`] or [`Record`]
///
/// More values are allowed for a query.
fn mutate_class(rng: impl Rng, class: &mut DNSClass, allow_query_values: bool) {
    *class = make_new_class(rng, allow_query_values);
}

/// Mutate the client query of a [`FuzzSuite`].
fn mutate_client_query(mut rng: impl Rng, label_set: &mut Vec<String>, msg: &mut Message) {
    #[derive(Clone, Copy)]
    enum QueryMutations {
        ModifyHeader,
        ModifyQuestion,
    }

    let mutations = [
        (QueryMutations::ModifyHeader, 1),
        (QueryMutations::ModifyQuestion, 1),
    ];
    let chosen_mutation = mutations
        .choose_weighted(&mut rng, |(_, weight): &(_, i32)| *weight)
        .unwrap()
        .0;
    match chosen_mutation {
        QueryMutations::ModifyHeader => mutate_header(rng, &mut *msg),
        QueryMutations::ModifyQuestion => mutate_query(rng, label_set, &mut msg.queries_mut()[0]),
    }
}

/// Mutate the [`Header`] of a [`Message`]
fn mutate_header(mut rng: impl Rng, header: &mut Header) {
    // |QR|   Opcode  |AA|TC|RD|RA|ZZ|AD|CD|   RCODE   |
    #[derive(Clone, Copy)]
    #[allow(clippy::enum_variant_names)]
    enum HeaderMutations {
        // Flag QR bit
        ModifyQuery,
        // Flag Opcode
        ModifyOpcode,
        // Flag AA bit
        ModifyAuthoritativeAnswer,
        // Flag TC bit
        ModifyTruncatedResponse,
        // Flag RD bit
        ModifyRecursionDesired,
        // Flag RA bit
        ModifyRecursionAvailable,
        // No API available to modify
        // // Flag Z bit (reserved)
        // ModifyReserved,
        // Flag AD bit
        ModifyAuthenticData,
        // Flag CD bit
        ModifyCheckingDisabled,
        // Flag RCODE
        ModifyRcode,
    }

    let mutations = [
        (HeaderMutations::ModifyQuery, 1),
        (HeaderMutations::ModifyOpcode, 1),
        (HeaderMutations::ModifyAuthoritativeAnswer, 1),
        (HeaderMutations::ModifyTruncatedResponse, 1),
        (HeaderMutations::ModifyRecursionDesired, 1),
        (HeaderMutations::ModifyRecursionAvailable, 1),
        // (HeaderMutations::ModifyReserved, 1),
        (HeaderMutations::ModifyAuthenticData, 1),
        (HeaderMutations::ModifyCheckingDisabled, 1),
        (HeaderMutations::ModifyRcode, 1),
    ];
    let chosen_mutation = mutations
        .choose_weighted(&mut rng, |(_, weight): &(_, i32)| *weight)
        .unwrap()
        .0;
    match chosen_mutation {
        HeaderMutations::ModifyQuery => {
            header.set_message_type(match header.message_type() {
                MessageType::Query => MessageType::Response,
                MessageType::Response => MessageType::Query,
            });
        }
        HeaderMutations::ModifyOpcode => {
            header.set_op_code(make_new_opcode(rng));
        }
        HeaderMutations::ModifyAuthoritativeAnswer => {
            header.set_authoritative(!header.authoritative());
        }
        HeaderMutations::ModifyTruncatedResponse => {
            header.set_truncated(!header.truncated());
        }
        HeaderMutations::ModifyRecursionDesired => {
            header.set_recursion_desired(!header.recursion_desired());
        }
        HeaderMutations::ModifyRecursionAvailable => {
            header.set_recursion_available(!header.recursion_available());
        }
        // HeaderMutations::ModifyReserved => {
        //     header.set_reserved(!header.reserved());
        // }
        HeaderMutations::ModifyAuthenticData => {
            header.set_authentic_data(!header.authentic_data());
        }
        HeaderMutations::ModifyCheckingDisabled => {
            header.set_checking_disabled(!header.checking_disabled());
        }
        HeaderMutations::ModifyRcode => {
            header.set_response_code(make_new_response_code(rng));
        }
    }
}

/// Mutate a [`Name`] by modifying its labels
fn mutate_name(mut rng: impl Rng, label_set: &mut Vec<String>, name: &mut Name) {
    #[allow(clippy::enum_variant_names)]
    #[derive(Clone, Copy)]
    enum NameMutations {
        PushLabel,
        PopLabel,
        MutateLabel { index: usize },
        // create label with internal `.`
        MergeLabels { index: usize },
        // Append `\0`` to TLD
        ZeroByte,
        // Append `\0`` to TLD and duplicate the name
        ZeroByteDuplicate,
    }

    let mut mutations = vec![
        (NameMutations::PushLabel, 20),
        (NameMutations::ZeroByte, 1),
        (NameMutations::ZeroByteDuplicate, 1),
    ];
    let zone = Name::from_labels(["test", "fuzz"]).unwrap();
    if zone.zone_of(name) && &zone != name {
        mutations.push((NameMutations::PopLabel, 30));
    }
    for idx in 0..(name.iter().count().saturating_sub(zone.iter().count())) {
        mutations.push((NameMutations::MutateLabel { index: idx }, 20));
    }
    for idx in 0..name.num_labels() - 1 {
        mutations.push((
            NameMutations::MergeLabels {
                index: idx as usize,
            },
            1,
        ));
    }
    let chosen_mutation = mutations
        .choose_weighted(&mut rng, |(_, weight): &(_, i32)| *weight)
        .unwrap()
        .0;

    let new_name =
        match chosen_mutation {
            NameMutations::PushLabel => {
                let new_label = label_set.choose(&mut rng).unwrap();
                Name::from_labels([Label::from_raw_bytes(new_label.as_bytes())
                    .expect("Bytes should be a valid label")])
                .unwrap()
                .append_domain(name)
                .unwrap()
            }
            NameMutations::PopLabel => name.base_name(),
            NameMutations::MutateLabel { index } => Name::from_labels(
                name.iter()
                    .enumerate()
                    .map(|(idx, label)| {
                        if idx == index {
                            label_set.choose(&mut rng).unwrap().as_bytes()
                        } else {
                            label
                        }
                    })
                    .map(|b| Label::from_raw_bytes(b).expect("Bytes should be a valid label")),
            )
            .unwrap(),
            NameMutations::MergeLabels { index } => {
                let mut labels = name.iter().collect::<Vec<_>>();
                let mut new_label = labels[index].to_vec();
                if new_label.len() + 1 + labels[index + 1].len() < 63 {
                    new_label.push(b'.');
                    new_label.extend_from_slice(labels[index + 1]);
                    labels[index] = &new_label;
                    labels.remove(index + 1);
                    let new_name =
                        Name::from_labels(labels.into_iter().map(|b| {
                            Label::from_raw_bytes(b).expect("Bytes should be a valid label")
                        }))
                        .unwrap();

                    label_set.push(String::from_utf8(new_label).unwrap());

                    new_name
                } else {
                    name.clone()
                }
            }
            NameMutations::ZeroByte => {
                let mut labels = name.iter().collect::<Vec<_>>();
                let mut new_label = labels.pop().unwrap().to_vec();
                if new_label.len() < 63 {
                    new_label.push(0);
                    labels.push(&new_label);
                    let new_name =
                        Name::from_labels(labels.into_iter().map(|b| {
                            Label::from_raw_bytes(b).expect("Bytes should be a valid label")
                        }))
                        .unwrap();

                    // All labels are ASCII, so also UTF-8, including the 0 byte
                    label_set.push(String::from_utf8(new_label).unwrap());

                    new_name
                } else {
                    name.clone()
                }
            }
            NameMutations::ZeroByteDuplicate => {
                let mut labels = name.iter().collect::<Vec<_>>();
                let mut new_label = labels.pop().unwrap().to_vec();
                if new_label.len() < 63 {
                    new_label.push(0);
                    labels.push(&new_label);
                    let new_name =
                        Name::from_labels(labels.into_iter().map(|b| {
                            Label::from_raw_bytes(b).expect("Bytes should be a valid label")
                        }))
                        .unwrap()
                        .append_domain(name)
                        .unwrap();

                    // All labels are ASCII, so also UTF-8, including the 0 byte
                    label_set.push(String::from_utf8(new_label).unwrap());

                    new_name
                } else {
                    name.clone()
                }
            }
        };
    *name = new_name;
}

/// Mutate the [`Query`] of a [`Message`]
fn mutate_query(mut rng: impl Rng, label_set: &mut Vec<String>, query: &mut Query) {
    #[allow(clippy::enum_variant_names)]
    #[derive(Clone, Copy)]
    enum QueryMutations {
        MutateQname,
        MutateQtype,
        MutateQclass,
    }
    let mutations = [
        (QueryMutations::MutateQname, 1),
        (QueryMutations::MutateQtype, 1),
        (QueryMutations::MutateQclass, 1),
    ];
    let chosen_mutation = mutations
        .choose_weighted(&mut rng, |(_, weight): &(_, i32)| *weight)
        .unwrap()
        .0;
    match chosen_mutation {
        QueryMutations::MutateQname => {
            let mut qname = query.name().clone();
            mutate_name(rng, label_set, &mut qname);
            query.set_name(qname)
        }
        QueryMutations::MutateQtype => query.set_query_type(make_new_qtype(rng)),
        QueryMutations::MutateQclass => {
            let mut class = query.query_class();
            mutate_class(rng, &mut class, true);
            query.set_query_class(class)
        }
    };
}

/// Mutate the [`RData`] of a [`Record`]
fn mutate_rdata(rng: impl Rng, label_set: &[String], rdata: &mut RData) {
    *rdata = make_new_rdata(rng, label_set);
}

/// Mutate a [`Record`]
fn mutate_record(mut rng: impl Rng, label_set: &mut Vec<String>, record: &mut Record) {
    #[allow(clippy::enum_variant_names)]
    #[derive(Clone, Copy)]
    enum RecordMutations {
        MutateName,
        MutateRdata,
        MutateTtl,
        MutateClass,
    }
    let mut mutations = vec![
        (RecordMutations::MutateName, 1),
        (RecordMutations::MutateTtl, 1),
        (RecordMutations::MutateClass, 1),
    ];
    if record.data().is_some() {
        mutations.push((RecordMutations::MutateRdata, 1));
    }
    let chosen_mutation = mutations
        .choose_weighted(&mut rng, |(_, weight): &(_, i32)| *weight)
        .unwrap()
        .0;
    match chosen_mutation {
        RecordMutations::MutateName => {
            let mut name = record.name().clone();
            mutate_name(rng, label_set, &mut name);
            record.set_name(name);
        }
        RecordMutations::MutateRdata => {
            let rdata = record
                .data_mut()
                .expect("Mutation is only availble if RData exists.");
            mutate_rdata(rng, label_set, rdata);
            let rtype = rdata.to_record_type();
            record.set_record_type(rtype);
        }
        RecordMutations::MutateTtl => {
            let mut ttl = record.ttl();
            make_new_ttl(rng, &mut ttl);
            record.set_ttl(ttl);
        }
        RecordMutations::MutateClass => {
            let mut class = record.dns_class();
            mutate_class(rng, &mut class, false);
            record.set_dns_class(class);
        }
    };
}

/// Mutate a server response.
///
/// This includes modifying the header, the query, or any of the three other sections.
fn mutate_response(mut rng: impl Rng, label_set: &mut Vec<String>, msg: &mut Message) {
    #[derive(Clone, Copy)]
    enum ResponseMutations {
        MutateHeader,
        MutateQuery,
        AddResourceRecord { section: Section, index: usize },
        RemoveResourceRecord { section: Section, index: usize },
        ModifyResourceRecord { section: Section, index: usize },
    }

    let mut mutations = vec![
        (ResponseMutations::MutateHeader, 5),
        (ResponseMutations::MutateQuery, 5),
    ];
    for section in [Section::Answers, Section::Authorities, Section::Additional] {
        let rrcount = msg.get_section_mut(section).len();
        for index in 0..rrcount {
            mutations.push((ResponseMutations::AddResourceRecord { section, index }, 1));
            mutations.push((
                ResponseMutations::RemoveResourceRecord { section, index },
                2,
            ));
            mutations.push((
                ResponseMutations::ModifyResourceRecord { section, index },
                2,
            ));
        }
        mutations.push((
            ResponseMutations::AddResourceRecord {
                section,
                index: rrcount,
            },
            1,
        ));
    }

    let chosen_mutation = mutations
        .choose_weighted(&mut rng, |(_, weight): &(_, i32)| *weight)
        .unwrap()
        .0;
    match chosen_mutation {
        ResponseMutations::MutateHeader => mutate_header(rng, &mut *msg),
        ResponseMutations::MutateQuery => mutate_query(rng, label_set, &mut msg.queries_mut()[0]),
        ResponseMutations::AddResourceRecord { section, index } => msg
            .get_section_mut(section)
            .insert(index, make_new_record(rng, label_set)),
        ResponseMutations::RemoveResourceRecord { section, index } => {
            msg.get_section_mut(section).remove(index);
        }
        ResponseMutations::ModifyResourceRecord { section, index } => {
            mutate_record(rng, label_set, &mut msg.get_section_mut(section)[index]);
        }
    }
}

///////////////////////////////////////////////////////////////////////////////////////////
// endregion: mutation functions
///////////////////////////////////////////////////////////////////////////////////////////
