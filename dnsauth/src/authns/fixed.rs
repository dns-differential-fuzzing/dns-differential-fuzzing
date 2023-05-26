//! This module contains an AuthNS server which only serves fixed, i.e., static, responses.
//!
//! This is an extension to the [`InMemoryAuthority`] and turns it into a fully fledged DNS server.

use super::*;
use crate::config::AuthConfig;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound;
use std::sync::Arc;
use trust_dns_server::authority::Authority;
use trust_dns_server::store::in_memory::InMemoryAuthority;

/// DNS server serving a static zone.
pub struct DnsAuthServer {
    authority: Rfc6672Searcher,
    nsid: String,
}

impl fmt::Debug for DnsAuthServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsAuthServer").finish_non_exhaustive()
    }
}

impl DnsAuthServer {
    pub fn with_config(config: AuthConfig) -> Result<Self> {
        let mut records = BTreeMap::new();
        let mut origin = None;

        for record in config.data.clone() {
            let (name, rr_key, rec_type, rdata) = record.into();
            if rec_type == RecordType::SOA {
                if origin.is_some() {
                    bail!("Found more than one SOA for zone {name}");
                }
                origin = Some((
                    name.clone(),
                    Record::from_rdata(name.clone(), config.ttl, rdata.clone()),
                ));
            }
            match records.entry(rr_key) {
                Entry::Vacant(entry) => {
                    let mut rec_set = RecordSet::with_ttl(name, rec_type, config.ttl);
                    rec_set.add_rdata(rdata);
                    entry.insert(rec_set);
                }
                Entry::Occupied(mut entry) => {
                    entry.get_mut().add_rdata(rdata);
                }
            }
        }
        let origin = origin.ok_or_else(|| eyre!("Missing SOA in zone"))?;

        let authority = Rfc6672Searcher {
            authority: InMemoryAuthority::new(
                origin.0,
                records,
                trust_dns_server::authority::ZoneType::Primary,
                false,
            )
            .map_err(|e| eyre!(e))?,
        };

        Ok(Self {
            authority,
            nsid: config
                .server_id
                .unwrap_or_else(|| "Static Server".to_string()),
        })
    }
}

#[async_trait::async_trait]
impl trust_dns_server::server::RequestHandler for DnsAuthServer {
    async fn handle_request<R: trust_dns_server::server::ResponseHandler>(
        &self,
        request: &trust_dns_server::server::Request,
        mut response_handle: R,
    ) -> trust_dns_server::server::ResponseInfo {
        let request_message = &**request;
        log::trace!("request: {:?}", request_message);
        let query = request_message.query();

        let mut msg = create_empty_response_from_request(request_message, &self.nsid);
        self.authority
            .lookup(query.name(), query.query_type(), &mut msg)
            .await;
        let mut builder = MessageResponseBuilder::from_message_request(request_message);
        if let Some(edns) = msg.edns() {
            builder.edns(edns.clone());
        }

        let msg = builder.build(
            *msg.header(),
            Box::new(msg.answers().iter()),
            Box::new(msg.name_servers().iter()),
            Box::new(std::iter::empty()),
            Box::new(msg.additionals().iter()),
        );

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

/// Perform a DNS search in authoritative zone according to RFC 6672 Section 3.2
///
/// The latest server algorithm in described in [RFC 6672 Section 3.2].
/// Previous versions of the algorithm are described in [RFC 2672 Section 4.1] and [RFC 1034 Section 4.3.2].
/// Another description can be found in the [Hello DNS] documents.
///
/// ```jsonc
/// {"method": "initialize", "parameters": {"command": "/home/user/projects/pdns-backend/target/release/pdns-backend", "timeout": "2000"}}
/// {"method": "lookup", "parameters": {"local": "0.0.0.0", "qname": "zero.a.e.dnsexperiments.de.", "qtype": "SOA", "real-remote": "0.0.0.0/0", "remote": "0.0.0.0", "zone-id": -1}}
/// {"method": "lookup", "parameters": {"local": "0.0.0.0", "qname": "a.e.dnsexperiments.de.", "qtype": "SOA", "real-remote": "0.0.0.0/0", "remote": "0.0.0.0", "zone-id": -1}}
/// {"method": "lookup", "parameters": {"local": "0.0.0.0", "qname": "e.dnsexperiments.de.", "qtype": "SOA", "real-remote": "0.0.0.0/0", "remote": "0.0.0.0", "zone-id": -1}}
/// {"method": "lookup", "parameters": {"local": "::1", "qname": "zero.a.e.dnsexperiments.de.", "qtype": "NS", "real-remote": "::1/128", "remote": "::1", "zone-id": 1000}}
/// {"method": "lookup", "parameters": {"local": "::1", "qname": "a.e.dnsexperiments.de.", "qtype": "NS", "real-remote": "::1/128", "remote": "::1", "zone-id": 1000}}
/// {"method": "getAllDomainMetadata", "parameters": {"name": "e.dnsexperiments.de."}}
/// {"method": "lookup", "parameters": {"local": "::1", "qname": "zero.a.e.dnsexperiments.de.", "qtype": "ANY", "real-remote": "::1/128", "remote": "::1", "zone-id": 1000}}
/// {"method": "initialize", "parameters": {"command": "/home/user/projects/pdns-backend/target/release/pdns-backend", "timeout": "2000"}}
/// {"method": "lookup", "parameters": {"local": "0.0.0.0", "qname": "zero.a.e.dnsexperiments.de.", "qtype": "SOA", "real-remote": "0.0.0.0/0", "remote": "0.0.0.0", "zone-id": -1}}
/// {"method": "lookup", "parameters": {"local": "0.0.0.0", "qname": "a.e.dnsexperiments.de.", "qtype": "SOA", "real-remote": "0.0.0.0/0", "remote": "0.0.0.0", "zone-id": -1}}
/// {"method": "lookup", "parameters": {"local": "0.0.0.0", "qname": "e.dnsexperiments.de.", "qtype": "SOA", "real-remote": "0.0.0.0/0", "remote": "0.0.0.0", "zone-id": -1}}
/// {"method": "lookup", "parameters": {"local": "::", "qname": "zero.a.e.dnsexperiments.de.", "qtype": "NS", "real-remote": "::1/128", "remote": "::1", "zone-id": 1000}}
/// {"method": "lookup", "parameters": {"local": "::", "qname": "a.e.dnsexperiments.de.", "qtype": "NS", "real-remote": "::1/128", "remote": "::1", "zone-id": 1000}}
/// {"method": "getAllDomainMetadata", "parameters": {"name": "e.dnsexperiments.de."}}
/// {"method": "lookup", "parameters": {"local": "::", "qname": "zero.a.e.dnsexperiments.de.", "qtype": "ANY", "real-remote": "::1/128", "remote": "::1", "zone-id": 1000}}
/// {"method": "lookup", "parameters": {"local": "0.0.0.0", "qname": "e.dnsexperiments.de.", "qtype": "SOA", "real-remote": "0.0.0.0/0", "remote": "0.0.0.0", "zone-id": -1}}
/// {"method": "lookup", "parameters": {"local": "::", "qname": "zero.a.e.dnsexperiments.de.", "qtype": "ANY", "real-remote": "::1/128", "remote": "::1", "zone-id": 1000}}
/// {"method": "lookup", "parameters": {"local": "0.0.0.0", "qname": "e.dnsexperiments.de.", "qtype": "SOA", "real-remote": "0.0.0.0/0", "remote": "0.0.0.0", "zone-id": -1}}
/// {"method": "lookup", "parameters": {"local": "::", "qname": "zero.a.e.dnsexperiments.de.", "qtype": "ANY", "real-remote": "::1/128", "remote": "::1", "zone-id": 1000}}
/// ```
///
/// [Hello DNS]: https://powerdns.org/hello-dns/auth.md.html#thealgorithm
/// [RFC 1034 Section 4.3.2]: https://tools.ietf.org/html/rfc1034#section-4.3.2
/// [RFC 2672 Section 4.1]: https://tools.ietf.org/html/rfc2672#section-4.1
/// [RFC 6672 Section 3.2]: https://tools.ietf.org/html/rfc6672#section-3.2
pub(super) struct Rfc6672Searcher {
    /// The backing data storage
    pub(super) authority: InMemoryAuthority,
}

impl Rfc6672Searcher {
    /// Write response records in the `msg` parameter based on the `qname` and `qtype` parameters.
    pub(super) async fn lookup(
        &self,
        original_name: &LowerName,
        query_type: RecordType,
        msg: &mut Message,
    ) {
        let mut answers = Vec::new();
        let mut authoritatives = Vec::new();
        let mut additionals = Vec::new();
        let mut error_code = None;

        // The qname must be part of the current zone
        if !self.authority.origin().zone_of(original_name) {
            error_code = Some(ResponseCode::ServFail);
        }

        for qname in
            Name::from(original_name).as_name_down_iter(&Name::from(self.authority.origin()))
        {
            if error_code.is_some() {
                break;
            }

            let qname = LowerName::from(qname);
            let records = self.authority.lookup_exact(&qname).await;

            if let Some(records) = records {
                // RFC 6672 Section 3.2; 3 B
                // If a match would take us out of the authoritative data

                // Without this check this would lead to a delegation loop delegation always to itself
                if &qname != self.authority.origin() {
                    let ns: Vec<_> = records
                        .iter()
                        .filter(|&r| r.record_type() == RecordType::NS)
                        .cloned()
                        .collect();

                    if !ns.is_empty() {
                        // Lookup glue records, i.e., A and AAAA
                        for record_set in &ns {
                            // Extract rdata name from record
                            for record in record_set.records_without_rrsigs() {
                                let name = LowerName::new(
                                    record.data().and_then(|rdata| rdata.as_ns()).unwrap(),
                                );
                                additionals.extend(
                                    self.authority
                                        .lookup_exact(&name)
                                        .await
                                        .map(|records| -> Vec<_> {
                                            records
                                                .into_iter()
                                                .filter(|r| {
                                                    r.record_type() == RecordType::A
                                                        || r.record_type() == RecordType::AAAA
                                                })
                                                .collect()
                                        })
                                        .unwrap_or_default(),
                                );
                            }
                        }

                        authoritatives.extend(ns);
                        break;
                    }
                }

                if &qname == original_name {
                    // RFC 6672 Section 3.2; 3 A
                    // If the whole of QNAME is matched, we have found the node.

                    let cname: Vec<_> = records
                        .iter()
                        .filter(|&r| r.record_type() == RecordType::CNAME)
                        .cloned()
                        .collect();
                    if !cname.is_empty() {
                        answers.extend(cname);
                        break;
                    }

                    let qtype: Vec<_> = records
                        .iter()
                        .filter(|&r| r.record_type() == query_type)
                        .cloned()
                        .collect();
                    if !qtype.is_empty() {
                        answers.extend(qtype);
                        break;
                    }

                    // We have records, but no CNAME nor QTYPE
                    // It still could be delegation, otherwise it is a NODATA response
                }
            } else {
                // RFC 6672 Section 3.2; 3 C
                // If at some label, a match is impossible.

                // If there was no DNAME record, look to see if the "*" label exists.
                let wildcard = qname.into_wildcard();
                let records = self.authority.lookup_exact(&wildcard).await;

                if let Some(wildcards) = &records {
                    let wildcards: Vec<_> = wildcards
                        .iter()
                        .filter(|&r| r.record_type() == query_type)
                        .cloned()
                        .collect();
                    // If the "*" label does exist, match RRs at that node against
                    // QTYPE.  If any match, copy them into the answer section, but
                    // set the owner of the RR to be QNAME, and not the node with
                    // the "*" label.  If the data at the node with the "*" label is
                    // a CNAME, and QTYPE doesn't match CNAME, copy the CNAME RR
                    // into the answer section of the response changing the owner
                    // name to the QNAME, change QNAME to the canonical name in the
                    // CNAME RR, and go back to step 1.  Otherwise, go to step 6.
                    answers.extend(wildcards);
                } else {
                    // If the "*" label does not exist, check whether the name we
                    // are looking for is the original QNAME in the query or a name
                    // we have followed due to a CNAME or DNAME.  If the name is
                    // original, set an authoritative name error in the response and
                    // exit.  Otherwise, just exit.
                    error_code = Some(ResponseCode::NXDomain);
                }
                break;
            }
        }

        // For NODATA responses we need an SOA
        if (answers.is_empty() && authoritatives.is_empty()) || error_code.is_some() {
            let soas: Vec<_> = self
                .authority
                .lookup_exact(self.authority.origin())
                .await
                .expect("At least the SOA must exist at the apex")
                .iter()
                .filter(|r| r.record_type() == RecordType::SOA)
                .cloned()
                .collect();
            authoritatives.extend(soas);
        }

        if let Some(error_code) = error_code {
            msg.set_response_code(error_code);
            if error_code.high() != 0 {
                msg.edns_mut().set_rcode_high(error_code.high());
            }
        }

        msg.add_answers(
            answers
                .into_iter()
                .flat_map(|rrset| -> Vec<_> { rrset.records_without_rrsigs().cloned().collect() }),
        )
        .add_name_servers(
            authoritatives
                .into_iter()
                .flat_map(|rrset| -> Vec<_> { rrset.records_without_rrsigs().cloned().collect() }),
        )
        .insert_additionals(
            additionals
                .into_iter()
                .flat_map(|rrset| -> Vec<_> { rrset.records_without_rrsigs().cloned().collect() })
                .collect(),
        );
    }
}

impl fmt::Debug for Rfc6672Searcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rfc6672Searcher").finish_non_exhaustive()
    }
}

/// Iterator over DNS names based on the labels.
///
/// Each iteration the returned [`Name`] has one more label depth until the original [`Name`] is returned.
struct NameDownIter<'a> {
    orig: &'a Name,
    curr_label_count: u8,
}

impl<'a> Iterator for NameDownIter<'a> {
    type Item = Name;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr_label_count > self.orig.num_labels() {
            return None;
        }
        let name = self.orig.trim_to(self.curr_label_count as usize);
        self.curr_label_count = self.curr_label_count.wrapping_add(1);
        Some(name)
    }
}

#[test]
fn test_name_down_iter_root() {
    use std::str::FromStr;

    let name = Name::from_str("foo.bar.example.com").unwrap();
    let mut iter = name.as_name_down_iter(&Name::from_str(".").unwrap());
    assert_eq!(iter.next(), Some(Name::from_str(".").unwrap()));
    assert_eq!(iter.next(), Some(Name::from_str("com").unwrap()));
    assert_eq!(iter.next(), Some(Name::from_str("example.com").unwrap()));
    assert_eq!(
        iter.next(),
        Some(Name::from_str("bar.example.com").unwrap())
    );
    assert_eq!(
        iter.next(),
        Some(Name::from_str("foo.bar.example.com").unwrap())
    );
    assert_eq!(iter.next(), None);
}

#[test]
fn test_name_down_iter_sld() {
    use std::str::FromStr;

    let name = Name::from_str("foo.bar.example.com.").unwrap();
    let mut iter = name.as_name_down_iter(&Name::from_str("example.com.").unwrap());
    assert_eq!(iter.next(), Some(Name::from_str("example.com.").unwrap()));
    assert_eq!(
        iter.next(),
        Some(Name::from_str("bar.example.com.").unwrap())
    );
    assert_eq!(
        iter.next(),
        Some(Name::from_str("foo.bar.example.com.").unwrap())
    );
    assert_eq!(iter.next(), None);
}

trait NameExt {
    /// Create an [`Iterator`] over the [`Name`] adding one label to the `zone` until the full [`Name`] is reached.
    fn as_name_down_iter<'a>(&'a self, zone: &Name) -> NameDownIter<'a>;
}

impl NameExt for Name {
    /// Create an [`Iterator`] over the [`Name`] adding one label to the `zone` until the full [`Name`] is reached.
    fn as_name_down_iter(&self, zone: &Name) -> NameDownIter<'_> {
        NameDownIter {
            orig: self,
            curr_label_count: zone.num_labels(),
        }
    }
}

#[async_trait::async_trait]
trait InMemoryAuthorityExt {
    /// Lookup exact matches based on `name` and `query_type`
    ///
    /// Returns `None` is name is NXDOMAIN
    async fn lookup_exact(&self, name: &LowerName) -> Option<Vec<Arc<RecordSet>>>;

    /// Return true if the name exists with any key
    async fn has_name(&self, name: &LowerName) -> bool;
}

#[async_trait::async_trait]
impl InMemoryAuthorityExt for InMemoryAuthority {
    /// Lookup exact matches based on `name` and `query_type`
    ///
    /// Returns `None` is name is NXDOMAIN
    async fn lookup_exact(&self, name: &LowerName) -> Option<Vec<Arc<RecordSet>>> {
        // // this range covers all the records for any of the RecordTypes at a given label.
        let start_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::min_value()));
        let end_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::max_value()));

        let tmp: Vec<Arc<RecordSet>> = self
            .records()
            .await
            .range((
                Bound::Included(start_range_key),
                Bound::Included(end_range_key),
            ))
            .map(|(_, v)| v)
            .cloned()
            .collect();
        if !tmp.is_empty() {
            Some(tmp)
        } else {
            // Might be NXDOMAIN
            let name_or_subdomain_exists = self
                .records()
                .await
                .keys()
                .any(|rrkey| name.zone_of(&rrkey.name));
            if name_or_subdomain_exists {
                Some(tmp)
            } else {
                None
            }
        }
    }

    /// Return true if the name exists with any key
    async fn has_name(&self, name: &LowerName) -> bool {
        // this range covers all the records for any of the RecordTypes at a given label.
        let start_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::min_value()));
        let end_range_key = RrKey::new(name.clone(), RecordType::Unknown(u16::max_value()));
        self.records()
            .await
            .range((
                Bound::Included(start_range_key),
                Bound::Included(end_range_key),
            ))
            .next()
            .is_some()
    }
}
