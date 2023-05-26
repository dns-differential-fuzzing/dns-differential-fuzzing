//! Input definitions for the fuzzer.
//!
//! This includes individual query/response pairs, plus additional information arround them.
//! Multiple pairs of [`FuzzCase`]s can be grouped together into a [`FuzzSuite`].

use super::{CacheKey, FuzzCaseId, FuzzSuiteId};
use crate::serialize::{BytesOrBase64, DnsWireFormatB64};
use color_eyre::eyre::{bail, Result};
use serde_with::DisplayFromStr;
use std::collections::BTreeSet;
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::{DNSClass, RecordType};

/// Input set for the fuzzer.
///
/// The inputs contain some general information, such as an ID to make it identifyable later again.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FuzzSuite {
    /// Unique value indicating the set of fuzzing inputs.
    pub id: FuzzSuiteId,

    /// Collection of individual fuzzing inputs.
    pub test_cases: Vec<FuzzCase>,
}

/// A single fuzzing input configuration.
///
/// This includes the client query and the one or multiple server responses.
#[serde_with::serde_as]
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FuzzCase {
    /// Unique identifer which allows matching later
    pub id: FuzzCaseId,

    /// The client query
    #[serde_as(as = "DnsWireFormatB64")]
    pub client_query: Message,
    /// The server responses
    #[serde_as(as = "Vec<DnsWireFormatB64>")]
    pub server_responses: Vec<Message>,
    /// Queries to check the state of the fuzzee cache
    pub check_cache: BTreeSet<CacheKey>,
}

impl FuzzCase {
    /// Extract names from query and responses.
    ///
    /// This extracts owner names from the query and responses and populates the `check_cache` field.
    pub fn update_check_cache(&mut self) {
        self.check_cache = Some(&self.client_query)
            .into_iter()
            .chain(self.server_responses.iter())
            .flat_map(|msg| {
                let queries = msg
                    .queries()
                    .iter()
                    .map(|q| CacheKey(q.name().clone(), q.query_type(), q.query_class()));
                let responses = None
                    .into_iter()
                    .chain(msg.answers())
                    .chain(msg.name_servers())
                    .chain(msg.additionals())
                    .map(|rr| CacheKey(rr.name().clone(), rr.record_type(), rr.dns_class()));

                queries.chain(responses)
            })
            .collect();
    }
}

/// Similar to [`FuzzSuite`] but fields are stored in bytes.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FuzzSuiteBytes {
    pub id: FuzzCaseId,
    pub test_cases: Vec<FuzzCaseBytes>,
}

/// Similar to [`FuzzCase`] but fields are stored in bytes.
#[serde_with::serde_as]
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FuzzCaseBytes {
    /// Unique identifer which allows matching later
    pub id: FuzzCaseId,

    /// The client query
    #[serde_as(as = "BytesOrBase64")]
    pub client_query: Vec<u8>,
    /// The server responses
    #[serde_as(as = "Vec<BytesOrBase64>")]
    pub server_responses: Vec<Vec<u8>>,
    /// Queries to check the state of the fuzzee cache
    #[serde_as(as = "Vec<(BytesOrBase64, _, DisplayFromStr)>")]
    pub check_cache: Vec<(Vec<u8>, RecordType, DNSClass)>,
}

impl FuzzCaseBytes {
    pub fn replace_label(&mut self, label: &[u8], replacement: &[u8]) -> Result<()> {
        use bstr::ByteSlice;

        if label.len() != replacement.len() {
            bail!(
                "Replacement label and original label must have the same length, but {} != {}",
                label.len(),
                replacement.len()
            );
        }
        if label.is_empty() {
            return Ok(());
        }
        if label.len() != label[0] as usize + 1 {
            bail!(
                "A label must start with a length byte of the remaining bytes, but {} does not \
                 match the label length {}",
                label[0],
                label.len(),
            );
        }
        if replacement.len() != replacement[0] as usize + 1 {
            bail!(
                "A replacement label must start with a length byte of the remaining bytes, but {} \
                 does not match the replacement label length {}",
                replacement[0],
                replacement.len(),
            );
        }

        self.client_query = self.client_query.replace(label, replacement);
        self.server_responses.iter_mut().for_each(|resp| {
            *resp = resp.replace(label, replacement);
        });
        self.check_cache.iter_mut().for_each(|(name, _, _)| {
            *name = name.replace(label, replacement);
        });

        Ok(())
    }
}
