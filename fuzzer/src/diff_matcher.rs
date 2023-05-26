//! Classify found differences into different types.

use crate::atom::{Natsorted, *};
use crate::key_values::{Value, ValueMap};
use crate::utils::ok;
use crate::FuzzCaseMeta;
use color_eyre::eyre::Result;
use dnsauth::definitions::{
    FuzzCase, FuzzCaseId, FuzzResult, FuzzResultDiff, FuzzResultSet, FuzzSuite, FuzzSuiteId,
    OracleResults, ResolverName,
};
use futures::{stream, StreamExt as _, TryStreamExt as _};
use misc_utils::fs;
use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

type DiffKeysSet = HashSet<Atom, nohash_hasher::BuildNoHashHasher<u32>>;
type Meta = BTreeMap<String, Arc<dyn std::any::Any + Send + Sync + 'static>>;

/// Known Difference
///
/// Each instance of the enum describes one known difference.
/// It has functions to get an ID or description for itself.
/// It can also filter the keys with differences, into whether they are covered by this difference.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    strum::AsRefStr,
    strum::IntoStaticStr,
)]
pub(crate) enum DifferenceKind {
    /// The tested resolver name is different.
    ResolverName,
    /// The DNS ID in the header is different.
    DnsId,
    /// The coverage counters between different resolvers are incomparable.
    IncomparableCounters,
    /// Difference in the meta data, e.g., a counter for the RRs in a section.
    ///
    /// This information is always redundant, and thus not interesting.
    /// In the case of the RR count, the actual RRs are more interesting and will show a difference too.
    MetaDiff,
    NonINRecursion,
    /// Cookies are an optional part of the specification.
    CookiesUnsupported,
    /// The value of DNS cookies is always different.
    CookiesUncomparable,
    TodoCacheIgnoredForNow,

    // BIND9 returns a ServFail if the answer returns a record for the wrong type.
    // Only one query is send for both BIND9 and Unbound.
    // This also affects the content of the answer section.
    ServFailOnWrongAuthnsAnswerType,
    // Similar to `ServFailOnWrongAuthnsAnswerType`, but for the classes not the type.
    // For BIND9 at least, if any record has the wrong class ServFail is returned.
    // This then affects the answer section.
    ServFailOnWrongAuthnsAnswerClass,
    // Unbound limits TTL to 86400
    MaxTtlLimit,
    // FormErr when sending query with TC bit set
    FormErrOnTruncatedQuery,
    // Related to `ErrorClientQueryIncomparableFuzzeeQueries`
    // No answer, authoritative, or additional section are expected in an error response (FormErr, NotImp, ServFail).
    //
    // Here is a variation of the diff between bind9 and maradns with ServFail
    //
    // *  .fuzz_result.fuzzee_response.answers.0.dns_class                                                  IN
    // *  .fuzz_result.fuzzee_response.answers.0.name_labels                                                gechu.0000.fuzz.
    // *  .fuzz_result.fuzzee_response.answers.0.rdata                                                      kyadc.0000.fuzz.
    // *  .fuzz_result.fuzzee_response.answers.0.rr_type                                                    NS
    // *  .fuzz_result.fuzzee_response.answers.0.ttl                                                        86400
    // *  .fuzz_result.fuzzee_response.header.answer_count          0                                       1
    //    .fuzz_result.fuzzee_response.header.authentic_data        false                                   false
    //    .fuzz_result.fuzzee_response.header.authoritative         false                                   false
    //    .fuzz_result.fuzzee_response.header.checking_disabled     false                                   false
    // .  .fuzz_result.fuzzee_response.header.id                    33512                                   43094                                   DnsId
    //    .fuzz_result.fuzzee_response.header.message_type          response                                response
    //    .fuzz_result.fuzzee_response.header.name_server_count     0                                       0
    //    .fuzz_result.fuzzee_response.header.op_code               query                                   query
    //    .fuzz_result.fuzzee_response.header.query_count           1                                       1
    //    .fuzz_result.fuzzee_response.header.recursion_available   true                                    true
    //    .fuzz_result.fuzzee_response.header.recursion_desired     true                                    true
    // *  .fuzz_result.fuzzee_response.header.response_code         ServFail                                NoError
    //    .fuzz_result.fuzzee_response.header.truncated             false                                   false
    //    .fuzz_result.fuzzee_response.name_servers.#count          0                                       0
    //    .fuzz_result.fuzzee_response.queries.#count               1                                       1
    //    .fuzz_result.fuzzee_response.queries.0.name               gechu.0000.fuzz.                        gechu.0000.fuzz.
    // *  .fuzz_result.fuzzee_response.queries.0.query_class        ANY                                     IN
    //    .fuzz_result.fuzzee_response.queries.0.query_type         NS                                      NS
    ErrorClientNoRrInAnswer,

    // A client query without the RD bit will not get any useful response.
    // Instead you see a delegation like response with name server and additionals section.
    // The name server section contains the NS records for the `fuzz.` zone, and the additionals contains the IP of `ns-fuzz.ns.`.
    //
    // The observed difference now showed slightly different TTL values for both records, i.e, 86400 vs 86399.
    // The TTL depends on the exact timing, thus allow for some variability.
    //
    // Another difference which can appear is that one side answers with a delegation (i.e, NS in authority, A in additional),
    // but the other side has an empty response. This should check that no resolver query was sent out.
    //
    //  .  .fuzz_result.fuzzee_response.additionals.#count           1                                     0                                     MetaDiff
    //  *  .fuzz_result.fuzzee_response.additionals.0.dns_class      IN
    //  *  .fuzz_result.fuzzee_response.additionals.0.name_labels    ns-fuzz.ns.
    //  *  .fuzz_result.fuzzee_response.additionals.0.rdata          127.97.1.1
    //  *  .fuzz_result.fuzzee_response.additionals.0.rr_type        A
    //  *  .fuzz_result.fuzzee_response.additionals.0.ttl            86319
    //     .fuzz_result.fuzzee_response.answers.#count               0                                     0
    //     .fuzz_result.fuzzee_response.edns.dnssec_ok               false                                 false
    //  *  .fuzz_result.fuzzee_response.edns.max_payload             1232                                  512
    //     .fuzz_result.fuzzee_response.edns.version                 0                                     0
    //  *  .fuzz_result.fuzzee_response.header.additional_count      2                                     1
    //     .fuzz_result.fuzzee_response.header.answer_count          0                                     0
    //     .fuzz_result.fuzzee_response.header.authentic_data        false                                 false
    //     .fuzz_result.fuzzee_response.header.authoritative         false                                 false
    //     .fuzz_result.fuzzee_response.header.checking_disabled     true                                  true
    //  .  .fuzz_result.fuzzee_response.header.id                    33359                                 21012                                 DnsId
    //     .fuzz_result.fuzzee_response.header.message_type          response                              response
    //  *  .fuzz_result.fuzzee_response.header.name_server_count     1                                     0
    //     .fuzz_result.fuzzee_response.header.op_code               query                                 query
    //     .fuzz_result.fuzzee_response.header.query_count           1                                     1
    //     .fuzz_result.fuzzee_response.header.recursion_available   true                                  true
    //     .fuzz_result.fuzzee_response.header.recursion_desired     false                                 false
    //     .fuzz_result.fuzzee_response.header.response_code         NoError                               NoError
    //     .fuzz_result.fuzzee_response.header.truncated             false                                 false
    //  .  .fuzz_result.fuzzee_response.name_servers.#count          1                                     0                                     MetaDiff
    //  *  .fuzz_result.fuzzee_response.name_servers.0.dns_class     IN
    //  *  .fuzz_result.fuzzee_response.name_servers.0.name_labels   fuzz.
    //  *  .fuzz_result.fuzzee_response.name_servers.0.rdata         ns-fuzz.ns.
    //  *  .fuzz_result.fuzzee_response.name_servers.0.rr_type       NS
    //  *  .fuzz_result.fuzzee_response.name_servers.0.ttl           86319
    //     .fuzz_result.fuzzee_response.queries.#count               1                                     1
    //     .fuzz_result.fuzzee_response.queries.0.name               gechu.0004.fuzz.                      gechu.0004.fuzz.
    //     .fuzz_result.fuzzee_response.queries.0.query_class        IN                                    IN
    //     .fuzz_result.fuzzee_response.queries.0.query_type         A                                     A
    //     .fuzz_result.fuzzee_response.sig0.#count                  0                                     0
    //     .fuzz_result.id                                           03463e16-ae1d-483f-83cf-2d0ad6d45d44  03463e16-ae1d-483f-83cf-2d0ad6d45d44
    //     .fuzz_result.response_idxs.#count                         0                                     0
    //  .  .resolver_name                                            bind9                                 pdns-recursor                         ResolverName
    ClientQueryWithoutRdBit,
    // Some resolvers do not support extended DNS errors in the responses.
    ExtendedErrorsUnsupported,

    // MaraDNS cannot handle EDNS in any way
    NoEdnsSupport,
    // MaraDNS has the bad habit of sometimes not providing a response at all.
    // This seems to happen when it experiences a SERVFAIL.
    // On the same inputs BIND9 will often see a SERVFAIL too.
    // Unbound often response with a NODATA response.
    //
    // This also covers the .fuzz_result.fuzzee_queries part, iff no queries were sent at all.
    MaradnsNoResponseServfail,

    // Only retransmissions
    // Check if one side has more queries than the other.
    // If all queries have the same query section, and the same query section was used in the shared part too, then they are retransmissions.
    // This conflicts with `ResolverQueryCountMismatchTooHard`.
    TrailingRetransmissions,

    // If a resolver does not process the client query for whatever reason, but the other one does, then comparing the list of fuzzee queries is pointless.
    // The refusing side will not have any queries, but the other side will have plenty.
    // This does cover a couple of status codes which all relate to "refusing" a client query, namely:
    // - `FormErr`: The server doesn't understand the query, so cannot process it,
    // - `NotImp`: The server does not support the query type, so cannot process it,
    // - `Refused`: The server refuses to process the query for some reason.
    // In all cases ensure that the refusing resolver really did not send a single query.
    // This is a generalization of the earlier `FormErrVoidsFuzzeeQueries`
    ErrorClientQueryIncomparableFuzzeeQueries,

    // The following diff was observed for a `Status` query which both bind9 and unbound answered as NotImp`.
    //
    // *  .fuzz_result.fuzzee_response.edns.max_payload             1232                                  1200
    // *  .fuzz_result.fuzzee_response.header.query_count           0                                     1
    // *  .fuzz_result.fuzzee_response.header.recursion_desired     false                                 true
    // .  .fuzz_result.fuzzee_response.queries.#count               0                                     1                                     MetaDiff
    // *  .fuzz_result.fuzzee_response.queries.0.name                                                     qxcjm.0006.fuzz.
    // *  .fuzz_result.fuzzee_response.queries.0.query_class                                              IN
    // *  .fuzz_result.fuzzee_response.queries.0.query_type                                               SRV
    //
    // The 1200 is mirrored from the client query.
    // The other differences all seem related to the NotImp response.
    // Bind9 does not include a query section for NotImp responses.
    Bind9NotImpMissingQuerySection,

    // Maradns makes up a new SOA record which does not exist.
    // This seems to only happen if the query type is AAAA and the AuthNS responds with a NODATA answer.
    // The original query was for naxrg.0000.fuzz IN AAAA, but the AuthNS only responds with a NODATA answer.
    // The common parts seem to be the `z.` and `y.` in the SOA record and the TTL of 0.
    //
    // *  .fuzz_result.fuzzee_response.header.name_server_count     0                                     1
    // *  .fuzz_result.fuzzee_response.name_servers.0.dns_class                                           IN
    // *  .fuzz_result.fuzzee_response.name_servers.0.name_labels                                         naxrg.0000.fuzz.
    // *  .fuzz_result.fuzzee_response.name_servers.0.rdata                                               z.naxrg.0000.fuzz. y.naxrg.0000.fuzz. 1 1 1 1 1
    // *  .fuzz_result.fuzzee_response.name_servers.0.rr_type                                             SOA
    // *  .fuzz_result.fuzzee_response.name_servers.0.ttl                                                 0
    MaradnsFakeSoaOnAAAA,

    // Entry between bind9 and unbound
    // Unbound seems to first issue a query using the A query type and then re-issue it but using the AAAA query type.
    // This might be related to query minimalization as an attempt to probe if there is a delegation or not.
    // Or maybe it is simply for priming the cache since often times both IP addresses are needed.
    //
    // BIND9 performs a single query, directly to AAAA, while Unbound does A first, then AAAA.
    // The client asked for an AAAA.
    //
    //    .fuzz_result.fuzzee_queries.0.queries.0.name              naxrg.0006.fuzz.                      naxrg.0006.fuzz.
    //    .fuzz_result.fuzzee_queries.0.queries.0.query_class       IN                                    IN
    // *  .fuzz_result.fuzzee_queries.0.queries.0.query_type        AAAA                                  A
    // .  .fuzz_result.fuzzee_queries.1.additionals.#count                                                0                                     MetaDiff
    // .  .fuzz_result.fuzzee_queries.1.queries.#count                                                    1                                     MetaDiff
    // *  .fuzz_result.fuzzee_queries.1.queries.0.name                                                    naxrg.0006.fuzz.
    // *  .fuzz_result.fuzzee_queries.1.queries.0.query_class                                             IN
    // *  .fuzz_result.fuzzee_queries.1.queries.0.query_type                                              AAAA
    UnboundProbesUsingARecord,

    // PowerDNS does not set the CD bit on outgoing queries.
    //
    // entry between bind9 and pdns-recursor
    // *  .fuzz_result.fuzzee_queries.0.header.checking_disabled    true                                  false
    // *  .fuzz_result.fuzzee_response.edns.max_payload             1232                                  512
    // .  .resolver_name                                            bind9                                 pdns-recursor                         ResolverName
    PdnsCheckingDisabled,

    // Maradns really hates the any query class besides IN, and simply uses IN in all cases.
    //
    //    .fuzz_case.client_query.queries.#count                    1                                       1
    //    .fuzz_case.client_query.queries.0.name                    gechu.test.fuzz.                        gechu.test.fuzz.
    //    .fuzz_case.client_query.queries.0.query_class             ANY                                     ANY
    //    .fuzz_case.client_query.queries.0.query_type              NS                                      NS
    //    .fuzz_result.fuzzee_response.queries.#count               1                                       1
    //    .fuzz_result.fuzzee_response.queries.0.name               gechu.0005.fuzz.                        gechu.0005.fuzz.
    // *  .fuzz_result.fuzzee_response.queries.0.query_class        IN                                      ANY
    // .  .resolver_name                                            maradns                                 pdns-recursor                           ResolverName
    MaradnsQueryClassNotIn,

    // PowerDNS uses answers with a buffer size of 512 bytes.
    // Outgoing queries are 1232 bytes.
    // This is meant to limit client queries to a reasonable size.
    // https://docs.powerdns.com/recursor/appendices/FAQ.html#edns-bufsize-in-response-packets
    PdnsEdnsClientBufsize,

    // BIND9 in v9.11 uses 4096 bufsize to answer the client
    Bind9_11EdnsClientBufsize,
    // BIND9 in v9.11 uses 512 to send queries to the AuthNS server
    Bind9_11EdnsServerBufsize,

    // Unbound sends FormErr responses with the Authentic Data (AD) bit or the Authoritative (AA) bit set.
    // This was seen with BIND9 (having Refused), Maradns (NoError), and PowerDNS (ServFail).
    // In all cases the bit was copied from the client query.
    //
    // This might overall be slightly more correct, since the AD and AA bit should be set if the records fulfill the requirements.
    // But since no records are returned, this is always true (qualifications about an empty set).
    // https://www.rfc-editor.org/rfc/rfc4035.html#section-3.2.3
    // https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.1
    UnboundFormErrCopiesAdAndAa,
    // Difference when the client sends a truncated TC query
    // *  .fuzz_result.fuzzee_response.header.response_code         Refused                                  ServFail
    // .  .resolver_name                                            bind9                                    pdns-recursor                            ResolverName
    //
    // Also works with query class NONE
    // .fuzz_case.client_query.queries.0.query_class             NONE
    RefusedCanBeServFail,
    // Account for differences in the behavior of QNAME minimization.
    // .fuzz_result.fuzzee_queries.0.queries.0.name  _.xtzoa.0000.fuzz.  xtzoa.0000.fuzz.
    QnameMinimalization,
    // BIND9 responds with REFUSED when the clients sends a query with HS class
    // Other resolvers might indicate NXDOMAIN instead
    BindHsProhibited,
    // MaraDNS fails to act (no queries, no response) if recursion desired bit is not set
    MaradnsNoRecursionDesired,
    // MaraDNS fails to act (no queries, no response) if null byte is present in the query name
    MaradnsEmbeddedZero,
    // BIND9 will on NotImp and FormErr responses use hardcoded values and not mirror the values from the client query.
    //
    // The client uses a max_payload of 1200.
    //
    // .fuzz_result.fuzzee_response.edns.max_payload             1232
    // .fuzz_result.fuzzee_response.header.checking_disabled     false
    // .fuzz_result.fuzzee_response.header.recursion_desired     false
    BindErrorsHaveHardcodedValues,
    // PDNS Recursor will not respond to queries with an OpCode that is not query.
    // For example, the notify, status, and update opcodes.
    PdnsRecursorsNonQueryNoResponse,
    // A NoData response always results in the ServFail response code.
    ResolvedServFailOnNoData,
    // BIND9 in v9.11 serves an extra nameserver record, even for valid answers.
    //
    //  *  .fuzz_result.fuzzee_response.additionals.0.dns_class                                            IN
    //  *  .fuzz_result.fuzzee_response.additionals.0.name_labels                                          ns-0001.ns.
    //  *  .fuzz_result.fuzzee_response.additionals.0.rdata                                                127.250.0.2
    //  *  .fuzz_result.fuzzee_response.additionals.0.rr_type                                              A
    //  *  .fuzz_result.fuzzee_response.additionals.0.ttl                                                  1800
    //  *  .fuzz_result.fuzzee_response.header.additional_count      1                                     2
    //     .fuzz_result.fuzzee_response.header.answer_count          1                                     1
    //  *  .fuzz_result.fuzzee_response.header.name_server_count     0                                     1
    //  *  .fuzz_result.fuzzee_response.name_servers.0.dns_class                                           IN
    //  *  .fuzz_result.fuzzee_response.name_servers.0.name_labels                                         0001.fuzz.
    //  *  .fuzz_result.fuzzee_response.name_servers.0.rdata                                               ns-0001.ns.
    //  *  .fuzz_result.fuzzee_response.name_servers.0.rr_type                                             NS
    //  *  .fuzz_result.fuzzee_response.name_servers.0.ttl                                                 1800
    Bind9_11ExtraNsRecord,
    // Bind9 can return NS records in NODATA responses
    //
    // *  .fuzz_result.fuzzee_response.header.name_server_count     1
    // .  .fuzz_result.fuzzee_response.name_servers.#count          1
    // *  .fuzz_result.fuzzee_response.name_servers.0.dns_class     IN
    // *  .fuzz_result.fuzzee_response.name_servers.0.name_labels   .
    // *  .fuzz_result.fuzzee_response.name_servers.0.rdata         ns-root.ns.
    // *  .fuzz_result.fuzzee_response.name_servers.0.rr_type       NS
    // *  .fuzz_result.fuzzee_response.name_servers.0.ttl           1799
    // .  .resolver_name                                            bind9
    Bind9ExtraNsRecord,
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    strum::AsRefStr,
    strum::IntoStaticStr,
)]
pub(crate) enum DifferenceKindCategory {
    /// Comparing these values never makes sense
    ///
    /// Some values are always random, e.g., the DNS ID.
    Incomparable,
    /// Resolver don't have to implement the same RFCs.
    ///
    /// For example, EDNS support is still technically optional (if proper errors are returned).
    /// EDNS cookies and extended DNS error are optional as well.
    MissingFeatures,
    /// These values are not directly part of the captured communication, but added afterwards.
    Metadata,
    /// Error handling looks totally different for all resolvers
    ErrorHandling,
    /// These differences are the result of (default) configuration values
    ///
    /// For example, setting a maximum TTL or the EDNS buffer size.
    Configuration,
    /// Difference in the upstream queries
    ///
    /// For example, the exact kind of QNAME minimization or re-transmission behavior.
    UpstreamQueries,
    /// Other differences that are specific to a single resolver
    ResolverSpecific,
}

impl DifferenceKind {
    #[allow(dead_code)]
    pub(crate) fn categorize(&self) -> DifferenceKindCategory {
        match self {
            Self::ResolverName => DifferenceKindCategory::Metadata,
            Self::DnsId => DifferenceKindCategory::Incomparable,
            Self::IncomparableCounters => DifferenceKindCategory::Incomparable,
            Self::MetaDiff => DifferenceKindCategory::Metadata,
            Self::NonINRecursion => DifferenceKindCategory::Configuration,
            Self::CookiesUnsupported => DifferenceKindCategory::MissingFeatures,
            Self::CookiesUncomparable => DifferenceKindCategory::Incomparable,
            Self::TodoCacheIgnoredForNow => DifferenceKindCategory::Metadata,
            Self::ServFailOnWrongAuthnsAnswerType => DifferenceKindCategory::ErrorHandling,
            Self::ServFailOnWrongAuthnsAnswerClass => DifferenceKindCategory::ErrorHandling,
            Self::MaxTtlLimit => DifferenceKindCategory::Configuration,
            Self::FormErrOnTruncatedQuery => DifferenceKindCategory::ErrorHandling,
            Self::ErrorClientNoRrInAnswer => DifferenceKindCategory::ErrorHandling,
            Self::ClientQueryWithoutRdBit => DifferenceKindCategory::Configuration,
            Self::ExtendedErrorsUnsupported => DifferenceKindCategory::MissingFeatures,
            Self::NoEdnsSupport => DifferenceKindCategory::MissingFeatures,
            Self::MaradnsNoResponseServfail => DifferenceKindCategory::ResolverSpecific,
            Self::TrailingRetransmissions => DifferenceKindCategory::UpstreamQueries,
            Self::ErrorClientQueryIncomparableFuzzeeQueries => {
                DifferenceKindCategory::ErrorHandling
            }
            Self::Bind9NotImpMissingQuerySection => DifferenceKindCategory::ErrorHandling,
            Self::MaradnsFakeSoaOnAAAA => DifferenceKindCategory::ResolverSpecific,
            Self::UnboundProbesUsingARecord => DifferenceKindCategory::UpstreamQueries,
            Self::PdnsCheckingDisabled => DifferenceKindCategory::UpstreamQueries,
            Self::MaradnsQueryClassNotIn => DifferenceKindCategory::ResolverSpecific,
            Self::PdnsEdnsClientBufsize => DifferenceKindCategory::ResolverSpecific,
            Self::Bind9_11EdnsClientBufsize => DifferenceKindCategory::Configuration,
            Self::Bind9_11EdnsServerBufsize => DifferenceKindCategory::Configuration,
            Self::UnboundFormErrCopiesAdAndAa => DifferenceKindCategory::ErrorHandling,
            Self::RefusedCanBeServFail => DifferenceKindCategory::ErrorHandling,
            Self::QnameMinimalization => DifferenceKindCategory::UpstreamQueries,
            Self::BindHsProhibited => DifferenceKindCategory::Configuration,
            Self::MaradnsNoRecursionDesired => DifferenceKindCategory::ResolverSpecific,
            Self::MaradnsEmbeddedZero => DifferenceKindCategory::ResolverSpecific,
            Self::BindErrorsHaveHardcodedValues => DifferenceKindCategory::ErrorHandling,
            Self::PdnsRecursorsNonQueryNoResponse => DifferenceKindCategory::ResolverSpecific,
            Self::ResolvedServFailOnNoData => DifferenceKindCategory::ResolverSpecific,
            Self::Bind9_11ExtraNsRecord => DifferenceKindCategory::ResolverSpecific,
            Self::Bind9ExtraNsRecord => DifferenceKindCategory::ResolverSpecific,
        }
    }

    /// Return how interesting each value is.
    ///
    /// A value of 1 means no interest.
    /// 0 should never be returned.
    pub(crate) fn interest_level(&self) -> u64 {
        match self {
            // Always different
            Self::ResolverName => 1,
            // Always different
            Self::DnsId => 1,
            // Always different
            Self::IncomparableCounters => 1,
            // Just meta information which are uninteresting
            Self::MetaDiff => 1,
            Self::NonINRecursion => 1,
            // Optional DNS feature
            Self::CookiesUnsupported => 2,
            // Always different
            Self::CookiesUncomparable => 1,
            Self::TodoCacheIgnoredForNow => 2,

            // ServFails do not carry an answer section, so little interest
            Self::ServFailOnWrongAuthnsAnswerType => 2,
            Self::ServFailOnWrongAuthnsAnswerClass => 2,

            Self::MaxTtlLimit => 3,
            // ServFails do not carry an answer section, so little interest
            Self::FormErrOnTruncatedQuery => 2,
            Self::ErrorClientNoRrInAnswer => 2,

            Self::ClientQueryWithoutRdBit => 3,
            // Purely diagnostic, so little interest
            Self::ExtendedErrorsUnsupported => 2,
            // No interest, since this is just a missing feature
            Self::NoEdnsSupport => 1,
            // Since no information is returned to the client this is of little interest
            Self::MaradnsNoResponseServfail => 1,
            // These carry no information, since they are just retransmissions
            // Likely most or all are also not accepted by the resolver, otherwise the resolver would not retry the query.
            Self::TrailingRetransmissions => 1,
            Self::ErrorClientQueryIncomparableFuzzeeQueries => 2,
            Self::Bind9NotImpMissingQuerySection => 2,
            Self::MaradnsFakeSoaOnAAAA => 1,
            // Normal behavior of unbound
            Self::UnboundProbesUsingARecord => 1,
            // Flag in outgoing queries is not relevant, since a malicious AuthNS can just ignore it
            Self::PdnsCheckingDisabled => 1,
            // Alternative query classes (not IN) are basically unused
            Self::MaradnsQueryClassNotIn => 2,
            // Client query sizes of 512 is plenty, since that is the maximum size of a DNS packet
            Self::PdnsEdnsClientBufsize => 1,
            Self::Bind9_11EdnsClientBufsize => 1,
            Self::Bind9_11EdnsServerBufsize => 1,
            // This might even be slightly more correct, than not setting the AD and AA flags
            Self::UnboundFormErrCopiesAdAndAa => 1,
            // Two different ways of error handling
            Self::RefusedCanBeServFail => 1,
            Self::QnameMinimalization => 2,
            Self::BindHsProhibited => 1,
            Self::MaradnsNoRecursionDesired => 1,
            Self::MaradnsEmbeddedZero => 1,
            Self::BindErrorsHaveHardcodedValues => 1,
            Self::PdnsRecursorsNonQueryNoResponse => 1,
            Self::ResolvedServFailOnNoData => 3,
            Self::Bind9_11ExtraNsRecord => 1,
            Self::Bind9ExtraNsRecord => 1,
        }
    }
}

#[allow(clippy::enum_variant_names)]
pub(crate) enum DifferenceResult {
    #[allow(dead_code)]
    NoDifference,
    KnownDifference(BTreeSet<DifferenceKind>),
    NewDifference((Box<DiffFingerprint>, KnownDiffs)),
}

/// Find differences between FuzzResults and optionally write to disk.
pub(crate) async fn process_differences(
    fuzz_results: &[impl Borrow<FuzzResultSet> + Sync],
    fuzz_cases: &BTreeMap<FuzzCaseId, FuzzCaseMeta>,
) -> Result<
    BTreeMap<
        FuzzCaseId,
        BTreeMap<(ResolverName, ResolverName), (DifferenceResult, OracleResults, OracleResults)>,
    >,
> {
    let mut fuzz_results_by_fuzzee: BTreeMap<FuzzCaseId, Vec<(ResolverName, FuzzResult)>> =
        BTreeMap::new();
    for resultset in fuzz_results {
        let resultset = resultset.borrow();
        for fuzz_result in &resultset.results {
            let fuzz_results = fuzz_results_by_fuzzee
                .entry(fuzz_result.id)
                .or_insert_with(Vec::new);
            fuzz_results.push((resultset.fuzzee.clone(), fuzz_result.clone()));
        }
    }
    let diff_tasks = fuzz_results_by_fuzzee
        .iter()
        .flat_map(|(caseid, results)| {
            results
                .iter()
                .enumerate()
                .flat_map(move |(first_idx, (first_fuzzee, first_result))| {
                    results[first_idx + 1..]
                        .iter()
                        .map(move |(second_fuzzee, second_result)| {
                            let fuzz_case = &fuzz_cases[caseid].fuzz_case;

                            async move {
                                // Sort the fuzzees alphabetically
                                let (first_fuzzee, second_fuzzee, first_result, second_result) =
                                    if first_fuzzee < second_fuzzee {
                                        (
                                            first_fuzzee.clone(),
                                            second_fuzzee.clone(),
                                            first_result,
                                            second_result,
                                        )
                                    } else {
                                        (
                                            second_fuzzee.clone(),
                                            first_fuzzee.clone(),
                                            second_result,
                                            first_result,
                                        )
                                    };

                                let difference_result = diff_two_resolvers(
                                    fuzz_case,
                                    &first_fuzzee,
                                    &second_fuzzee,
                                    first_result,
                                    second_result,
                                )
                                .await?;
                                ok((
                                    fuzz_case.id,
                                    first_fuzzee,
                                    second_fuzzee,
                                    difference_result,
                                    first_result.oracles,
                                    second_result.oracles,
                                ))
                            }
                        })
                })
        })
        .collect::<Vec<_>>();
    let diff_tasks = stream::iter(diff_tasks)
        .buffer_unordered(10)
        .try_fold(
            BTreeMap::new(),
            |mut acc, (caseid, first_fuzzee, second_fuzzee, diff, left_oracle, right_oracle)| async move {
                let case_diffs = acc.entry(caseid).or_insert_with(BTreeMap::new);
                case_diffs.insert((first_fuzzee, second_fuzzee), (diff, left_oracle, right_oracle));
                Ok(acc)
            },
        )
        .await?;

    Ok(diff_tasks)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn diff_two_resolvers(
    fuzz_case: &FuzzCase,
    first_fuzzee: &ResolverName,
    second_fuzzee: &ResolverName,
    first_result: &FuzzResult,
    second_result: &FuzzResult,
) -> Result<DifferenceResult> {
    let get_keyvalues = |resolver_name, fuzz_result| {
        let frd = FuzzResultDiff {
            fuzz_case,
            resolver_name,
            fuzz_result,
        };

        ValueMap::from(&frd).unwrap()
    };

    // Extract key-value pairs from the FuzzResults
    let first_keyvalue: ValueMap = get_keyvalues(first_fuzzee, first_result);
    let second_keyvalue: ValueMap = get_keyvalues(second_fuzzee, second_result);

    // // Create a filtered subset
    // // The filter allows us to focus on some keys deemed more important
    // fn filter_keys(s: &str) -> bool {
    //     // IDs are always different and can never match
    //     if s.contains(&**HEADER__ID) {
    //         return false;
    //     }
    //     // The data is always the same on both sides
    //     // This is the data we feed into the fuzzing
    //     if s.starts_with(".fuzz_case") {
    //         return false;
    //     }
    //     // Cookies like IDs are random, can never match, and are not semantically significant
    //     if s.contains(".edns.Cookie.") {
    //         return false;
    //     }
    //     // Coverage counters differ, but are just meta information
    //     if s == ".fuzz_result.counters" {
    //         return false;
    //     }
    //     // The resolver name is always different and not significant
    //     if s == ".resolver_name" {
    //         return false;
    //     }
    //     true
    // }
    // let first_keyvalue_filtered: ValueMap = first_keyvalue.filter_keys(filter_keys);
    // let second_keyvalue_filtered: ValueMap = second_keyvalue.filter_keys(filter_keys);

    // if first_keyvalue_filtered == second_keyvalue_filtered {
    //     return Ok(DifferenceResult::NoDifference);
    // }

    let first_keyvalue_sorted = first_keyvalue.as_sorted();
    let second_keyvalue_sorted = second_keyvalue.as_sorted();

    let diff_keys: DiffKeysSet =
        crate::zip_sorted::zip_sorted(&first_keyvalue_sorted, &second_keyvalue_sorted)
            .filter_map(
                |(k, vl, vr)| {
                    if vl != vr {
                        Some(k.0.clone())
                    } else {
                        None
                    }
                },
            )
            .collect();

    // Check if this is a known difference
    let known_diffs = search_known_differences(&diff_keys, &first_keyvalue, &second_keyvalue);
    let keydiffs: DiffKeysSet = {
        let known_diff_keys: DiffKeysSet = known_diffs
            .0
            .iter()
            .filter_map(|(k, v)| if v.is_empty() { None } else { Some(k.clone()) })
            .collect();
        diff_keys.difference(&known_diff_keys).cloned().collect()
    };
    if keydiffs.is_empty() {
        // All differences are known, so we can skip this
        return Ok(DifferenceResult::KnownDifference(
            known_diffs.get_total_set(),
        ));
    }

    log::info!(
        "Difference detected between {} and {}: {}",
        first_fuzzee,
        second_fuzzee,
        fuzz_case.id
    );

    let diff_fingerprint = DiffFingerprint::new(&keydiffs, &first_keyvalue, &second_keyvalue);
    Ok(DifferenceResult::NewDifference((
        Box::new(diff_fingerprint),
        known_diffs,
    )))
}

/// Return a table showing the differing keys
///
/// Also returns the set of keys that are different.
fn tablefy(
    left: &BTreeMap<Natsorted, &Value>,
    right: &BTreeMap<Natsorted, &Value>,
    explanation: &KnownDiffs,
) -> comfy_table::Table {
    use comfy_table::{Cell as TableCell, CellAlignment, Table};

    let mut msg_diff = Table::new();
    msg_diff.load_preset(comfy_table::presets::NOTHING);
    crate::zip_sorted::zip_sorted(left, right).for_each(|(k, fir, sec)| {
        let (is_diff, expl) = if fir != sec {
            match explanation.get(&k.0) {
                Some(expl) if !expl.is_empty() => (
                    TableCell::new(".").set_alignment(CellAlignment::Right),
                    TableCell::new(itertools::join(expl.iter().map(|e| e.as_ref()), ", ")),
                ),
                Some(_) | None => (
                    TableCell::new("*").set_alignment(CellAlignment::Right),
                    TableCell::new(""),
                ),
            }
        } else {
            (TableCell::new(""), TableCell::new(""))
        };

        msg_diff.add_row(vec![
            is_diff,
            TableCell::new(k),
            TableCell::new(fir.map(ToString::to_string).unwrap_or_default()),
            TableCell::new(sec.map(ToString::to_string).unwrap_or_default()),
            expl,
        ]);
    });
    msg_diff
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn dump_difference_information(
    diff_dir: PathBuf,
    fuzz_case: FuzzCase,
    fuzz_suite: Arc<FuzzSuite>,
    first_fuzzee: ResolverName,
    second_fuzzee: ResolverName,
    first_result: FuzzResult,
    second_result: FuzzResult,
    first_meta: Meta,
    second_meta: Meta,
    fingerprint: DiffFingerprint,
    known_diffs: KnownDiffs,
) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        // TODO Unify this code with the code in `diff_two_resolvers`
        let get_keyvalues = |resolver_name, fuzz_result| {
            let frd = FuzzResultDiff {
                fuzz_case: &fuzz_case,
                resolver_name,
                fuzz_result,
            };

            ValueMap::from(&frd).unwrap()
        };

        // Extract key-value pairs from the FuzzResults
        let first_keyvalue = get_keyvalues(&first_fuzzee, &first_result);
        let first_keyvalue_sorted = first_keyvalue.as_sorted();
        let second_keyvalue = get_keyvalues(&second_fuzzee, &second_result);
        let second_keyvalue_sorted = second_keyvalue.as_sorted();

        // Convert the key-value pairs into a table
        // The table shows which keys differ and is more human friendly
        let msg_fulldiff = tablefy(
            &first_keyvalue_sorted,
            &second_keyvalue_sorted,
            &known_diffs,
        );

        let diff_dir = diff_dir
            .join(fuzz_case.id.to_string())
            .join(format!("{first_fuzzee}-{second_fuzzee}"));
        // Here we are not in an async context, since we are inside `spawn_blocking`
        #[allow(clippy::disallowed_methods)]
        std::fs::create_dir_all(&diff_dir)?;

        // Store:
        // * The FuzzCase as a FuzzSuite
        // * Pre-normalized results
        // * Post-normalized results
        // * Diff

        let suite = FuzzSuite {
            id: FuzzSuiteId::new(),
            test_cases: vec![fuzz_case.clone()],
        };

        fn json_file<T: serde::Serialize>(
            diff_dir: &Path,
            filename: &str,
            value: &T,
        ) -> Result<()> {
            let data = serde_json::to_vec(value)?;
            fs::file_write(diff_dir.join(filename))
                .create_new(true)
                .truncate()?
                .write_all(&data)?;
            Ok(())
        }
        fn postcard_file<T: serde::Serialize>(
            diff_dir: &Path,
            filename: &str,
            value: &T,
        ) -> Result<()> {
            let data = postcard::to_allocvec(value)?;
            fs::file_write(diff_dir.join(filename))
                .create_new(true)
                .truncate()?
                .write_all(&data)?;
            Ok(())
        }
        fn plain_file(diff_dir: &Path, filename: &str, data: &[u8]) -> Result<()> {
            fs::file_write(diff_dir.join(filename))
                .create_new(true)
                .truncate()?
                .write_all(data)?;
            Ok(())
        }

        postcard_file(&diff_dir, "fuzz-suite.postcard", &suite)?;
        postcard_file(&diff_dir, "fuzz-suite-full.postcard.gz", &*fuzz_suite)?;
        json_file(&diff_dir, &format!("{first_fuzzee}.json.gz"), &first_result)?;
        json_file(
            &diff_dir,
            &format!("{second_fuzzee}.json.gz"),
            &second_result,
        )?;
        json_file(&diff_dir, "fingerprint.json", &fingerprint)?;

        plain_file(
            &diff_dir,
            "fulldiff.txt",
            msg_fulldiff.to_string().as_bytes(),
        )?;
        if let Some(pcap) = first_meta.get("tcpdump.pcap") {
            if let Some(pcap) = pcap.downcast_ref::<Box<[u8]>>() {
                // Wireshark can open .pcap.gz files
                plain_file(&diff_dir, &format!("{first_fuzzee}.pcap.gz"), pcap)?;
            }
        };
        if let Some(pcap) = second_meta.get("tcpdump.pcap") {
            if let Some(pcap) = pcap.downcast_ref::<Box<[u8]>>() {
                plain_file(&diff_dir, &format!("{second_fuzzee}.pcap.gz"), pcap)?;
            }
        };

        Ok(())
    })
    .await?
}

/// Helper type to avoid boilerplate when marking keys with their `DifferenceKind`s
pub(crate) struct KnownDiffs(
    /// The map **must** be initialized with all keys that are expected to differ
    HashMap<Atom, Vec<DifferenceKind>, nohash_hasher::BuildNoHashHasher<u32>>,
);

impl KnownDiffs {
    /// Create a new `KnownDiffs` with the given set of differing keys
    fn from(diff_keys: &DiffKeysSet) -> Self {
        Self(diff_keys.iter().map(|k| (k.clone(), Vec::new())).collect())
    }

    fn get(&self, key: &Atom) -> Option<&Vec<DifferenceKind>> {
        self.0.get(key)
    }

    fn get_total_set(&self) -> BTreeSet<DifferenceKind> {
        self.0.values().flat_map(|v| v.iter()).copied().collect()
    }

    /// Mark the exact `key` with the given `kind` of difference
    fn mark(&mut self, key: &Atom, kind: DifferenceKind) {
        // At creation all keys are inserted, so if a key is missing, the value is not different.
        if let Some(diff_kinds) = self.0.get_mut(key) {
            diff_kinds.push(kind);
        }
    }

    /// Mark the exact `key` with the given `kind` of difference, if `cond` returns `true`
    fn mark_if(&mut self, key: &Atom, kind: DifferenceKind, cond: impl Fn() -> bool) {
        // At creation all keys are inserted, so if a key is missing, the value is not different.
        if let Some(diff_kinds) = self.0.get_mut(key) {
            if cond() {
                diff_kinds.push(kind);
            }
        };
    }

    /// Mark any key containing `needle` with the given `kind` of difference
    fn mark_contains(&mut self, needle: &str, kind: DifferenceKind) {
        self.0
            .iter_mut()
            .filter(|(k, _)| k.as_ref().contains(needle))
            .for_each(|(_, v)| v.push(kind));
    }

    /// Mark any key starting with `prefix` with the given `kind` of difference
    fn mark_prefix(&mut self, prefix: &str, kind: DifferenceKind) {
        self.0
            .iter_mut()
            .filter(|(k, _)| k.as_ref().starts_with(prefix))
            .for_each(|(_, v)| v.push(kind));
    }

    /// Mark any key starting with `prefix` with the given `kind` of difference, if `cond` returns `true`
    ///
    /// The condition has access to the key being checked.
    fn mark_prefix_if(&mut self, prefix: &str, kind: DifferenceKind, cond: impl Fn(&Atom) -> bool) {
        self.0
            .iter_mut()
            .filter(|(k, _)| k.as_ref().starts_with(prefix) && cond(k))
            .for_each(|(_, v)| v.push(kind));
    }

    /// Mark any key ending with `suffix` with the given `kind` of difference
    fn mark_suffix(&mut self, suffix: &str, kind: DifferenceKind) {
        self.0
            .iter_mut()
            .filter(|(k, _)| k.as_ref().ends_with(suffix))
            .for_each(|(_, v)| v.push(kind));
    }

    /// Mark any key ending with `suffix` with the given `kind` of difference, if `cond` returns `true`
    ///
    /// The condition has access to the key being checked.
    fn mark_suffix_if(&mut self, suffix: &str, kind: DifferenceKind, cond: impl Fn(&Atom) -> bool) {
        self.0
            .iter_mut()
            .filter(|(k, _)| k.as_ref().ends_with(suffix) && cond(k))
            .for_each(|(_, v)| v.push(kind));
    }

    /// Return `true` if any key is markedf with the given `kind` difference
    fn has_kind(&self, kind: DifferenceKind) -> bool {
        self.0.values().any(|v| v.contains(&kind))
    }
}

pub(crate) fn search_known_differences<'a>(
    // Keys with known differences
    diff_keys: &'a DiffKeysSet,
    mut left: &'a ValueMap,
    mut right: &'a ValueMap,
) -> KnownDiffs {
    // Ensure the resolvers are listed in lexicographic order
    if left[RESOLVER_NAME] > right[RESOLVER_NAME] {
        std::mem::swap(&mut left, &mut right);
    }

    let mut known_diffs = KnownDiffs::from(diff_keys);

    if left[FUZZ_RESULT__FUZZEE_QUERIES__COUNT] != left[FUZZ_RESULT__RESPONSE_IDXS__COUNT] {
        log::error!(
            "More queries are recorded than in the response idx list noted.\nLeft\n{left:?}"
        );
        return known_diffs;
    }
    if right[FUZZ_RESULT__FUZZEE_QUERIES__COUNT] != right[FUZZ_RESULT__RESPONSE_IDXS__COUNT] {
        log::error!(
            "More queries are recorded than in the response idx list noted.\nRight\n{right:?}"
        );
        return known_diffs;
    }

    // Check for Resolver Name differences
    known_diffs.mark(RESOLVER_NAME, DifferenceKind::ResolverName);

    // Check for DNS ID differences
    known_diffs.mark_suffix(HEADER__ID, DifferenceKind::DnsId);

    // Counters can only be compared if we have the same resolver
    known_diffs.mark_if(
        FUZZ_RESULT__COUNTERS,
        DifferenceKind::IncomparableCounters,
        || left[RESOLVER_NAME] != right[RESOLVER_NAME],
    );

    // Paths starting with `#` are meta information and can be ignored
    // Their information is encoded separately
    known_diffs.mark_contains(".#", DifferenceKind::MetaDiff);

    // Query class for non-IN queries is indeterminate
    known_diffs.mark_if(
        FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RECURSION_AVAILABLE,
        DifferenceKind::NonINRecursion,
        || left[FUZZ_CASE__CLIENT_QUERY__QUERIES__0__QUERY_CLASS] != VALUE_IN,
    );

    // DNS Cookie support is not required and as such can be missing in the queries send to the AuthNS
    // Unbound does not send Cookies
    let left_query_count = left[FUZZ_RESULT__FUZZEE_QUERIES__COUNT].as_i64().unwrap();
    let right_query_count = right[FUZZ_RESULT__FUZZEE_QUERIES__COUNT].as_i64().unwrap();
    for i in 0..std::cmp::min(left_query_count, right_query_count) {
        match (
            diff_keys.get(&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{i}.edns.Cookie.code"
            ))),
            diff_keys.get(&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{i}.edns.Cookie.value"
            ))),
        ) {
            // Either both sides are missing cookies or both sides have the same cookie.
            // Having the same cookie is weird, but ok
            (None, None) => {}
            // Only the value is different, but both sides have a cookie
            (None, Some(cookie_val)) => {
                known_diffs.mark(cookie_val, DifferenceKind::CookiesUncomparable);
            }
            // Only the code part is different, but both sides have the same cookie value
            // This should not occur, but we handle it anyway
            (Some(cookie), None) => {
                known_diffs.mark(cookie, DifferenceKind::CookiesUnsupported);
            }
            // Only one side has a cookie set, but we don't know which
            (Some(cookie), Some(cookie_val)) => {
                known_diffs.mark(cookie, DifferenceKind::CookiesUnsupported);
                known_diffs.mark(cookie_val, DifferenceKind::CookiesUnsupported);
            }
        }
    }

    // Cache comparison is difficult
    // Some resolvers do not support cache probing
    // Some resolvers always error for "weird" types or classes
    // Instead of hard-coding all these special cases, simply ignore all cache states which could not be deterimined for both resolvers.
    // This still might lead to some problems, e.g., one resolver errored but the other returned a value.
    // But that would be a real difference caused by some other value.
    known_diffs.mark_prefix_if(
        ".fuzz_result.cache_state.",
        DifferenceKind::TodoCacheIgnoredForNow,
        |key| left[key] == VALUE_ERROR || right[key] == VALUE_ERROR,
    );

    // ServFail if the AuthNS answer type does not match the query
    fn servfail_if_authns_answer_wrong_type(
        diff_keys: &DiffKeysSet,
        known_diffs: &mut KnownDiffs,
        left: &ValueMap,
        right: &ValueMap,
    ) {
        if diff_keys.contains(FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE)
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_SERVFAIL
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_NOERROR
        {
            // Get the number of queries, such that we can inspect the last one:
            let query_count = left[FUZZ_RESULT__FUZZEE_QUERIES__COUNT].as_i64().unwrap();
            let qtype = &left[format!(
                ".fuzz_result.fuzzee_queries.{}.queries.0.query_type",
                query_count - 1
            )];
            // This fails if the answer_idx is usize::MAX, in which case no answer was received
            let Some(answer_idx) =
                left[format!(".fuzz_result.response_idxs.{}", query_count - 1)].as_i64() else {return};

            // Check the last send answer to the resolver.
            // This is the minimal count between queries and answers.
            // If queries is higher than they all go unanswered, also leading to a servfail.
            let Some(answer_count) =
                left[format!(".fuzz_case.server_responses.{answer_idx}.answers.#count")].as_i64() else {return};
            // If all answers are different than qtype this is a match
            let all_answer_types_differ = (0..answer_count).all(|i| {
                let answer_type =
                    &left[format!(".fuzz_case.server_responses.{answer_idx}.answers.{i}.rr_type")];

                answer_type != qtype
            });

            if all_answer_types_differ {
                known_diffs.mark(
                    FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE,
                    DifferenceKind::ServFailOnWrongAuthnsAnswerType,
                );

                for keyprefix in [
                    ".fuzz_result.fuzzee_response.header.answer_count",
                    ".fuzz_result.fuzzee_response.answers",
                ] {
                    known_diffs
                        .mark_prefix(keyprefix, DifferenceKind::ServFailOnWrongAuthnsAnswerType);
                }
            }
        }
    }
    servfail_if_authns_answer_wrong_type(diff_keys, &mut known_diffs, left, right);
    servfail_if_authns_answer_wrong_type(diff_keys, &mut known_diffs, right, left);

    // ServFail if the AuthNS answer class does not match the query
    fn servfail_if_authns_answer_wrong_class(
        diff_keys: &DiffKeysSet,
        known_diffs: &mut KnownDiffs,
        left: &ValueMap,
        right: &ValueMap,
    ) {
        if diff_keys.contains(FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE)
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_SERVFAIL
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_NOERROR
        {
            // Get the number of queries, such that we can inspect the last one:
            let query_count = left[FUZZ_RESULT__FUZZEE_QUERIES__COUNT].as_i64().unwrap();
            let qclass = &left[format!(
                ".fuzz_result.fuzzee_queries.{}.queries.0.query_class",
                query_count - 1
            )];
            // This fails if the answer_idx is usize::MAX, in which case no answer was received
            let Some(answer_idx) =
                left[format!(".fuzz_result.response_idxs.{}", query_count - 1)].as_i64() else {return};

            // Check the last send answer to the resolver.
            // This is the minimal count between queries and answers.
            // If queries is higher than they all go unanswered, also leading to a servfail.
            let Some(answer_count) =
                left[format!(".fuzz_case.server_responses.{answer_idx}.answers.#count")].as_i64() else {return};
            // If all answers are different than qclass this is a match
            let any_answer_class_differs = (0..answer_count).any(|i| {
                let answer_class = &left
                    [format!(".fuzz_case.server_responses.{answer_idx}.answers.{i}.dns_class")];

                answer_class != qclass
            });

            if any_answer_class_differs {
                known_diffs.mark(
                    FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE,
                    DifferenceKind::ServFailOnWrongAuthnsAnswerClass,
                );

                for keyprefix in [
                    ".fuzz_result.fuzzee_response.header.answer_count",
                    ".fuzz_result.fuzzee_response.answers",
                ] {
                    known_diffs
                        .mark_prefix(keyprefix, DifferenceKind::ServFailOnWrongAuthnsAnswerClass);
                }
            }
        }
    }
    servfail_if_authns_answer_wrong_class(diff_keys, &mut known_diffs, left, right);
    servfail_if_authns_answer_wrong_class(diff_keys, &mut known_diffs, right, left);

    // Max limit for TTL reached
    fn ttl_max_limit(
        diff_keys: &DiffKeysSet,
        known_diffs: &mut KnownDiffs,
        left: &ValueMap,
        right: &ValueMap,
    ) {
        diff_keys
            .iter()
            .filter(|ttl| {
                ttl.as_ref()
                    .starts_with(".fuzz_result.fuzzee_response.answers.")
                    && ttl.as_ref().ends_with(".ttl")
            })
            .for_each(|ttl| {
                if left[ttl] == 86400 && left[RESOLVER_NAME] == VALUE_UNBOUND && right[ttl] > 86400
                {
                    let answer_key = ttl.as_ref().strip_suffix(".ttl").unwrap();

                    let mut checked_answer_idxs = BTreeSet::new();
                    // Iterate over all possible answers in the AuthNS responses and search for the original TTL
                    for response_idx in
                        0..right[FUZZ_RESULT__RESPONSE_IDXS__COUNT].as_i64().unwrap()
                    {
                        // TODO this can panic, since the answer can be usize::MAX
                        let Some(answer_idx) =
                            right[format!(".fuzz_result.response_idxs.{response_idx}")].as_i64() else {return};
                        if !checked_answer_idxs.insert(answer_idx) {
                            // Answer was already checked previously
                            continue;
                        }

                        for answer_rr_idx in 0..right
                            [format!(".fuzz_case.server_responses.{answer_idx}.answers.#count")]
                        .as_i64()
                        .unwrap()
                        {
                            // Check for matching dns_class, name_labels, and rr_type
                            let mut is_matching_answer = [".dns_class", ".rr_type"]
                                .into_iter()
                                .all(|keypart| {
                                    if right[format!("{answer_key}{keypart}")].is_missing() {
                                        log::error!(
                                            "answer_key={answer_key} keypart={keypart} \
                                             response_idx={response_idx} answer_idx={answer_idx}"
                                        );
                                    }

                                    right[format!(
                                        ".fuzz_case.server_responses.{answer_idx}.answers.\
                                         {answer_rr_idx}{keypart}"
                                    )] == right[format!("{answer_key}{keypart}")]
                                });
                            // rdata cannot be compared for identity since it might contain a name with "test." and that part will not match
                            is_matching_answer = is_matching_answer && if let Some(str) = right[format!(".fuzz_case.server_responses.{answer_idx}.answers.{answer_rr_idx}.rdata")].as_str() {
                                str.len() == right[format!("{answer_key}.rdata")].as_str().unwrap_or("").len()
                            } else {
                                // If we are not dealing with a string, we still compare identity
                                right[format!(".fuzz_case.server_responses.{answer_idx}.answers.{answer_rr_idx}.rdata")] == right[format!("{answer_key}.rdata")]
                            };

                            let orig = right[format!(
                                ".fuzz_case.server_responses.{answer_idx}.answers.{answer_rr_idx}.\
                                 name_labels",
                            )]
                            .as_str()
                            .unwrap();
                            let answ = right[format!("{answer_key}.name_labels")].as_str().unwrap();
                            // Compare values while ignoring the `test.fuzz.` part: akztd.test.fuzz.
                            is_matching_answer = is_matching_answer
                                && (orig[..orig.len() - 10] == answ[..answ.len() - 10]);

                            // All entries of the RR match, let's check if the TTL is the same too or not
                            if is_matching_answer
                                && right[format!(
                                    ".fuzz_case.server_responses.{answer_idx}.answers.\
                                     {answer_rr_idx}.ttl"
                                )] == right[ttl]
                            {
                                known_diffs.mark(ttl, DifferenceKind::MaxTtlLimit);
                            }
                        }
                    }
                }
            });
    }
    ttl_max_limit(diff_keys, &mut known_diffs, left, right);
    ttl_max_limit(diff_keys, &mut known_diffs, right, left);

    // FormErr when sending a query with TC bit set
    fn formerr_for_tc_query(
        diff_keys: &DiffKeysSet,
        known_diffs: &mut KnownDiffs,
        middle: &ValueMap,
    ) {
        if diff_keys.contains(FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE)
            && middle[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_FORMERR
            && middle[FUZZ_CASE__CLIENT_QUERY__HEADER__TRUNCATED] == true
        {
            // These diffs occur between BIND9 and Unbound
            // The 1200 max_payload is copied from the query.
            //
            // *  .fuzz_result.fuzzee_response.header.recursion_available   true                                  false
            // *  .fuzz_result.fuzzee_response.header.response_code         ServFail                              FormErr
            for key in [
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RECURSION_AVAILABLE,
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE,
            ] {
                known_diffs.mark(key, DifferenceKind::FormErrOnTruncatedQuery);
            }
        }
    }
    formerr_for_tc_query(diff_keys, &mut known_diffs, left);
    formerr_for_tc_query(diff_keys, &mut known_diffs, right);

    fn error_client_no_rr_in_answer(
        known_diffs: &mut KnownDiffs,
        left: &ValueMap,
        right: &ValueMap,
    ) {
        let rcode_left = &left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE];
        if (rcode_left == VALUE_FORMERR
            || rcode_left == VALUE_NOTIMP
            || rcode_left == VALUE_REFUSED)
            && rcode_left != (&right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE])
        {
            // error responses are not expected to cary any RR in the answer, authoritative, or additional section
            for keyprefix in [
                ".fuzz_result.fuzzee_response.additionals",
                ".fuzz_result.fuzzee_response.answers",
                ".fuzz_result.fuzzee_response.name_servers",
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ADDITIONAL_COUNT,
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ANSWER_COUNT,
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__NAME_SERVER_COUNT,
            ] {
                known_diffs.mark_prefix(keyprefix, DifferenceKind::ErrorClientNoRrInAnswer);
            }
        }
    }
    error_client_no_rr_in_answer(&mut known_diffs, left, right);
    error_client_no_rr_in_answer(&mut known_diffs, right, left);

    // Client Query without RD bit results in delegation like response with varying TTL values.
    // The TTL values for the name server and additionals section are affected.
    if let Some(ns_ttl) = diff_keys.get(FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__TTL) {
        let matches = left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__NAME_LABELS]
            == VALUE_FUZZ
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__NAME_LABELS] == VALUE_FUZZ
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__RDATA] == VALUE_NS_FUZZ_NS
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__RDATA] == VALUE_NS_FUZZ_NS
            && left[ns_ttl] <= 86400
            && right[ns_ttl] <= 86400;
        if matches {
            known_diffs.mark(
                FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__TTL,
                DifferenceKind::ClientQueryWithoutRdBit,
            );
        }

        // Check the same as above but for the additional section
        known_diffs.mark_if(
            FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__TTL,
            DifferenceKind::ClientQueryWithoutRdBit,
            || {
                left[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__NAME_LABELS] == VALUE_NS_FUZZ_NS
                    && right[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__NAME_LABELS]
                        == VALUE_NS_FUZZ_NS
                    && left[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__RDATA] == VALUE_127_97_1_1
                    && right[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__RDATA]
                        == VALUE_127_97_1_1
                    && left[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__TTL] <= 86400
                    && right[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__TTL] <= 86400
            },
        );
    }

    // Extend the previous check to cover RRs in the authority and additionals section.
    fn no_rd_bit_delegation_response(known_diffs: &mut KnownDiffs, left: &ValueMap) {
        // Check the authority section
        if left[FUZZ_RESULT__RESPONSE_IDXS__COUNT] == 0
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__COUNT] == 1
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__NAME_LABELS] == VALUE_FUZZ
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__RR_TYPE] == VALUE_NS
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__RDATA] == VALUE_NS_FUZZ_NS
        {
            known_diffs.mark_prefix(
                ".fuzz_result.fuzzee_response.name_servers.0.",
                DifferenceKind::ClientQueryWithoutRdBit,
            );
            known_diffs.mark(
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__NAME_SERVER_COUNT,
                DifferenceKind::ClientQueryWithoutRdBit,
            );
        }
        // Check the additional section
        if left[FUZZ_RESULT__RESPONSE_IDXS__COUNT] == 0
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__COUNT] == 1
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__NAME_LABELS] == VALUE_NS_FUZZ_NS
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__RR_TYPE] == VALUE_A
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__RDATA] == VALUE_127_97_1_1
        {
            known_diffs.mark_prefix(
                ".fuzz_result.fuzzee_response.additionals.0.",
                DifferenceKind::ClientQueryWithoutRdBit,
            );
            known_diffs.mark(
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ADDITIONAL_COUNT,
                DifferenceKind::ClientQueryWithoutRdBit,
            );
        }
    }
    no_rd_bit_delegation_response(&mut known_diffs, left);
    no_rd_bit_delegation_response(&mut known_diffs, right);

    // Check for unsupported extended DNS errors
    if diff_keys.contains(FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__CODE15__CODE)
        && (left[RESOLVER_NAME] == VALUE_UNBOUND
            || right[RESOLVER_NAME] == VALUE_UNBOUND
            || left[RESOLVER_NAME] == VALUE_PDNS_RECURSOR
            || right[RESOLVER_NAME] == VALUE_PDNS_RECURSOR)
    {
        known_diffs.mark(
            FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__CODE15__CODE,
            DifferenceKind::ExtendedErrorsUnsupported,
        );

        // These two keys are only present if the first one is available too.
        known_diffs.mark(
            FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__CODE15__ERROR_CODE,
            DifferenceKind::ExtendedErrorsUnsupported,
        );
        known_diffs.mark(
            FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__CODE15__ERROR_VALUE,
            DifferenceKind::ExtendedErrorsUnsupported,
        );
    }

    fn no_edns_support(known_diffs: &mut KnownDiffs, left: &ValueMap, right: &ValueMap) {
        // Check for no EDNS support on the left side
        if left[RESOLVER_NAME] == VALUE_MARADNS
            || left[RESOLVER_NAME] == VALUE_RESOLVED
            || left[RESOLVER_NAME] == VALUE_TRUST_DNS
        {
            known_diffs.mark_contains(".edns.", DifferenceKind::NoEdnsSupport);
            // Checking bit is only set to true when supporting DNSSEC which requires EDNS
            known_diffs.mark_suffix(".header.checking_disabled", DifferenceKind::NoEdnsSupport);
            known_diffs.mark_suffix_if(
                ".header.additional_count",
                DifferenceKind::NoEdnsSupport,
                |key| {
                    // The only allowed difference is the single additional record for the OPT RR
                    // Any more and this should not match.
                    left[key].as_i64().map(|x| x + 1) == right[key].as_i64()
                },
            );
        }
    }
    no_edns_support(&mut known_diffs, left, right);
    no_edns_support(&mut known_diffs, right, left);

    // If maradns has no answer at all and the other side is either a SERVFAIL or a NODATA response, we assume that is the reason for the difference.
    fn maradns_no_response_servfail(
        known_diffs: &mut KnownDiffs,
        left: &ValueMap,
        right: &ValueMap,
    ) {
        if left[RESOLVER_NAME] == VALUE_MARADNS {
            // Check that all keys under .fuzz_result.fuzzee_response are missing
            let no_response_entry = left
                .into_iter()
                .filter(|(key, _)| key.starts_with(".fuzz_result.fuzzee_response"))
                .all(|(_, value)| value.is_missing());
            let other_side_nodata = right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ANSWER_COUNT] == 0
                && right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__NAME_SERVER_COUNT] == 0;
            if no_response_entry && other_side_nodata {
                known_diffs.mark_prefix(
                    ".fuzz_result.fuzzee_response",
                    DifferenceKind::MaradnsNoResponseServfail,
                );
            }

            // Mark the whole fuzzee query section as affected too, if and only if maradns did not sent a single query.
            if left[FUZZ_RESULT__RESPONSE_IDXS__COUNT] == 0 {
                known_diffs.mark_prefix(
                    ".fuzz_result.fuzzee_queries.",
                    DifferenceKind::MaradnsNoResponseServfail,
                );
                known_diffs.mark_prefix(
                    ".fuzz_result.response_idxs.",
                    DifferenceKind::MaradnsNoResponseServfail,
                );
            }
        }
    }
    maradns_no_response_servfail(&mut known_diffs, left, right);
    maradns_no_response_servfail(&mut known_diffs, right, left);

    // Mark all additional responses of one side if they are all retransmissions
    fn trailing_retransmissions(known_diffs: &mut KnownDiffs, left: &ValueMap, right: &ValueMap) {
        let left_idx_count = left[FUZZ_RESULT__RESPONSE_IDXS__COUNT].as_i64().unwrap();
        let right_idx_count = right[FUZZ_RESULT__RESPONSE_IDXS__COUNT].as_i64().unwrap();
        // Ensure that both sides sent at least one query
        // Otherwise we might have a case where one side refused the client query and never worked.
        if left_idx_count > right_idx_count && right_idx_count > 0 {
            let min_count = std::cmp::min(left_idx_count, right_idx_count);
            let max_count = std::cmp::max(left_idx_count, right_idx_count);

            // .fuzz_result.fuzzee_queries.1.queries.#count
            // .fuzz_result.fuzzee_queries.1.queries.0.name
            // .fuzz_result.fuzzee_queries.1.queries.0.query_class
            // .fuzz_result.fuzzee_queries.1.queries.0.query_type

            let get_query_section = |idx: i64| {
                let count = left
                    [&Atom::from(format!(".fuzz_result.fuzzee_queries.{idx}.queries.#count"))]
                    .clone();
                let name = left
                    [&Atom::from(format!(".fuzz_result.fuzzee_queries.{idx}.queries.0.name"))]
                    .clone();
                let class = left[&Atom::from(format!(
                    ".fuzz_result.fuzzee_queries.{idx}.queries.0.query_class"
                ))]
                    .clone();
                let ty = left[&Atom::from(format!(
                    ".fuzz_result.fuzzee_queries.{idx}.queries.0.query_type"
                ))]
                    .clone();
                (count, name, class, ty)
            };

            let last_query_section_query = get_query_section(max_count - 1);
            // Make sure all the queries are the same
            let all_identical_query = (min_count..(max_count - 1))
                .all(|i| get_query_section(i) == last_query_section_query);
            if all_identical_query {
                // Verify that these queries are actually retransmissions by checking if they also occur in the shared query part
                let are_retransmissions = (0..min_count)
                    .rev()
                    .any(|i| get_query_section(i) == last_query_section_query);
                if are_retransmissions {
                    // Mark all the additional queries as retransmissions
                    for i in min_count..max_count {
                        known_diffs.mark(
                            &Atom::from(format!(".fuzz_result.response_idxs.{i}")),
                            DifferenceKind::TrailingRetransmissions,
                        );
                        known_diffs.mark_prefix(
                            &Atom::from(format!(".fuzz_result.fuzzee_queries.{i}.")),
                            DifferenceKind::TrailingRetransmissions,
                        );
                    }
                }
            }
            // TODO handle corner cases around one side having 0 queries.
            // In this case nothing is a re-transmission, since there is no original transmission.
        }
    }
    trailing_retransmissions(&mut known_diffs, left, right);
    trailing_retransmissions(&mut known_diffs, right, left);

    // If a resolver does not process the client query for whatever reason, but the other one does, then comparing the list of fuzzee queries is pointless.
    // The refusing side will not have any queries, but the other side will have plenty.
    // This does cover a couple of status codes which all relate to "refusing" a client query, namely:
    // - `FormErr`: The server doesn't understand the query, so cannot process it,
    // - `NotImp`: The server does not support the query type, so cannot process it,
    // - `Refused`: The server refuses to process the query for some reason.
    // In all cases ensure that the refusing resolver really did not send a single query.
    // If the other side has the same response code, than this matching also it not important, because then both sides should have similar behavior again.
    // This is a generalization of the earlier `FormErrVoidsFuzzeeQueries`

    // // FormErr voids all differences under `.fuzz_result.fuzzee_queries`
    // // If a resolver has a FormErr, it will not send any queries to the AuthNS, thus all these keys
    // known_diffs.mark_prefix(
    //     ".fuzz_result.fuzzee_queries",
    //     DifferenceKind::FormErrVoidsFuzzeeQueries,
    // );
    fn error_client_query_incomparable_fuzzee_queries(
        known_diffs: &mut KnownDiffs,
        left: &ValueMap,
        right: &ValueMap,
    ) {
        let rcode_left = &left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE];
        if (rcode_left == VALUE_FORMERR
            || rcode_left == VALUE_NOTIMP
            || rcode_left == VALUE_REFUSED)
            && left[FUZZ_RESULT__RESPONSE_IDXS__COUNT].as_i64().unwrap() == 0
            && rcode_left != &right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE]
        {
            known_diffs.mark_prefix(
                ".fuzz_result.fuzzee_queries",
                DifferenceKind::ErrorClientQueryIncomparableFuzzeeQueries,
            );
            known_diffs.mark_prefix(
                ".fuzz_result.response_idxs.",
                DifferenceKind::ErrorClientQueryIncomparableFuzzeeQueries,
            );
        }
    }
    error_client_query_incomparable_fuzzee_queries(&mut known_diffs, left, right);
    error_client_query_incomparable_fuzzee_queries(&mut known_diffs, right, left);

    // Bind9 does not include a query section if the answer has a NotImp response code.
    fn bind9_not_imp_missing_query_section(known_diffs: &mut KnownDiffs, map: &ValueMap) {
        if map[RESOLVER_NAME] == VALUE_BIND9
            && map[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_NOTIMP
        {
            known_diffs.mark_prefix(
                ".fuzz_result.fuzzee_response.queries.",
                DifferenceKind::Bind9NotImpMissingQuerySection,
            );
            // *  .fuzz_result.fuzzee_response.header.query_count
            // *  .fuzz_result.fuzzee_response.header.recursion_desired
            known_diffs.mark(
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__QUERY_COUNT,
                DifferenceKind::Bind9NotImpMissingQuerySection,
            );
            known_diffs.mark(
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RECURSION_DESIRED,
                DifferenceKind::Bind9NotImpMissingQuerySection,
            );
        }
    }
    bind9_not_imp_missing_query_section(&mut known_diffs, left);
    bind9_not_imp_missing_query_section(&mut known_diffs, right);

    // Maradns makes up a new SOA record which does not exist.
    // This seems to only happen if the query type is AAAA and the AuthNS responds with a NODATA answer.
    // The original query was for naxrg.0000.fuzz IN AAAA, but the AuthNS only responds with a NODATA answer.
    // The common parts seem to be the `z.` and `y.` in the SOA record and the TTL of 0.
    //
    // *  .fuzz_result.fuzzee_response.header.name_server_count     0                                     1
    // *  .fuzz_result.fuzzee_response.name_servers.0.dns_class                                           IN
    // *  .fuzz_result.fuzzee_response.name_servers.0.name_labels                                         naxrg.0000.fuzz.
    // *  .fuzz_result.fuzzee_response.name_servers.0.rdata                                               z.naxrg.0000.fuzz. y.naxrg.0000.fuzz. 1 1 1 1 1
    // *  .fuzz_result.fuzzee_response.name_servers.0.rr_type                                             SOA
    // *  .fuzz_result.fuzzee_response.name_servers.0.ttl                                                 0
    fn maradns_fake_soa(known_diffs: &mut KnownDiffs, left: &ValueMap, right: &ValueMap) {
        if left[RESOLVER_NAME] == VALUE_MARADNS
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__NAME_SERVER_COUNT] == 1
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__NAME_SERVER_COUNT] == 0
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__QUERIES__0__QUERY_TYPE] == VALUE_AAAA
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__RR_TYPE] == VALUE_SOA
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__TTL] == 0
        {
            let name = left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__NAME_LABELS]
                .as_str()
                .unwrap();

            if left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__RDATA]
                .as_str()
                .unwrap()
                .starts_with(&format!("z.{name}"))
            {
                known_diffs.mark(
                    FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__NAME_SERVER_COUNT,
                    DifferenceKind::MaradnsFakeSoaOnAAAA,
                );
                known_diffs.mark_prefix(
                    ".fuzz_result.fuzzee_response.name_servers.0.",
                    DifferenceKind::MaradnsFakeSoaOnAAAA,
                );
            }
        }
    }
    maradns_fake_soa(&mut known_diffs, left, right);
    maradns_fake_soa(&mut known_diffs, right, left);

    // Unbound probes using the `A` record which it then follows up with the correct type.
    // This matches if unbound has exactly one more query than the other side, which is also the last query, and the last query is a repeat of the previous.
    // The last query must be for the same type as the client query, and the previous query must be for type A.
    fn unbound_probes_using_a_record(
        known_diffs: &mut KnownDiffs,
        left: &ValueMap,
        right: &ValueMap,
    ) {
        let left_query_count = left[FUZZ_RESULT__RESPONSE_IDXS__COUNT].as_i64().unwrap();
        let right_query_count = right[FUZZ_RESULT__RESPONSE_IDXS__COUNT].as_i64().unwrap();
        if left[RESOLVER_NAME] == VALUE_UNBOUND
            && left_query_count == right_query_count + 1
            // Check that the all DNS messages only carry a single query, as matching otherwise becomes too complicated.
            && (left[&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{}.header.query_count",
                left_query_count - 1
            ))] == 1 && left[&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{}.header.query_count",
                left_query_count - 1
            ))] == left[&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{}.header.query_count",
                left_query_count - 2
            ))] && left[&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{}.header.query_count",
                left_query_count - 1
            ))] == left[FUZZ_CASE__CLIENT_QUERY__HEADER__QUERY_COUNT])
            // Check that the name matches
            && (left[&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{}.queries.0.name",
                left_query_count - 1
            ))] == left[&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{}.queries.0.name",
                left_query_count - 2
            ))] &&
            // Cannot directly compare strings, since the client query is still generic using `test.fuzz`.
            left[&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{}.queries.0.name",
                left_query_count - 1
            ))].as_str().unwrap_or("").len() == left[FUZZ_CASE__CLIENT_QUERY__QUERIES__0__NAME].as_str().unwrap_or("").len())
            // Check that the class matches
            && (left[&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{}.queries.0.query_class",
                left_query_count - 1
            ))] == left[&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{}.queries.0.query_class",
                left_query_count - 2
            ))] && left[&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{}.queries.0.query_class",
                left_query_count - 1
            ))] == left[FUZZ_CASE__CLIENT_QUERY__QUERIES__0__QUERY_CLASS])
            // Check that the type matches
            && (left[&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{}.queries.0.query_type",
                left_query_count - 2
            ))] == VALUE_A && left[&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{}.queries.0.query_type",
                left_query_count - 1
            ))] == left[FUZZ_CASE__CLIENT_QUERY__QUERIES__0__QUERY_TYPE])
        {
            // Mark the extra query as a known difference
            known_diffs.mark_prefix(
                &format!(".fuzz_result.fuzzee_queries.{}.", left_query_count - 1),
                DifferenceKind::UnboundProbesUsingARecord,
            );
            known_diffs.mark(
                &Atom::from(format!(
                    ".fuzz_result.response_idxs.{}",
                    left_query_count - 1
                )),
                DifferenceKind::UnboundProbesUsingARecord,
            );
            // Mark the type difference in the previous query as a known difference
            known_diffs.mark(
                &Atom::from(format!(
                    ".fuzz_result.fuzzee_queries.{}.queries.0.query_type",
                    left_query_count - 2
                )),
                DifferenceKind::UnboundProbesUsingARecord,
            );
        }
    }
    unbound_probes_using_a_record(&mut known_diffs, left, right);
    unbound_probes_using_a_record(&mut known_diffs, right, left);

    // PowerDNS does not set the CD bit in queries
    fn powerdns_cd_bit_query(known_diffs: &mut KnownDiffs, left: &ValueMap) {
        if left[RESOLVER_NAME] == VALUE_PDNS_RECURSOR {
            let query_count = left[FUZZ_RESULT__FUZZEE_QUERIES__COUNT].as_i64().unwrap();
            for i in 0..query_count {
                known_diffs.mark(
                    &Atom::from(format!(
                        ".fuzz_result.fuzzee_queries.{i}.header.checking_disabled"
                    )),
                    DifferenceKind::PdnsCheckingDisabled,
                );
            }
        }
    }
    powerdns_cd_bit_query(&mut known_diffs, left);
    powerdns_cd_bit_query(&mut known_diffs, right);

    // MaraDNS hates the ANY query class and replies with a different value
    fn maradns_query_class_any(known_diffs: &mut KnownDiffs, left: &ValueMap) {
        if left[RESOLVER_NAME] == VALUE_MARADNS {
            let query_count = left[FUZZ_RESULT__FUZZEE_RESPONSE__QUERIES__COUNT]
                .as_i64()
                .unwrap_or(0);
            for i in 0..query_count {
                // check if the value should be ANY but in reality is not
                if left[&Atom::from(format!(".fuzz_case.client_query.queries.{i}.query_class"))]
                    != VALUE_IN
                    && left[&Atom::from(format!(
                        ".fuzz_result.fuzzee_response.queries.{i}.query_class"
                    ))] == VALUE_IN
                {
                    known_diffs.mark(
                        &Atom::from(format!(
                            ".fuzz_result.fuzzee_response.queries.{i}.query_class"
                        )),
                        DifferenceKind::MaradnsQueryClassNotIn,
                    );
                }
            }
        }
    }
    maradns_query_class_any(&mut known_diffs, left);
    maradns_query_class_any(&mut known_diffs, right);

    // PowerDNS responds with an allowed EDNS buffer size of 512
    fn powerdns_edns_client_bufsize(known_diffs: &mut KnownDiffs, left: &ValueMap) {
        if left[RESOLVER_NAME] == VALUE_PDNS_RECURSOR
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__MAX_PAYLOAD] == 512
        {
            known_diffs.mark(
                FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__MAX_PAYLOAD,
                DifferenceKind::PdnsEdnsClientBufsize,
            );
        }
    }
    powerdns_edns_client_bufsize(&mut known_diffs, left);
    powerdns_edns_client_bufsize(&mut known_diffs, right);

    // BIND9 v9.11 uses the older 4096 standard for client bufsize
    fn bind9_11_edns_bufsize(known_diffs: &mut KnownDiffs, left: &ValueMap) {
        if left[RESOLVER_NAME] == VALUE_BIND9_11 {
            if left[FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__MAX_PAYLOAD] == 4096 {
                known_diffs.mark(
                    FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__MAX_PAYLOAD,
                    DifferenceKind::Bind9_11EdnsClientBufsize,
                );
            }
            let left_query_count = left[FUZZ_RESULT__FUZZEE_QUERIES__COUNT].as_i64().unwrap();
            for i in 0..left_query_count {
                if left[&Atom::from(format!(".fuzz_result.fuzzee_queries.{i}.edns.max_payload"))]
                    == 512
                {
                    known_diffs.mark_prefix(
                        &format!(".fuzz_result.fuzzee_queries.{i}.", i = i),
                        DifferenceKind::Bind9_11EdnsServerBufsize,
                    );
                }
            }
        }
    }
    bind9_11_edns_bufsize(&mut known_diffs, left);
    bind9_11_edns_bufsize(&mut known_diffs, right);

    // Unbound FormErr copies the AA and AD bits from the client query
    fn unbound_formerr_aa_ad_bit_copy(known_diffs: &mut KnownDiffs, left: &ValueMap) {
        if left[RESOLVER_NAME] == VALUE_UNBOUND
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_FORMERR
        {
            known_diffs.mark_if(
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__AUTHENTIC_DATA,
                DifferenceKind::UnboundFormErrCopiesAdAndAa,
                || {
                    left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__AUTHENTIC_DATA] == true
                        && left[FUZZ_CASE__CLIENT_QUERY__HEADER__AUTHENTIC_DATA] == true
                },
            );
            known_diffs.mark_if(
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__AUTHORITATIVE,
                DifferenceKind::UnboundFormErrCopiesAdAndAa,
                || {
                    left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__AUTHORITATIVE] == true
                        && left[FUZZ_CASE__CLIENT_QUERY__HEADER__AUTHORITATIVE] == true
                },
            );
        }
    }
    unbound_formerr_aa_ad_bit_copy(&mut known_diffs, left);
    unbound_formerr_aa_ad_bit_copy(&mut known_diffs, right);

    if (
        // Check conditions in which a ServFail and Refused can occur
        left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_REFUSED
            || left[FUZZ_CASE__CLIENT_QUERY__QUERIES__0__QUERY_CLASS] == VALUE_NONE
    ) && (
        // Check that one side is Refused and the other ServFail
        (left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_REFUSED
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_SERVFAIL)
            || (left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_SERVFAIL
                && right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_REFUSED)
    ) {
        known_diffs.mark(
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE,
            DifferenceKind::RefusedCanBeServFail,
        );
    }

    // Check for differences in qname minimalization
    // Queries to these two should give the same result
    // _.xtzoa.0000.fuzz.  xtzoa.0000.fuzz.
    fn qname_minimalization_differences(
        diff_keys: &DiffKeysSet,
        known_diffs: &mut KnownDiffs,
        left: &ValueMap,
        right: &ValueMap,
    ) {
        let client_qname_len = left[FUZZ_CASE__CLIENT_QUERY__QUERIES__0__NAME]
            .as_str()
            .unwrap_or("")
            .len();

        // For all queries in common, check if the difference can be explained by qname minimalization
        let left_query_count = left[FUZZ_RESULT__FUZZEE_QUERIES__COUNT].as_i64().unwrap();
        let right_query_count = right[FUZZ_RESULT__FUZZEE_QUERIES__COUNT].as_i64().unwrap();
        let mut prev_is_underscore_query;
        let mut is_underscore_query = false;
        for i in 0..std::cmp::min(left_query_count, right_query_count) {
            if let Some(key) = diff_keys.get(&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{i}.queries.0.name"
            ))) {
                if let Some(l) = left[key].as_str() {
                    // Check for a case where one side is shorter (i.e., suffix) and uses A or NS queries
                    // Assume left is suffix
                    //
                    // *  .fuzz_result.fuzzee_queries.0.queries.0.name              ayfkq.ibopv.0000.fuzz.                ibopv.0000.fuzz.
                    //    .fuzz_result.fuzzee_queries.0.queries.0.query_class       IN                                    IN
                    // *  .fuzz_result.fuzzee_queries.0.queries.0.query_type        NS                                    A
                    if right[key].as_str().unwrap_or("").ends_with(l) {
                        let left_qtype = &left[&Atom::from(format!(
                            ".fuzz_result.fuzzee_queries.{i}.queries.0.query_type"
                        ))];
                        if left_qtype == VALUE_NS || left_qtype == VALUE_A {
                            known_diffs.mark(key, DifferenceKind::QnameMinimalization);
                            known_diffs.mark(
                                &Atom::from(format!(
                                    ".fuzz_result.fuzzee_queries.{i}.queries.0.query_type"
                                )),
                                DifferenceKind::QnameMinimalization,
                            );
                            // besides the name itself, the response can also differ
                            // That is because a matching response is selected by the qname
                            // It shows by having different values for `.fuzz_result.response_idxs.0`
                            known_diffs.mark(
                                &Atom::from(format!(".fuzz_result.response_idxs.{i}")),
                                DifferenceKind::QnameMinimalization,
                            );
                        }
                    }

                    prev_is_underscore_query = is_underscore_query;
                    if l.starts_with("_.") {
                        is_underscore_query = true;

                        known_diffs.mark(key, DifferenceKind::QnameMinimalization);
                        // besides the name itself, the response can also differ
                        // That is because a matching response is selected by the qname
                        // It shows by having different values for `.fuzz_result.response_idxs.0`
                        known_diffs.mark(
                            &Atom::from(format!(".fuzz_result.response_idxs.{i}")),
                            DifferenceKind::QnameMinimalization,
                        );
                    } else {
                        is_underscore_query = false;
                    }

                    // If the previous query was an underscore query, and this one is not
                    // The query type can also differ for the later entry
                    // Check the the length of the last query is the same as the client query
                    // We cannot check for identidy, because the client query is not unique but uses `test.fuzz`
                    //
                    // .fuzz_result.fuzzee_queries.3.queries.0.name  _.xpcls.0000.fuzz\000.xpcls.0000.fuzz.
                    // .fuzz_result.fuzzee_queries.4.queries.0.name  0000.fuzz\000.xpcls.0000.fuzz\000.xpcls.0000.fuzz\000.xpcls.0000.fuzz.
                    // .fuzz_result.fuzzee_queries.4.queries.0.query_type  SRV
                    if prev_is_underscore_query
                        && !is_underscore_query
                        && left[key].as_str().unwrap_or("").len() == client_qname_len
                    {
                        known_diffs.mark(key, DifferenceKind::QnameMinimalization);
                        known_diffs.mark(
                            &Atom::from(format!(
                                ".fuzz_result.fuzzee_queries.{i}.queries.0.query_type"
                            )),
                            DifferenceKind::QnameMinimalization,
                        );
                        // besides the name itself, the response can also differ
                        // That is because a matching response is selected by the qname
                        // It shows by having different values for `.fuzz_result.response_idxs.0`
                        known_diffs.mark(
                            &Atom::from(format!(".fuzz_result.response_idxs.{i}")),
                            DifferenceKind::QnameMinimalization,
                        );
                    }
                }
            }
            if let Some(key) = diff_keys.get(&Atom::from(format!(
                ".fuzz_result.fuzzee_queries.{i}.queries.0.query_type"
            ))) {
                // trust-dns performs qname minimization using NS queries
                if left[RESOLVER_NAME] == VALUE_TRUST_DNS && left[key] == VALUE_NS {
                    known_diffs.mark(key, DifferenceKind::QnameMinimalization);
                    // besides the name itself, the response can also differ
                    // That is because a matching response is selected by the qname
                    // It shows by having different values for `.fuzz_result.response_idxs.0`
                    known_diffs.mark(
                        &Atom::from(format!(".fuzz_result.response_idxs.{i}")),
                        DifferenceKind::QnameMinimalization,
                    );
                }
            }
        }

        // For the further queries only one side send them
        // Ensure that both sides sent at least one query
        // Otherwise we might have a case where one side refused the client query and never worked.
        //
        // Here we see how one side "jumps" ahead to the end while the other iterates one label at a time.
        //
        // ```text
        //     .fuzz_case.client_query.queries.0.name        dsxbl.ursag.xtzoa.test.fuzz\000.ursag.xtzoa.test.fuzz.  dsxbl.ursag.xtzoa.test.fuzz\000.ursag.xtzoa.test.fuzz.
        //     .fuzz_case.server_responses.0.queries.0.name  xtzoa.test.fuzz.                                        xtzoa.test.fuzz.
        //  *  .fuzz_result.fuzzee_queries.0.queries.0.name  _.xtzoa.0001.fuzz.                                      xtzoa.0001.fuzz.
        //  *  .fuzz_result.fuzzee_queries.1.queries.0.name  _.ursag.xtzoa.0001.fuzz.                                ursag.xtzoa.0001.fuzz.
        //  *  .fuzz_result.fuzzee_queries.2.queries.0.name  _.fuzz\000.ursag.xtzoa.0001.fuzz.                       fuzz\000.ursag.xtzoa.0001.fuzz.
        //  *  .fuzz_result.fuzzee_queries.3.queries.0.name  _.0001.fuzz\000.ursag.xtzoa.0001.fuzz.                  0001.fuzz\000.ursag.xtzoa.0001.fuzz.
        //  *  .fuzz_result.fuzzee_queries.4.queries.0.name  dsxbl.ursag.xtzoa.0001.fuzz\000.ursag.xtzoa.0001.fuzz.  xtzoa.0001.fuzz\000.ursag.xtzoa.0001.fuzz.
        //  *  .fuzz_result.fuzzee_queries.5.queries.0.name                                                          ursag.xtzoa.0001.fuzz\000.ursag.xtzoa.0001.fuzz.
        //  *  .fuzz_result.fuzzee_queries.6.queries.0.name                                                          dsxbl.ursag.xtzoa.0001.fuzz\000.ursag.xtzoa.0001.fuzz.
        //     .fuzz_result.fuzzee_response.queries.0.name   dsxbl.ursag.xtzoa.0001.fuzz\000.ursag.xtzoa.0001.fuzz.  dsxbl.ursag.xtzoa.0001.fuzz\000.ursag.xtzoa.0001.fuzz.
        // ```
        if left_query_count > right_query_count && right_query_count > 0 {
            // -1 to include one query of the shared part, such that the first non-shared query can be properly checked
            let query_idxs = std::cmp::min(left_query_count, right_query_count) - 1
                ..std::cmp::max(left_query_count, right_query_count);
            let data_per_idx = query_idxs
                .map(|idx| {
                    let key =
                        Atom::from(format!(".fuzz_result.fuzzee_queries.{idx}.queries.0.name"));
                    let qname = left[&key].as_str().unwrap_or("");
                    (idx, split_dns_string(qname))
                })
                .collect::<Vec<_>>();

            let is_all_qname_minimization_steps = data_per_idx.windows(2).all(|data| {
                if let [(_, prev_labels), (_, this_labels)] = data {
                    // Check that exactly one label is added to the front and that all the other labels are identical
                    if prev_labels.len() + 1 == this_labels.len()
                        && prev_labels[..] == this_labels[1..]
                    {
                        return true;
                    }
                }
                false
            });
            if is_all_qname_minimization_steps {
                // The first entry is still in the shared part, only the later ones are qname minimization steps
                for (idx, _) in data_per_idx.into_iter().skip(1) {
                    known_diffs.mark_prefix(
                        &format!(".fuzz_result.fuzzee_queries.{idx}."),
                        DifferenceKind::QnameMinimalization,
                    );
                    // Mark the extra responses in the index as covered too
                    known_diffs.mark(
                        &Atom::from(format!(".fuzz_result.response_idxs.{idx}")),
                        DifferenceKind::QnameMinimalization,
                    );
                }
            }
        }
    }
    qname_minimalization_differences(diff_keys, &mut known_diffs, left, right);
    qname_minimalization_differences(diff_keys, &mut known_diffs, right, left);

    // QNAME differences will lead to cache differences.
    // Due to the different normalizations of the QNAMEs, different results will be returned from the AuthNS.
    // Ignore any cache differences for now, if QnameMinimization is detected.
    if known_diffs.has_kind(DifferenceKind::QnameMinimalization) {
        known_diffs.mark_prefix(
            ".fuzz_result.cache_state.",
            DifferenceKind::TodoCacheIgnoredForNow,
        );
    }

    fn bind_hs_refused(known_diffs: &mut KnownDiffs, left: &ValueMap) {
        if left[RESOLVER_NAME] == VALUE_BIND9
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_REFUSED
        {
            known_diffs.mark(
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE,
                DifferenceKind::BindHsProhibited,
            );
        }
    }
    bind_hs_refused(&mut known_diffs, left);
    bind_hs_refused(&mut known_diffs, right);

    fn maradns_no_recursion_desired(known_diffs: &mut KnownDiffs, left: &ValueMap) {
        if left[RESOLVER_NAME] == VALUE_MARADNS
            && left[FUZZ_CASE__CLIENT_QUERY__HEADER__RECURSION_DESIRED] == false
        {
            known_diffs.mark_prefix(".fuzz_result", DifferenceKind::MaradnsNoRecursionDesired);
        }
    }
    maradns_no_recursion_desired(&mut known_diffs, left);
    maradns_no_recursion_desired(&mut known_diffs, right);

    fn maradns_embedded_zero_byte(known_diffs: &mut KnownDiffs, left: &ValueMap) {
        if left[RESOLVER_NAME] == VALUE_MARADNS
            && left[FUZZ_CASE__CLIENT_QUERY__QUERIES__0__NAME]
                .as_str()
                .unwrap_or("")
                .contains("\\000")
        {
            known_diffs.mark_prefix(".fuzz_result", DifferenceKind::MaradnsEmbeddedZero);
        }
    }
    maradns_embedded_zero_byte(&mut known_diffs, left);
    maradns_embedded_zero_byte(&mut known_diffs, right);

    // BIND9 will on NotImp and FormErr responses use hardcoded values and not mirror the values from the client query.
    //
    // The client uses a max_payload of 1200.
    //
    // .fuzz_result.fuzzee_response.edns.max_payload             1232
    // .fuzz_result.fuzzee_response.header.checking_disabled     false
    // .fuzz_result.fuzzee_response.header.recursion_desired     false
    fn bind_errors_have_hardcoded_values(known_diffs: &mut KnownDiffs, left: &ValueMap) {
        if left[RESOLVER_NAME] == VALUE_BIND9
            && (left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_NOTIMP
                || left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_FORMERR)
        {
            if left[FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__MAX_PAYLOAD] == 1232 {
                known_diffs.mark(
                    FUZZ_RESULT__FUZZEE_RESPONSE__EDNS__MAX_PAYLOAD,
                    DifferenceKind::BindErrorsHaveHardcodedValues,
                );
            }
            if left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__CHECKING_DISABLED] == false {
                known_diffs.mark(
                    FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__CHECKING_DISABLED,
                    DifferenceKind::BindErrorsHaveHardcodedValues,
                );
            }
            if left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RECURSION_DESIRED] == false {
                known_diffs.mark(
                    FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RECURSION_DESIRED,
                    DifferenceKind::BindErrorsHaveHardcodedValues,
                );
            }
        }
    }
    bind_errors_have_hardcoded_values(&mut known_diffs, left);
    bind_errors_have_hardcoded_values(&mut known_diffs, right);

    // PDNS Recursor will not respond to queries with an OpCode that is not query.
    // For example, the notify, status, and update opcodes.
    fn pdns_recursor_non_query_no_response(known_diffs: &mut KnownDiffs, left: &ValueMap) {
        if left[RESOLVER_NAME] == VALUE_PDNS_RECURSOR
            && left[FUZZ_CASE__CLIENT_QUERY__HEADER__OP_CODE]
                .as_str()
                .map(|x| x != VALUE_QUERY)
                .unwrap_or(false)
        {
            known_diffs.mark_prefix(
                ".fuzz_result.fuzzee_response.",
                DifferenceKind::PdnsRecursorsNonQueryNoResponse,
            );
        }
    }
    pdns_recursor_non_query_no_response(&mut known_diffs, left);
    pdns_recursor_non_query_no_response(&mut known_diffs, right);

    // Resolved returns ServFail instead of NoData
    fn resolved_servfail_on_nodata(
        known_diffs: &mut KnownDiffs,
        left: &ValueMap,
        right: &ValueMap,
    ) {
        // Resolved is ServFail with no answers
        // other resolver is noerror and no data
        if left[RESOLVER_NAME] == VALUE_RESOLVED
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_SERVFAIL
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_NOERROR
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ANSWER_COUNT] == 0
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ANSWER_COUNT] == 0
        {
            known_diffs.mark(
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE,
                DifferenceKind::ResolvedServFailOnNoData,
            );
        }
    }
    resolved_servfail_on_nodata(&mut known_diffs, left, right);
    resolved_servfail_on_nodata(&mut known_diffs, right, left);

    // BIND9 in v9.11 serves an extra NS records with the IP address in the additional section
    //
    //  *  .fuzz_result.fuzzee_response.additionals.0.dns_class                                            IN
    //  *  .fuzz_result.fuzzee_response.additionals.0.name_labels                                          ns-0001.ns.
    //  *  .fuzz_result.fuzzee_response.additionals.0.rdata                                                127.250.0.2
    //  *  .fuzz_result.fuzzee_response.additionals.0.rr_type                                              A
    //  *  .fuzz_result.fuzzee_response.additionals.0.ttl                                                  1800
    //  *  .fuzz_result.fuzzee_response.header.additional_count      1                                     2
    //     .fuzz_result.fuzzee_response.header.answer_count          1                                     1
    //  *  .fuzz_result.fuzzee_response.header.name_server_count     0                                     1
    //  *  .fuzz_result.fuzzee_response.name_servers.0.dns_class                                           IN
    //  *  .fuzz_result.fuzzee_response.name_servers.0.name_labels                                         0001.fuzz.
    //  *  .fuzz_result.fuzzee_response.name_servers.0.rdata                                               ns-0001.ns.
    //  *  .fuzz_result.fuzzee_response.name_servers.0.rr_type                                             NS
    //  *  .fuzz_result.fuzzee_response.name_servers.0.ttl                                                 1800
    fn bind9_11_extra_ns_record(known_diffs: &mut KnownDiffs, left: &ValueMap, right: &ValueMap) {
        // Resolved is ServFail with no answers
        // other resolver is noerror and no data
        if left[RESOLVER_NAME] == VALUE_BIND9_11
        // No error occured during checking
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_NOERROR
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_NOERROR
            // Both sides have the same number of answers and the number is >0
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ANSWER_COUNT] > 0
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ANSWER_COUNT] == right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ANSWER_COUNT]
            // BIND9 9.11 has an extra name server and additional record
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__COUNT] == 1
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__COUNT] == 0
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__COUNT] == 1
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__COUNT] == 0
            // The name server record is of type NS and the additional record is of type A since IPv4 is the only protocol used for fuzzing
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__RR_TYPE] == VALUE_NS
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__RR_TYPE] == VALUE_A
        {
            known_diffs.mark_prefix(
                // There is only one entry in the section
                ".fuzz_result.fuzzee_response.name_servers.0.",
                DifferenceKind::Bind9_11ExtraNsRecord,
            );
            known_diffs.mark_prefix(
                // There is only one entry in the section
                ".fuzz_result.fuzzee_response.additionals.0.",
                DifferenceKind::Bind9_11ExtraNsRecord,
            );
            // Update the header fields too
            known_diffs.mark(
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__NAME_SERVER_COUNT,
                DifferenceKind::Bind9_11ExtraNsRecord,
            );
            known_diffs.mark(
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ADDITIONAL_COUNT,
                DifferenceKind::Bind9_11ExtraNsRecord,
            );
        }
    }
    bind9_11_extra_ns_record(&mut known_diffs, left, right);
    bind9_11_extra_ns_record(&mut known_diffs, right, left);

    // TODO Unbound also has the option of including NS and A records in the authoritative/additional sections
    // 2023-05-15 23%3A47/01fdd3d4-cef0-4b8f-b644-da2e3e7ab39c/bind9-unbound/fulldiff.txt?_xsrf=2|def96d73|6d14cf9e9f01b2f77902aa6e6a4a1451|1631006237

    fn bind9_extra_ns_record(known_diffs: &mut KnownDiffs, left: &ValueMap, right: &ValueMap) {
        // Resolved is ServFail with no answers
        // other resolver is noerror and no data
        if left[RESOLVER_NAME] == VALUE_BIND9
        // No error occured during checking
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_NOERROR
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE] == VALUE_NOERROR
            // Both sides have the same number of answers and the number is >0
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ANSWER_COUNT] > 0
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ANSWER_COUNT] == right[FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ANSWER_COUNT]
            // BIND9 9.11 has an extra name server and additional record
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__COUNT] == 1
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__COUNT] == 0
            // The authoritative record is of type NS
            && left[FUZZ_RESULT__FUZZEE_RESPONSE__NAME_SERVERS__0__RR_TYPE] == VALUE_NS
            // The other resolver has no additional records
            && right[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__COUNT] == 0
            && (
                // There is an optional additional record with the IP address of the name server
                 left[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__COUNT] == 0
                || (
                    left[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__COUNT] == 1
                    // The name server record is of type NS and the additional record is of type A since IPv4 is the only protocol used for fuzzing
                    && left[FUZZ_RESULT__FUZZEE_RESPONSE__ADDITIONALS__0__RR_TYPE] == VALUE_A
                )
            )
        {
            dbg!("inner");
            known_diffs.mark_prefix(
                // There is only one entry in the section
                ".fuzz_result.fuzzee_response.name_servers.0.",
                DifferenceKind::Bind9ExtraNsRecord,
            );
            known_diffs.mark_prefix(
                // There is only one entry in the section
                ".fuzz_result.fuzzee_response.additionals.0.",
                DifferenceKind::Bind9ExtraNsRecord,
            );
            // Update the header fields too
            known_diffs.mark(
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__NAME_SERVER_COUNT,
                DifferenceKind::Bind9ExtraNsRecord,
            );
            known_diffs.mark(
                FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ADDITIONAL_COUNT,
                DifferenceKind::Bind9ExtraNsRecord,
            );
        }
    }
    bind9_extra_ns_record(&mut known_diffs, left, right);
    bind9_extra_ns_record(&mut known_diffs, right, left);

    known_diffs
}

/// A fingerprint describing a difference
///
/// Capture all different keys which are unexplained.
/// For some special keys, we also capture the values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub(crate) struct DiffFingerprint {
    /// key differences which are otherwise unexplained
    // Needs to be BTreeSet to have Ord
    pub(crate) key_diffs: BTreeSet<Atom>,
    /// Special keys including values, but unsorted values
    ///
    /// Right now this includes the response header `.fuzz_result.fuzzee_response.header`
    pub(crate) special_fields: UnorderedPair<[Value; 13]>,
}

impl DiffFingerprint {
    fn new(key_diffs: &DiffKeysSet, first_keyvalue: &ValueMap, second_keyvalue: &ValueMap) -> Self {
        // Omit .fuzz_result.fuzzee_response.header.id because it is random
        static SPECIAL_KEYS: [&Atom; 13] = [
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ADDITIONAL_COUNT,
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__ANSWER_COUNT,
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__AUTHENTIC_DATA,
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__AUTHORITATIVE,
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__CHECKING_DISABLED,
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__MESSAGE_TYPE,
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__NAME_SERVER_COUNT,
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__OP_CODE,
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__QUERY_COUNT,
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RECURSION_AVAILABLE,
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RECURSION_DESIRED,
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__RESPONSE_CODE,
            FUZZ_RESULT__FUZZEE_RESPONSE__HEADER__TRUNCATED,
        ];
        let first_values = SPECIAL_KEYS.map(|sk| first_keyvalue[sk].clone());
        let second_values = SPECIAL_KEYS.map(|sk| second_keyvalue[sk].clone());

        // Always remove the cache state entries.
        // These will always be different, since the SLD is non-deterministic.
        // Futher labels are also random.
        // So matches here are unlikely to impossible.
        let key_diffs = key_diffs
            .iter()
            .filter(|k| !k.starts_with(".fuzz_result.cache_state"))
            .cloned()
            .collect();

        Self {
            key_diffs,
            special_fields: UnorderedPair::from((first_values, second_values)),
        }
    }
}

/// A tuple struct representing an unordered pair
#[derive(Debug, Copy, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnorderedPair<T>(pub T, pub T);

impl<T: Ord> UnorderedPair<T> {
    pub fn as_ordered_tuple(&self) -> (&T, &T) {
        let UnorderedPair(first, second) = self;

        match first.cmp(second) {
            std::cmp::Ordering::Greater => (second, first),
            _ => (first, second),
        }
    }
}

impl<T> From<(T, T)> for UnorderedPair<T> {
    fn from(tuple: (T, T)) -> UnorderedPair<T> {
        UnorderedPair(tuple.0, tuple.1)
    }
}

impl<T> From<UnorderedPair<T>> for (T, T) {
    fn from(pair: UnorderedPair<T>) -> (T, T) {
        (pair.0, pair.1)
    }
}

/// Compares two pairs while disregarding the order of the contained items
impl<T> PartialEq for UnorderedPair<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &UnorderedPair<T>) -> bool {
        (self.0 == other.0 && self.1 == other.1) || (self.0 == other.1 && self.1 == other.0)
    }
}

impl<T> Eq for UnorderedPair<T> where T: Eq {}

impl<T> PartialOrd for UnorderedPair<T>
where
    T: Ord,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for UnorderedPair<T>
where
    T: Ord,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ordered_tuple().cmp(&other.as_ordered_tuple())
    }
}

/// Split DNS string into labels while accounting for escaped dots
fn split_dns_string(s: &str) -> Vec<&str> {
    let mut labels = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if c == '.' && !escaped {
            labels.push(&s[start..i]);
            start = i + 1;
        } else if c == '\\' {
            escaped = !escaped;
        } else {
            escaped = false;
        }
    }
    labels.push(&s[start..]);
    labels
}
