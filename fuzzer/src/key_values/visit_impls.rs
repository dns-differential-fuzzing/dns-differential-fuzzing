use super::{DiffVisitable, Visitor};
use color_eyre::eyre::{Context as _, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;

/// Helper to bulk implement DiffVisitable for all primites which also implement [`Display`].
macro_rules! diff_visitable_primitive {
    ($($fn:ident $ty:ty,)*) => {$(
        impl DiffVisitable for $ty {
            fn visit<V>(&self, visitor: &mut V) -> Result<(), >
            where
                V: Visitor + ?Sized,
            {
                visitor.$fn(*self)
            }
        }
    )*};
}
diff_visitable_primitive!(
    visit_integer i8,
    visit_integer i16,
    visit_integer i32,
    visit_integer i64,
    visit_integer u8,
    visit_integer u16,
    visit_integer u32,

    visit_bool bool,
);

impl DiffVisitable for usize {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        if *self == usize::MAX {
            visitor.visit_string("usize::MAX")
        } else {
            visitor.visit_integer(
                i64::try_from(*self)
                    .with_context(|| format!("usize {self} does not fit into i64"))?,
            )
        }
    }
}

impl DiffVisitable for str {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        visitor.visit_string(self)
    }
}

impl DiffVisitable for String {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        visitor.visit_string(self)
    }
}

impl<T> DiffVisitable for Vec<T>
where
    T: DiffVisitable,
{
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        visitor.visit_scope("#count", &self.len())?;
        self.iter()
            .enumerate()
            .try_for_each(|(idx, val)| visitor.visit_scope(&idx, val))
    }
}

impl<'a, VAL> DiffVisitable for &'a VAL
where
    VAL: DiffVisitable,
{
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        (*self).visit(visitor)
    }
}

impl<K, V> DiffVisitable for BTreeMap<K, V>
where
    K: Display,
    V: DiffVisitable,
{
    fn visit<VISITOR>(&self, visitor: &mut VISITOR) -> Result<()>
    where
        VISITOR: Visitor + ?Sized,
    {
        self.iter()
            .try_for_each(|(key, val)| visitor.visit_scope(&key, val))
    }
}

impl<V> DiffVisitable for BTreeSet<V>
where
    V: DiffVisitable,
{
    fn visit<VISITOR>(&self, visitor: &mut VISITOR) -> Result<()>
    where
        VISITOR: Visitor + ?Sized,
    {
        visitor.visit_scope("#size", &self.len())?;
        self.iter()
            .enumerate()
            .try_for_each(|(idx, val)| visitor.visit_scope(&idx, val))
    }
}

impl<T> DiffVisitable for Option<T>
where
    T: DiffVisitable,
{
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        if let Some(val) = self {
            val.visit(visitor)
        } else {
            Ok(())
        }
    }
}

macro_rules! visit_fields {
    ($visitor:ident, $($ident:ident)*) => {$(
        $visitor.visit_scope(stringify!($ident), $ident)?;
    )*};
}

macro_rules! visit_fields_call {
    ($self:ident, $visitor:ident, $($ident:ident)*) => {$(
        $visitor.visit_scope(stringify!($ident), &($self.$ident()))?;
    )*};
}

impl<'a> DiffVisitable for dnsauth::definitions::FuzzResultDiff<'a> {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        let Self {
            fuzz_case,
            resolver_name,
            fuzz_result,
        } = self;
        visit_fields!(visitor, fuzz_case resolver_name fuzz_result);
        Ok(())
    }
}

impl DiffVisitable for dnsauth::definitions::FuzzCase {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        let Self {
            id,
            client_query,
            server_responses,
            check_cache,
        } = self;
        visit_fields!(visitor, id client_query server_responses check_cache);
        Ok(())
    }
}

impl DiffVisitable for dnsauth::definitions::FuzzResult {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        let Self {
            id,
            counters,
            cache_state,
            fuzzee_response,
            fuzzee_queries,
            response_idxs,
            oracles,
        } = self;
        visit_fields!(visitor, id counters cache_state fuzzee_response fuzzee_queries response_idxs oracles);
        Ok(())
    }
}

impl DiffVisitable for dnsauth::definitions::OracleResults {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        let Self {
            crashed_resolver,
            excessive_queries,
            excessive_answer_records,
            duplicate_records,
            fake_data,
            responds_to_response,
        } = self;
        visit_fields!(visitor, crashed_resolver excessive_queries excessive_answer_records duplicate_records fake_data responds_to_response);
        Ok(())
    }
}

impl DiffVisitable for dnsauth::definitions::FuzzCaseId {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        self.to_string().visit(visitor)
    }
}

impl DiffVisitable for dnsauth::definitions::ResolverName {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        self.as_ref().visit(visitor)
    }
}

impl DiffVisitable for fuzzer_protocol::Counters {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        self.len().visit(visitor)
    }
}

impl DiffVisitable for dnsauth::definitions::CacheKey {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        format!("{}-{}-{}", self.0, self.1, self.2).visit(visitor)
    }
}

impl DiffVisitable for dnsauth::definitions::CachePresent {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        visitor.visit_string(match self {
            dnsauth::definitions::CachePresent::Present => "present",
            dnsauth::definitions::CachePresent::Absent => "absent",
            dnsauth::definitions::CachePresent::Error => "error",
        })
    }
}

impl DiffVisitable for dnsauth::definitions::CacheState {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        self.values.iter().try_for_each(|(key, val)| {
            visitor.visit_scope(&format!("{}-{}-{}", key.0, key.1, key.2), val)
        })
    }
}

impl DiffVisitable for trust_dns_proto::op::message::Message {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        self.clone().into_parts().visit(visitor)
    }
}

impl DiffVisitable for trust_dns_proto::op::message::MessageParts {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        let Self {
            header,
            queries,
            answers,
            name_servers,
            additionals,
            sig0,
            edns,
        } = self;
        visit_fields!(visitor, header queries answers name_servers additionals sig0 edns);
        Ok(())
    }
}

impl DiffVisitable for trust_dns_proto::op::Header {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        visit_fields_call!(self, visitor, id message_type op_code authoritative truncated recursion_desired
          recursion_available authentic_data checking_disabled response_code query_count answer_count
          name_server_count additional_count
        );
        Ok(())
    }
}

impl DiffVisitable for trust_dns_proto::op::query::Query {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        self.clone().into_parts().visit(visitor)
    }
}

impl DiffVisitable for trust_dns_proto::op::query::QueryParts {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        let Self {
            name,
            query_type,
            query_class,
        } = self;
        visit_fields!(visitor, name query_type query_class);
        Ok(())
    }
}

impl DiffVisitable for trust_dns_proto::rr::Record {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        self.clone().into_parts().visit(visitor)
    }
}

impl DiffVisitable for trust_dns_proto::rr::resource::RecordParts {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        let Self {
            name_labels,
            rr_type,
            dns_class,
            ttl,
            rdata,
        } = self;
        visit_fields!(visitor, name_labels rr_type dns_class ttl rdata);
        Ok(())
    }
}

impl DiffVisitable for trust_dns_proto::op::Edns {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        visit_fields_call!(self, visitor, max_payload version dnssec_ok);
        self.options().as_ref().iter().try_for_each(|(key, val)| {
            if let trust_dns_proto::rr::rdata::opt::EdnsCode::Unknown(unk) = key {
                visitor.visit_scope(&format!("Code{unk}"), val)
            } else {
                visitor.visit_scope(&format!("{key:?}"), val)
            }
        })
    }
}

impl DiffVisitable for trust_dns_proto::rr::rdata::opt::EdnsOption {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        match self {
            trust_dns_proto::rr::rdata::opt::EdnsOption::Unknown(code, value) => {
                let buf;
                let code_desc = match code {
                    1 => "LLQ",
                    2 => "UL",
                    3 => "NSID",
                    5 => "DAU",
                    6 => "DHU",
                    7 => "N3U",
                    8 => "CLIENT_SUBNET",
                    9 => "EXPIRE",
                    10 => "COOKIE",
                    11 => "TCP_KEEPALIVE",
                    12 => "PADDING",
                    13 => "CHAIN",
                    14 => "KEY_TAG",
                    15 => "EXTENDED_ERROR",
                    16 => "CLIENT_TAG",
                    17 => "SERVER_TAG",
                    20292 => "UMBRELLA_IDENT",
                    26946 => "DEVICEID",
                    18..=20291 | 20293..=26945 | 26947..=65000 => {
                        buf = format!("Code{code}");
                        &buf
                    }
                    0 | 4 | 65001..=65535 => {
                        buf = format!("Reserved{code}");
                        &buf
                    }
                };

                visitor.visit_scope("code", code_desc)?;
                match code {
                    15 => visit_extended_error(visitor, value),
                    _ => visitor.visit_scope("value", &misc_utils::byteascii::byteascii(value)),
                }
            }
            _ => Ok(()),
        }
    }
}

fn visit_extended_error<V>(visitor: &mut V, extended_error: &[u8]) -> Result<()>
where
    V: Visitor + ?Sized,
{
    // Parse first two bytes as a u16
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&extended_error[0..2]);
    let code = u16::from_be_bytes(bytes);

    let buf;
    let code_desc = match code {
        0 => "Other Error",
        1 => "Unsupported DNSKEY Algorithm",
        2 => "Unsupported DS Digest Type",
        3 => "Stale Answer",
        4 => "Forged Answer",
        5 => "DNSSEC Indeterminate",
        6 => "DNSSEC Bogus",
        7 => "Signature Expired",
        8 => "Signature Not Yet Valid",
        9 => "DNSKEY Missing",
        10 => "RRSIGs Missing",
        11 => "No Zone Key Bit Set",
        12 => "NSEC Missing",
        13 => "Cached Error",
        14 => "Not Ready",
        15 => "Blocked",
        16 => "Censored",
        17 => "Filtered",
        18 => "Prohibited",
        19 => "Stale NXDomain Answer",
        20 => "Not Authoritative",
        21 => "Not Supported",
        22 => "No Reachable Authority",
        23 => "Network Error",
        24 => "Invalid Data",
        25 => "Signature Expired before Valid",
        26 => "Too Early",
        27 => "Unsupported NSEC3 Iterations Value",
        28..=49151 => {
            buf = format!("Unassigned({code})");
            &*buf
        }
        49152..=65535 => {
            buf = format!("Private({code})");
            &*buf
        }
    };

    visitor.visit_scope("error_code", code_desc)?;
    visitor.visit_scope(
        "error_value",
        &misc_utils::byteascii::byteascii(&extended_error[2..]),
    )
}

impl DiffVisitable for trust_dns_proto::op::MessageType {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        visitor.visit_string(match self {
            trust_dns_proto::op::MessageType::Query => "query",
            trust_dns_proto::op::MessageType::Response => "response",
        })
    }
}

impl DiffVisitable for trust_dns_proto::op::OpCode {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        visitor.visit_string(match self {
            trust_dns_proto::op::OpCode::Query => "query",
            trust_dns_proto::op::OpCode::Status => "status",
            trust_dns_proto::op::OpCode::Notify => "notify",
            trust_dns_proto::op::OpCode::Update => "update",
        })
    }
}

impl DiffVisitable for trust_dns_proto::op::ResponseCode {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        if let trust_dns_proto::op::ResponseCode::Unknown(unk) = self {
            visitor.visit_string(format!("RCODE{unk}"))
        } else {
            visitor.visit_string(format!("{self:?}"))
        }
    }
}

impl DiffVisitable for trust_dns_proto::rr::Name {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        self.to_string().visit(visitor)
    }
}

impl DiffVisitable for trust_dns_proto::rr::RecordType {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        if let trust_dns_proto::rr::RecordType::Unknown(unk) = self {
            format!("RTYPE{unk}").visit(visitor)
        } else {
            format!("{self:?}").visit(visitor)
        }
    }
}

impl DiffVisitable for trust_dns_proto::rr::DNSClass {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        match self {
            trust_dns_proto::rr::DNSClass::IN => "IN".visit(visitor),
            trust_dns_proto::rr::DNSClass::CH => "CH".visit(visitor),
            trust_dns_proto::rr::DNSClass::HS => "HS".visit(visitor),
            trust_dns_proto::rr::DNSClass::NONE => "NONE".visit(visitor),
            trust_dns_proto::rr::DNSClass::ANY => "ANY".visit(visitor),
            trust_dns_proto::rr::DNSClass::OPT(opt) => format!("OPT{opt}").visit(visitor),
        }
    }
}

impl DiffVisitable for trust_dns_proto::rr::RData {
    fn visit<V>(&self, visitor: &mut V) -> Result<()>
    where
        V: Visitor + ?Sized,
    {
        self.to_string().visit(visitor)
    }
}

// Export macros to use in the rest of the crate
pub(crate) use {visit_fields, visit_fields_call};
