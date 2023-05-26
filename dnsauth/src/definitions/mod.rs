//! Types to specify fuzzing configurations and the resulting output.

mod fuzz_cases;
mod fuzz_results;

pub use self::fuzz_cases::*;
pub use self::fuzz_results::*;
use crate::serialize::DnsWireFormatB64;
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

#[serde_with::serde_as]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct CacheKey(
    #[serde_as(as = "DnsWireFormatB64")] pub trust_dns_client::rr::Name,
    pub trust_dns_client::rr::RecordType,
    #[serde_as(as = "serde_with::DisplayFromStr")] pub trust_dns_client::rr::DNSClass,
);

impl fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CacheKey({} {} {})", self.0, self.1, self.2)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct FuzzSuiteId(uuid::Uuid);

impl FuzzSuiteId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for FuzzSuiteId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FuzzSuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FuzzSuiteId({})", self.0)
    }
}

impl fmt::Display for FuzzSuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for FuzzSuiteId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct FuzzCaseId(uuid::Uuid);

impl FuzzCaseId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for FuzzCaseId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FuzzCaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FuzzCaseId({})", self.0)
    }
}

impl fmt::Display for FuzzCaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for FuzzCaseId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ResolverName(Cow<'static, str>);

impl ResolverName {
    const RESOLVERS: [&'static str; 4] = ["bind9", "maradns", "pdns-recursor", "unbound"];

    pub fn new(s: String) -> Self {
        for r in Self::RESOLVERS {
            if s == r {
                return Self(Cow::Borrowed(r));
            }
        }
        Self(Cow::Owned(s))
    }
}

impl fmt::Debug for ResolverName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fuzzee({})", self.0)
    }
}

impl fmt::Display for ResolverName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for ResolverName {
    fn from(id: String) -> Self {
        Self::new(id)
    }
}

impl AsRef<str> for ResolverName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub struct FuzzResultDiff<'a> {
    pub fuzz_case: &'a FuzzCase,
    pub resolver_name: &'a ResolverName,
    pub fuzz_result: &'a FuzzResult,
}
