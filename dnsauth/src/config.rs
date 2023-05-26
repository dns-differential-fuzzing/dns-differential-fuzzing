//! Configuration for fuzzer and fuzzee

use color_eyre::Result;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use trust_dns_client::rr::{LowerName, RrKey};
use trust_dns_proto::rr::{Name, RData, RecordType};

/// Shared config for Client and Server.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    pub common: CommonConfig,
    pub auth: Vec<AuthConfig>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct CommonConfig {
    pub log_level: Option<LogLevel>,
    /// Number of messages used for fuzzing
    pub fuzzing_messages: Option<usize>,
}

/// Configurations about the authoritative DNS zone for the server.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AuthConfig {
    pub server_id: Option<String>,
    pub listen_addresses: Vec<SocketAddr>,
    pub zone: LowerName,
    pub ttl: u32,
    pub data: Vec<ResouceRecord>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ResouceRecord {
    pub name: LowerName,
    #[serde(flatten)]
    pub record: Record,
}

impl From<ResouceRecord> for (Name, RrKey, RecordType, RData) {
    fn from(rr: ResouceRecord) -> Self {
        let (rec_type, rdata) = rr.record.into();
        (
            Name::from(&rr.name),
            RrKey::new(rr.name, rec_type),
            rec_type,
            rdata,
        )
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "UPPERCASE", tag = "type")]
pub enum Record {
    A { rdata: Ipv4Addr },
    SOA { rdata: SOA },
    NS { rdata: Name },
}

impl From<Record> for (RecordType, RData) {
    fn from(record: Record) -> Self {
        use RecordType::*;
        match record {
            Record::A { rdata } => (A, RData::A(rdata)),
            Record::SOA { rdata } => {
                let soa = trust_dns_proto::rr::rdata::SOA::new(
                    rdata.mname,
                    rdata.rname,
                    rdata.serial,
                    rdata.refresh,
                    rdata.retry,
                    rdata.expire,
                    rdata.minimum,
                );
                (SOA, RData::SOA(soa))
            }
            Record::NS { rdata } => (NS, RData::NS(rdata)),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, serde_with::DeserializeFromStr, serde_with::SerializeDisplay)]
pub struct SOA {
    mname: Name,
    rname: Name,
    serial: u32,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32,
}

impl fmt::Display for SOA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {}",
            self.mname,
            self.rname,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum
        )
    }
}

impl FromStr for SOA {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(' ').collect();
        if parts.len() != 7 {
            return Err(format!(
                "An SOA requires 7 parts, but only {} are provided",
                parts.len()
            ));
        }
        let minimum: u32 = parts[6]
            .parse()
            .map_err(|_| "SOA minimum is not a u32 number.")?;
        let expire: i32 = parts[5]
            .parse()
            .map_err(|_| "SOA expire is not a i32 number.")?;
        let retry: i32 = parts[4]
            .parse()
            .map_err(|_| "SOA retry is not a i32 number.")?;
        let refresh: i32 = parts[3]
            .parse()
            .map_err(|_| "SOA refresh is not a i32 number.")?;
        let serial: u32 = parts[2]
            .parse()
            .map_err(|_| "SOA serial is not a u32 number.")?;
        let rname = Name::from_utf8(parts[1]).map_err(|err| err.to_string())?;
        let mname = Name::from_utf8(parts[0]).map_err(|err| err.to_string())?;

        Ok(Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        })
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Warn,
    Info,
    Debug,
    Trace,
}

#[test]
fn test_can_parse_config() -> Result<()> {
    let content = misc_utils::fs::read_to_string("./config.toml")?;
    let config: Config = toml::from_str(&content)?;
    eprintln!("{config:?}");
    eprintln!("{}", toml::to_string(&config).unwrap());
    Ok(())
}
