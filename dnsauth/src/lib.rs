#![warn(
    clippy::semicolon_if_nothing_returned,
    missing_copy_implementations,
    missing_debug_implementations,
    noop_method_call,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unused_extern_crates,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications,
    variant_size_differences
)]

pub mod authns;
pub mod config;
pub mod definitions;
#[cfg(feature = "diffing")]
pub mod diff;
#[cfg(feature = "app")]
pub mod fuzzee;
mod serialize;

use std::fmt;
use trust_dns_proto::op::Message;

trait MessageExt {
    fn display_short(&self) -> MessageShortDisplay<'_>;
}

impl MessageExt for Message {
    fn display_short(&self) -> MessageShortDisplay<'_> {
        MessageShortDisplay(self)
    }
}

struct MessageShortDisplay<'a>(&'a Message);

impl fmt::Display for MessageShortDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = [
            if self.0.authoritative() { "AA|" } else { "" },
            if self.0.truncated() { "TC|" } else { "" },
            if self.0.recursion_desired() {
                "RD|"
            } else {
                ""
            },
            if self.0.recursion_desired() {
                "RA|"
            } else {
                ""
            },
            if self.0.authentic_data() { "AD|" } else { "" },
            if self.0.checking_disabled() {
                "CD|"
            } else {
                ""
            },
        ]
        .join("");

        let rcode = trust_dns_proto::op::ResponseCode::from(
            self.0.edns().map(|edns| edns.rcode_high()).unwrap_or(0),
            self.0.response_code().low(),
        );
        write!(
            f,
            "{:?},{:?},{},{}",
            self.0.message_type(),
            rcode,
            self.0.id(),
            &flags[0..flags.len().saturating_sub(1)],
        )?;
        if let Some(edns) = self.0.edns() {
            write!(
                f,
                " EDNS{} {}B{}",
                edns.version(),
                edns.max_payload(),
                if edns.dnssec_ok() { " DO" } else { "" }
            )?;
        }
        if self.0.queries().is_empty() {
            write!(f, " No-Q")?;
        } else {
            write!(
                f,
                " Q {} {} {}",
                self.0.queries()[0].name(),
                self.0.queries()[0].query_class(),
                self.0.queries()[0].query_type(),
            )?;
        }
        write!(
            f,
            " {}/{}/{}/{}",
            self.0.query_count(),
            self.0.answer_count(),
            self.0.name_server_count(),
            self.0.additional_count(),
        )?;

        Ok(())
    }
}

pub mod utils {
    use std::net::Ipv4Addr;

    /// Return the next IPv4 address.
    pub fn next_ipv4(addr: Ipv4Addr) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(addr) + 1)
    }
}
