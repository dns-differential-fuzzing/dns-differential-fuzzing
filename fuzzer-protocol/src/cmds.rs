use crate::Counters;

#[cfg_attr(feature = "client", derive(serde::Serialize))]
#[cfg_attr(feature = "server", derive(serde::Deserialize))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Commands {
    /// Expects [`CommandResponses::Counters`] as response
    Get {},
    /// Expects [`CommandResponses::Counters`] as response
    GetAndReset {},
    /// Expects [`CommandResponses::Ok`] as response
    Terminate {},
    /// Expects [`CommandResponses::UnknownCommand`] as response
    #[serde(other)]
    Unknown,
}

/// Answer messages for [`Commands`]
#[cfg_attr(feature = "client", derive(serde::Deserialize))]
#[cfg_attr(feature = "server", derive(serde::Serialize))]
#[derive(Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum CommandResponses {
    /// Message indicating the command got received and executed without response value.
    Ok,
    /// Answer message for [`Commands::Get`]
    Counters { values: Counters },
    /// Answer message for [`Commands::Unknown`]
    UnknownCommand,
}
