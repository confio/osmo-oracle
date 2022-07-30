use thiserror::Error;

use cosmwasm_std::StdError;
use cw_utils::ParseReplyError;

use osmo_oracle::OsmoOracleError;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    OsmoOracle(#[from] OsmoOracleError),

    #[error("Cannot register over an existing channel")]
    ChannelAlreadyRegistered,
    s,
}
