use thiserror::Error;

use cosmwasm_std::StdError;
use cw_utils::PaymentError;

use osmo_oracle::OsmoOracleError;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    OsmoOracle(#[from] OsmoOracleError),

    #[error("{0}")]
    Payment(#[from] PaymentError),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Not such route")]
    NoRoute,
}
