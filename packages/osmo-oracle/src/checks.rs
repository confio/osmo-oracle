use cosmwasm_std::IbcOrder;
use thiserror::Error;

use crate::{APP_ORDER, IBC_APP_VERSION};

#[derive(Error, Debug, PartialEq)]
pub enum OsmoOracleError {
    #[error("Only supports unordered channels")]
    InvalidChannelOrder,

    #[error("Counterparty version must be '{0}'")]
    InvalidChannelVersion(&'static str),
}

pub fn check_order(order: &IbcOrder) -> Result<(), OsmoOracleError> {
    if order != &APP_ORDER {
        Err(OsmoOracleError::InvalidChannelOrder)
    } else {
        Ok(())
    }
}

pub fn check_version(version: &str) -> Result<(), OsmoOracleError> {
    if version != IBC_APP_VERSION {
        Err(OsmoOracleError::InvalidChannelVersion(IBC_APP_VERSION))
    } else {
        Ok(())
    }
}
