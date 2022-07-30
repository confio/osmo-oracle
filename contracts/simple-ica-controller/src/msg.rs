use cosmwasm_std::{Decimal, Timestamp};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// This needs no info. Owner of the contract is whoever signed the InstantiateMsg.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct InstantiateMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    GetPrice {
        input: String,
        output: String,
        callback: bool,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    LastPrice { input: String, output: String },
    Channel {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct LastPriceResponse {
    pub spot_price: Decimal,
    pub spot_price_with_fee: Decimal,
    pub updated: Timestamp,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ChannelResponse {
    pub channel_id: Option<String>,
}
