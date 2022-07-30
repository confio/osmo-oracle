use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::GetPriceResponse;
use cosmwasm_std::{to_binary, Decimal, StdResult, WasmMsg};

/// Return the data field for each message
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct GetPriceAcknowledgement {
    pub spot_price: Decimal,
    pub spot_price_with_fee: Decimal,
    pub input: String,
    pub output: String,
}

// This is just a helper to properly serialize the above message
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum GotPriceCallbackMsg {
    GotPrice(GetPriceAcknowledgement),
}

pub fn build_callback(
    response: GetPriceResponse,
    input: String,
    output: String,
    contract_addr: String,
) -> StdResult<WasmMsg> {
    let ack = GetPriceAcknowledgement {
        spot_price: response.spot_price,
        spot_price_with_fee: response.spot_price_with_fee,
        input,
        output,
    };
    let msg = GotPriceCallbackMsg::GotPrice(ack);
    let msg = to_binary(&msg)?;
    Ok(WasmMsg::Execute {
        contract_addr,
        msg,
        funds: vec![],
    })
}
