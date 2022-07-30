use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{to_binary, StdResult, WasmMsg};

use crate::ibc_msg::GetPriceResponse;

// This is just a helper to properly serialize the above message
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
enum GotPriceCallbackMsg {
    GotPrice(GetPriceResponse),
}

pub fn build_callback(response: GetPriceResponse, contract_addr: String) -> StdResult<WasmMsg> {
    let msg = GotPriceCallbackMsg::GotPrice(response);
    let msg = to_binary(&msg)?;
    Ok(WasmMsg::Execute {
        contract_addr,
        msg,
        funds: vec![],
    })
}
