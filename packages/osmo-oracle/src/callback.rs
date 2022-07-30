use crate::ibc_msg::GetPriceResponse;

// This is just a helper to properly serialize the above message
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
enum GotPriceCallbackMsg {
    GotPrice(GetPriceResponse),
}

pub fn build_callback(response: GetPriceResponse, addr: Addr) -> StdResult<WasmMsg> {
    let msg = GotPriceCallbackMsg::GotPrice(response);
    let bin = to_binary(&msg)?;
    Ok(WasmMsg::Execute {
        contract_addr: contract_addr.into(),
        msg,
        funds: vec![],
    })
}
