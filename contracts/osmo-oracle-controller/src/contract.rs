use crate::error::ContractError;
use cosmwasm_std::{
    entry_point, to_binary, Deps, DepsMut, Env, IbcMsg, MessageInfo, QueryResponse, Response,
    StdResult,
};
use osmo_oracle::PacketMsg;

use crate::ibc::PACKET_LIFETIME;
use crate::msg::{ChannelResponse, ExecuteMsg, InstantiateMsg, LastPriceResponse, QueryMsg};
use crate::state::{CHANNEL, LAST_PRICE};

#[entry_point]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    Ok(Response::new())
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    cw_utils::nonpayable(&info)?;
    match msg {
        ExecuteMsg::GetPrice {
            input,
            output,
            callback,
        } => execute_get_price(deps, env, info, input, output, callback),
    }
}

pub fn execute_get_price(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    input: String,
    output: String,
    callback: bool,
) -> Result<Response, ContractError> {
    let channel_id = CHANNEL.load(deps.storage)?;
    let requester = if callback {
        Some(info.sender.into_string())
    } else {
        None
    };

    // Trigger packet
    let packet = PacketMsg::GetPrice {
        input,
        output,
        requester,
    };
    let msg = IbcMsg::SendPacket {
        channel_id,
        data: to_binary(&packet)?,
        timeout: env.block.time.plus_seconds(PACKET_LIFETIME).into(),
    };

    let res = Response::new().add_message(msg);
    Ok(res)
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<QueryResponse> {
    match msg {
        QueryMsg::LastPrice { input, output } => to_binary(&query_last_price(deps, input, output)?),
        QueryMsg::Channel {} => to_binary(&query_channel(deps)?),
    }
}

pub fn query_last_price(deps: Deps, input: String, output: String) -> StdResult<LastPriceResponse> {
    LAST_PRICE.load(deps.storage, (&input, &output))
}

pub fn query_channel(deps: Deps) -> StdResult<ChannelResponse> {
    let channel_id = CHANNEL.may_load(deps.storage)?;
    Ok(ChannelResponse { channel_id })
}
