use cosmwasm_std::{
    entry_point, from_slice, DepsMut, Env, Ibc3ChannelOpenResponse, IbcBasicResponse,
    IbcChannelCloseMsg, IbcChannelConnectMsg, IbcChannelOpenMsg, IbcPacketAckMsg,
    IbcPacketReceiveMsg, IbcPacketTimeoutMsg, IbcReceiveResponse, StdResult,
};

use osmo_oracle::{
    build_callback, check_order, check_version, GetPriceResponse, PacketMsg, StdAck,
};

use crate::error::ContractError;
use crate::msg::LastPriceResponse;
use crate::state::{CHANNEL, LAST_PRICE};

// TODO: make configurable?
/// packets live one hour
pub const PACKET_LIFETIME: u64 = 60 * 60;

#[entry_point]
/// enforces ordering and versioning constraints
pub fn ibc_channel_open(
    deps: DepsMut,
    _env: Env,
    msg: IbcChannelOpenMsg,
) -> Result<Option<Ibc3ChannelOpenResponse>, ContractError> {
    let channel = msg.channel();
    check_order(&channel.order)?;
    check_version(&channel.version)?;
    if let Some(counter_version) = msg.counterparty_version() {
        check_version(counter_version)?;
    }
    // ensure we have no existing channel_id
    if CHANNEL.may_load(deps.storage)?.is_some() {
        Err(ContractError::AlreadyRegistered)
    } else {
        Ok(None)
    }
}

#[entry_point]
pub fn ibc_channel_connect(
    deps: DepsMut,
    _env: Env,
    msg: IbcChannelConnectMsg,
) -> Result<IbcBasicResponse, ContractError> {
    let channel = msg.channel();
    check_version(&channel.version)?;
    if let Some(counter_version) = msg.counterparty_version() {
        check_version(counter_version)?;
    }

    // store channel id on first connect
    if CHANNEL.may_load(deps.storage)?.is_some() {
        Err(ContractError::AlreadyRegistered)
    } else {
        CHANNEL.save(deps.storage, &channel.endpoint.channel_id)?;
        Ok(IbcBasicResponse::new())
    }
}

#[entry_point]
/// On closed channel, simply delete the channel
pub fn ibc_channel_close(
    deps: DepsMut,
    _env: Env,
    _msg: IbcChannelCloseMsg,
) -> StdResult<IbcBasicResponse> {
    CHANNEL.remove(deps.storage);
    Ok(IbcBasicResponse::new())
}

#[entry_point]
/// never should be called as the other side never sends packets
pub fn ibc_packet_receive(
    _deps: DepsMut,
    _env: Env,
    _packet: IbcPacketReceiveMsg,
) -> StdResult<IbcReceiveResponse> {
    Ok(IbcReceiveResponse::new()
        .set_ack(b"{}")
        .add_attribute("action", "ibc_packet_ack"))
}

#[entry_point]
pub fn ibc_packet_ack(
    deps: DepsMut,
    env: Env,
    msg: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // we need to parse the ack based on our request
    let res: StdAck = from_slice(&msg.acknowledgement.data)?;
    match res {
        StdAck::Result(data) => {
            let packet: PacketMsg = from_slice(&msg.original_packet.data)?;
            match packet {
                PacketMsg::GetPrice {
                    input,
                    output,
                    requester,
                } => {
                    let msg: GetPriceResponse = from_slice(&data)?;
                    acknowledge_get_price(deps, env, input, output, requester, msg)
                }
            }
        }
        StdAck::Error(e) => Ok(IbcBasicResponse::new()
            .add_attribute("ack", "failed")
            .add_attribute("error", e)),
    }
}

// receive PacketMsg::Dispatch response
#[allow(clippy::unnecessary_wraps)]
fn acknowledge_get_price(
    deps: DepsMut,
    env: Env,
    input: String,
    output: String,
    requester: Option<String>,
    response: GetPriceResponse,
) -> Result<IbcBasicResponse, ContractError> {
    // store the price locally
    let data = LastPriceResponse {
        spot_price: response.spot_price.clone(),
        spot_price_with_fee: response.spot_price_with_fee.clone(),
        updated: env.block.time,
    };
    LAST_PRICE.save(deps.storage, (&input, &output), &data)?;

    // start res
    let mut res = IbcBasicResponse::new().add_attribute("ack", "success");

    // check to see if we do a callback
    if let Some(contract) = requester {
        res = res.add_message(build_callback(response, input, output, contract)?);
    }

    Ok(res)
}

#[entry_point]
/// we just ignore these now. shall we store some info?
pub fn ibc_packet_timeout(
    _deps: DepsMut,
    _env: Env,
    _msg: IbcPacketTimeoutMsg,
) -> StdResult<IbcBasicResponse> {
    Ok(IbcBasicResponse::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{execute, instantiate, query_channel, query_last_price};
    use crate::msg::{ExecuteMsg, InstantiateMsg};

    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_ibc_channel_connect_ack, mock_ibc_channel_open_init,
        mock_ibc_channel_open_try, mock_ibc_packet_ack, mock_info, MockApi, MockQuerier,
        MockStorage,
    };
    use cosmwasm_std::{
        to_binary, CosmosMsg, Decimal, IbcAcknowledgement, IbcMsg, OwnedDeps, WasmMsg,
    };
    use osmo_oracle::{
        GetPriceAcknowledgement, GotPriceCallbackMsg, APP_ORDER, BAD_APP_ORDER, IBC_APP_VERSION,
    };

    const CREATOR: &str = "creator";

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier> {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {};
        let info = mock_info(CREATOR, &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
        deps
    }

    // connect will run through the entire handshake to set up a proper connect and
    // save the account (tested in detail in `proper_handshake_flow`)
    fn connect(mut deps: DepsMut, channel_id: &str) {
        let handshake_open = mock_ibc_channel_open_init(channel_id, APP_ORDER, IBC_APP_VERSION);
        // first we try to open with a valid handshake
        ibc_channel_open(deps.branch(), mock_env(), handshake_open).unwrap();

        // then we connect (with counter-party version set)
        let handshake_connect =
            mock_ibc_channel_connect_ack(channel_id, APP_ORDER, IBC_APP_VERSION);
        let res = ibc_channel_connect(deps.branch(), mock_env(), handshake_connect).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn enforce_version_in_handshake() {
        let mut deps = setup();

        let wrong_order = mock_ibc_channel_open_try("channel-12", BAD_APP_ORDER, IBC_APP_VERSION);
        ibc_channel_open(deps.as_mut(), mock_env(), wrong_order).unwrap_err();

        let wrong_version = mock_ibc_channel_open_try("channel-12", APP_ORDER, "reflect");
        ibc_channel_open(deps.as_mut(), mock_env(), wrong_version).unwrap_err();

        let valid_handshake = mock_ibc_channel_open_try("channel-12", APP_ORDER, IBC_APP_VERSION);
        ibc_channel_open(deps.as_mut(), mock_env(), valid_handshake).unwrap();
    }

    #[test]
    fn proper_handshake_flow() {
        // setup and connect handshake
        let mut deps = setup();

        // no channel set
        let r = query_channel(deps.as_ref()).unwrap();
        assert_eq!(r.channel_id, None);

        // connect
        let channel_id = "channel-1234";
        connect(deps.as_mut(), channel_id);

        // check proper channel
        let r = query_channel(deps.as_ref()).unwrap();
        assert_eq!(r.channel_id, Some(channel_id.to_string()));
    }

    #[test]
    fn get_price_send_and_ack_no_callback() {
        let orig_channel_id = "channel-1234";

        // init contract
        let mut deps = setup();
        // channel handshake
        connect(deps.as_mut(), orig_channel_id);

        let input = "ujuno";
        let output = "uosmo";
        let handle_msg = ExecuteMsg::GetPrice {
            input: input.to_string(),
            output: output.to_string(),
            callback: false,
        };
        let info = mock_info("anyone", &[]);
        let mut res = execute(deps.as_mut(), mock_env(), info, handle_msg).unwrap();
        assert_eq!(1, res.messages.len());
        let msg = match res.messages.swap_remove(0).msg {
            CosmosMsg::Ibc(IbcMsg::SendPacket {
                channel_id, data, ..
            }) => {
                assert_eq!(channel_id.as_str(), orig_channel_id);
                assert_eq!(
                    data,
                    to_binary(&PacketMsg::GetPrice {
                        input: input.to_string(),
                        output: output.to_string(),
                        requester: None,
                    })
                    .unwrap()
                );

                let response = GetPriceResponse {
                    spot_price: Decimal::percent(123),
                    spot_price_with_fee: Decimal::percent(112),
                };
                let ack = IbcAcknowledgement::new(StdAck::success(&response));
                let mut msg = mock_ibc_packet_ack(&channel_id, &data, ack).unwrap();
                msg.original_packet.data = data;
                msg
            }
            o => panic!("Unexpected message: {:?}", o),
        };

        // no callbacks, but let's make sure this stores data
        let res = ibc_packet_ack(deps.as_mut(), mock_env(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        let price = query_last_price(deps.as_ref(), input.to_string(), output.to_string()).unwrap();
        let expected = LastPriceResponse {
            spot_price: Decimal::percent(123),
            spot_price_with_fee: Decimal::percent(112),
            updated: mock_env().block.time,
        };
        assert_eq!(price, expected);
    }

    #[test]
    fn get_price_send_and_ack_with_callback() {
        let orig_channel_id = "channel-1234";

        // init contract
        let mut deps = setup();
        // channel handshake
        connect(deps.as_mut(), orig_channel_id);

        let input = "ujuno";
        let output = "uosmo";
        let handle_msg = ExecuteMsg::GetPrice {
            input: input.to_string(),
            output: output.to_string(),
            callback: true,
        };
        let info = mock_info("call-me-back", &[]);
        let mut res = execute(deps.as_mut(), mock_env(), info, handle_msg).unwrap();
        assert_eq!(1, res.messages.len());
        let msg = match res.messages.swap_remove(0).msg {
            CosmosMsg::Ibc(IbcMsg::SendPacket {
                channel_id, data, ..
            }) => {
                assert_eq!(channel_id.as_str(), orig_channel_id);
                assert_eq!(
                    data,
                    to_binary(&PacketMsg::GetPrice {
                        input: input.to_string(),
                        output: output.to_string(),
                        requester: Some("call-me-back".to_string())
                    })
                    .unwrap()
                );

                let response = GetPriceResponse {
                    spot_price: Decimal::percent(123),
                    spot_price_with_fee: Decimal::percent(112),
                };
                let ack = IbcAcknowledgement::new(StdAck::success(&response));
                let mut msg = mock_ibc_packet_ack(&channel_id, &data, ack).unwrap();
                msg.original_packet.data = data;
                msg
            }
            o => panic!("Unexpected message: {:?}", o),
        };

        // ensure callbacks, but let's make sure this stores data
        let mut res = ibc_packet_ack(deps.as_mut(), mock_env(), msg).unwrap();
        assert_eq!(1, res.messages.len());

        let price = query_last_price(deps.as_ref(), input.to_string(), output.to_string()).unwrap();
        let expected = LastPriceResponse {
            spot_price: Decimal::percent(123),
            spot_price_with_fee: Decimal::percent(112),
            updated: mock_env().block.time,
        };
        assert_eq!(price, expected);

        // make sure we have proper callback
        match res.messages.swap_remove(0).msg {
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr,
                msg,
                funds,
            }) => {
                assert_eq!(funds.len(), 0);
                // this is always the original caller
                assert_eq!(contract_addr.as_str(), "call-me-back");
                let parsed: GotPriceCallbackMsg = from_slice(&msg).unwrap();
                assert_eq!(
                    parsed,
                    GotPriceCallbackMsg::GotPrice(GetPriceAcknowledgement {
                        input: input.to_string(),
                        output: output.to_string(),
                        spot_price: Decimal::percent(123),
                        spot_price_with_fee: Decimal::percent(112),
                    })
                );
            }
            o => panic!("Unexpected message: {:?}", o),
        };
    }
}
