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
use crate::state::{CALLBACK, CHANNEL, LAST_PRICE};

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
    requester: String,
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
    if CALLBACK
        .may_load(deps.storage, (&requester, &input, &output))?
        .unwrap_or(false)
    {
        res = res.add_message(build_callback(response, requester)?);
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
    use crate::contract::{execute, instantiate, query};
    use crate::msg::{AccountResponse, ExecuteMsg, InstantiateMsg, QueryMsg};

    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_ibc_channel_connect_ack, mock_ibc_channel_open_init,
        mock_ibc_channel_open_try, mock_ibc_packet_ack, mock_info, MockApi, MockQuerier,
        MockStorage,
    };
    use cosmwasm_std::{coin, coins, BankMsg, CosmosMsg, IbcAcknowledgement, OwnedDeps};
    use simple_ica::{APP_ORDER, BAD_APP_ORDER, IBC_APP_VERSION};

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

        // this should send a WhoAmI request, which is received some blocks later
        assert_eq!(1, res.messages.len());
        match &res.messages[0].msg {
            CosmosMsg::Ibc(IbcMsg::SendPacket {
                channel_id: packet_channel,
                ..
            }) => assert_eq!(packet_channel.as_str(), channel_id),
            o => panic!("Unexpected message: {:?}", o),
        };
    }

    fn who_am_i_response(deps: DepsMut, channel_id: &str, account: impl Into<String>) {
        let packet = PacketMsg::WhoAmI {};
        let res = StdAck::success(WhoAmIResponse {
            account: account.into(),
        });
        let ack = IbcAcknowledgement::new(res);
        let msg = mock_ibc_packet_ack(channel_id, &packet, ack).unwrap();
        let res = ibc_packet_ack(deps, mock_env(), msg).unwrap();
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
        let channel_id = "channel-1234";
        connect(deps.as_mut(), channel_id);

        // check for empty account
        let q = QueryMsg::Account {
            channel_id: channel_id.into(),
        };
        let r = query(deps.as_ref(), mock_env(), q).unwrap();
        let acct: AccountResponse = from_slice(&r).unwrap();
        assert!(acct.remote_addr.is_none());
        assert!(acct.remote_balance.is_empty());
        assert_eq!(0, acct.last_update_time.nanos());

        // now get feedback from WhoAmI packet
        let remote_addr = "account-789";
        who_am_i_response(deps.as_mut(), channel_id, remote_addr);

        // account should be set up
        let q = QueryMsg::Account {
            channel_id: channel_id.into(),
        };
        let r = query(deps.as_ref(), mock_env(), q).unwrap();
        let acct: AccountResponse = from_slice(&r).unwrap();
        assert_eq!(acct.remote_addr.unwrap(), remote_addr);
        assert!(acct.remote_balance.is_empty());
        assert_eq!(0, acct.last_update_time.nanos());
    }

    #[test]
    fn dispatch_message_send_and_ack() {
        let channel_id = "channel-1234";
        let remote_addr = "account-789";

        // init contract
        let mut deps = setup();
        // channel handshake
        connect(deps.as_mut(), channel_id);
        // get feedback from WhoAmI packet
        who_am_i_response(deps.as_mut(), channel_id, remote_addr);

        // try to dispatch a message
        let msgs_to_dispatch = vec![BankMsg::Send {
            to_address: "my-friend".into(),
            amount: coins(123456789, "uatom"),
        }
        .into()];
        let handle_msg = ExecuteMsg::SendMsgs {
            channel_id: channel_id.into(),
            msgs: msgs_to_dispatch,
        };
        let info = mock_info(CREATOR, &[]);
        let mut res = execute(deps.as_mut(), mock_env(), info, handle_msg).unwrap();
        assert_eq!(1, res.messages.len());
        let msg = match res.messages.swap_remove(0).msg {
            CosmosMsg::Ibc(IbcMsg::SendPacket {
                channel_id, data, ..
            }) => {
                let ack = IbcAcknowledgement::new(StdAck::success(&()));
                let mut msg = mock_ibc_packet_ack(&channel_id, &1u32, ack).unwrap();
                msg.original_packet.data = data;
                msg
            }
            o => panic!("Unexpected message: {:?}", o),
        };
        let res = ibc_packet_ack(deps.as_mut(), mock_env(), msg).unwrap();
        // no actions expected, but let's check the events to see it was dispatched properly
        assert_eq!(0, res.messages.len());
        assert_eq!(vec![("action", "acknowledge_dispatch")], res.attributes)
    }

    #[test]
    fn send_remote_funds() {
        let reflect_channel_id = "channel-1234";
        let remote_addr = "account-789";
        let transfer_channel_id = "transfer-2";

        // init contract
        let mut deps = setup();
        // channel handshake
        connect(deps.as_mut(), reflect_channel_id);
        // get feedback from WhoAmI packet
        who_am_i_response(deps.as_mut(), reflect_channel_id, remote_addr);

        // let's try to send funds to a channel that doesn't exist
        let msg = ExecuteMsg::SendFunds {
            reflect_channel_id: "random-channel".into(),
            transfer_channel_id: transfer_channel_id.into(),
        };
        let info = mock_info(CREATOR, &coins(12344, "utrgd"));
        execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();

        // let's try with no sent funds in the message
        let msg = ExecuteMsg::SendFunds {
            reflect_channel_id: reflect_channel_id.into(),
            transfer_channel_id: transfer_channel_id.into(),
        };
        let info = mock_info(CREATOR, &[]);
        execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();

        // 3rd times the charm
        let msg = ExecuteMsg::SendFunds {
            reflect_channel_id: reflect_channel_id.into(),
            transfer_channel_id: transfer_channel_id.into(),
        };
        let info = mock_info(CREATOR, &coins(12344, "utrgd"));
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(1, res.messages.len());
        match &res.messages[0].msg {
            CosmosMsg::Ibc(IbcMsg::Transfer {
                channel_id,
                to_address,
                amount,
                timeout,
            }) => {
                assert_eq!(transfer_channel_id, channel_id.as_str());
                assert_eq!(remote_addr, to_address.as_str());
                assert_eq!(&coin(12344, "utrgd"), amount);
                assert!(timeout.block().is_none());
                assert!(timeout.timestamp().is_some());
            }
            o => panic!("unexpected message: {:?}", o),
        }
    }
}
