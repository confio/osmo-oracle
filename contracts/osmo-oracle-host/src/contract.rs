use cosmwasm_std::{
    entry_point, from_slice, to_binary, wasm_execute, BankMsg, CosmosMsg, Deps, DepsMut, Empty,
    Env, Event, Ibc3ChannelOpenResponse, IbcBasicResponse, IbcChannelCloseMsg,
    IbcChannelConnectMsg, IbcChannelOpenMsg, IbcChannelOpenResponse, IbcPacketAckMsg,
    IbcPacketReceiveMsg, IbcPacketTimeoutMsg, IbcReceiveResponse, MessageInfo, Order,
    QueryResponse, Reply, Response, StdResult, SubMsg, WasmMsg,
};
use cw_utils::parse_reply_instantiate_data;
use osmo_oracle::{
    check_order, check_version, BalancesResponse, DispatchResponse, PacketMsg, StdAck,
    WhoAmIResponse, IBC_APP_VERSION,
};

use crate::error::ContractError;
use crate::msg::{
    AccountInfo, AccountResponse, InstantiateMsg, ListAccountsResponse, QueryMsg, ReflectExecuteMsg,
};
use crate::state::{Config, ACCOUNTS, CONFIG, PENDING, RESULTS};

pub const RECEIVE_DISPATCH_ID: u64 = 1234;
pub const INIT_CALLBACK_ID: u64 = 7890;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // we store the reflect_id for creating accounts later
    let cfg = Config {
        reflect_code_id: msg.reflect_code_id,
    };
    CONFIG.save(deps.storage, &cfg)?;

    Ok(Response::new())
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<QueryResponse> {
    match msg {
        QueryMsg::Account { channel_id } => to_binary(&query_account(deps, channel_id)?),
        QueryMsg::ListAccounts {} => to_binary(&query_list_accounts(deps)?),
    }
}

pub fn query_account(deps: Deps, channel_id: String) -> StdResult<AccountResponse> {
    let account = ACCOUNTS.load(deps.storage, &channel_id)?;
    Ok(AccountResponse {
        account: Some(account.into()),
    })
}

pub fn query_list_accounts(deps: Deps) -> StdResult<ListAccountsResponse> {
    let accounts = ACCOUNTS
        .range(deps.storage, None, None, Order::Ascending)
        .map(|item| {
            let (channel_id, account) = item?;
            Ok(AccountInfo {
                account: account.into(),
                channel_id,
            })
        })
        .collect::<StdResult<_>>()?;
    Ok(ListAccountsResponse { accounts })
}

#[entry_point]
/// enforces ordering and versioing constraints
pub fn ibc_channel_open(
    _deps: DepsMut,
    _env: Env,
    msg: IbcChannelOpenMsg,
) -> Result<IbcChannelOpenResponse, ContractError> {
    let channel = msg.channel();

    check_order(&channel.order)?;
    // In ibcv3 we don't check the version string passed in the message
    // and only check the counterparty version.
    if let Some(counter_version) = msg.counterparty_version() {
        check_version(counter_version)?;
    }

    // We return the version we need (which could be different than the counterparty version)
    Ok(Some(Ibc3ChannelOpenResponse {
        version: IBC_APP_VERSION.to_string(),
    }))
}

#[entry_point]
/// once it's established, we create the reflect contract
pub fn ibc_channel_connect(
    deps: DepsMut,
    env: Env,
    msg: IbcChannelConnectMsg,
) -> StdResult<IbcBasicResponse> {
    let channel = msg.channel();
    let cfg = CONFIG.load(deps.storage)?;
    let chan_id = &channel.endpoint.channel_id;

    let init_msg = cw1_whitelist::msg::InstantiateMsg {
        admins: vec![env.contract.address.into_string()],
        mutable: false,
    };
    let msg = WasmMsg::Instantiate {
        admin: None,
        code_id: cfg.reflect_code_id,
        msg: to_binary(&init_msg)?,
        funds: vec![],
        label: format!("ibc-reflect-{}", chan_id),
    };
    let msg = SubMsg::reply_on_success(msg, INIT_CALLBACK_ID);

    // store the channel id for the reply handler
    PENDING.save(deps.storage, chan_id)?;

    Ok(IbcBasicResponse::new()
        .add_submessage(msg)
        .add_attribute("action", "ibc_connect")
        .add_attribute("channel_id", chan_id)
        .add_event(Event::new("ibc").add_attribute("channel", "connect")))
}

#[entry_point]
/// On closed channel, we take all tokens from reflect contract to this contract.
/// We also delete the channel entry from accounts.
pub fn ibc_channel_close(
    deps: DepsMut,
    env: Env,
    msg: IbcChannelCloseMsg,
) -> StdResult<IbcBasicResponse> {
    let channel = msg.channel();
    // get contract address and remove lookup
    let channel_id = channel.endpoint.channel_id.as_str();
    let reflect_addr = ACCOUNTS.load(deps.storage, channel_id)?;
    ACCOUNTS.remove(deps.storage, channel_id);

    // transfer current balance if any (steal the money)
    let amount = deps.querier.query_all_balances(&reflect_addr)?;
    let messages: Vec<SubMsg<Empty>> = if !amount.is_empty() {
        let bank_msg = BankMsg::Send {
            to_address: env.contract.address.into(),
            amount,
        };
        let reflect_msg = ReflectExecuteMsg::ReflectMsg {
            msgs: vec![bank_msg.into()],
        };
        let wasm_msg = wasm_execute(reflect_addr, &reflect_msg, vec![])?;
        vec![SubMsg::new(wasm_msg)]
    } else {
        vec![]
    };
    let steal_funds = !messages.is_empty();

    Ok(IbcBasicResponse::new()
        .add_submessages(messages)
        .add_attribute("action", "ibc_close")
        .add_attribute("channel_id", channel_id)
        .add_attribute("steal_funds", steal_funds.to_string()))
}

#[entry_point]
pub fn reply(deps: DepsMut, _env: Env, reply: Reply) -> Result<Response, ContractError> {
    match reply.id {
        RECEIVE_DISPATCH_ID => reply_dispatch_callback(deps, reply),
        INIT_CALLBACK_ID => reply_init_callback(deps, reply),
        _ => Err(ContractError::InvalidReplyId),
    }
}

pub fn reply_dispatch_callback(deps: DepsMut, reply: Reply) -> Result<Response, ContractError> {
    // add the new result to the current tracker
    let mut results = RESULTS.load(deps.storage)?;
    results.push(reply.result.unwrap().data.unwrap_or_default());
    RESULTS.save(deps.storage, &results)?;

    // update result data if this is the last
    let data = StdAck::success(&DispatchResponse { results });
    Ok(Response::new().set_data(data))
}

pub fn reply_init_callback(deps: DepsMut, reply: Reply) -> Result<Response, ContractError> {
    // we use storage to pass info from the caller to the reply
    let id = PENDING.load(deps.storage)?;
    PENDING.remove(deps.storage);

    // parse contract info from data
    let raw_addr = parse_reply_instantiate_data(reply)?.contract_address;
    let contract_addr = deps.api.addr_validate(&raw_addr)?;

    // store id -> contract_addr if it is empty
    // id comes from: `let chan_id = msg.endpoint.channel_id;` in `ibc_channel_connect`
    if ACCOUNTS.may_load(deps.storage, &id)?.is_some() {
        return Err(ContractError::ChannelAlreadyRegistered);
    }
    ACCOUNTS.save(deps.storage, &id, &contract_addr)?;

    Ok(Response::new())
}

#[entry_point]
/// we look for a the proper reflect contract to relay to and send the message
/// We cannot return any meaningful response value as we do not know the response value
/// of execution. We just return ok if we dispatched, error if we failed to dispatch
pub fn ibc_packet_receive(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, ContractError> {
    let packet = msg.packet;
    // which local channel did this packet come on
    let caller = packet.dest.channel_id;
    let msg: PacketMsg = from_slice(&packet.data)?;
    match msg {
        PacketMsg::Dispatch { msgs } => receive_dispatch(deps, caller, msgs),
        PacketMsg::WhoAmI {} => receive_who_am_i(deps, caller),
        PacketMsg::Balances {} => receive_balances(deps, caller),
    }
}

// processes PacketMsg::WhoAmI variant
fn receive_who_am_i(deps: DepsMut, caller: String) -> Result<IbcReceiveResponse, ContractError> {
    let account = ACCOUNTS.load(deps.storage, &caller)?;
    let response = WhoAmIResponse {
        account: account.into(),
    };
    let acknowledgement = StdAck::success(&response);
    // and we are golden
    Ok(IbcReceiveResponse::new()
        .set_ack(acknowledgement)
        .add_attribute("action", "receive_who_am_i"))
}

// processes PacketMsg::Balances variant
fn receive_balances(deps: DepsMut, caller: String) -> Result<IbcReceiveResponse, ContractError> {
    let account = ACCOUNTS.load(deps.storage, &caller)?;
    let balances = deps.querier.query_all_balances(&account)?;
    let response = BalancesResponse {
        account: account.into(),
        balances,
    };
    let acknowledgement = StdAck::success(&response);
    // and we are golden
    Ok(IbcReceiveResponse::new()
        .set_ack(acknowledgement)
        .add_attribute("action", "receive_balances"))
}

// processes PacketMsg::Dispatch variant
fn receive_dispatch(
    deps: DepsMut,
    caller: String,
    msgs: Vec<CosmosMsg>,
) -> Result<IbcReceiveResponse, ContractError> {
    // what is the reflect contract here
    let reflect_addr = ACCOUNTS.load(deps.storage, &caller)?;

    // let them know we're fine
    let response = DispatchResponse { results: vec![] };
    let acknowledgement = StdAck::success(&response);
    // create the message to re-dispatch to the reflect contract
    let reflect_msg = cw1_whitelist::msg::ExecuteMsg::Execute { msgs };
    let wasm_msg = wasm_execute(reflect_addr, &reflect_msg, vec![])?;

    // we wrap it in a submessage to properly report results
    let msg = SubMsg::reply_on_success(wasm_msg, RECEIVE_DISPATCH_ID);

    // reset the data field
    RESULTS.save(deps.storage, &vec![])?;

    Ok(IbcReceiveResponse::new()
        .set_ack(acknowledgement)
        .add_submessage(msg)
        .add_attribute("action", "receive_dispatch"))
}

#[entry_point]
/// never should be called as we do not send packets
pub fn ibc_packet_ack(
    _deps: DepsMut,
    _env: Env,
    _msg: IbcPacketAckMsg,
) -> StdResult<IbcBasicResponse> {
    Ok(IbcBasicResponse::new().add_attribute("action", "ibc_packet_ack"))
}

#[entry_point]
/// never should be called as we do not send packets
pub fn ibc_packet_timeout(
    _deps: DepsMut,
    _env: Env,
    _msg: IbcPacketTimeoutMsg,
) -> StdResult<IbcBasicResponse> {
    Ok(IbcBasicResponse::new().add_attribute("action", "ibc_packet_timeout"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_ibc_channel_close_init, mock_ibc_channel_connect_ack,
        mock_ibc_channel_open_init, mock_ibc_channel_open_try, mock_ibc_packet_recv, mock_info,
        mock_wasmd_attr, MockApi, MockQuerier, MockStorage, MOCK_CONTRACT_ADDR,
    };
    use cosmwasm_std::{
        attr, coin, coins, from_slice, BankMsg, Binary, OwnedDeps, SubMsgResponse, SubMsgResult,
        WasmMsg,
    };
    use simple_ica::{APP_ORDER, BAD_APP_ORDER};

    const CREATOR: &str = "creator";
    // code id of the reflect contract
    const REFLECT_ID: u64 = 101;
    // address of first reflect contract instance that we created
    const REFLECT_ADDR: &str = "reflect-acct-1";

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier> {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            reflect_code_id: REFLECT_ID,
        };
        let info = mock_info(CREATOR, &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
        deps
    }

    fn fake_data(reflect_addr: &str) -> Binary {
        // works with length < 128
        let mut encoded = vec![0x0a, reflect_addr.len() as u8];
        encoded.extend(reflect_addr.as_bytes());
        Binary::from(encoded)
    }

    fn fake_events(reflect_addr: &str) -> Vec<Event> {
        let event = Event::new("instantiate").add_attributes(vec![
            attr("code_id", "17"),
            // We have to force this one to avoid the debug assertion against _
            mock_wasmd_attr("_contract_address", reflect_addr),
        ]);
        vec![event]
    }

    // connect will run through the entire handshake to set up a proper connect and
    // save the account (tested in detail in `proper_handshake_flow`)
    fn connect(mut deps: DepsMut, channel_id: &str, account: impl Into<String>) {
        let account: String = account.into();

        let handshake_open = mock_ibc_channel_open_init(channel_id, APP_ORDER, IBC_APP_VERSION);
        // first we try to open with a valid handshake
        ibc_channel_open(deps.branch(), mock_env(), handshake_open).unwrap();

        // then we connect (with counter-party version set)
        let handshake_connect =
            mock_ibc_channel_connect_ack(channel_id, APP_ORDER, IBC_APP_VERSION);
        let res = ibc_channel_connect(deps.branch(), mock_env(), handshake_connect).unwrap();
        assert_eq!(1, res.messages.len());
        assert_eq!(1, res.events.len());
        assert_eq!(
            Event::new("ibc").add_attribute("channel", "connect"),
            res.events[0]
        );
        let id = res.messages[0].id;

        // fake a reply and ensure this works
        let response = Reply {
            id,
            result: SubMsgResult::Ok(SubMsgResponse {
                events: fake_events(&account),
                data: Some(fake_data(&account)),
            }),
        };
        reply(deps.branch(), mock_env(), response).unwrap();
    }

    #[test]
    fn instantiate_works() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            reflect_code_id: 17,
        };
        let info = mock_info("creator", &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len())
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
        let mut deps = setup();
        let channel_id = "channel-1234";

        // first we try to open with a valid handshake
        let handshake_open = mock_ibc_channel_open_init(channel_id, APP_ORDER, IBC_APP_VERSION);
        ibc_channel_open(deps.as_mut(), mock_env(), handshake_open).unwrap();

        // then we connect (with counter-party version set)
        let handshake_connect =
            mock_ibc_channel_connect_ack(channel_id, APP_ORDER, IBC_APP_VERSION);
        let res = ibc_channel_connect(deps.as_mut(), mock_env(), handshake_connect).unwrap();
        // and set up a reflect account
        assert_eq!(1, res.messages.len());
        let id = res.messages[0].id;
        if let CosmosMsg::Wasm(WasmMsg::Instantiate {
            admin,
            code_id,
            msg: _,
            funds,
            label,
        }) = &res.messages[0].msg
        {
            assert_eq!(*admin, None);
            assert_eq!(*code_id, REFLECT_ID);
            assert_eq!(funds.len(), 0);
            assert!(label.contains(channel_id));
        } else {
            panic!("invalid return message: {:?}", res.messages[0]);
        }

        // no accounts set yet
        let raw = query(deps.as_ref(), mock_env(), QueryMsg::ListAccounts {}).unwrap();
        let res: ListAccountsResponse = from_slice(&raw).unwrap();
        assert_eq!(0, res.accounts.len());

        // fake a reply and ensure this works
        let response = Reply {
            id,
            result: SubMsgResult::Ok(SubMsgResponse {
                events: fake_events(REFLECT_ADDR),
                data: Some(fake_data(REFLECT_ADDR)),
            }),
        };
        reply(deps.as_mut(), mock_env(), response).unwrap();

        // ensure this is now registered
        let raw = query(deps.as_ref(), mock_env(), QueryMsg::ListAccounts {}).unwrap();
        let res: ListAccountsResponse = from_slice(&raw).unwrap();
        assert_eq!(1, res.accounts.len());
        assert_eq!(
            &res.accounts[0],
            &AccountInfo {
                account: REFLECT_ADDR.into(),
                channel_id: channel_id.to_string(),
            }
        );

        // and the account query also works
        let raw = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::Account {
                channel_id: channel_id.to_string(),
            },
        )
        .unwrap();
        let res: AccountResponse = from_slice(&raw).unwrap();
        assert_eq!(res.account.unwrap(), REFLECT_ADDR);
    }

    #[test]
    fn handle_dispatch_packet() {
        let mut deps = setup();

        let channel_id = "channel-123";
        let account = "acct-123";

        // receive a packet for an unregistered channel returns app-level error (not Result::Err)
        let msgs_to_dispatch = vec![BankMsg::Send {
            to_address: "my-friend".into(),
            amount: coins(123456789, "uatom"),
        }
        .into()];
        let ibc_msg = PacketMsg::Dispatch {
            msgs: msgs_to_dispatch.clone(),
        };
        let msg = mock_ibc_packet_recv(channel_id, &ibc_msg).unwrap();
        // this returns an error
        ibc_packet_receive(deps.as_mut(), mock_env(), msg).unwrap_err();

        // register the channel
        connect(deps.as_mut(), channel_id, account);

        // receive a packet for an unregistered channel returns app-level error (not Result::Err)
        let msg = mock_ibc_packet_recv(channel_id, &ibc_msg).unwrap();
        let res = ibc_packet_receive(deps.as_mut(), mock_env(), msg).unwrap();

        // assert app-level success
        let ack: StdAck = from_slice(&res.acknowledgement).unwrap();
        ack.unwrap();

        // and we dispatch the BankMsg via submessage
        assert_eq!(1, res.messages.len());
        assert_eq!(RECEIVE_DISPATCH_ID, res.messages[0].id);

        // parse the output, ensuring it matches
        if let CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr,
            msg,
            funds,
        }) = &res.messages[0].msg
        {
            assert_eq!(account, contract_addr.as_str());
            assert_eq!(0, funds.len());
            // parse the message - should callback with proper channel_id
            let rmsg: cw1_whitelist::msg::ExecuteMsg = from_slice(msg).unwrap();
            assert_eq!(
                rmsg,
                cw1_whitelist::msg::ExecuteMsg::Execute {
                    msgs: msgs_to_dispatch
                }
            );
        } else {
            panic!("invalid return message: {:?}", res.messages[0]);
        }

        // invalid packet format on registered channel also returns error
        let bad_data = InstantiateMsg {
            reflect_code_id: 12345,
        };
        let msg = mock_ibc_packet_recv(channel_id, &bad_data).unwrap();
        ibc_packet_receive(deps.as_mut(), mock_env(), msg).unwrap_err();
    }

    #[test]
    fn check_close_channel() {
        let mut deps = setup();

        let channel_id = "channel-123";
        let account = "acct-123";

        // register the channel
        connect(deps.as_mut(), channel_id, account);
        // assign it some funds
        let funds = vec![coin(123456, "uatom"), coin(7654321, "tgrd")];
        deps.querier.update_balance(account, funds.clone());

        // channel should be listed and have balance
        let raw = query(deps.as_ref(), mock_env(), QueryMsg::ListAccounts {}).unwrap();
        let res: ListAccountsResponse = from_slice(&raw).unwrap();
        assert_eq!(1, res.accounts.len());
        let balance = deps.as_ref().querier.query_all_balances(account).unwrap();
        assert_eq!(funds, balance);

        // close the channel
        let channel = mock_ibc_channel_close_init(channel_id, APP_ORDER, IBC_APP_VERSION);
        let res = ibc_channel_close(deps.as_mut(), mock_env(), channel).unwrap();

        // it pulls out all money from the reflect contract
        assert_eq!(1, res.messages.len());
        if let CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr, msg, ..
        }) = &res.messages[0].msg
        {
            assert_eq!(contract_addr.as_str(), account);
            let reflect: ReflectExecuteMsg = from_slice(msg).unwrap();
            match reflect {
                ReflectExecuteMsg::ReflectMsg { msgs } => {
                    assert_eq!(1, msgs.len());
                    assert_eq!(
                        &msgs[0],
                        &BankMsg::Send {
                            to_address: MOCK_CONTRACT_ADDR.into(),
                            amount: funds
                        }
                        .into()
                    )
                }
            }
        } else {
            panic!("Unexpected message: {:?}", &res.messages[0]);
        }

        // and removes the account lookup
        let raw = query(deps.as_ref(), mock_env(), QueryMsg::ListAccounts {}).unwrap();
        let res: ListAccountsResponse = from_slice(&raw).unwrap();
        assert_eq!(0, res.accounts.len());
    }
}
