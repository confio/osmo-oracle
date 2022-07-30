use cosmwasm_std::{
    entry_point, from_slice, to_binary, Deps, DepsMut, Env, Ibc3ChannelOpenResponse,
    IbcBasicResponse, IbcChannelCloseMsg, IbcChannelConnectMsg, IbcChannelOpenMsg,
    IbcChannelOpenResponse, IbcPacketAckMsg, IbcPacketReceiveMsg, IbcPacketTimeoutMsg,
    IbcReceiveResponse, MessageInfo, Order, QueryRequest, QueryResponse, Response, StdResult,
};
use cw_utils::nonpayable;
use osmo_bindings::{OsmosisQuery, SpotPriceResponse, Swap};
use osmo_oracle::{
    check_order, check_version, GetPriceResponse, PacketMsg, StdAck, IBC_APP_VERSION,
};

use crate::error::ContractError;
use crate::msg::{
    ExecuteMsg, InstantiateMsg, ListRouteResponse, QueryMsg, RouteInfo, RouteResponse,
};
use crate::state::{ADMIN, ROUTES};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    ADMIN.save(deps.storage, &info.sender)?;
    Ok(Response::new())
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    nonpayable(&info)?;
    // only open to admin
    if ADMIN.load(deps.storage)? != info.sender {
        return Err(ContractError::Unauthorized);
    }

    // process message
    match msg {
        ExecuteMsg::RegisterRoute {
            input,
            output,
            route,
        } => register_route(deps, input, output, route),
        ExecuteMsg::UnregisterRoute { input, output } => unregister_route(deps, input, output),
    }
}

pub fn register_route(
    deps: DepsMut,
    input: String,
    output: String,
    route: Swap,
) -> Result<Response, ContractError> {
    ROUTES.save(deps.storage, (&input, &output), &route)?;
    Ok(Response::new())
}

pub fn unregister_route(
    deps: DepsMut,
    input: String,
    output: String,
) -> Result<Response, ContractError> {
    ROUTES.remove(deps.storage, (&input, &output));
    Ok(Response::new())
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<QueryResponse> {
    match msg {
        QueryMsg::Route { input, output } => to_binary(&query_route(deps, input, output)?),
        QueryMsg::ListRoutes {} => to_binary(&query_list_routes(deps)?),
    }
}

pub fn query_route(deps: Deps, input: String, output: String) -> StdResult<RouteResponse> {
    let route = ROUTES.may_load(deps.storage, (&input, &output))?;
    Ok(RouteResponse { route })
}

pub fn query_list_routes(deps: Deps) -> StdResult<ListRouteResponse> {
    let routes = ROUTES
        .range(deps.storage, None, None, Order::Ascending)
        .map(|item| {
            let ((input, output), route) = item?;
            Ok(RouteInfo {
                input,
                output,
                route,
            })
        })
        .collect::<StdResult<_>>()?;
    Ok(ListRouteResponse { routes })
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
// nothing special on connect
pub fn ibc_channel_connect(
    _deps: DepsMut,
    _env: Env,
    msg: IbcChannelConnectMsg,
) -> Result<IbcBasicResponse, ContractError> {
    let channel = msg.channel();
    check_order(&channel.order)?;
    // In ibcv3 we don't check the version string passed in the message
    // and only check the counterparty version.
    if let Some(counter_version) = msg.counterparty_version() {
        check_version(counter_version)?;
    }
    Ok(IbcBasicResponse::new())
}

#[entry_point]
pub fn ibc_channel_close(
    _deps: DepsMut,
    _env: Env,
    _msg: IbcChannelCloseMsg,
) -> StdResult<IbcBasicResponse> {
    Ok(IbcBasicResponse::new())
}

#[entry_point]
/// we look for a the proper reflect contract to relay to and send the message
/// We cannot return any meaningful response value as we do not know the response value
/// of execution. We just return ok if we dispatched, error if we failed to dispatch
pub fn ibc_packet_receive(
    deps: DepsMut<OsmosisQuery>,
    _env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, ContractError> {
    let packet = msg.packet;
    let msg: PacketMsg = from_slice(&packet.data)?;
    match msg {
        PacketMsg::GetPrice { input, output, .. } => receive_get_price(deps, input, output),
    }
}

fn receive_get_price(
    deps: DepsMut<OsmosisQuery>,
    input: String,
    output: String,
) -> Result<IbcReceiveResponse, ContractError> {
    let swap = ROUTES
        .load(deps.storage, (&input, &output))
        .map_err(|_| ContractError::NoRoute)?;

    let query = OsmosisQuery::SpotPrice {
        swap: swap.clone(),
        with_swap_fee: false,
    };
    let swap_price: SpotPriceResponse = deps.querier.query(&QueryRequest::Custom(query))?;

    let query = OsmosisQuery::SpotPrice {
        swap,
        with_swap_fee: true,
    };
    let swap_price_with_fee: SpotPriceResponse =
        deps.querier.query(&QueryRequest::Custom(query))?;

    let result = GetPriceResponse {
        spot_price: swap_price.price,
        spot_price_with_fee: swap_price_with_fee.price,
    };
    let ack = StdAck::success(&result);
    Ok(IbcReceiveResponse::new().set_ack(ack))
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
