use cosmwasm_std::{
    entry_point, from_slice, to_binary, Env, Ibc3ChannelOpenResponse, IbcBasicResponse,
    IbcChannelCloseMsg, IbcChannelConnectMsg, IbcChannelOpenMsg, IbcChannelOpenResponse,
    IbcPacketAckMsg, IbcPacketReceiveMsg, IbcPacketTimeoutMsg, IbcReceiveResponse, MessageInfo,
    Order, QueryRequest, QueryResponse, Response, StdResult,
};
use cw_utils::nonpayable;
use osmo_bindings::{OsmosisQuery, SpotPriceResponse, Swap};
use osmo_oracle::{
    check_order, check_version, GetPriceResponse, PacketMsg, StdAck, IBC_APP_VERSION,
};

use crate::error::ContractError;
use crate::msg::{
    AdminResponse, ExecuteMsg, InstantiateMsg, ListRouteResponse, QueryMsg, RouteInfo,
    RouteResponse,
};
use crate::state::{ADMIN, ROUTES};

type Deps<'a> = cosmwasm_std::Deps<'a, OsmosisQuery>;
type DepsMut<'a> = cosmwasm_std::DepsMut<'a, OsmosisQuery>;

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
        QueryMsg::Admin {} => to_binary(&query_admin(deps)?),
        QueryMsg::Route { input, output } => to_binary(&query_route(deps, input, output)?),
        QueryMsg::ListRoutes {} => to_binary(&query_list_routes(deps)?),
    }
}

pub fn query_admin(deps: Deps) -> StdResult<AdminResponse> {
    let admin = ADMIN.load(deps.storage)?.into_string();
    Ok(AdminResponse { admin })
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
    deps: DepsMut,
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
    deps: DepsMut,
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
        mock_env, mock_ibc_channel_connect_ack, mock_ibc_channel_open_init,
        mock_ibc_channel_open_try, mock_ibc_packet_recv, mock_info, MockApi, MockQuerier,
        MockStorage,
    };
    use cosmwasm_std::OwnedDeps;
    use osmo_oracle::{APP_ORDER, BAD_APP_ORDER};
    use std::marker::PhantomData;

    const CREATOR: &str = "creator";

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier, OsmosisQuery> {
        let mut deps = OwnedDeps {
            storage: MockStorage::default(),
            api: MockApi::default(),
            querier: MockQuerier::default(),
            custom_query_type: PhantomData,
        };
        let msg = InstantiateMsg {};
        let info = mock_info(CREATOR, &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
        deps
    }

    #[test]
    fn instantiate_works() {
        let mut deps = OwnedDeps {
            storage: MockStorage::default(),
            api: MockApi::default(),
            querier: MockQuerier::default(),
            custom_query_type: PhantomData,
        };

        let msg = InstantiateMsg {};
        let info = mock_info("creator", &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // admin set
        let admin = query_admin(deps.as_ref()).unwrap();
        assert_eq!(admin.admin, "creator".to_string());
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
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn register_routes() {
        let mut deps = setup();

        let input = "ujuno";
        let output = "uosmo";
        let route = Swap {
            pool_id: 17,
            denom_in: "ibc/128jf83hf9823h98gh3289ghw498ghw498gh89".to_string(),
            denom_out: "uosmo".to_string(),
        };

        // random cannot set this
        let msg = ExecuteMsg::RegisterRoute {
            input: input.to_string(),
            output: output.to_string(),
            route: route.clone(),
        };
        let err = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("random", &[]),
            msg.clone(),
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized);

        // admin sets this
        execute(deps.as_mut(), mock_env(), mock_info(CREATOR, &[]), msg).unwrap();

        // check list
        let routes = query_list_routes(deps.as_ref()).unwrap();
        assert_eq!(routes.routes.len(), 1);

        // check hit
        let res = query_route(deps.as_ref(), input.to_string(), output.to_string()).unwrap();
        assert_eq!(res.route, Some(route));

        // check miss
        let res = query_route(deps.as_ref(), input.to_string(), "uatom".to_string()).unwrap();
        assert_eq!(res.route, None);
    }

    #[test]
    fn handle_get_price_packet() {
        let mut deps = setup();

        let channel_id = "channel-123";

        // set route
        let input = "uatom";
        let output = "uosmo";
        let route = Swap {
            pool_id: 17,
            denom_in: "ibc/532532t353535432532532".to_string(),
            denom_out: "uosmo".to_string(),
        };
        register_route(deps.as_mut(), input.to_string(), output.to_string(), route).unwrap();

        let ibc_msg = PacketMsg::GetPrice {
            input: input.to_string(),
            output: "uregen".to_string(),
            requester: Some("someone".to_string()),
        };
        let msg = mock_ibc_packet_recv(channel_id, &ibc_msg).unwrap();
        // this returns an error as missing route
        let err = ibc_packet_receive(deps.as_mut(), mock_env(), msg).unwrap_err();
        assert_eq!(err, ContractError::NoRoute);

        // TODO: we want to check success, but no mocks for osmosis query
    }
}
