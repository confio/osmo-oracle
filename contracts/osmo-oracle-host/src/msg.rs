use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use osmo_bindings::Swap;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Registers a new route for a pair
    RegisterRoute {
        input: String,
        output: String,
        route: Swap,
    },
    /// Removes previously registered route
    UnregisterRoute { input: String, output: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Route { input: String, output: String },
    // TODO: pagination
    ListRoutes {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct RouteResponse {
    pub route: Option<Swap>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ListRouteResponse {
    pub routes: Vec<RouteInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct RouteInfo {
    pub input: String,
    pub output: String,
    pub route: Swap,
}
