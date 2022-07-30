use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};
use osmo_bindings::Swap;

pub const ADMIN: Item<Addr> = Item::new("admin");
pub const ROUTES: Map<(&str, &str), Swap> = Map::new("routes");

// note: we allow many channels to the host and treat them equally
