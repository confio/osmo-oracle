use cw_storage_plus::{Item, Map};

use crate::msg::LastPriceResponse;

// key is (input, output)
pub const LAST_PRICE: Map<(&str, &str), LastPriceResponse> = Map::new("last_price");
// we only store one channel, ensure exactly one handshake then use that for all queries
pub const CHANNEL: Item<String> = Item::new("channel");
