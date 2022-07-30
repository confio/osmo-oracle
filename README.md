# IBC Osmosis Oracle

Forked from `cw-ibc-demo`

This is asymetrical contracts.

Osmosis side contains registry of token pairs to swap paths. It handles incoming queries
in the type of `{"input": "ujuno", "output": "uosmo"}`. It then figures out how to query
the spot price or return error if not in registry.

It currently returns spot price. It will return TWAP in the future when that is exposed in Osmosis.
