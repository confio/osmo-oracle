# IBC Osmosis Oracle

Forked from `cw-ibc-demo`

This is asymetrical contracts.

Osmosis side contains registry of token pairs to swap paths. It handles incoming queries
in the type of `{"input": "ujuno", "output": "uosmo"}`. It then figures out how to query
the spot price or return error if not in registry. This can map to ibc names, so like:

```json
{
  "pool_id": 123,
  "input": "ibc/19879867986af097ea8b0d7d",
  "output": "uosmo"
}
```

It allows you to provide sensible names to the remote client and one DAO configuires the mapping on Osmosis.

It currently returns spot price. It will return TWAP in the future when that is exposed in Osmosis.
