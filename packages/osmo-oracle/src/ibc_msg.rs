use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{from_slice, to_binary, Binary, Decimal};

/// This is the message we send over the IBC channel
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PacketMsg {
    GetPrice {
        // token to sell
        input: String,
        // token to receive
        output: String,
        // the requester on controller side, for handling acks
        requester: String,
    },
}

/// Return the data field for each message
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct GetPriceResponse {
    pub spot_price: Decimal,
    pub spot_price_with_fee: Decimal,
}

/// This is a generic ICS acknowledgement format.
/// Proto defined here: https://github.com/cosmos/cosmos-sdk/blob/v0.42.0/proto/ibc/core/channel/v1/channel.proto#L141-L147
/// If ibc_receive_packet returns Err(), then x/wasm runtime will rollback the state and return an error message in this format
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StdAck {
    Result(Binary),
    Error(String),
}

impl StdAck {
    // create a serialized success message
    pub fn success(data: impl Serialize) -> Binary {
        let res = to_binary(&data).unwrap();
        StdAck::Result(res).ack()
    }

    // create a serialized error message
    pub fn fail(err: String) -> Binary {
        StdAck::Error(err).ack()
    }

    pub fn ack(&self) -> Binary {
        to_binary(self).unwrap()
    }

    pub fn unwrap(self) -> Binary {
        match self {
            StdAck::Result(data) => data,
            StdAck::Error(err) => panic!("{}", err),
        }
    }

    pub fn unwrap_into<T: DeserializeOwned>(self) -> T {
        from_slice(&self.unwrap()).unwrap()
    }

    pub fn unwrap_err(self) -> String {
        match self {
            StdAck::Result(_) => panic!("not an error"),
            StdAck::Error(err) => err,
        }
    }
}
