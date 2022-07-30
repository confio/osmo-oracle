use std::env::current_dir;
use std::fs::create_dir_all;

use cosmwasm_schema::{export_schema, remove_schemas, schema_for};

use osmo_oracle::{GetPriceResponse, PacketMsg, StdAck};

fn main() {
    let mut out_dir = current_dir().unwrap();
    out_dir.push("schema");
    create_dir_all(&out_dir).unwrap();
    remove_schemas(&out_dir).unwrap();

    export_schema(&schema_for!(PacketMsg), &out_dir);
    export_schema(&schema_for!(StdAck), &out_dir);
    export_schema(&schema_for!(GetPriceResponse), &out_dir);
}
