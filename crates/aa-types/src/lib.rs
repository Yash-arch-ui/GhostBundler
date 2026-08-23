use serde::{Deserialize, Serialize};
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackedUserOperation {
pub sender: String,
pub nonce: String,
pub init_code:String, 
pub call_data: String,
pub account_gas_limits: String,
pub pre_verification_gas: String,
pub gas_fees: String, 
pub paymaster_and_data: String,
pub signature: String,
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn serialize_and_deserialize(){
        let op = PackedUserOperation{
            sender: "0x1234567890123456789012345678901234567890".into(), // 20-byte address
            nonce: "0x1".into(),
            init_code: "0x".into(), // empty bytes
            call_data: "0xdeadbeef".into(), // arbitrary bytes
            account_gas_limits: "0x00000000000000000000000000000000000000000000000000000000000186a0".into(), // 32-byte packed
            pre_verification_gas: "0x5208".into(), // 21000 in hex
            gas_fees: "0x0000000000000000000000000000000000000000000000000000000000000000".into(), // 32-byte packed
            paymaster_and_data: "0x".into(), // empty bytes
            signature: "0x1234".into(), // arbitrary bytes
        };
        let json = serde_json::to_string(&op).unwrap();
        let back: PackedUserOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(op.sender, back.sender);
        assert_eq!(op.account_gas_limits, back.account_gas_limits);
    }
}