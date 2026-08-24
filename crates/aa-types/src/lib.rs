use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolCall, SolValue};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedCall{
    pub target : Address,
    pub value: U256,
    pub data: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackedUserOperation {
pub sender: Address,
pub nonce: U256,
pub init_code: Bytes, 
pub call_data: Bytes,
pub account_gas_limits: B256,
pub pre_verification_gas: U256,
pub gas_fees: B256, 
pub paymaster_and_data: Bytes,
pub signature: Bytes,
}

sol!{
    function execute(address target , uint256 value, bytes calldata data) external;
    struct Call{
        address target;
        uint256 value;
        bytes data;
    }
    function executeBatch(Call[] calldata calls) external;

}

impl PackedUserOperation{
    pub fn hash(&self) -> B256{
        let init_code_hash = keccak256(&self.init_code);
        let call_data_hash = keccak256(&self.call_data);
        let paymaster_and_data_hash = keccak256(&self.paymaster_and_data);

        let encoded = (
            self.sender,
            self.nonce,
            init_code_hash,
            call_data_hash,
            self.account_gas_limits,
            self.pre_verification_gas,
            self.gas_fees,
            paymaster_and_data_hash,
        )
            .abi_encode();

        keccak256(encoded)
    }

    /// Final userOpHash: binds the op hash to entryPoint + chaindId(replay Protection)
    pub fn user_op_hash(&self, entry_point: Address , chain_id: U256) -> B256 {
        let op_hash = self.hash();
        let encoded = (op_hash, entry_point, chain_id).abi_encode();
        keccak256(encoded)
    }
    pub fn selector(&self) -> Option<[u8; 4]> {
        self.call_data.get(0..4)?.try_into().ok()
    }
    pub fn decode_calls(&self) -> Option<Vec<DecodedCall>>{
        if let Ok(decoded) = executeCall::abi_decode(&self.call_data){
            return Some(vec![DecodedCall{
                target: decoded.target,
                value: decoded.value,
                data: decoded.data,
            }]);
        }

        if let Ok(decoded) = executeBatchCall::abi_decode(&self.call_data) {
            return Some(
                decoded.calls
                .into_iter()
                .map(|c| DecodedCall {
                    target: c.target,
                    value: c.value,
                    data: c.data,
                })
                .collect(),
            );
        }

        None
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_op() -> PackedUserOperation {
        PackedUserOperation {
            sender: Address::ZERO,
            nonce: U256::from(0),
            init_code: Bytes::new(),
            call_data: Bytes::new(),
            account_gas_limits: B256::ZERO,
            pre_verification_gas: U256::from(21000),
            gas_fees: B256::ZERO,
            paymaster_and_data: Bytes::new(),
            signature: Bytes::new(),
        }
    }
    #[test]
        fn decodes_single_execute_call(){
        let call = executeCall {
            target: Address::repeat_byte(0xAA),
            value: U256::from(100),
            data: Bytes::from(vec![0x12, 0x34]),
        };
        let mut op = sample_op();
         op.call_data = Bytes::from(call.abi_encode());
        let decoded = op.decode_calls().unwrap();
        assert_eq!(decoded[0].target, Address::repeat_byte(0xAA));
        assert_eq!(decoded[0].value, U256::from(100));

    }
   
    #[test]
    fn decodes_execute_batch_call(){
        let calls = vec![
            Call{ target: Address::repeat_byte(0x01), value: U256::from(1), data:Bytes::new()},
            Call{ target: Address::repeat_byte(0x02), value: U256::from(2), data:Bytes::new()},

        ];
        let batch = executeBatchCall{calls};
        let mut op = sample_op();
        op.call_data = Bytes::from(batch.abi_encode());
        let decoded = op.decode_calls().unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[1].target, Address::repeat_byte(0x02));
    }
    #[test]
    fn serializes_and_deserializes() {
        let op = sample_op();
        let json = serde_json::to_string(&op).unwrap();
        let back: PackedUserOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(op.sender, back.sender);
    }

    #[test]
    fn hash_is_deterministic() {
        let op = sample_op();
        let h1 = op.hash();
        let h2 = op.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn user_op_hash_changes_with_chain_id() {
        let op = sample_op();
        let entry_point = Address::ZERO;
        let hash_chain_1 = op.user_op_hash(entry_point, U256::from(1));
        let hash_chain_2 = op.user_op_hash(entry_point, U256::from(2));
        assert_ne!(hash_chain_1, hash_chain_2);
    }
    #[test]
    fn extracts_selector_from_execute_calldata() {
        // First 4 bytes = selector, rest is padding (doesn't matter for this test)
        let call_data = Bytes::from(vec![0xb6, 0x1d, 0x27, 0xf6, 0x00, 0x00, 0x00, 0x00]);
        let mut op = sample_op();
        op.call_data = call_data;
        let selector = op.selector();
        assert_eq!(selector, Some([0xb6, 0x1d, 0x27, 0xf6]));
    }

    #[test]
    fn returns_none_when_calldata_too_short() {
        let mut op = sample_op();
        op.call_data = Bytes::from(vec![0x01, 0x02]); // only 2 bytes, not enough
        assert_eq!(op.selector(), None);
    }
}
