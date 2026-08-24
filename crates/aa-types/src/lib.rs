use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

#[derive(Debug,Clone,Serialize,Deserialize)]
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
}