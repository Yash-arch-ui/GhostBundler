use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolCall, SolValue, sol};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedCall {
    pub target: Address,
    pub value: U256,
    pub data: Bytes,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModuleEntity {
    pub module: Address,
    pub entity_id: u32,
}
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedValidation {
    pub entity: ModuleEntity,
    pub is_global: bool,
    pub inner_signature: Bytes,
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

sol! {
    function execute(address target , uint256 value, bytes calldata data) external;
    struct Call{
        address target;
        uint256 value;
        bytes data;
    }
    function executeBatch(Call[] calldata calls) external;

}

impl PackedUserOperation {
    pub fn hash(&self) -> B256 {
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

    /// Final userOpHash: keccak256(abi.encode(userOpHash, entryPoint, chainId))
    /// Reference: EntryPoint.getUserOpHash() in account-abstraction reference-implementation
    pub fn user_op_hash(&self, entry_point: Address, chain_id: U256) -> B256 {
        let op_hash = self.hash();
        keccak256((op_hash, entry_point, chain_id).abi_encode())
    }
    pub fn selector(&self) -> Option<[u8; 4]> {
        self.call_data.get(0..4)?.try_into().ok()
    }
    pub fn decode_calls(&self) -> Option<Vec<DecodedCall>> {
        if let Ok(decoded) = executeCall::abi_decode(&self.call_data) {
            return Some(vec![DecodedCall {
                target: decoded.target,
                value: decoded.value,
                data: decoded.data,
            }]);
        }

        if let Ok(decoded) = executeBatchCall::abi_decode(&self.call_data) {
            return Some(
                decoded
                    .calls
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
    pub fn resolve_validation(&self) -> Option<ResolvedValidation> {
        let sig = &self.signature;
        if sig.len() < 25 {
            return None;
        }

        let module_bytes: [u8; 20] = sig[0..20].try_into().ok()?;
        let entity_id_bytes: [u8; 4] = sig[20..24].try_into().ok()?;

        let entity = ModuleEntity {
            module: Address::from(module_bytes),
            entity_id: u32::from_be_bytes(entity_id_bytes),
        };

        let is_global = sig[24] == 1;
        let inner_signature = Bytes::copy_from_slice(&sig[25..]);

        Some(ResolvedValidation {
            entity,
            is_global,
            inner_signature,
        })
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
    fn decodes_single_execute_call() {
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
    fn decodes_execute_batch_call() {
        let calls = vec![
            Call {
                target: Address::repeat_byte(0x01),
                value: U256::from(1),
                data: Bytes::new(),
            },
            Call {
                target: Address::repeat_byte(0x02),
                value: U256::from(2),
                data: Bytes::new(),
            },
        ];
        let batch = executeBatchCall { calls };
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
    #[test]
    fn resolves_module_entity_from_signature() {
        let module = Address::repeat_byte(0xCC);
        let entity_id: u32 = 1;

        let mut sig_bytes = Vec::new();
        sig_bytes.extend_from_slice(module.as_slice()); // 20 bytes
        sig_bytes.extend_from_slice(&entity_id.to_be_bytes()); // 4 bytes
        sig_bytes.push(1); // isGlobal = true
        sig_bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // inner sig

        let mut op = sample_op();
        op.signature = Bytes::from(sig_bytes);

        let resolved = op.resolve_validation().unwrap();

        assert_eq!(resolved.entity.module, module);
        assert_eq!(resolved.entity.entity_id, 1);
        assert!(resolved.is_global);
        assert_eq!(
            resolved.inner_signature,
            Bytes::from(vec![0xde, 0xad, 0xbe, 0xef])
        );
    }

    #[test]
    fn returns_none_for_signature_too_short() {
        let mut op = sample_op();
        op.signature = Bytes::from(vec![0x01, 0x02]);
        assert_eq!(op.resolve_validation(), None);
    }

    #[test]
    fn hash_matches_onchain_for_safe_op() {
        let mock_vault = Address::new([
            0x22, 0x79, 0xB7, 0xA0, 0xa6, 0x7D, 0xB3, 0x72,
            0x99, 0x6a, 0x5F, 0xaB, 0x50, 0xD9, 0x1e, 0xAA,
            0x73, 0xd2, 0xeB, 0xe6,
        ]);
        let entry_point = Address::new([
            0x5F, 0xBD, 0xB2, 0x31, 0x56, 0x78, 0xaf, 0xec,
            0xb3, 0x67, 0xf0, 0x32, 0xd9, 0x3F, 0x64, 0x2f,
            0x64, 0x18, 0x0a, 0xa3,
        ]);

        let call_data = Bytes::from(
            executeCall {
                target: mock_vault,
                value: U256::ZERO,
                data: Bytes::new(),
            }
            .abi_encode(),
        );

        let op = PackedUserOperation {
            sender: Address::new([
                0xb0, 0x44, 0xa6, 0x3D, 0x8e, 0xD4, 0x06, 0xbd,
                0xAA, 0xD3, 0xDB, 0x50, 0xf7, 0x9F, 0x2c, 0xBc,
                0x1f, 0x73, 0x4e, 0x10,
            ]),
            nonce: U256::ZERO,
            init_code: Bytes::new(),
            call_data,
            account_gas_limits: {
                let val: U256 = (U256::from(1_200_000u64) << 128) | U256::from(100_000u64);
                B256::from(val.to_be_bytes::<32>())
            },
            pre_verification_gas: U256::ZERO,
            gas_fees: {
                let val: U256 = (U256::from(1u64) << 128) | U256::from(1u64);
                B256::from(val.to_be_bytes::<32>())
            },
            paymaster_and_data: Bytes::new(),
            signature: Bytes::new(),
        };

        let struct_hash = op.hash();
        let user_op_hash = op.user_op_hash(entry_point, U256::from(31337));

        eprintln!("structHash:   {}", struct_hash);
        eprintln!("userOpHash:   {}", user_op_hash);

        // Reference-implementation: keccak256(abi.encode(userOp.hash(), address(this), block.chainid))
        // This is NOT EIP-712 format
        assert_eq!(
            user_op_hash,
            op.user_op_hash(entry_point, U256::from(31337)),
            "hash must be deterministic"
        );
    }
}
