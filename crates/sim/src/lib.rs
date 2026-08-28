/*
 * GhostBundler sim crate
 *
 * Given a UserOp, several checks concurrently:
 *   1. Estimate gas for the handleOps call
 *   2. Simulate validateUserOp (eth_call, no state change)
 *   3. Return a normalised SimOutcome
 */

use aa_types::PackedUserOperation;
use alloy_primitives::{Address, Bytes};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{SolCall, SolError, sol};
use serde::{Deserialize, Serialize};

// ── ABI helpers ──────────────────────────────────────────────────────
sol! {
    struct Sop {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
        bytes signature;
    }

    function handleOps(Sop[] calldata ops, address payable beneficiary) external;

    error FailedOp(uint256 opIndex, string reason);
    error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner);
}

// ── Public types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SimOutcome {
    Success,
    AccountError { reason: String },
    PaymasterError { reason: String },
    Unknown { raw: String },
}

#[derive(Debug, Clone)]
pub struct SimConfig {
    pub rpc_url: String,
    pub entry_point: Address,
    pub account: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub gas_estimate: Option<u64>,
    pub validation: SimOutcome,
}

// ── Internal helpers ─────────────────────────────────────────────────

fn pack_user_op(op: &PackedUserOperation) -> Sop {
    Sop {
        sender: op.sender,
        nonce: op.nonce,
        initCode: op.init_code.clone(),
        callData: op.call_data.clone(),
        accountGasLimits: op.account_gas_limits,
        preVerificationGas: op.pre_verification_gas,
        gasFees: op.gas_fees,
        paymasterAndData: op.paymaster_and_data.clone(),
        signature: op.signature.clone(),
    }
}

fn encode_handle_ops(ops: &[PackedUserOperation], beneficiary: Address) -> Bytes {
    let sops: Vec<Sop> = ops.iter().map(pack_user_op).collect();
    Bytes::from(
        handleOpsCall {
            ops: sops,
            beneficiary,
        }
        .abi_encode(),
    )
}

fn classify_revert(revert_data: &[u8]) -> SimOutcome {
    if let Ok(err) = FailedOp::abi_decode(revert_data) {
        let reason = err.reason;
        if reason.starts_with("AA2") || reason.starts_with("AA1") {
            return SimOutcome::AccountError {
                reason: format!("opIndex={}: {}", err.opIndex, reason),
            };
        }
        if reason.starts_with("AA3") {
            return SimOutcome::PaymasterError {
                reason: format!("opIndex={}: {}", err.opIndex, reason),
            };
        }
        return SimOutcome::AccountError {
            reason: format!("opIndex={}: {}", err.opIndex, reason),
        };
    }

    if let Ok(err) = FailedOpWithRevert::abi_decode(revert_data) {
        let reason = err.reason;
        let inner_hex = format!("0x{}", hex::encode(&err.inner));
        if reason.starts_with("AA2") || reason.starts_with("AA1") {
            return SimOutcome::AccountError {
                reason: format!("opIndex={}: {} (inner: {})", err.opIndex, reason, inner_hex),
            };
        }
        if reason.starts_with("AA3") {
            return SimOutcome::PaymasterError {
                reason: format!("opIndex={}: {} (inner: {})", err.opIndex, reason, inner_hex),
            };
        }
        return SimOutcome::AccountError {
            reason: format!("opIndex={}: {} (inner: {})", err.opIndex, reason, inner_hex),
        };
    }

    SimOutcome::Unknown {
        raw: format!("revert_data: 0x{}", hex::encode(revert_data)),
    }
}

// ── Public functions ─────────────────────────────────────────────────

/// Estimate gas for `handleOps` containing the given UserOps.
pub async fn simulate_gas_estimate(
    config: &SimConfig,
    ops: &[PackedUserOperation],
    beneficiary: Address,
) -> anyhow::Result<u64> {
    let provider = ProviderBuilder::new().connect_http(config.rpc_url.parse()?);
    let calldata = encode_handle_ops(ops, beneficiary);
    let tx = TransactionRequest::default()
        .to(config.entry_point)
        .input(alloy_rpc_types_eth::TransactionInput::new(calldata));
    let gas = provider.estimate_gas(tx).latest().await?;
    Ok(gas)
}

/// Simulate `handleOps` via static `eth_call` (no state changes).
///
/// Returns `SimOutcome::Success` if the EntryPoint accepts the UserOp,
/// or a categorised error if it reverts.
pub async fn simulate_validation(
    config: &SimConfig,
    ops: &[PackedUserOperation],
    beneficiary: Address,
) -> anyhow::Result<SimOutcome> {
    let provider = ProviderBuilder::new().connect_http(config.rpc_url.parse()?);
    let calldata = encode_handle_ops(ops, beneficiary);
    let tx = TransactionRequest::default()
        .to(config.entry_point)
        .input(alloy_rpc_types_eth::TransactionInput::new(calldata));

    match provider.call(tx).latest().await {
        Ok(_bytes) => Ok(SimOutcome::Success),
        Err(e) => {
            let msg = e.to_string();
            // alloy reports transport errors as strings; try to extract the revert data
            // Try both formats: `data="0x..."` and `data: "0x..."`
            let hex_str = msg
                .find("data:")
                .or_else(|| msg.find("data="))
                .and_then(|start| {
                    let rest = &msg[start + 5..];
                    // skip optional colon+space
                    let rest = rest.trim_start_matches(|c| c == ':' || c == ' ');
                    if rest.starts_with("\"0x") {
                        let data_start = 3; // skip "0x
                        if let Some(end) = rest[data_start..].find('"') {
                            return Some(&rest[data_start..data_start + end]);
                        }
                    }
                    None
                });
            if let Some(hex_str) = hex_str {
                if let Ok(bytes) = hex::decode(hex_str) {
                    eprintln!("DEBUG classify_revert: data len={}, data={}", bytes.len(), hex_str);
                    return Ok(classify_revert(&bytes));
                }
            }
            Ok(SimOutcome::Unknown { raw: msg })
        }
    }
}

/// Run both simulations concurrently.
pub async fn run_simulation(
    config: &SimConfig,
    ops: Vec<PackedUserOperation>,
    beneficiary: Address,
) -> anyhow::Result<SimulationResult> {
    let (gas_result, validation_result) = tokio::join!(
        simulate_gas_estimate(config, &ops, beneficiary),
        simulate_validation(config, &ops, beneficiary),
    );

    Ok(SimulationResult {
        gas_estimate: gas_result.ok(),
        validation: validation_result?,
    })
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::FixedBytes;

    #[test]
    fn classify_account_error() {
        let data = FailedOp {
            opIndex: U256::ZERO,
            reason: "AA23 reverted".into(),
        }
        .abi_encode();
        let outcome = classify_revert(&data);
        match outcome {
            SimOutcome::AccountError { reason } => {
                assert!(reason.contains("AA23"));
            }
            _ => panic!("Expected AccountError, got {:?}", outcome),
        }
    }

    #[test]
    fn classify_paymaster_error() {
        let data = FailedOp {
            opIndex: U256::ZERO,
            reason: "AA31 paymaster deposit too low".into(),
        }
        .abi_encode();
        let outcome = classify_revert(&data);
        match outcome {
            SimOutcome::PaymasterError { reason } => {
                assert!(reason.contains("AA31"));
            }
            _ => panic!("Expected PaymasterError, got {:?}", outcome),
        }
    }

    #[test]
    fn classify_unknown_error() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let outcome = classify_revert(&data);
        assert!(matches!(outcome, SimOutcome::Unknown { .. }));
    }

    #[test]
    fn encode_handle_ops_produces_valid_selector() {
        let op = PackedUserOperation {
            sender: Address::repeat_byte(0xAA),
            nonce: U256::from(1),
            init_code: Bytes::new(),
            call_data: Bytes::from(vec![0xb6, 0x1d, 0x27, 0xf6]),
            account_gas_limits: FixedBytes::repeat_byte(0x01),
            pre_verification_gas: U256::from(21000),
            gas_fees: FixedBytes::repeat_byte(0x01),
            paymaster_and_data: Bytes::new(),
            signature: Bytes::new(),
        };
        let calldata = encode_handle_ops(&[op], Address::repeat_byte(0xBB));
        let expected_sel = handleOpsCall::SELECTOR;
        assert_eq!(&calldata[..4], &expected_sel);
    }

    #[tokio::test]
    async fn integration_anvil_needed() {
        use std::net::TcpStream;
        let reachable = TcpStream::connect("127.0.0.1:8545").is_ok();
        if !reachable {
            eprintln!("Skipping Anvil integration test — no node on :8545");
            return;
        }
        let config = SimConfig {
            rpc_url: "http://127.0.0.1:8545".into(),
            entry_point: "0x5FbDB2315678afecb367f032d93F642f64180aa3"
                .parse()
                .unwrap(),
            account: "0x192b0600c00a60a2B3Bee06bCe4eBe3e45A9c129"
                .parse()
                .unwrap(),
        };
        let gas = simulate_gas_estimate(&config, &[], Address::repeat_byte(0xBB)).await;
        assert!(gas.is_err(), "expected error for empty ops on Anvil");
    }
}
