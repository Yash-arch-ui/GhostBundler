use aa_types::PackedUserOperation;
use policy::AuthorityGraph;
use sim::{SimConfig, run_simulation, SimOutcome};
use permit::{RiskPermit, PermitSigner};
use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::OnceLock;
use alloy_primitives::{Address, U256, keccak256};

// ---------------------------------------------------------------------------
// FIX #1 — Real GhostBundler permit-signer key (Anvil key #2)
// ---------------------------------------------------------------------------
// This is the private key whose corresponding address matches RiskGate.sol's
// PERMIT_SIGNER constant (0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC).
// OnceLock ensures we decode + construct the signer exactly once, not per-request.
fn permit_signer() -> &'static PermitSigner {
    static SIGNER: OnceLock<PermitSigner> = OnceLock::new();
    SIGNER.get_or_init(|| {
        let key_bytes: [u8; 32] = hex::decode(
            "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
        )
        .expect("valid hex")
        .try_into()
        .expect("32-byte key");
        PermitSigner::new(key_bytes).expect("valid secp256k1 key")
    })
}

// ---------------------------------------------------------------------------
// FIX #2 — RiskGate's deployed address (NOT the ERC-4337 EntryPoint)
// ---------------------------------------------------------------------------
// RiskGate.sol preUserOpValidationHook computes the permit digest using
// `address(this)` — its OWN address, not EntryPoint's. The Rust signing
// code must match: entry_point in RiskPermit = RiskGate's address.
//
// Deployed by Deploy.s.sol as the 6th contract (nonce 5) from the Anvil
// deployer (0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266).
const RISK_GATE_ADDRESS: Address = Address::new([
    0x01, 0x65, 0x87, 0x8A, 0x59, 0x4c, 0xa2, 0x55,
    0x33, 0x8a, 0xdf, 0xa4, 0xd4, 0x84, 0x49, 0xf6,
    0x92, 0x42, 0xEB, 0x8F,
]);

// ---------------------------------------------------------------------------
// FIX #3 — Real selector for MockVault::drain(address)
// ---------------------------------------------------------------------------
// Computed as bytes4(keccak256("drain(address)")) = 0xece53132
const DRAIN_SELECTOR: [u8; 4] = 0xece53132_u32.to_be_bytes();

#[derive(Deserialize, Serialize)]
// the request shape
struct PreFlightRequest {
    user_op: PackedUserOperation,
    beneficiary: Address,
}
/* The Request Shape -> beneficiary is the address that would receive leftover gas refunds in handleOps
- required by the ERC 4337 function signature , so the caller has to supply it . */

// The response shape
#[derive(Debug, Serialize)]
struct PreFlightResponse {
    verdict: String,
    findings: Vec<String>,
    gas_estimate: Option<u64>,
    permit_issued: bool,
    permit_signature: Option<String>,
}
// WHAT YOU SEND BACK : Serialize means " this can be turned into Outgoing JSON." Findings is a plain list of human readbale string simplfied from policy::Finidng struct

// The handler function signature
async fn preflight(Json(req): Json<PreFlightRequest>) -> Json<PreFlightResponse> {
    // It autmoatically parses the incoming request body as JSON into a PreflightRequest, and binds the unwrapped value to req. Returning Json<PreFlightResponse> tells axum to serialize ur struct and give it back to JSON automatically !!!
    let op = &req.user_op;
    let decoded_calls = op.decode_calls();
    let resolved = op.resolve_validation();
    /* docode_calls() and resolve_validation() are the exact aa_types methods you built at he very start
    - one gets you the target . value/ data from the execute/executeBatch, the other gets you whihc which ModuleEntity signed this and whether its global
    */
    let mut graph = AuthorityGraph::new();
    if let (Some(calls), Some(validation)) = (decoded_calls, &resolved) {
        if let Some(selector) = op.selector() {
            // FIX #4 — explicitly_scoped is hardcoded to `false` as a known simplification.
            // A complete implementation would query the account's on-chain validation config
            // via IERC6900AccountView.getValidationData() to check whether this selector is
            // in the validator's explicitly-installed allowed-selector list. When
            // explicitly_scoped=true, the path is NOT flagged as "via global" even if the
            // validator itself is global, because the account owner explicitly scoped it.
            // For now, every call through a global validator is treated as potentially
            // amplified, which is the safe/conservative default.
            graph.add_validates_for(
                validation.entity.clone(),
                validation.is_global,
                selector,
                false,
            );
            for call in calls {
                graph.add_invokes(selector, call.target);
            }
            /*
            Draws the validator→selector edge, then loops over
            every decoded inner call and draws selector→target
            edges for each one. .clone() on validation.entity is
             needed because add_validates_for takes ownership of
              the ModuleEntity, but validation itself is only
              borrowed here (from the resolved variable), so you
               clone it rather than move it.
            */
        }
    }

    let mut sensitive_selectors = HashSet::new();
    // FIX #3 — Real drain(address) selector, not a placeholder.
    sensitive_selectors.insert(DRAIN_SELECTOR);
    let findings = graph.run_all_rules(&sensitive_selectors);
    let is_safe = findings.is_empty();

    let config = SimConfig {
        rpc_url: "http://localhost:8545".into(),
        entry_point: "0x5FbDB2315678afecb367f032d93F642f64180aa3"
            .parse()
            .unwrap(),
        account: op.sender,
    };
    let sim_result = run_simulation(&config, vec![op.clone()], req.beneficiary).await;
    /*
    */

    let (gas_estimate, sim_outcome) = match sim_result {
        Ok(r) => (r.gas_estimate, r.validation),
        Err(_) => (
            None,
            SimOutcome::Unknown {
                raw: "simulation failed".into(),
            },
        ),
    };

    let sim_ok = matches!(sim_outcome, SimOutcome::Success);
    let mut permit_issued = false;
    let mut permit_signature = None;

    if is_safe && sim_ok {
        // FIX #2 — Bind permit digest to RiskGate's address, not EntryPoint.
        // This MUST match RiskGate.sol's keccak256(abi.encode(userOpHash,
        // block.chainid, address(this), policyRoot, validUntil)).
        let user_op_hash = op.user_op_hash(RISK_GATE_ADDRESS, U256::from(31337));
        let permit = RiskPermit {
            user_op_hash,
            chain_id: U256::from(31337),
            entry_point: RISK_GATE_ADDRESS,
            policy_root: keccak256(b"ghostbundler-policy-v2"),
            valid_until: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs())
                + 300,
        };

        // FIX #1 — Use the real permit signer (Anvil key #2), lazily initialized.
        let signer = permit_signer();
        if let Ok(sig) = signer.sign(&permit) {
            permit_issued = true;
            permit_signature = Some(format!("0x{}", hex::encode(sig)));
        }
        /*
        Signs the permit using sign_prehash_recoverable (no double-hash).
        If signing succeeds, mark permit_issued = true and format the 65
        raw bytes as a 0x-prefixed hex string.
        */
    }

    Json(PreFlightResponse {
        verdict: if is_safe && sim_ok {
            "safe".into()
        } else {
            "unsafe".into()
        },
        findings: findings.into_iter().map(|f| f.reason).collect(),
        gas_estimate,
        permit_issued,
        permit_signature,
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/preflight", post(preflight));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("ghostd listening on :3000");
    axum::serve(listener, app).await.unwrap();
}

// ── Integration tests ────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use aa_types::executeCall;
    use alloy_primitives::{B256, Bytes};
    use alloy_sol_types::SolCall;
    use k256::ecdsa::SigningKey;
    use std::net::TcpStream;

    // ── Deterministic addresses from Deploy.s.sol on Anvil (chain 31337) ─────
    const ACCOUNT: Address = Address::new([
        0xb0, 0x44, 0xa6, 0x3D, 0x8e, 0xD4, 0x06, 0xbd,
        0xAA, 0xD3, 0xDB, 0x50, 0xf7, 0x9F, 0x2c, 0xBc,
        0x1f, 0x73, 0x4e, 0x10,
    ]);
    const MOCK_VAULT: Address = Address::new([
        0x22, 0x79, 0xB7, 0xA0, 0xa6, 0x7D, 0xB3, 0x72,
        0x99, 0x6a, 0x5F, 0xaB, 0x50, 0xD9, 0x1e, 0xAA,
        0x73, 0xd2, 0xeB, 0xe6,
    ]);
    const SINGLE_SIGNER_MODULE: Address = Address::new([
        0xe7, 0xf1, 0x72, 0x5E, 0x77, 0x34, 0xCE, 0x28,
        0x8F, 0x83, 0x67, 0xe1, 0xBb, 0x14, 0x3E, 0x90,
        0xbb, 0x3F, 0x05, 0x12,
    ]);
    const ENTRY_POINT_ADDR: Address = Address::new([
        0x5F, 0xBD, 0xB2, 0x31, 0x56, 0x78, 0xaf, 0xec,
        0xb3, 0x67, 0xf0, 0x32, 0xd9, 0x3F, 0x64, 0x2f,
        0x64, 0x18, 0x0a, 0xa3,
    ]);

    // ── Anvil default private keys ───────────────────────────────────────────
    // Key #0 = owner
    const OWNER_KEY: [u8; 32] = [
        0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3,
        0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
        0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc,
        0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
    ];
    // Key #1 = session key
    const SESSION_KEY: [u8; 32] = [
        0x59, 0xc6, 0x99, 0x5e, 0x99, 0x8f, 0x97, 0xa5,
        0xa0, 0x04, 0x49, 0x66, 0xf0, 0x94, 0x53, 0x89,
        0xdc, 0x9e, 0x86, 0xda, 0xe8, 0x8c, 0x7a, 0x84,
        0x12, 0xf4, 0x60, 0x3b, 0x6b, 0x78, 0x69, 0x0d,
    ];

    // ── Gas encoding (must match _encodeGas in Deploy.t.sol) ─────────────────
    // accountGasLimits = encodeGas(1_200_000, 100_000)
    fn encode_gas(g1: u64, g2: u64) -> B256 {
        let val: U256 = (U256::from(g1) << 128) | U256::from(g2);
        B256::from(val.to_be_bytes::<32>())
    }

    // ── Ethereum signed message hash (EIP-191) ───────────────────────────────
    fn eth_sign_hash(message: B256) -> B256 {
        let mut buf = Vec::with_capacity(28 + 32);
        buf.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
        buf.extend_from_slice(message.as_slice());
        keccak256(&buf)
    }

    // ── ECDSA sign + pack as r||s||v ────────────────────────────────────────
    fn sign_hash(hash: B256, key_bytes: &[u8; 32]) -> [u8; 65] {
        let signing_key = SigningKey::from_bytes(key_bytes.into()).expect("valid key");
        let eth_hash = eth_sign_hash(hash);
        let (sig, recid) = signing_key
            .sign_prehash_recoverable(eth_hash.as_slice())
            .expect("signing should succeed");
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&sig.r().to_bytes());
        out[32..64].copy_from_slice(&sig.s().to_bytes());
        out[64] = recid.to_byte() + 27;
        out
    }

    // ── Build the UserOp signature prefix: module(20) + entityId(4) + isGlobal(1) + segment_marker(1) ─
    // The ERC-6900 reference implementation uses SparseCalldataSegmentLib. After the
    // validation prefix, the remaining signature must start with 0xFF (RESERVED_VALIDATION_DATA_INDEX)
    // before the actual ECDSA signature bytes.
    fn build_validation_prefix(entity_id: u32, is_global: bool) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(26);
        prefix.extend_from_slice(SINGLE_SIGNER_MODULE.as_slice());
        prefix.extend_from_slice(&entity_id.to_be_bytes());
        prefix.push(if is_global { 1 } else { 0 });
        prefix.push(0xFF); // RESERVED_VALIDATION_DATA_INDEX segment marker
        prefix
    }

    // ── Build drain(address) calldata ─────────────────────────────────────────
    fn drain_calldata(to: Address) -> Bytes {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&DRAIN_SELECTOR);
        let mut addr_padded = [0u8; 32];
        addr_padded[12..].copy_from_slice(to.as_slice());
        data.extend_from_slice(&addr_padded);
        Bytes::from(data)
    }

    // ── Build a UserOp that calls MockVault.drain() through account.execute() ─
    fn build_drain_user_op() -> PackedUserOperation {
        // Outer callData: execute(vault, 0, drain(account))
        let inner = drain_calldata(ACCOUNT);
        let call_data = Bytes::from(
            executeCall {
                target: MOCK_VAULT,
                value: U256::ZERO,
                data: inner,
            }
            .abi_encode(),
        );

        PackedUserOperation {
            sender: ACCOUNT,
            nonce: U256::ZERO,
            init_code: Bytes::new(),
            call_data,
            account_gas_limits: encode_gas(1_200_000, 100_000),
            pre_verification_gas: U256::ZERO,
            gas_fees: encode_gas(1, 1),
            paymaster_and_data: Bytes::new(),
            signature: Bytes::new(), // filled in later
        }
    }

    // ── Build a safe UserOp: owner calls a benign target with empty data ──────
    fn build_safe_user_op() -> PackedUserOperation {
        // Outer callData: execute(MOCK_VAULT, 0, "") — a benign no-op call
        let call_data = Bytes::from(
            executeCall {
                target: MOCK_VAULT,
                value: U256::ZERO,
                data: Bytes::new(),
            }
            .abi_encode(),
        );

        PackedUserOperation {
            sender: ACCOUNT,
            nonce: U256::ZERO,
            init_code: Bytes::new(),
            call_data,
            account_gas_limits: encode_gas(1_200_000, 100_000),
            pre_verification_gas: U256::ZERO,
            gas_fees: encode_gas(1, 1),
            paymaster_and_data: Bytes::new(),
            signature: Bytes::new(), // filled in later
        }
    }

    /// Unsafe case: session key (isGlobal=true) calls MockVault.drain() through
    /// the account's execute(). Policy should flag this as privilege amplification
    /// via the global-validation escape hatch.
    #[tokio::test]
    async fn unsafe_drain_captured_by_policy() {
        if TcpStream::connect("127.0.0.1:8545").is_err() {
            eprintln!("Skipping integration test — no Anvil on :8545");
            return;
        }

        let mut op = build_drain_user_op();

        // Sign with session key (entityId=1, isGlobal=true)
        let user_op_hash = op.user_op_hash(ENTRY_POINT_ADDR, U256::from(31337));
        let inner_sig = sign_hash(user_op_hash, &SESSION_KEY);
        let mut prefix = build_validation_prefix(1, true);
        prefix.extend_from_slice(&inner_sig);
        op.signature = Bytes::from(prefix);

        let beneficiary = Address::repeat_byte(0xBB);
        let request = PreFlightRequest {
            user_op: op,
            beneficiary,
        };

        let resp = preflight(Json(request)).await;
        let body = resp.0;

        println!("=== UNSAFE CASE ===");
        println!("verdict:         {}", body.verdict);
        println!("findings:        {:?}", body.findings);
        println!("permit_issued:   {}", body.permit_issued);
        println!("gas_estimate:    {:?}", body.gas_estimate);

        assert_eq!(body.verdict, "unsafe", "session key drain should be unsafe");
        assert!(!body.findings.is_empty(), "should have at least one finding");
        assert!(
            body.findings
                .iter()
                .any(|f| f.contains("global")),
            "findings should mention global validation: {:?}",
            body.findings
        );
        assert!(!body.permit_issued, "no permit for unsafe ops");
    }

    /// Safe case: owner (isGlobal=false) calls a benign function. Policy should
    /// find no issues and issue a valid permit.
    #[tokio::test]
    async fn safe_call_gets_permit() {
        if TcpStream::connect("127.0.0.1:8545").is_err() {
            eprintln!("Skipping integration test — no Anvil on :8545");
            return;
        }

        let mut op = build_safe_user_op();

        // Sign with owner key (entityId=0, isGlobal=false)
        let user_op_hash = op.user_op_hash(ENTRY_POINT_ADDR, U256::from(31337));
        let inner_sig = sign_hash(user_op_hash, &OWNER_KEY);
        let mut prefix = build_validation_prefix(0, false);
        prefix.extend_from_slice(&inner_sig);
        op.signature = Bytes::from(prefix);

        let beneficiary = Address::repeat_byte(0xBB);
        let request = PreFlightRequest {
            user_op: op,
            beneficiary,
        };

        let resp = preflight(Json(request)).await;
        let body = resp.0;

        println!("=== SAFE CASE ===");
        println!("verdict:         {}", body.verdict);
        println!("findings:        {:?}", body.findings);
        println!("permit_issued:   {}", body.permit_issued);
        println!("permit_signature: {:?}", body.permit_signature);
        println!("gas_estimate:    {:?}", body.gas_estimate);

        assert_eq!(body.verdict, "safe", "owner benign call should be safe");
        assert!(body.findings.is_empty(), "safe op should have no findings");
        assert!(body.permit_issued, "safe op should receive a permit");

        // Verify the permit signature is a valid 0x-prefixed 130 hex char string
        let sig = body.permit_signature.expect("permit_signature should be Some");
        assert!(sig.starts_with("0x"), "permit sig should start with 0x");
        assert_eq!(
            sig.len(),
            132,
            "permit sig should be 0x + 130 hex chars (65 bytes), got len={}",
            sig.len()
        );
        // Verify it's valid hex
        hex::decode(&sig[2..]).expect("permit sig should be valid hex");
    }

    /// Debug: print the raw simulation result for the safe UserOp
    #[tokio::test]
    async fn debug_simulation_result() {
        if TcpStream::connect("127.0.0.1:8545").is_err() {
            eprintln!("Skipping debug test — no Anvil on :8545");
            return;
        }
        let op = build_safe_user_op();
        let beneficiary = Address::repeat_byte(0xBB);
        let config = SimConfig {
            rpc_url: "http://localhost:8545".into(),
            entry_point: ENTRY_POINT_ADDR,
            account: ACCOUNT,
        };
        let result = sim::run_simulation(&config, vec![op], beneficiary).await;
        match &result {
            Ok(r) => {
                println!("DEBUG gas_estimate: {:?}", r.gas_estimate);
                println!("DEBUG validation: {:?}", r.validation);
            }
            Err(e) => {
                println!("DEBUG run_simulation ERROR: {e:#}");
            }
        }
    }

    /// Debug: compare Rust user_op_hash with on-chain getUserOpHash
    #[tokio::test]
    async fn debug_compare_hash() {
        if TcpStream::connect("127.0.0.1:8545").is_err() {
            eprintln!("Skipping debug test — no Anvil on :8545");
            return;
        }

        let op = build_safe_user_op();

        // Compute Rust hash
        let rust_hash = op.user_op_hash(ENTRY_POINT_ADDR, U256::from(31337));
        println!("Rust user_op_hash:    {}", rust_hash);

        // Build the call data for getUserOpHash(PackedUserOperation)
        // selector = keccak256("getUserOpHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes))")
        let mut encoded = Vec::new();

        // Encode the tuple as ABI:
        // offset 0x00: address sender (padded to 32)
        encoded.extend_from_slice(&[0u8; 12]);
        encoded.extend_from_slice(op.sender.as_slice());
        // offset 0x20: uint256 nonce
        let nonce_bytes = op.nonce.to_be_bytes::<32>();
        encoded.extend_from_slice(&nonce_bytes);
        // offset 0x40: offset to bytes initCode = 0x120 (9 * 32 = 288 = 0x120)
        encoded.extend_from_slice(&[0u8; 31]);
        encoded.push(0x90); // wrong... let me just use cast

        // Actually let's just use cast call to compare
        println!("Expected owner address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        println!("ENTRY_POINT: {}", ENTRY_POINT_ADDR);
        println!("ACCOUNT: {}", ACCOUNT);
        println!("SINGLE_SIGNER_MODULE: {}", SINGLE_SIGNER_MODULE);

        // Use the sim crate's existing ethereum provider to call getUserOpHash
        // Simpler: call via the EntryPointSimulations contract
        let beneficiary = Address::repeat_byte(0xBB);
        let config = SimConfig {
            rpc_url: "http://localhost:8545".into(),
            entry_point: ENTRY_POINT_ADDR,
            account: ACCOUNT,
        };

        // Build signed op
        let user_op_hash = op.user_op_hash(ENTRY_POINT_ADDR, U256::from(31337));
        let inner_sig = sign_hash(user_op_hash, &OWNER_KEY);
        let mut prefix = build_validation_prefix(0, false);
        prefix.extend_from_slice(&inner_sig);
        let mut signed_op = op.clone();
        signed_op.signature = Bytes::from(prefix);

        println!("Signed signature len: {}", signed_op.signature.len());
        println!("Signature prefix: {}", hex::encode(&signed_op.signature[..26]));
        println!("Signature 0xFF marker: {}", signed_op.signature[26]);
        println!("ECDSA sig len: {}", signed_op.signature.len() - 27);
        println!("user_op_hash: {}", user_op_hash);
        println!("eth_sign_hash: {}", eth_sign_hash(user_op_hash));

        let result = sim::run_simulation(&config, vec![signed_op], beneficiary).await;
        match &result {
            Ok(r) => {
                println!("DEBUG gas_estimate: {:?}", r.gas_estimate);
                println!("DEBUG validation: {:?}", r.validation);
                println!("DEBUG findings: {:?}", r.validation);
            }
            Err(e) => {
                println!("DEBUG run_simulation ERROR: {e:#}");
            }
        }
    }
}
