use aa_types::PackedUserOperation;
use policy::AuthorityGraph;
use sim::{SimConfig, run_simulation, SimOutcome};
use permit::{RiskPermit, PermitSigner};
use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use alloy_primitives::{Address, U256, keccak256};

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
    sensitive_selectors.insert([0x00, 0x00, 0x00, 0x00]);
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
        let user_op_hash = op.user_op_hash(config.entry_point, U256::from(31337));
        let permit = RiskPermit {
            user_op_hash,
            chain_id: U256::from(31337),
            entry_point: config.entry_point,
            policy_root: keccak256(b"ghostbundler-policy-v2"),
            valid_until: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs())
                + 300,
        };

        let signer = PermitSigner::new([0xab; 32]).unwrap();
        if let Ok(sig) = signer.sign(&permit) {
            permit_issued = true;
            permit_signature = Some(format!("0x{}", hex::encode(sig)));
        }
        /*
        Creates the signer (placeholder key — must become your real one) and
         signs the permit using the exact function you verified earlier
         (sign_prehash_recoverable, no double-hash). If signing succeeds,
         mark permit_issued = true and format the 65 raw bytes as a
         0x-prefixed hex string (readable JSON output, and the format
          Solidity/tooling expects)
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
