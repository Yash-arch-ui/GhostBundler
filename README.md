# GhostBundler

**GhostBundler is an adversarial Rust preflight and sponsorship firewall for ERC-4337 UserOperations sent by ERC-6900 modular accounts. It explains the effective authorization path, simulates validation, and issues an onchain-verifiable Risk Permit only when the path satisfies policy.**

## What This Is

GhostBundler is a developer tool — a Rust HTTP service that sits in front of an ERC-4337 bundler and inspects each incoming UserOperation before it reaches the EntryPoint. For each UserOperation, it decodes the call path, builds a directed authority graph of which validator authorizes which selector targets which contract, runs a set of policy rules against that graph, simulates the operation against a local Anvil node, and issues a cryptographic Risk Permit (ECDSA-signed, onchain-verifiable) only if both the policy check and simulation pass.

It is a weekend hackathon-scale MVP, not production software.

## What This Is NOT

- **Not a production firewall.** It has a hardcoded RPC URL (`http://localhost:8545`), a hardcoded Anvil chain ID (`31337`), a hardcoded EntryPoint address, and a demo-only permit signer key (`[0xab; 32]`). None of these are configurable without code changes.
- **Not a full ERC-4337 bundler.** It does not collect, order, or submit UserOperations. It is a preflight check that runs before a bundler picks up the operation.
- **Not a general-purpose module discovery engine.** It only resolves the specific submitted call path from the UserOperation's `callData` and `signature`. It does not walk on-chain account state to discover all installed modules or all registered validation-execution mappings.
- **Single account implementation, single EntryPoint version.** The Solidity contracts target the [eth-infinitism/account-abstraction](https://github.com/eth-infinitism/account-abstraction) EntryPoint (ERC-4337 v0.7 packed UserOp format) and the [erc6900/reference-implementation](https://github.com/erc6900/reference-implementation) modular account. Solidity `^0.8.28`, EVM version `cancun`. ERC-6900 is a **Draft** standard — not Final — and has narrower real-world adoption than the competing ERC-7579 standard (used by Safe, ZeroDev, Biconomy, Rhinestone, OpenZeppelin). ERC-6900 is primarily associated with Alchemy's Modular Account.

## The Vulnerability Class This Addresses

ERC-6900 modular accounts allow validation functions to be marked `isGlobal`, meaning they can authorize *any* execution function on the account — not just the ones they were explicitly installed for. Execution functions can also have an `allowGlobalValidation` flag, meaning they accept authorization from global validators.

The danger is the *combination*: a validator marked `isGlobal` is like a **master keycard** that opens every door, and a selector marked `allowGlobalValidation` is like a **door that accepts master keycards**. When these two flags combine, the validator can authorize execution of selectors it was never explicitly scoped to — and nobody explicitly decided that specific combination should be allowed. A session key installed to approve token transfers can, through this path, drain a vault holding unrelated assets.

The ERC-6900 spec itself documents this risk:

> "In a sense, these global validation functions could gain root access to the exposed native execution functions and potentially the whole account."
>
> — [ERC-6900, Security Considerations](https://eips.ethereum.org/EIPS/eip-6900)

GhostBundler detects this class of privilege escalation *before* the UserOperation is submitted on-chain, by building a directed graph of the effective authorization path and checking whether any global-validation escape hatch is reachable.

## Architecture

```
                        ┌──────────────────────────────────┐
                        │        ghostd (axum HTTP)        │
                        │   POST /preflight                │
                        └──────┬──────────┬───────────┬────┘
                               │          │           │
                    ┌──────────▼──┐ ┌─────▼─────┐ ┌──▼──────────┐
                    │  aa-types   │ │   policy   │ │     sim     │
                    │ UserOp hash │ │ Authority  │ │ eth_call    │
                    │ decode/call │ │ Graph +    │ │ simulation  │
                    │ resolve sig │ │ 3 rules    │ │ + gas est.  │
                    └─────────────┘ └───────────┘ └──────┬──────┘
                                                         │
                    ┌─────────────────────────────────────▼──┐
                    │                permit                   │
                    │   RiskPermit signing (k256/ECDSA)       │
                    └────────────────────┬────────────────────┘
                                         │  signed Risk Permit
                                         ▼
                        ┌────────────────────────────────────┐
                        │     RiskGate.sol (validation hook)  │
                        │  preUserOpValidationHook verifies   │
                        │  the permit on-chain via ECDSA      │
                        └────────────────────────────────────┘

                        ┌────────────────────────────────────┐
                        │  VerifyingPaymaster.sol             │
                        │  Permit-gated gas sponsorship       │
                        │  (reads permit from paymasterAndData)│
                        └────────────────────────────────────┘
```

### Request Flow

1. **UserOperation arrives** at `POST /preflight` (JSON body: `{ userOp, beneficiary }`).
2. **aa-types** decodes the UserOp's `callData` (supports `execute` and `executeBatch`) and resolves the validator from the packed `signature` (module address + entity ID + `isGlobal` flag + inner signature).
3. **policy** builds a directed `AuthorityGraph` with nodes for validators, selectors, and targets, then runs 3 policy rules to find privilege amplification, validation applicability violations, and missing hooks.
4. **sim** concurrently calls `eth_call` (static `handleOps` simulation) and `eth_estimateGas` against a local Anvil node. Reverts are classified as `AccountError` (AA1/AA2 prefixes), `PaymasterError` (AA3 prefix), or `Unknown`.
5. If both policy and simulation pass, **permit** signs a `RiskPermit` — a keccak256 digest binding `userOpHash`, `chainId`, `address(this)`, `policyRoot`, and `validUntil` — using ECDSA `sign_prehash_recoverable` (no double-hash).
6. **Response**: `{ verdict, findings, gas_estimate, permit_issued, permit_signature }`.

> **Note:** The flow ends at permit issuance. There is no onchain relay step (`handleOps` submission) — that is the bundler's responsibility. GhostBundler is a preflight gate, not a relay.

## Policy Rules

GhostBundler implements **3 of the originally-planned 5** policy rules. The implemented rules are:

1. **Privilege Amplification** (`find_privilege_amplification`) — Catches when a validator marked `isGlobal` can reach a selector and its target through the global validation escape hatch, rather than through explicit scoping. This is the core "master keycard + permissive door" detection.

2. **Validation Applicability Violation** (`find_validation_applicability_violations`) — Catches when a validator has *no authorization path at all* to a selector that the operation invokes. The validator shouldn't be able to authorize execution of selectors it was never registered for.

3. **Missing Execution Hook** (`find_missing_hooks`) — Catches when a sensitive selector (passed in as a `HashSet<[u8; 4]>`) has no pre/post execution hook guarding it. Sensitive selectors are currently hardcoded as `[0x00, 0x00, 0x00, 0x00]`.

The remaining 2 originally-planned rules are **not implemented** and represent future work.

## Demo

The demo files (`demo/safe.json`, `demo/privilege-escalation.json`, `demo/run-demo.sh`) are currently empty placeholders. There is no integration test for ghostd that produces real verdict output.

The closest thing to a real demonstration is the `DeployTest::test_vaultDrainViaSessionKeyGlobalValidation` Solidity test, which end-to-end demonstrates the privilege escalation: a session key with `isGlobal=true` drains a MockVault holding 1000 MockUSDC by calling `vault.drain()` — a selector it was never explicitly scoped to. This test passes on every `forge test` run (5/5 tests pass across `DeployTest`).

To see real verdict output from ghostd, you would need to:
1. Start Anvil and deploy the contracts
2. Start ghostd
3. Send a `POST /preflight` request with a shaped `PreFlightRequest`

This has not been scripted yet. **TODO: script the full demo flow and capture real output.**

## Known Limitations / Honest Simplifications

1. **`explicitly_scoped` is hardcoded to `false`.** When ghostd builds the authority graph, it always calls `add_validates_for(entity, is_global, selector, false)`. This means the graph cannot distinguish between validators that are globally reachable by design versus those that are globally reachable by accident. The policy check always treats `isGlobal + false` as a potential privilege amplification path.

2. **`policy_root` is a placeholder constant.** Ghostd sets `policy_root = keccak256(b"ghostbundler-policy-v2")` — a fixed hash of a string, not a hash of which rules were actually checked or their parameters. It does not reflect the actual policy configuration.

3. **RiskGate binds to `address(this)`, not the ERC-4337 EntryPoint.** Both `RiskGate.sol` and `VerifyingPaymaster.sol` compute the permit digest using `address(this)` — the contract's own address — rather than the EntryPoint address. This is a deliberate scoping choice: the permit is bound to the contract that *verifies* it, preventing cross-module replay. In the Rust signing code, `entry_point` in the `RiskPermit` struct should be set to RiskGate's deployed address (for signature-tail permits) or VerifyingPaymaster's deployed address (for paymasterAndData permits). The two contracts require **separate permits** signed against their respective addresses.

4. **Hardcoded RPC URL.** `ghostd` always connects to `http://localhost:8545`. No environment variable or configuration file is supported.

5. **Hardcoded chain ID.** The permit is always signed with `chain_id = 31337` (Anvil's default). This is not configurable.

6. **Hardcoded EntryPoint address.** `ghostd` uses `0x5FbDB2315678afecb367f032d93F642f64180aa3` as the EntryPoint address for simulation. This is the Anvil default deploy address.

7. **Demo-only permit signer key.** Ghostd signs permits with the hardcoded key `[0xab; 32]`. RiskGate.sol and VerifyingPaymaster.sol expect the signer to be `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC` (Anvil key #2). The demo key does **not** match the on-chain expected signer — permits issued by ghostd will be rejected by RiskGate in a real Anvil deployment unless the signer key is aligned.

8. **No `handleOps` relay.** GhostBundler is a preflight check only. It does not submit UserOperations to the EntryPoint. The bundler (or a relay) must do that separately.

9. **No batch UserOp support in policy.** The policy graph is built for a single UserOperation at a time. Batched `handleOps` calls with multiple UserOps are not analyzed for cross-Op interactions.

10. **ERC-6900 is a Draft standard.** It is not Final. The competing ERC-7579 standard has broader ecosystem adoption (Safe, ZeroDev, Biconomy, Rhinestone, OpenZeppelin). ERC-6900 is primarily associated with Alchemy's Modular Account. This project is a proof-of-concept against the ERC-6900 reference implementation, not a production-grade security tool for any specific wallet.

## Running It Locally

```bash
# 1. Start Anvil (local Ethereum node)
anvil

# 2. Deploy contracts to Anvil
cd contracts
forge script script/Deploy.s.sol:DeployScript \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast
cd ..

# 3. Start ghostd
cargo run -p ghostd
# ghostd listening on :3000

# 4. Send a preflight request
curl -X POST http://localhost:3000/preflight \
  -H 'Content-Type: application/json' \
  -d '{
    "userOp": {
      "sender": "0x0000000000000000000000000000000000000000",
      "nonce": "0x0",
      "initCode": "0x",
      "callData": "0xb61d27f6000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000064",
      "accountGasLimits": "0x00000000000000000000000000000000000000000000000000000000000f4240",
      "preVerificationGas": "0x5208",
      "gasFees": "0x0000000000000000000000000000000000000000000000000000000000000001",
      "paymasterAndData": "0x",
      "signature": "0x"
    },
    "beneficiary": "0x0000000000000000000000000000000000000000"
  }'
```

The `callData` above encodes `execute(address,uint256,bytes)` with a target, zero value, and minimal calldata. The `PreFlightRequest` struct accepts `{ userOp: PackedUserOperation, beneficiary: Address }` (all fields use `camelCase` in JSON).

### Running the Solidity Tests

```bash
cd contracts
forge test -vv
# DeployTest      | 5 passed
# RiskGateTest    | 10 passed
# VerifyingPaymasterTest | 8 passed
# Total: 23 tests, all passing
```

### Running the Rust Tests

```bash
cargo test
# aa-types:  9 passed
# policy:    3 passed
# sim:       5 passed (including 1 integration test that skips without Anvil)
# permit:    6 passed
# ghostd:    0 tests
# Total: 23 tests, all passing
```

## Tech Stack

### Rust

| Crate | Dependencies |
|-------|-------------|
| `aa-types` | `alloy-primitives` 1.6.1, `alloy-sol-types` 1.6.1, `serde` 1, `serde_json` 1 |
| `policy` | `aa-types` (path), `alloy-primitives` 1.6.1, `petgraph` 0.6 |
| `sim` | `aa-types` (path), `alloy-primitives` 1.7.1, `alloy-provider` 2.4.1, `alloy-rpc-types-eth` 2.4.1, `alloy-sol-types` 1.7.1, `anyhow` 1.0.104, `hex` 0.4, `tokio` 1.53.1 |
| `permit` | `alloy-primitives` 1.7.1, `alloy-sol-types` 1.7.1, `anyhow` 1.0.104, `k256` 0.13, `sha3` 0.10 |
| `ghostd` | `aa-types`, `policy`, `sim`, `permit` (all path), `axum` 0.8, `tokio` 1, `serde` 1, `serde_json` 1, `alloy-primitives` 1.7, `hex` 0.4 |

### Solidity / Foundry

- **Solidity compiler:** `0.8.28`
- **EVM version:** `cancun`
- **Foundry** (forge, anvil, cast)

### Vendored Dependencies

- [`erc6900/reference-implementation`](https://github.com/erc6900/reference-implementation) — ERC-6900 modular account implementation (ReferenceModularAccount, SemiModularAccount, AccountFactory, SingleSignerValidationModule)
- [`eth-infinitism/account-abstraction`](https://github.com/eth-infinitism/account-abstraction) — ERC-4337 EntryPoint and related interfaces
- `openzeppelin-contracts` — ECDSA, IERC165, MessageHashUtils (via reference-implementation)
- `forge-std` — Foundry test framework

## Primary References

- [ERC-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337) — the account abstraction standard this project builds on
- [ERC-6900: Modular Smart Contract Accounts](https://eips.ethereum.org/EIPS/eip-6900) — the modular account standard defining `isGlobal`, `allowGlobalValidation`, and validation hooks
- [erc6900/reference-implementation](https://github.com/erc6900/reference-implementation) — the reference ERC-6900 account implementation used in this project
- [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) — ECDSA, IERC165, and other utility contracts
- [eth-infinitism/account-abstraction](https://github.com/eth-infinitism/account-abstraction) — the canonical ERC-4337 EntryPoint implementation
