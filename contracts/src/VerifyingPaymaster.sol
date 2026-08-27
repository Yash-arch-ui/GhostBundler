// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {BasePaymaster} from "@eth-infinitism/account-abstraction/core/BasePaymaster.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "@eth-infinitism/account-abstraction/core/Helpers.sol";

/// @title VerifyingPaymaster — sponsors gas for UserOps carrying a valid, unexpired Risk Permit.
///
/// DESIGN DECISION (approach A — standard ERC-4337 pattern):
/// This paymaster reads its OWN copy of the permit from userOp.paymasterAndData,
/// independent of what RiskGate reads from userOp.signature. The paymasterAndData
/// layout is: [8 bytes validUntil][32 bytes policyRoot][65 bytes permitSig (r||s||v)].
///
/// Why approach A over sharing RiskGate's permit:
/// - Matches ERC-4337 convention (paymasterAndData is the designated field for paymaster data)
/// - Each verifier (RiskGate, VerifyingPaymaster) independently checks its own authorization
/// - No cross-field coupling or GhostBundler-specific conventions to learn
/// - A UserOp using both RiskGate AND this paymaster carries two permits (one in signature
///   tail, one in paymasterAndData) — redundant but explicit and auditable
///
/// IMPORTANT: The digest binds to address(this) (this paymaster), NOT to RiskGate's address.
/// This means the Rust signing code must use this paymaster's deployed address as `entry_point`
/// when signing permits for paymasterAndData. RiskGate and VerifyingPaymaster require
/// SEPARATE permits signed against their respective addresses.
///
/// PERMIT_SIGNER is intentionally the same as RiskGate.sol's PERMIT_SIGNER — both trust the
/// same GhostBundler identity to approve operations. This is distinct from the session-key /
/// permit-signer separation which was intentionally kept distinct for security.
contract VerifyingPaymaster is BasePaymaster {
    // Same signer as RiskGate.sol — both trust the same GhostBundler identity.
    address public constant PERMIT_SIGNER = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;

    error PermitExpired();
    error InvalidPermitSignature();
    error MalformedPermitData();

    constructor(IEntryPoint entryPoint) BasePaymaster(entryPoint) {}

    /// @notice Validates the paymaster portion of a UserOperation.
    /// @dev paymasterAndData layout (105 bytes):
    ///      [8 bytes validUntil (big-endian uint64)] [32 bytes policyRoot] [65 bytes permitSig (r||s||v)]
    function _validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 /* maxCost */
    ) internal override view returns (bytes memory context, uint256 validationData) {
        bytes calldata paymasterData = userOp.paymasterAndData;

        if (paymasterData.length < 105) revert MalformedPermitData();

        // Parse: [validUntil: 8] [policyRoot: 32] [permitSig: 65]
        uint64 validUntil = uint64(bytes8(paymasterData[:8]));
        bytes32 policyRoot = bytes32(paymasterData[8:40]);
        bytes calldata permitSig = paymasterData[40:105]; // exactly 65 bytes

        // Check expiry
        if (block.timestamp > validUntil) revert PermitExpired();

        // Recompute digest — MUST match crates/permit RiskPermit::digest() field order:
        //   keccak256(abi.encode(userOpHash, chainId, address(this), policyRoot, validUntil))
        // address(this) = this paymaster (NOT RiskGate).
        bytes32 digest = keccak256(
            abi.encode(userOpHash, block.chainid, address(this), policyRoot, validUntil)
        );

        // Recover signer from raw digest (single keccak256, no prefix).
        address recovered = ECDSA.recover(digest, permitSig);

        if (recovered != PERMIT_SIGNER) {
            return ("", SIG_VALIDATION_FAILED);
        }

        return ("", SIG_VALIDATION_SUCCESS);
    }

    /// @notice Post-op handler — no-op for this demo paymaster.
    function _postOp(
        PostOpMode, /* mode */
        bytes calldata, /* context */
        uint256, /* actualGasCost */
        uint256 /* actualUserOpFeePerGas */
    ) internal override {}
}
