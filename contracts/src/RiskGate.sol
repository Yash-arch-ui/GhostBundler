// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {IERC6900ValidationHookModule} from "reference-implementation/src/interfaces/IERC6900ValidationHookModule.sol";
import {IERC6900Module} from "reference-implementation/src/interfaces/IERC6900Module.sol";
import {BaseModule} from "reference-implementation/src/modules/BaseModule.sol";

/// @title RiskGate — ERC-6900 validation hook module that enforces a risk permit signature.
/// @notice The permit is a signed digest binding userOpHash, chainId, this contract's address,
///         a policy root, and a validity window. The signer must be PERMIT_SIGNER.
contract RiskGate is IERC6900ValidationHookModule, BaseModule {
    // MUST be distinct from any account validator signer (e.g. session key, owner key).
    // If this matched a session key signer, "GhostBundler approved this" and "session key
    // authorized this" would collapse into the same fact, defeating independent risk-gating.
    address public constant PERMIT_SIGNER = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;

    error PermitExpired();
    error InvalidPermitSignature();
    error MalformedPermitData();

    /// @notice Pre-UserOp validation hook. Verifies the risk permit attached to the tail of
    ///         userOp.signature.
    /// @dev Layout of userOp.signature tail (last 105 bytes):
    ///      [8 bytes validUntil (big-endian uint64)] [32 bytes policyRoot] [65 bytes permitSig (r||s||v)]
    ///      The 65-byte permitSig uses the standard Ethereum r||s||v format where v is 27 or 28.
    ///
    ///      Digest computation (must match crates/permit RiskPermit::digest() exactly):
    ///        keccak256(abi.encode(userOpHash, chainId, address(this), policyRoot, validUntil))
    ///
    ///      Note: address(this) is used instead of the EntryPoint address because RiskGate is the
    ///      contract that verifies the permit. Binding to RiskGate's address prevents cross-module
    ///      replay attacks. In the Rust signing code, set entry_point = RiskGate's deployed address.
    function preUserOpValidationHook(
        uint32, /* entityId */
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        bytes calldata sig = userOp.signature;

        // Minimum signature: at least the 105-byte permit tail (could have prefix bytes before it)
        if (sig.length < 105) revert MalformedPermitData();

        // Extract the 105-byte permit tail from the end of the signature
        uint256 tailLen = 105;
        bytes calldata permitTail = sig[sig.length - tailLen:];

        // Parse fields from the tail
        // Layout: [validUntil: 8] [policyRoot: 32] [permitSig: 65]
        uint64 validUntil = uint64(bytes8(permitTail[:8]));
        bytes32 policyRoot = bytes32(permitTail[8:40]);
        bytes calldata permitSig = permitTail[40:105]; // exactly 65 bytes

        // Check expiry
        if (block.timestamp > validUntil) revert PermitExpired();

        // Recompute digest — MUST match crates/permit RiskPermit::digest():
        //   (user_op_hash, chain_id, entry_point, policy_root, valid_until).abi_encode() → keccak256
        // In Rust, entry_point maps to address(this) (this RiskGate contract).
        bytes32 digest = keccak256(
            abi.encode(userOpHash, block.chainid, address(this), policyRoot, validUntil)
        );

        // Recover the signer from the raw digest (single keccak256, no prefix).
        // This matches Rust's sign_prehash_recoverable which signs the 32-byte digest directly.
        address recovered = ECDSA.recover(digest, permitSig);

        if (recovered != PERMIT_SIGNER) revert InvalidPermitSignature();

        // Return 0 = validation passed (validAfter=0, validUntil=0, authorizer=0x0)
        return 0;
    }

    /// @notice Pre-runtime validation hook — not supported in demo.
    function preRuntimeValidationHook(
        uint32, /* entityId */
        address, /* sender */
        uint256, /* value */
        bytes calldata, /* data */
        bytes calldata /* authorization */
    ) external pure {
        revert("RiskGate: not supported in demo");
    }

    /// @notice Pre-signature validation hook — not supported in demo.
    function preSignatureValidationHook(
        uint32, /* entityId */
        address, /* sender */
        bytes32, /* hash */
        bytes calldata /* signature */
    ) external pure {
        revert("RiskGate: not supported in demo");
    }

    /// @inheritdoc IERC6900Module
    function onInstall(bytes calldata) external override {}

    /// @inheritdoc IERC6900Module
    function onUninstall(bytes calldata) external override {}

    /// @inheritdoc IERC6900Module
    function moduleId() external pure returns (string memory) {
        return "ghostbundler.risk-gate.1.0.0";
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(BaseModule, IERC165)
        returns (bool)
    {
        return
            interfaceId == type(IERC6900ValidationHookModule).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
