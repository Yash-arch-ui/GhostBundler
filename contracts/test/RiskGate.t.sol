// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC6900Module} from "reference-implementation/src/interfaces/IERC6900Module.sol";

import {RiskGate} from "../src/RiskGate.sol";

contract RiskGateTest is Test {
    RiskGate riskGate;

    // Anvil key #2 — dedicated GhostBundler permit signer (must match RiskGate.PERMIT_SIGNER)
    uint256 constant PERMIT_SIGNER_KEY = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    address constant PERMIT_SIGNER_ADDR = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;

    // Anvil key #1 — used as the "wrong signer" (it's a real account validator key, just not the permit signer)
    uint256 constant WRONG_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    bytes32 constant POLICY_ROOT = bytes32(uint256(0x3333));

    function setUp() public {
        riskGate = new RiskGate();
    }

    // ── Helpers ──────────────────────────────────────────────────────

    function _buildPermitDigest(
        bytes32 userOpHash,
        uint64 validUntil_,
        bytes32 policyRoot_
    ) internal view returns (bytes32) {
        return keccak256(abi.encode(userOpHash, block.chainid, address(riskGate), policyRoot_, validUntil_));
    }

    function _signPermit(uint256 privateKey, bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _buildUserOpSig(
        bytes32 userOpHash,
        uint64 validUntil_,
        bytes32 policyRoot_,
        uint256 signerKey
    ) internal view returns (bytes memory) {
        bytes32 digest = _buildPermitDigest(userOpHash, validUntil_, policyRoot_);
        bytes memory permitSig = _signPermit(signerKey, digest);
        // Tail: [8 validUntil] [32 policyRoot] [65 permitSig] = 105 bytes
        return abi.encodePacked(validUntil_, policyRoot_, permitSig);
    }

    function _dummyUserOp() internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(0xBEEF),
            nonce: 0,
            initCode: hex"",
            callData: hex"",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    // ── Tests ────────────────────────────────────────────────────────

    function test_validPermitPasses() public {
        uint64 validUntil = uint64(block.timestamp + 1 hours);
        bytes32 userOpHash = keccak256("test-op-1");
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = _buildUserOpSig(userOpHash, validUntil, POLICY_ROOT, PERMIT_SIGNER_KEY);

        uint256 result = riskGate.preUserOpValidationHook(0, userOp, userOpHash);
        assertEq(result, 0, "hook should return 0 (pass)");
    }

    function test_expiredPermitReverts() public {
        uint64 expiredUntil = uint64(block.timestamp - 1);
        bytes32 userOpHash = keccak256("test-op-expired");
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = _buildUserOpSig(userOpHash, expiredUntil, POLICY_ROOT, PERMIT_SIGNER_KEY);

        vm.expectRevert(RiskGate.PermitExpired.selector);
        riskGate.preUserOpValidationHook(0, userOp, userOpHash);
    }

    function test_wrongSignerReverts() public {
        uint64 validUntil = uint64(block.timestamp + 1 hours);
        bytes32 userOpHash = keccak256("test-op-wrong-key");
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = _buildUserOpSig(userOpHash, validUntil, POLICY_ROOT, WRONG_KEY);

        vm.expectRevert(RiskGate.InvalidPermitSignature.selector);
        riskGate.preUserOpValidationHook(0, userOp, userOpHash);
    }

    function test_tamperedUserOpHashReverts() public {
        uint64 validUntil = uint64(block.timestamp + 1 hours);
        bytes32 realUserOpHash = keccak256("real-op");
        bytes32 fakeUserOpHash = keccak256("tampered-op");

        // Sign with the REAL hash
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = _buildUserOpSig(realUserOpHash, validUntil, POLICY_ROOT, PERMIT_SIGNER_KEY);

        // But call the hook with a DIFFERENT hash
        vm.expectRevert(RiskGate.InvalidPermitSignature.selector);
        riskGate.preUserOpValidationHook(0, userOp, fakeUserOpHash);
    }

    function test_malformedSignatureTooShort() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = hex"deadbeef"; // only 4 bytes, need >= 105

        vm.expectRevert(RiskGate.MalformedPermitData.selector);
        riskGate.preUserOpValidationHook(0, userOp, keccak256("x"));
    }

    function test_tamperedPolicyRootReverts() public {
        uint64 validUntil = uint64(block.timestamp + 1 hours);
        bytes32 userOpHash = keccak256("test-op-tampered-policy");
        bytes32 wrongPolicyRoot = bytes32(uint256(0x9999));

        // Build correct permit signature
        bytes32 digest = _buildPermitDigest(userOpHash, validUntil, POLICY_ROOT);
        bytes memory permitSig = _signPermit(PERMIT_SIGNER_KEY, digest);

        // Tamper: replace the policyRoot in the tail with a wrong one
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.signature = abi.encodePacked(validUntil, wrongPolicyRoot, permitSig);

        vm.expectRevert(RiskGate.InvalidPermitSignature.selector);
        riskGate.preUserOpValidationHook(0, userOp, userOpHash);
    }

    function test_preRuntimeValidationHookReverts() public {
        vm.expectRevert("RiskGate: not supported in demo");
        riskGate.preRuntimeValidationHook(0, address(this), 0, hex"", hex"");
    }

    function test_preSignatureValidationHookReverts() public {
        vm.expectRevert("RiskGate: not supported in demo");
        riskGate.preSignatureValidationHook(0, address(this), bytes32(0), hex"");
    }

    function test_moduleId() public view {
        assertEq(riskGate.moduleId(), "ghostbundler.risk-gate.1.0.0");
    }

    function test_supportsInterface() public view {
        assertTrue(riskGate.supportsInterface(type(IERC165).interfaceId));
        assertTrue(riskGate.supportsInterface(type(IERC6900Module).interfaceId));
    }
}
