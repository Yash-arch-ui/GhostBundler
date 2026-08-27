// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {VerifyingPaymaster} from "../src/VerifyingPaymaster.sol";
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";

contract VerifyingPaymasterTest is Test {
    EntryPoint entryPoint;
    VerifyingPaymaster paymaster;

    // Anvil key #2 — dedicated GhostBundler permit signer (must match VerifyingPaymaster.PERMIT_SIGNER)
    uint256 constant PERMIT_SIGNER_KEY = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    address constant PERMIT_SIGNER_ADDR = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;

    // Anvil key #1 — used as "wrong signer" (real account validator key, not permit signer)
    uint256 constant WRONG_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    bytes32 constant POLICY_ROOT = bytes32(uint256(0x3333));
    uint256 constant DEPOSIT_AMOUNT = 1 ether;

    function setUp() public {
        entryPoint = new EntryPoint();
        paymaster = new VerifyingPaymaster(IEntryPoint(address(entryPoint)));

        // Fund the paymaster's EntryPoint deposit so it can sponsor gas
        vm.deal(address(paymaster), DEPOSIT_AMOUNT);
        paymaster.deposit{value: DEPOSIT_AMOUNT}();
    }

    // ── Helpers ──────────────────────────────────────────────────────

    function _buildPermitDigest(
        bytes32 userOpHash,
        uint64 validUntil_,
        bytes32 policyRoot_
    ) internal view returns (bytes32) {
        // Must match Rust RiskPermit::digest() field order:
        //   keccak256(abi.encode(userOpHash, chainId, address(paymaster), policyRoot, validUntil))
        return keccak256(abi.encode(userOpHash, block.chainid, address(paymaster), policyRoot_, validUntil_));
    }

    function _signPermit(uint256 privateKey, bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _buildPaymasterAndData(
        bytes32 userOpHash,
        uint64 validUntil_,
        bytes32 policyRoot_,
        uint256 signerKey
    ) internal view returns (bytes memory) {
        bytes32 digest = _buildPermitDigest(userOpHash, validUntil_, policyRoot_);
        bytes memory permitSig = _signPermit(signerKey, digest);
        // Layout: [8 validUntil] [32 policyRoot] [65 permitSig] = 105 bytes
        return abi.encodePacked(validUntil_, policyRoot_, permitSig);
    }

    function _dummyUserOp() internal view returns (PackedUserOperation memory) {
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

    function _callValidate(
        bytes32 userOpHash,
        bytes memory paymasterData
    ) internal returns (uint256) {
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.paymasterAndData = paymasterData;

        vm.prank(address(entryPoint));
        (bool success, bytes memory returnData) = address(paymaster).call(
            abi.encodeWithSelector(
                IPaymaster.validatePaymasterUserOp.selector,
                userOp,
                userOpHash,
                uint256(0) // maxCost
            )
        );

        if (!success) {
            // Decode custom errors
            if (returnData.length >= 4) {
                bytes4 selector;
                assembly { selector := mload(add(returnData, 32)) }
                if (selector == VerifyingPaymaster.PermitExpired.selector) revert VerifyingPaymaster.PermitExpired();
                if (selector == VerifyingPaymaster.MalformedPermitData.selector) revert VerifyingPaymaster.MalformedPermitData();
            }
            assembly { revert(add(returnData, 32), mload(returnData)) }
        }

        (, uint256 validationData) = abi.decode(returnData, (bytes, uint256));
        return validationData;
    }

    // ── Tests ────────────────────────────────────────────────────────

    function test_validPermitPasses() public {
        bytes32 userOpHash = keccak256("test-op-1");
        uint64 validUntil = uint64(block.timestamp + 1 hours);
        bytes memory paymasterData = _buildPaymasterAndData(userOpHash, validUntil, POLICY_ROOT, PERMIT_SIGNER_KEY);

        uint256 result = _callValidate(userOpHash, paymasterData);
        assertEq(result, 0, "validationData should be 0 (success)");
    }

    function test_expiredPermitReverts() public {
        bytes32 userOpHash = keccak256("test-op-expired");
        uint64 expiredUntil = uint64(block.timestamp - 1);
        bytes memory paymasterData = _buildPaymasterAndData(userOpHash, expiredUntil, POLICY_ROOT, PERMIT_SIGNER_KEY);

        vm.expectRevert(VerifyingPaymaster.PermitExpired.selector);
        _callValidate(userOpHash, paymasterData);
    }

    function test_wrongSignerRejected() public {
        bytes32 userOpHash = keccak256("test-op-wrong-key");
        uint64 validUntil = uint64(block.timestamp + 1 hours);
        bytes memory paymasterData = _buildPaymasterAndData(userOpHash, validUntil, POLICY_ROOT, WRONG_KEY);

        uint256 result = _callValidate(userOpHash, paymasterData);
        assertEq(result, 1, "validationData should be 1 (SIG_VALIDATION_FAILED)");
    }

    function test_tamperedUserOpHashRejected() public {
        uint64 validUntil = uint64(block.timestamp + 1 hours);
        bytes32 realHash = keccak256("real-op");
        bytes32 fakeHash = keccak256("tampered-op");

        // Sign with the real hash
        bytes memory paymasterData = _buildPaymasterAndData(realHash, validUntil, POLICY_ROOT, PERMIT_SIGNER_KEY);

        // But call validate with a different hash
        uint256 result = _callValidate(fakeHash, paymasterData);
        assertEq(result, 1, "validationData should be 1 (SIG_VALIDATION_FAILED)");
    }

    function test_malformedPaymasterDataTooShort() public {
        PackedUserOperation memory userOp = _dummyUserOp();
        userOp.paymasterAndData = hex"deadbeef"; // only 4 bytes

        vm.prank(address(entryPoint));
        vm.expectRevert(VerifyingPaymaster.MalformedPermitData.selector);
        paymaster.validatePaymasterUserOp(userOp, keccak256("x"), 0);
    }

    function test_depositWorks() public view {
        uint256 deposit = paymaster.getDeposit();
        assertEq(deposit, DEPOSIT_AMOUNT, "paymaster should have deposit at EntryPoint");
    }

    function test_withdrawToWorks() public {
        address payable recipient = payable(address(0xBEEF));
        uint256 before = recipient.balance;

        paymaster.withdrawTo(recipient, DEPOSIT_AMOUNT / 2);

        assertEq(recipient.balance, before + DEPOSIT_AMOUNT / 2, "recipient should receive ETH");
        assertEq(paymaster.getDeposit(), DEPOSIT_AMOUNT / 2, "deposit should decrease");
    }

    function test_addStakeWorks() public {
        paymaster.addStake{value: 0.5 ether}(100);
        // Stake is recorded at EntryPoint (no getter on stake in this version, but no revert = success)
    }
}
