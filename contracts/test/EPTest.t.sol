// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {UserOperationLib} from "@eth-infinitism/account-abstraction/core/UserOperationLib.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

contract EPTest is Test {
    function test_reference_impl_hash_matches_manual() public {
        EntryPoint ep = new EntryPoint();
        
        address account = address(0xb044a63D8eD406bdAAD3Db50f79F2cbC1f734e10);
        address mockVault = address(0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6);
        
        bytes memory executeCallData = abi.encodeWithSignature(
            "execute(address,uint256,bytes)", mockVault, 0, ""
        );
        bytes32 accountGasLimits = bytes32((uint256(1200000) << 128) | uint256(100000));
        bytes32 gasFees = bytes32((uint256(1) << 128) | uint256(1));

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: executeCallData,
            accountGasLimits: accountGasLimits,
            preVerificationGas: 0,
            gasFees: gasFees,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 onchainHash = ep.getUserOpHash(userOp);
        console2.log("onchain hash:");
        console2.logBytes32(onchainHash);

        // Manual computation matching reference-implementation
        bytes32 structHash = keccak256(abi.encode(
            account,
            uint256(0),
            keccak256(""),
            keccak256(executeCallData),
            accountGasLimits,
            uint256(0),
            gasFees,
            keccak256("")
        ));
        
        bytes32 manualHash = keccak256(abi.encode(structHash, address(ep), block.chainid));
        
        console2.log("manual hash:");
        console2.logBytes32(manualHash);
        console2.log("match:", onchainHash == manualHash);
        assertEq(onchainHash, manualHash, "manual hash must match on-chain");
    }
}
