// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {ReferenceModularAccount} from "reference-implementation/src/account/ReferenceModularAccount.sol";
import {SemiModularAccount} from "reference-implementation/src/account/SemiModularAccount.sol";
import {AccountFactory} from "reference-implementation/src/account/AccountFactory.sol";
import {SingleSignerValidationModule} from "reference-implementation/src/modules/validation/SingleSignerValidationModule.sol";
import {ValidationConfigLib} from "reference-implementation/src/libraries/ValidationConfigLib.sol";
import {ModuleEntityLib} from "reference-implementation/src/libraries/ModuleEntityLib.sol";
import {IERC6900Account, ModuleEntity, ValidationFlags} from "reference-implementation/src/interfaces/IERC6900Account.sol";
import {IERC6900AccountView, ValidationDataView} from "reference-implementation/src/interfaces/IERC6900AccountView.sol";

import {MockUSDC} from "../src/MockUSDC.sol";
import {MockVault} from "../src/MockVault.sol";

contract DeployTest is Test {
    using MessageHashUtils for bytes32;

    EntryPoint entryPoint;
    SingleSignerValidationModule singleSigner;
    AccountFactory factory;
    ReferenceModularAccount account;

    address owner;
    uint256 ownerKey;
    address sessionKey;
    uint256 sessionKeyKey;

    address payable beneficiary;

    ModuleEntity ownerValidation;
    ModuleEntity sessionKeyValidation;

    MockUSDC usdc;
    MockVault vault;

    uint256 constant MINT_AMOUNT = 1000e6;

    function setUp() public {
        ownerKey = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        owner = vm.addr(ownerKey);
        sessionKeyKey = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
        sessionKey = vm.addr(sessionKeyKey);
        beneficiary = payable(makeAddr("beneficiary"));

        entryPoint = new EntryPoint();
        singleSigner = new SingleSignerValidationModule();

        ReferenceModularAccount refImpl = new ReferenceModularAccount(IEntryPoint(address(entryPoint)));
        SemiModularAccount semiImpl = new SemiModularAccount(IEntryPoint(address(entryPoint)));

        factory = new AccountFactory(
            IEntryPoint(address(entryPoint)),
            refImpl,
            semiImpl,
            address(singleSigner),
            owner
        );

        account = factory.createAccount(owner, 0, 0);
        vm.deal(address(account), 10 ether);

        ownerValidation = ModuleEntityLib.pack(address(singleSigner), 0);
        sessionKeyValidation = ModuleEntityLib.pack(address(singleSigner), 1);

        // Factory installed entityId 0 with isGlobal=true.
        // Uninstall, reinstall with isGlobal=false.
        vm.prank(address(account));
        account.uninstallValidation(
            ownerValidation,
            abi.encode(uint32(0)),
            new bytes[](0)
        );

        vm.prank(address(account));
        account.installValidation(
            ValidationConfigLib.pack(address(singleSigner), 0, false, true, true),
            new bytes4[](0),
            abi.encode(uint32(0), owner),
            new bytes[](0)
        );

        // Install entityId 1 = session key, isGlobal=true
        vm.prank(address(account));
        account.installValidation(
            ValidationConfigLib.pack(address(singleSigner), 1, true, true, true),
            new bytes4[](0),
            abi.encode(uint32(1), sessionKey),
            new bytes[](0)
        );

        // Deploy mocks
        usdc = new MockUSDC();
        vault = new MockVault(address(usdc));
        usdc.mint(address(vault), MINT_AMOUNT);
    }

    function test_accountDeployed() public view {
        assertTrue(address(account).code.length > 0, "account should have code");
    }

    function test_ownerValidatorIsNotGlobal() public view {
        ValidationDataView memory data = account.getValidationData(ownerValidation);
        assertFalse(
            ValidationConfigLib.isGlobal(data.validationFlags),
            "owner validator should NOT be global"
        );
        assertTrue(
            ValidationConfigLib.isUserOpValidation(data.validationFlags),
            "owner validator should support userOp validation"
        );
    }

    function test_sessionKeyValidatorIsGlobal() public view {
        ValidationDataView memory data = account.getValidationData(sessionKeyValidation);
        assertTrue(
            ValidationConfigLib.isGlobal(data.validationFlags),
            "session key validator SHOULD be global"
        );
    }

    function test_signerIsCorrect() public view {
        assertEq(
            singleSigner.signers(0, address(account)),
            owner,
            "entityId 0 signer should be owner"
        );
        assertEq(
            singleSigner.signers(1, address(account)),
            sessionKey,
            "entityId 1 signer should be session key"
        );
    }

    function test_vaultDrainViaSessionKeyGlobalValidation() public {
        // Verify pre-conditions
        assertEq(usdc.balanceOf(address(vault)), MINT_AMOUNT, "vault should hold USDC");
        assertEq(usdc.balanceOf(address(account)), 0, "account should have no USDC");

        // Build callData: account.execute(vault, 0, vault.drain(account))
        bytes memory callData = abi.encodeCall(
            IERC6900Account.execute,
            (address(vault), 0, abi.encodeWithSelector(MockVault.drain.selector, address(account)))
        );

        // Build UserOp signed by session key
        PackedUserOperation memory userOp = _buildUserOp(callData);
        userOp.signature = _signWithSessionKey(userOp);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        entryPoint.handleOps(ops, beneficiary);

        // Assert drain succeeded
        assertEq(usdc.balanceOf(address(vault)), 0, "vault should be drained");
        assertEq(usdc.balanceOf(address(account)), MINT_AMOUNT, "account should hold all USDC");
    }

    function _buildUserOp(bytes memory callData) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(account),
            nonce: entryPoint.getNonce(address(account), 0),
            initCode: hex"",
            callData: callData,
            accountGasLimits: _encodeGas(1_200_000, 100_000),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _signWithSessionKey(PackedUserOperation memory userOp) internal view returns (bytes memory) {
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionKeyKey, userOpHash.toEthSignedMessageHash());
        bytes memory ecSig = abi.encodePacked(r, s, v);

        return abi.encodePacked(
            sessionKeyValidation,
            uint8(1),
            uint8(type(uint8).max),
            ecSig
        );
    }

    function _encodeGas(uint256 g1, uint256 g2) internal pure returns (bytes32) {
        return bytes32(uint256((g1 << 128) + uint128(g2)));
    }
}
