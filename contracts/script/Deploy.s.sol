// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {ReferenceModularAccount} from "reference-implementation/src/account/ReferenceModularAccount.sol";
import {SemiModularAccount} from "reference-implementation/src/account/SemiModularAccount.sol";
import {AccountFactory} from "reference-implementation/src/account/AccountFactory.sol";
import {SingleSignerValidationModule} from "reference-implementation/src/modules/validation/SingleSignerValidationModule.sol";
import {ValidationConfigLib} from "reference-implementation/src/libraries/ValidationConfigLib.sol";
import {ModuleEntityLib} from "reference-implementation/src/libraries/ModuleEntityLib.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address owner = vm.addr(deployerKey);
        address sessionKey = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

        // --- Phase 1: Deploy contracts (broadcast) ---
        vm.startBroadcast(deployerKey);

        EntryPoint entryPoint = new EntryPoint();
        SingleSignerValidationModule singleSigner = new SingleSignerValidationModule();
        ReferenceModularAccount refImpl = new ReferenceModularAccount(IEntryPoint(address(entryPoint)));
        SemiModularAccount semiImpl = new SemiModularAccount(IEntryPoint(address(entryPoint)));
        AccountFactory factory = new AccountFactory(
            IEntryPoint(address(entryPoint)),
            refImpl,
            semiImpl,
            address(singleSigner),
            owner
        );
        ReferenceModularAccount account = factory.createAccount(owner, 0, 0);

        vm.stopBroadcast();

        // --- Phase 2: Configure validators (prank as account, not broadcast) ---
        // Fund account for gas
        vm.deal(address(account), 1 ether);

        // Factory installed entityId 0 with isGlobal=true.
        // Uninstall it and reinstall with isGlobal=false (scoped).
        vm.prank(address(account));
        account.uninstallValidation(
            ModuleEntityLib.pack(address(singleSigner), 0),
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

        // Install entityId 1 = session key, isGlobal=true (intentionally unsafe)
        vm.prank(address(account));
        account.installValidation(
            ValidationConfigLib.pack(address(singleSigner), 1, true, true, true),
            new bytes4[](0),
            abi.encode(uint32(1), sessionKey),
            new bytes[](0)
        );

        // --- Phase 3: Log everything ---
        console.log("====================================");
        console.log("  GHOSTBUNDLER DEPLOYED ADDRESSES");
        console.log("====================================");
        console.log("EntryPoint:             ", address(entryPoint));
        console.log("SingleSignerValidation: ", address(singleSigner));
        console.log("AccountFactory:         ", address(factory));
        console.log("Account:                ", address(account));
        console.log("Owner:                  ", owner);
        console.log("Session Key:            ", sessionKey);
        console.log("====================================");
    }
}
