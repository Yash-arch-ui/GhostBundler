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

import {RiskGate} from "../src/RiskGate.sol";
import {MockUSDC} from "../src/MockUSDC.sol";
import {MockVault} from "../src/MockVault.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address owner = vm.addr(deployerKey);
        address sessionKey = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

        // --- Phase 1: Deploy contracts ---
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

        RiskGate riskGate = new RiskGate();
        MockUSDC usdc = new MockUSDC();
        MockVault vault = new MockVault(address(usdc));

        // Fund account for EntryPoint gas prefund
        (bool sent,) = address(account).call{value: 1 ether}("");
        require(sent, "ETH transfer failed");

        vm.stopBroadcast();

        // --- Phase 2: Fund vault with USDC (cheatcode, no broadcast needed) ---
        usdc.mint(address(vault), 1000e6);

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
        console.log("RiskGate:               ", address(riskGate));
        console.log("MockUSDC:               ", address(usdc));
        console.log("MockVault:              ", address(vault));
        console.log("====================================");
    }
}
