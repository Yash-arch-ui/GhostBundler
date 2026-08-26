// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockUSDC} from "./MockUSDC.sol";

/// @title MockVault
/// @notice Holds MockUSDC balance. Intentionally allows global-validation draining for demo purposes.
/// @dev DANGER: allowGlobalValidation-style dangerous — any global validator on a linked account can call drain().
contract MockVault {
    MockUSDC public immutable token;

    // Flag: this vault is intentionally vulnerable to global validation drain paths
    bool public constant ALLOW_GLOBAL_VALIDATION = true;

    constructor(address _token) {
        token = MockUSDC(_token);
    }

    function drain(address to) external {
        uint256 bal = token.balanceOf(address(this));
        require(bal > 0, "nothing to drain");
        token.transfer(to, bal);
    }

    receive() external payable {}
}
