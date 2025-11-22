// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {
    IVaultConfigurator
} from "@symbioticfi/core/src/interfaces/IVaultConfigurator.sol";
import {MockVault} from "./MockVault.sol";

contract MockVaultConfigurator {
    function create(
        IVaultConfigurator.InitParams calldata
    ) external returns (address, address, address) {
        MockVault vault = new MockVault();
        return (address(vault), address(0), address(0));
    }
}
