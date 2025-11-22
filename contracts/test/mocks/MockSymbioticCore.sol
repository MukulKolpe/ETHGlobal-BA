// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

contract MockSymbioticCore {
    function registerOperator() external {}
    function optIn(address) external {}
    function NETWORK() external pure returns (address) {
        return address(0x1);
    }
    function SUBNETWORK_IDENTIFIER() external pure returns (bytes32) {
        return bytes32(0);
    }
    function setMaxNetworkLimit(address, uint96, uint256) external {}
}
