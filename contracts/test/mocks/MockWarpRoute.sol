// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

contract MockWarpRoute {
    event RemoteTransfer(uint32 dest, bytes32 recipient, uint256 amount);
    function transferRemote(
        uint32 _d,
        bytes32 _r,
        uint256 _a
    ) external payable returns (bytes32) {
        emit RemoteTransfer(_d, _r, _a);
        return bytes32(uint256(1));
    }
}
