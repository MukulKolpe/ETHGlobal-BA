// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
contract MockMailbox {
    event Dispatch(uint32 dest, bytes32 recipient, bytes body);
    function dispatch(
        uint32 _d,
        bytes32 _r,
        bytes calldata _b
    ) external payable returns (bytes32) {
        emit Dispatch(_d, _r, _b);
        return bytes32(uint256(1));
    }
}
