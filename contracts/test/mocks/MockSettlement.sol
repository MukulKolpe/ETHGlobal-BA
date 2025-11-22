// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

contract MockSettlement {
    bool public shouldVerifySucceed = true;
    uint48 public nextEpochTimestamp = 0;
    uint8 public currentKeyTag = 15;

    function setVerifySucceed(bool _status) external {
        shouldVerifySucceed = _status;
    }
    function setNextEpochTimestamp(uint48 _timestamp) external {
        nextEpochTimestamp = _timestamp;
    }
    function setKeyTag(uint8 _tag) external {
        currentKeyTag = _tag;
    }

    function verifyQuorumSigAt(
        bytes calldata,
        uint8,
        uint256,
        bytes calldata,
        uint48,
        bytes calldata
    ) external view returns (bool) {
        return shouldVerifySucceed;
    }

    function getCaptureTimestampFromValSetHeaderAt(
        uint48
    ) external view returns (uint48) {
        return nextEpochTimestamp;
    }

    function getRequiredKeyTagFromValSetHeaderAt(
        uint48
    ) external view returns (uint8) {
        return currentKeyTag;
    }

    function getQuorumThresholdFromValSetHeaderAt(
        uint48
    ) external pure returns (uint256) {
        return 0;
    }

    fallback() external {
        bool s = shouldVerifySucceed;
        assembly {
            mstore(0, s)
            return(0, 32)
        }
    }
}
