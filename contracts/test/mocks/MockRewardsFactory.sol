// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {
    IDefaultStakerRewards
} from "@symbioticfi/rewards/src/interfaces/defaultStakerRewards/IDefaultStakerRewards.sol";
import {MockRewards} from "./MockRewards.sol";

contract MockRewardsFactory {
    function create(
        IDefaultStakerRewards.InitParams calldata
    ) external returns (address) {
        MockRewards rewards = new MockRewards();
        return address(rewards);
    }
}
