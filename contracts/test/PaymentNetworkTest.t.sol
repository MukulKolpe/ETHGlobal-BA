// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {PaymentNetwork} from "../src/PaymentNetwork.sol";
import {VotingPowers} from "../src/symbiotic/VotingPowers.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {
    IVaultConfigurator
} from "@symbioticfi/core/src/interfaces/IVaultConfigurator.sol";
import {
    IDefaultStakerRewardsFactory
} from "@symbioticfi/rewards/src/interfaces/defaultStakerRewards/IDefaultStakerRewardsFactory.sol";
import {
    IDefaultStakerRewards
} from "@symbioticfi/rewards/src/interfaces/defaultStakerRewards/IDefaultStakerRewards.sol";
import {
    IVotingPowerProvider
} from "@symbioticfi/relay-contracts/src/interfaces/modules/voting-power/IVotingPowerProvider.sol";
import {
    IOpNetVaultAutoDeploy
} from "@symbioticfi/relay-contracts/src/interfaces/modules/voting-power/extensions/IOpNetVaultAutoDeploy.sol";
import {
    IOzOwnable
} from "@symbioticfi/relay-contracts/src/interfaces/modules/common/permissions/IOzOwnable.sol";
import {
    IBaseRewards
} from "@symbioticfi/relay-contracts/src/interfaces/modules/voting-power/extensions/IBaseRewards.sol";
import {
    IBaseSlashing
} from "@symbioticfi/relay-contracts/src/interfaces/modules/voting-power/extensions/IBaseSlashing.sol";
import {
    INetworkManager
} from "@symbioticfi/relay-contracts/src/interfaces/modules/base/INetworkManager.sol";
import {
    IOzEIP712
} from "@symbioticfi/relay-contracts/src/interfaces/modules/base/IOzEIP712.sol";

import {MockERC20} from "./mocks/MockERC20.sol";
import {MockSettlement} from "./mocks/MockSettlement.sol";
import {MockVaultConfigurator} from "./mocks/MockVaultConfigurator.sol";
import {MockRewardsFactory} from "./mocks/MockRewardsFactory.sol";
import {MockRewards} from "./mocks/MockRewards.sol";
import {MockVault} from "./mocks/MockVault.sol";
import {MockSymbioticCore} from "./mocks/MockSymbioticCore.sol";

contract PaymentNetworkTest is Test {
    PaymentNetwork network;
    VotingPowers votingPowers;

    MockERC20 usdc;
    MockSettlement settlement;
    MockSymbioticCore coreMock;
    MockVaultConfigurator vaultConfigurator;
    MockRewardsFactory rewardsFactory;

    address owner = address(0x1);
    address admin = address(0x1337);
    address hacker = address(0xBAD);
    address alice = address(0xB);
    address bob = address(0xC);

    bytes32 orgA_Id = keccak256("Organization_A");
    bytes32 orgB_Id = keccak256("Organization_B");
    uint32 constant EXPIRY = 1 days;
    uint256 constant KEY_TAG_BLS = 15;

    function setUp() public {
        usdc = new MockERC20("USDC", "USDC");
        settlement = new MockSettlement();
        coreMock = new MockSymbioticCore();
        vaultConfigurator = new MockVaultConfigurator();
        rewardsFactory = new MockRewardsFactory();

        vm.prank(owner);
        votingPowers = new VotingPowers(
            address(coreMock),
            address(coreMock),
            address(vaultConfigurator)
        );

        vm.prank(owner);
        votingPowers.initialize(
            IVotingPowerProvider.VotingPowerProviderInitParams({
                networkManagerInitParams: INetworkManager
                    .NetworkManagerInitParams({
                        network: address(coreMock),
                        subnetworkId: 0
                    }),
                ozEip712InitParams: IOzEIP712.OzEIP712InitParams({
                    name: "VP",
                    version: "1"
                }),
                requireSlasher: false,
                minVaultEpochDuration: 0,
                token: address(usdc)
            }),
            IOpNetVaultAutoDeploy.OpNetVaultAutoDeployInitParams({
                isAutoDeployEnabled: false,
                config: IOpNetVaultAutoDeploy.AutoDeployConfig({
                    epochDuration: 1 days,
                    collateral: address(usdc),
                    burner: address(0),
                    withSlasher: false,
                    isBurnerHook: false
                }),
                isSetMaxNetworkLimitHookEnabled: false
            }),
            IOzOwnable.OzOwnableInitParams({owner: owner}),
            IBaseRewards.BaseRewardsInitParams({rewarder: owner}),
            IBaseSlashing.BaseSlashingInitParams({slasher: address(0)})
        );

        vm.prank(owner);
        network = new PaymentNetwork(
            address(vaultConfigurator),
            address(coreMock),
            address(coreMock),
            address(rewardsFactory),
            address(coreMock)
        );

        vm.prank(owner);
        network.initialize(
            PaymentNetwork.InitParams({
                votingPowers: address(votingPowers),
                settlement: address(settlement),
                collateral: address(usdc),
                vaultEpochDuration: 1 days,
                messageExpiry: EXPIRY,
                protocolFeeBps: 100,
                owner: owner,
                expectedKeyTag: KEY_TAG_BLS
            })
        );

        vm.prank(owner);
        votingPowers.setPaymentNetwork(address(network));

        vm.prank(owner);
        votingPowers.setRewarder(address(network));

        usdc.transfer(admin, 100_000 ether);
        vm.prank(owner);
        network.setTokenWhitelist(address(usdc), true);
    }

    function test_RegisterOrg_DeploysVault() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        (
            address savedAdmin,
            bool exists,
            address vault,
            address rewards
        ) = network.organizations(orgA_Id);
        assertTrue(exists);
        assertEq(savedAdmin, admin);
        assertTrue(vault != address(0));
        assertTrue(rewards != address(0));
    }

    function test_RegisterOrg_Fail_Duplicate() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        vm.prank(admin);
        vm.expectRevert(PaymentNetwork.OrgAlreadyExists.selector);
        network.registerOrganization(orgA_Id, admin);
    }

    function test_SetTokenWhitelist_Success() public {
        address newToken = address(0x999);
        assertFalse(network.allowedTokens(newToken));

        vm.prank(owner);
        network.setTokenWhitelist(newToken, true);
        assertTrue(network.allowedTokens(newToken));
    }

    function test_SetTokenWhitelist_Fail_NotOwner() public {
        vm.prank(hacker);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                hacker
            )
        );
        network.setTokenWhitelist(address(0x999), true);
    }

    function test_DepositLiquidity_ERC20() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        uint256 amount = 500 ether;
        vm.startPrank(admin);
        usdc.approve(address(network), amount);
        network.depositLiquidity(orgA_Id, address(usdc), amount);
        vm.stopPrank();

        assertEq(network.orgBalances(orgA_Id, address(usdc)), amount);
        assertEq(usdc.balanceOf(address(network)), amount);
        assertEq(network.totalRecordedLiquidity(address(usdc)), amount);
    }

    function test_DepositLiquidity_ETH() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        uint256 amount = 5 ether;
        vm.deal(admin, 10 ether);

        vm.prank(admin);
        network.depositETH{value: amount}(orgA_Id);

        assertEq(network.orgBalances(orgA_Id, address(0)), amount);
        assertEq(address(network).balance, amount);
        assertEq(network.totalRecordedLiquidity(address(0)), amount);
    }

    function test_BatchDepositERC20_Success() public {
        MockERC20 dai = new MockERC20("DAI", "DAI");
        dai.transfer(admin, 100_000 ether);

        vm.prank(owner);
        network.setTokenWhitelist(address(dai), true);

        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        vm.startPrank(admin);
        usdc.approve(address(network), 100 ether);
        dai.approve(address(network), 200 ether);

        address[] memory tokens = new address[](2);
        tokens[0] = address(usdc);
        tokens[1] = address(dai);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 100 ether;
        amounts[1] = 200 ether;

        network.batchDepositERC20Liquidity(orgA_Id, tokens, amounts);
        vm.stopPrank();

        assertEq(network.orgBalances(orgA_Id, address(usdc)), 100 ether);
        assertEq(network.orgBalances(orgA_Id, address(dai)), 200 ether);
    }

    function test_WithdrawERC20_Success() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        vm.startPrank(admin);
        usdc.approve(address(network), 500 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 500 ether);

        network.withdrawLiquidity(orgA_Id, address(usdc), 200 ether);
        vm.stopPrank();

        assertEq(network.orgBalances(orgA_Id, address(usdc)), 300 ether);
        assertEq(usdc.balanceOf(admin), 100_000 ether - 300 ether);
    }

    function test_WithdrawETH_Success() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        uint256 depositAmount = 5 ether;
        vm.deal(admin, 10 ether);
        vm.prank(admin);
        network.depositETH{value: depositAmount}(orgA_Id);

        uint256 preBalance = admin.balance;
        uint256 withdrawAmount = 2 ether;

        vm.prank(admin);
        network.withdrawLiquidity(orgA_Id, address(0), withdrawAmount);

        assertEq(admin.balance, preBalance + withdrawAmount);
        assertEq(network.orgBalances(orgA_Id, address(0)), 3 ether);
    }

    function test_ProcessPayout_ERC20_WithRewards() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        vm.startPrank(admin);
        usdc.approve(address(network), 1000 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 1000 ether);
        vm.stopPrank();

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(alice, 100 ether);

        uint256 votingPowersBalanceBefore = usdc.balanceOf(
            address(votingPowers)
        );

        network.processPayoutBatch(
            orgA_Id,
            keccak256("Batch1"),
            address(usdc),
            payments,
            1,
            ""
        );

        assertEq(usdc.balanceOf(alice), 100 ether);
        assertEq(network.orgBalances(orgA_Id, address(usdc)), 899 ether);
        assertEq(
            usdc.balanceOf(address(votingPowers)),
            votingPowersBalanceBefore + 1 ether
        );
    }

    function test_ProcessPayout_ETH_WithRewards() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        uint256 depositAmount = 200 ether;
        vm.deal(admin, 200 ether);
        vm.prank(admin);
        network.depositETH{value: depositAmount}(orgA_Id);

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(alice, 100 ether);

        uint256 ownerBalanceBefore = owner.balance;

        network.processPayoutBatch(
            orgA_Id,
            keccak256("BatchETH"),
            address(0),
            payments,
            1,
            ""
        );

        assertEq(alice.balance, 100 ether);
        assertEq(owner.balance, ownerBalanceBefore + 1 ether);
    }

    function test_Fail_InvalidKeyTag() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);
        vm.startPrank(admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        settlement.setKeyTag(99);

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(alice, 10 ether);

        vm.expectRevert(PaymentNetwork.InvalidKeyTag.selector);
        network.processPayoutBatch(
            orgA_Id,
            keccak256("Batch_BadKey"),
            address(usdc),
            payments,
            1,
            ""
        );
    }

    function test_Fail_SignatureExpired() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);
        vm.startPrank(admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        vm.warp(1000);
        settlement.setNextEpochTimestamp(2000);
        vm.warp(2000 + 1 days + 1);

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(alice, 10 ether);

        vm.expectRevert(PaymentNetwork.InvalidEpoch.selector);
        network.processPayoutBatch(
            orgA_Id,
            keccak256("Batch_Expired"),
            address(usdc),
            payments,
            1,
            ""
        );
    }

    function test_RescueSlashedFunds() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        usdc.transfer(address(network), 50 ether);

        assertEq(usdc.balanceOf(address(network)), 150 ether);
        assertEq(network.totalRecordedLiquidity(address(usdc)), 100 ether);

        uint256 ownerBalanceBefore = usdc.balanceOf(owner);

        vm.prank(owner);
        network.rescueSlashedFunds(address(usdc), owner);

        assertEq(usdc.balanceOf(owner), ownerBalanceBefore + 50 ether);
        assertEq(usdc.balanceOf(address(network)), 100 ether);
    }

    function test_Isolation_SeparateBalances() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        network.registerOrganization(orgB_Id, admin);
        usdc.approve(address(network), 2000 ether);

        network.depositLiquidity(orgA_Id, address(usdc), 1000 ether);
        network.depositLiquidity(orgB_Id, address(usdc), 500 ether);
        vm.stopPrank();

        PaymentNetwork.Payment[] memory p1 = new PaymentNetwork.Payment[](1);
        p1[0] = PaymentNetwork.Payment(alice, 800 ether);
        network.processPayoutBatch(
            orgA_Id,
            keccak256("A_Batch"),
            address(usdc),
            p1,
            1,
            ""
        );

        PaymentNetwork.Payment[] memory p2 = new PaymentNetwork.Payment[](1);
        p2[0] = PaymentNetwork.Payment(alice, 600 ether);

        vm.expectRevert(PaymentNetwork.InsufficientOrgLiquidity.selector);
        network.processPayoutBatch(
            orgB_Id,
            keccak256("B_Batch"),
            address(usdc),
            p2,
            1,
            ""
        );
    }

    function test_Fail_ReplayProtection() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        vm.startPrank(admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(alice, 10 ether);
        bytes32 batchId = keccak256("UniqueBatch");

        network.processPayoutBatch(
            orgA_Id,
            batchId,
            address(usdc),
            payments,
            1,
            ""
        );

        vm.expectRevert(PaymentNetwork.BatchAlreadyProcessed.selector);
        network.processPayoutBatch(
            orgA_Id,
            batchId,
            address(usdc),
            payments,
            1,
            ""
        );
    }

    function test_Withdraw_Fail_NotAdmin() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        vm.startPrank(admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        vm.prank(hacker);
        vm.expectRevert(PaymentNetwork.NotOrgAdmin.selector);
        network.withdrawLiquidity(orgA_Id, address(usdc), 50 ether);
    }

    function test_Withdraw_Fail_InsufficientBalance() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        vm.startPrank(admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);

        vm.expectRevert(PaymentNetwork.InsufficientOrgLiquidity.selector);
        network.withdrawLiquidity(orgA_Id, address(usdc), 200 ether); // Only 100 deposited
        vm.stopPrank();
    }

    function test_BatchDeposit_Fail_LengthMismatch() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        address[] memory tokens = new address[](2);
        tokens[0] = address(usdc);
        tokens[1] = address(usdc);

        uint256[] memory amounts = new uint256[](1); // Mismatch!
        amounts[0] = 100;

        vm.prank(admin);
        vm.expectRevert(PaymentNetwork.ArrayLengthMismatch.selector);
        network.batchDepositERC20Liquidity(orgA_Id, tokens, amounts);
    }

    function test_Deposit_Fail_NotWhitelisted() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        MockERC20 fakeToken = new MockERC20("FAKE", "FAKE");
        fakeToken.transfer(admin, 1000 ether);

        vm.startPrank(admin);
        fakeToken.approve(address(network), 1000 ether);

        vm.expectRevert(PaymentNetwork.TokenNotAllowed.selector);
        network.depositLiquidity(orgA_Id, address(fakeToken), 100 ether);
        vm.stopPrank();
    }

    function test_ProcessPayout_Fail_NotWhitelisted() public {
        // Token was whitelisted, funds deposited, then token removed from whitelist
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        vm.startPrank(admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        // Owner removes USDC from whitelist
        vm.prank(owner);
        network.setTokenWhitelist(address(usdc), false);

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(alice, 100 ether);

        vm.expectRevert(PaymentNetwork.TokenNotAllowed.selector);
        network.processPayoutBatch(
            orgA_Id,
            keccak256("Batch1"),
            address(usdc),
            payments,
            1,
            ""
        );
    }

    function test_Rescue_Fail_NoSurplus() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        vm.startPrank(admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        // Try to rescue when Balance == Recorded Liquidity
        vm.prank(owner);
        vm.expectRevert(PaymentNetwork.NoSlashedFundsToRescue.selector);
        network.rescueSlashedFunds(address(usdc), owner);
    }

    function test_Middleware_SetMaxLimit_Fail_Auth() public {
        vm.prank(hacker);
        vm.expectRevert(VotingPowers.NotPaymentNetwork.selector);

        votingPowers.setMaxNetworkLimit(address(0x123));
    }

    function test_ProcessPayout_MultipleRecipients() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin);

        vm.startPrank(admin);
        usdc.approve(address(network), 1000 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 1000 ether);
        vm.stopPrank();

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            3
        );
        payments[0] = PaymentNetwork.Payment(alice, 100 ether);
        payments[1] = PaymentNetwork.Payment(bob, 200 ether);
        payments[2] = PaymentNetwork.Payment(hacker, 300 ether);

        // Total Payment = 600. Fee (1%) = 6. Total Deducted = 606.

        network.processPayoutBatch(
            orgA_Id,
            keccak256("BatchMulti"),
            address(usdc),
            payments,
            1,
            ""
        );

        assertEq(usdc.balanceOf(alice), 100 ether);
        assertEq(usdc.balanceOf(bob), 200 ether);
        assertEq(usdc.balanceOf(hacker), 300 ether);
        assertEq(
            network.orgBalances(orgA_Id, address(usdc)),
            1000 ether - 606 ether
        );
    }
}
