// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import {PaymentNetwork} from "../src/PaymentNetwork.sol";
import {VotingPowers} from "../src/symbiotic/VotingPowers.sol";
import {
    SymbioticDestinationVerifier
} from "../src/symbiotic/SymbioticDestinationVerifier.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {TypeCasts} from "@hyperlane-xyz/libs/TypeCasts.sol";

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
import {MockSymbioticCore} from "./mocks/MockSymbioticCore.sol";
import {MockVaultConfigurator} from "./mocks/MockVaultConfigurator.sol";
import {MockRewardsFactory} from "./mocks/MockRewardsFactory.sol";
import {MockWarpRoute} from "./mocks/MockWarpRoute.sol";
import {MockMailbox} from "./mocks/MockMailbox.sol";
import {MockRewards} from "./mocks/MockRewards.sol";
import {MockVault} from "./mocks/MockVault.sol";

contract PaymentNetworkTest is Test {
    using TypeCasts for address;

    PaymentNetwork network;
    VotingPowers votingPowers;
    SymbioticDestinationVerifier destVerifier;

    MockERC20 usdc;
    MockERC20 dai;
    MockSettlement settlement;
    MockSymbioticCore coreMock;
    MockVaultConfigurator vaultConfigurator;
    MockRewardsFactory rewardsFactory;
    MockWarpRoute warpRouteOP;
    MockWarpRoute warpRouteARB;
    MockMailbox mailbox;

    address owner = address(0x1);
    address admin = address(0x1337);
    address hacker = address(0xBAD);
    address alice = address(0xB);
    address bob = address(0xC);

    bytes32 orgA_Id = keccak256("Organization_A");
    bytes32 orgB_Id = keccak256("Organization_B");
    uint32 constant EXPIRY = 1 days;
    uint256 constant KEY_TAG_BLS = 15;

    uint32 constant DOMAIN_OP = 10;
    uint32 constant DOMAIN_ARB = 42161;

    event CrossChainPayoutDispatched(
        uint32 indexed destination,
        address indexed token,
        address recipient,
        uint256 amount
    );
    event ValidatorSetSynced(uint48 indexed epoch, uint256[4] key);

    function setUp() public {
        usdc = new MockERC20("USDC", "USDC");
        dai = new MockERC20("DAI", "DAI");
        settlement = new MockSettlement();
        coreMock = new MockSymbioticCore();
        vaultConfigurator = new MockVaultConfigurator();
        rewardsFactory = new MockRewardsFactory();
        warpRouteOP = new MockWarpRoute();
        warpRouteARB = new MockWarpRoute();
        mailbox = new MockMailbox();

        vm.startPrank(owner);

        votingPowers = new VotingPowers(
            address(coreMock),
            address(coreMock),
            address(vaultConfigurator)
        );
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

        network = new PaymentNetwork(
            address(vaultConfigurator),
            address(coreMock),
            address(coreMock),
            address(rewardsFactory),
            address(coreMock)
        );
        network.initialize(
            PaymentNetwork.InitParams({
                votingPowers: address(votingPowers),
                settlement: address(settlement),
                collateral: address(usdc),
                vaultEpochDuration: 1 days,
                messageExpiry: EXPIRY,
                protocolFeeBps: 100,
                owner: owner,
                expectedKeyTag: KEY_TAG_BLS,
                mailbox: address(mailbox)
            })
        );

        destVerifier = new SymbioticDestinationVerifier(
            address(mailbox),
            1, // Chain ID of source
            address(network)
        );

        votingPowers.setPaymentNetwork(address(network));
        votingPowers.setRewarder(address(network));
        network.setTokenWhitelist(address(usdc), true);
        network.setTokenWhitelist(address(dai), true);

        network.setWarpRoute(address(usdc), DOMAIN_OP, address(warpRouteOP));
        network.setWarpRoute(address(usdc), DOMAIN_ARB, address(warpRouteARB));
        network.setDestinationVerifier(
            DOMAIN_OP,
            address(destVerifier).addressToBytes32()
        );

        vm.stopPrank();
        usdc.transfer(admin, 100_000 ether);
        dai.transfer(admin, 100_000 ether);
    }

    // =========================================================
    //  ORGANIZATION SETUP
    // =========================================================

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
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        vm.expectRevert(PaymentNetwork.OrgAlreadyExists.selector);
        network.registerOrganization(orgA_Id, admin);
        vm.stopPrank();
    }

    function test_Setup_TokenWhitelist() public {
        address randomToken = address(0x999);
        assertFalse(network.allowedTokens(randomToken));
        vm.prank(owner);
        network.setTokenWhitelist(randomToken, true);
        assertTrue(network.allowedTokens(randomToken));
    }

    function test_Setup_OnlyOwnerCanWhitelist() public {
        vm.prank(hacker);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                hacker
            )
        );
        network.setTokenWhitelist(address(0x999), true);
    }

    // =========================================================
    //  LIQUIDITY MANAGEMENT
    // =========================================================

    function test_Deposit_ERC20() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 500 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 500 ether);
        vm.stopPrank();

        assertEq(network.orgBalances(orgA_Id, address(usdc)), 500 ether);
        assertEq(network.totalRecordedLiquidity(address(usdc)), 500 ether);
    }

    function test_Deposit_ETH() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        vm.deal(admin, 10 ether);
        network.depositETH{value: 5 ether}(orgA_Id);
        vm.stopPrank();

        assertEq(network.orgBalances(orgA_Id, address(0)), 5 ether);
        assertEq(address(network).balance, 5 ether);
    }

    function test_Deposit_Fail_ZeroAmount() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        vm.expectRevert(PaymentNetwork.InvalidDepositAmount.selector);
        network.depositETH{value: 0}(orgA_Id);
        vm.stopPrank();
    }

    function test_Deposit_Fail_NotWhitelisted() public {
        MockERC20 fake = new MockERC20("FAKE", "FAKE");
        fake.transfer(admin, 100 ether);
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        fake.approve(address(network), 100 ether);

        vm.expectRevert(PaymentNetwork.TokenNotAllowed.selector);
        network.depositLiquidity(orgA_Id, address(fake), 100 ether);
        vm.stopPrank();
    }

    function test_BatchDeposit_Success() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
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

    function test_BatchDeposit_Fail_LengthMismatch() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        address[] memory tokens = new address[](2);
        tokens[0] = address(usdc);
        tokens[1] = address(dai);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100 ether;

        vm.expectRevert(PaymentNetwork.ArrayLengthMismatch.selector);
        network.batchDepositERC20Liquidity(orgA_Id, tokens, amounts);
        vm.stopPrank();
    }

    function test_Withdraw_ERC20() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 500 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 500 ether);
        network.withdrawLiquidity(orgA_Id, address(usdc), 200 ether);
        vm.stopPrank();
        assertEq(network.orgBalances(orgA_Id, address(usdc)), 300 ether);
        assertEq(usdc.balanceOf(admin), 100_000 ether - 300 ether);
    }

    function test_Withdraw_ETH() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        vm.deal(admin, 10 ether);
        network.depositETH{value: 5 ether}(orgA_Id);
        uint256 preBal = admin.balance;
        network.withdrawLiquidity(orgA_Id, address(0), 2 ether);
        vm.stopPrank();
        assertEq(admin.balance, preBal + 2 ether);
    }

    function test_Withdraw_Fail_NotAdmin() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        vm.prank(hacker);
        vm.expectRevert(PaymentNetwork.NotOrgAdmin.selector);
        network.withdrawLiquidity(orgA_Id, address(usdc), 50 ether);
    }

    // =========================================================
    //  LOCAL EXECUTION
    // =========================================================

    function test_Process_Local_WithFee() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 1000 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 1000 ether);
        vm.stopPrank();

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(0, alice, 100 ether, 0);

        uint256 mwBal = usdc.balanceOf(address(votingPowers));

        network.processPayoutBatch(
            orgA_Id,
            keccak256("Local"),
            address(usdc),
            payments,
            1,
            ""
        );

        assertEq(usdc.balanceOf(alice), 100 ether);
        // 100 + 1% fee = 101
        assertEq(network.orgBalances(orgA_Id, address(usdc)), 899 ether);
        assertEq(usdc.balanceOf(address(votingPowers)), mwBal + 1 ether);
    }

    function test_Process_Fail_InsufficientLiquidity() public {
        vm.prank(admin);
        network.registerOrganization(orgA_Id, admin); // No deposit
        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(0, alice, 100 ether, 0);

        vm.expectRevert(PaymentNetwork.InsufficientOrgLiquidity.selector);
        network.processPayoutBatch(
            orgA_Id,
            keccak256("Fail"),
            address(usdc),
            payments,
            1,
            ""
        );
    }

    function test_Process_Fail_TokenRemovedFromWhitelist() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        vm.prank(owner);
        network.setTokenWhitelist(address(usdc), false);

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(0, alice, 50 ether, 0);

        vm.expectRevert(PaymentNetwork.TokenNotAllowed.selector);
        network.processPayoutBatch(
            orgA_Id,
            keccak256("FailW"),
            address(usdc),
            payments,
            1,
            ""
        );
    }

    // =========================================================
    //  CROSS-CHAIN EXECUTION
    // =========================================================

    function test_CrossChain_Single() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 1000 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 1000 ether);
        vm.stopPrank();

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(
            DOMAIN_OP,
            alice,
            100 ether,
            0.01 ether
        );

        vm.deal(address(this), 1 ether);
        vm.expectEmit(true, true, false, true);
        emit CrossChainPayoutDispatched(
            DOMAIN_OP,
            address(usdc),
            alice,
            100 ether
        );

        network.processPayoutBatch{value: 0.01 ether}(
            orgA_Id,
            keccak256("Cross1"),
            address(usdc),
            payments,
            1,
            ""
        );
        assertEq(network.orgBalances(orgA_Id, address(usdc)), 899 ether);
    }

    function test_CrossChain_MultiDest() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 1000 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 1000 ether);
        vm.stopPrank();

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            3
        );
        payments[0] = PaymentNetwork.Payment(
            DOMAIN_OP,
            alice,
            100 ether,
            0.01 ether
        );
        payments[1] = PaymentNetwork.Payment(
            DOMAIN_ARB,
            bob,
            200 ether,
            0.02 ether
        );
        payments[2] = PaymentNetwork.Payment(0, hacker, 50 ether, 0); // Local

        vm.deal(address(this), 1 ether);
        network.processPayoutBatch{value: 0.03 ether}(
            orgA_Id,
            keccak256("Multi"),
            address(usdc),
            payments,
            1,
            ""
        );

        assertEq(usdc.balanceOf(hacker), 50 ether);
        assertEq(network.orgBalances(orgA_Id, address(usdc)), 646.5 ether);
    }

    function test_CrossChain_Fail_Gas() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(
            DOMAIN_OP,
            alice,
            10 ether,
            0.05 ether
        );

        vm.deal(address(this), 0.01 ether);
        vm.expectRevert(PaymentNetwork.InsufficientBridgeFee.selector);
        network.processPayoutBatch{value: 0.01 ether}(
            orgA_Id,
            keccak256("FailG"),
            address(usdc),
            payments,
            1,
            ""
        );
    }

    function test_CrossChain_Fail_NoRoute() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 1000 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 1000 ether);
        vm.stopPrank();

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(9999, alice, 100 ether, 0);

        vm.expectRevert(PaymentNetwork.RouteNotConfigured.selector);
        network.processPayoutBatch(
            orgA_Id,
            keccak256("NoRoute"),
            address(usdc),
            payments,
            1,
            ""
        );
    }

    function test_Security_ReplayProtection() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(0, alice, 10 ether, 0);
        bytes32 batchId = keccak256("Replay");

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

    function test_Security_InvalidKeyTag() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        settlement.setKeyTag(99);
        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(0, alice, 10 ether, 0);

        vm.expectRevert(PaymentNetwork.InvalidKeyTag.selector);
        network.processPayoutBatch(
            orgA_Id,
            keccak256("BadKey"),
            address(usdc),
            payments,
            1,
            ""
        );
    }

    function test_Security_SignatureExpired() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        vm.warp(1000);
        settlement.setNextEpochTimestamp(2000);
        vm.warp(2000 + 1 days + 1);

        PaymentNetwork.Payment[] memory payments = new PaymentNetwork.Payment[](
            1
        );
        payments[0] = PaymentNetwork.Payment(0, alice, 10 ether, 0);

        vm.expectRevert(PaymentNetwork.InvalidEpoch.selector);
        network.processPayoutBatch(
            orgA_Id,
            keccak256("Exp"),
            address(usdc),
            payments,
            1,
            ""
        );
    }

    function test_Security_Isolation() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        network.registerOrganization(orgB_Id, admin);
        usdc.approve(address(network), 2000 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 1000 ether);
        network.depositLiquidity(orgB_Id, address(usdc), 500 ether);
        vm.stopPrank();

        PaymentNetwork.Payment[] memory p1 = new PaymentNetwork.Payment[](1);
        p1[0] = PaymentNetwork.Payment(0, alice, 600 ether, 0);

        // Org B only has 500, tries to spend 600
        vm.expectRevert(PaymentNetwork.InsufficientOrgLiquidity.selector);
        network.processPayoutBatch(
            orgB_Id,
            keccak256("FailIso"),
            address(usdc),
            p1,
            1,
            ""
        );
    }

    function test_Security_MiddlewareAuth() public {
        vm.prank(hacker);
        vm.expectRevert(VotingPowers.NotPaymentNetwork.selector);
        votingPowers.setMaxNetworkLimit(address(0x123));
    }

    // =========================================================
    //  ACCOUNTING
    // =========================================================

    function test_Accounting_RescueSlashed() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        // Simulate Slash
        usdc.transfer(address(network), 50 ether);

        uint256 bal = usdc.balanceOf(owner);
        vm.prank(owner);
        network.rescueSlashedFunds(address(usdc), owner);
        assertEq(usdc.balanceOf(owner), bal + 50 ether);
    }

    function test_Accounting_Rescue_Fail() public {
        vm.startPrank(admin);
        network.registerOrganization(orgA_Id, admin);
        usdc.approve(address(network), 100 ether);
        network.depositLiquidity(orgA_Id, address(usdc), 100 ether);
        vm.stopPrank();

        vm.prank(owner);
        vm.expectRevert(PaymentNetwork.NoSlashedFundsToRescue.selector);
        network.rescueSlashedFunds(address(usdc), owner);
    }

    // =========================================================
    //  DESTINATION VERIFICATION
    // =========================================================

    function test_Dest_Sync() public {
        uint48 epoch = 1;
        uint256[4] memory key = [uint256(1), 2, 3, 4];

        vm.expectEmit(true, true, false, true);
        emit MockMailbox.Dispatch(
            DOMAIN_OP,
            address(destVerifier).addressToBytes32(),
            abi.encode(epoch, key)
        );

        network.syncValidatorSet{value: 0.1 ether}(DOMAIN_OP, key);

        vm.prank(address(mailbox));
        emit ValidatorSetSynced(epoch, key);
        destVerifier.handle(
            1,
            address(network).addressToBytes32(),
            abi.encode(epoch, key)
        );

        uint256 x1 = destVerifier.epochKeys(epoch, 0);
        assertEq(x1, 1);
    }

    function test_Dest_Verify_Fail_NotSynced() public {
        uint48 epoch = 99;
        uint256[2] memory sig = [uint256(9), 9];
        bytes32 hash = keccak256("payload");

        vm.expectRevert(SymbioticDestinationVerifier.EpochNotSynced.selector);
        destVerifier.verifySymbioticProof(hash, epoch, sig);
    }
}
