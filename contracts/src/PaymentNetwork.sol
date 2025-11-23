// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {VotingPowers} from "./symbiotic/VotingPowers.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {TypeCasts} from "@hyperlane-xyz/libs/TypeCasts.sol";

import {
    IBaseDelegator
} from "@symbioticfi/core/src/interfaces/delegator/IBaseDelegator.sol";
import {
    IBaseRewards
} from "@symbioticfi/relay-contracts/src/interfaces/modules/voting-power/extensions/IBaseRewards.sol";
import {
    IBaseSlasher
} from "@symbioticfi/core/src/interfaces/slasher/IBaseSlasher.sol";
import {
    IBaseSlashing
} from "@symbioticfi/relay-contracts/src/interfaces/modules/voting-power/extensions/IBaseSlashing.sol";
import {
    IDefaultStakerRewardsFactory
} from "@symbioticfi/rewards/src/interfaces/defaultStakerRewards/IDefaultStakerRewardsFactory.sol";
import {
    IDefaultStakerRewards
} from "@symbioticfi/rewards/src/interfaces/defaultStakerRewards/IDefaultStakerRewards.sol";
import {
    INetworkManager
} from "@symbioticfi/relay-contracts/src/interfaces/modules/base/INetworkManager.sol";
import {
    IOperatorNetworkSpecificDelegator
} from "@symbioticfi/core/src/interfaces/delegator/IOperatorNetworkSpecificDelegator.sol";
import {
    IOperatorRegistry
} from "@symbioticfi/core/src/interfaces/IOperatorRegistry.sol";
import {
    IOptInService
} from "@symbioticfi/core/src/interfaces/service/IOptInService.sol";
import {
    ISettlement
} from "@symbioticfi/relay-contracts/src/interfaces/modules/settlement/ISettlement.sol";
import {ISlasher} from "@symbioticfi/core/src/interfaces/slasher/ISlasher.sol";
import {
    IVaultConfigurator
} from "@symbioticfi/core/src/interfaces/IVaultConfigurator.sol";
import {IVault} from "@symbioticfi/core/src/interfaces/vault/IVault.sol";
import {
    IVotingPowerProvider
} from "@symbioticfi/relay-contracts/src/interfaces/modules/voting-power/IVotingPowerProvider.sol";
import {
    NetworkManager
} from "@symbioticfi/relay-contracts/src/modules/base/NetworkManager.sol";
import {
    Subnetwork
} from "@symbioticfi/core/src/contracts/libraries/Subnetwork.sol";

interface ITokenRouter {
    function transferRemote(
        uint32 _destination,
        bytes32 _recipient,
        uint256 _amountOrId
    ) external payable returns (bytes32 messageId);
}

interface IMailbox {
    function dispatch(
        uint32 _destinationDomain,
        bytes32 _recipientAddress,
        bytes calldata _messageBody
    ) external payable returns (bytes32);
}

/**
 * @title PaymentNetwork
 * @notice Handles liquidity management, organization registration, Orchestrates multi-chain multi-token payments secured by Symbiotic Relay.
 */
contract PaymentNetwork is NetworkManager, Ownable {
    using SafeERC20 for IERC20;
    using Subnetwork for bytes32;
    using TypeCasts for address;

    // --- Errors ---
    error NotOrgAdmin();
    error InsufficientOrgLiquidity();
    error OrgAlreadyExists();
    error OrgDoesNotExist();
    error BatchAlreadyProcessed();
    error SignatureVerificationFailed();
    error InvalidEpoch();
    error ArrayLengthMismatch();
    error TokenNotAllowed();
    error ETHTransferFailed();
    error InvalidDepositAmount();
    error FeeTransferFailed();
    error InvalidKeyTag();
    error NoSlashedFundsToRescue();
    error RouteNotConfigured();
    error InsufficientBridgeFee();

    // --- Events ---
    event OrganizationRegistered(
        bytes32 indexed orgId,
        address indexed admin,
        address vault,
        address rewards
    );
    event LiquidityDeposited(
        bytes32 indexed orgId,
        address indexed token,
        uint256 amount
    );
    event LiquidityWithdrawn(
        bytes32 indexed orgId,
        address indexed token,
        uint256 amount
    );
    event PayoutProcessed(
        bytes32 indexed orgId,
        bytes32 batchId,
        uint256 totalAmount,
        uint256 feesPaid
    );
    event TokenWhitelistUpdated(address indexed token, bool isAllowed);
    event SlashedFundsRescued(address indexed token, uint256 amount);
    event WarpRouteSet(
        address indexed token,
        uint32 indexed destination,
        address route
    );
    event CrossChainPayoutDispatched(
        uint32 indexed destination,
        address indexed token,
        address recipient,
        uint256 amount
    );

    // --- Structs ---
    struct Organization {
        address admin;
        bool exists;
        address activeVault;
        address rewardContract;
    }

    struct Payment {
        uint32 destinationDomain; // 0 for Local, >0 for Destination Chain ID
        address recipient;
        uint256 amount;
        uint256 bridgeFee; // Native Token required for Hyperlane Gas
    }

    struct InitParams {
        address votingPowers;
        address settlement;
        address collateral;
        uint48 vaultEpochDuration;
        uint32 messageExpiry;
        uint256 protocolFeeBps;
        address owner;
        uint256 expectedKeyTag;
        address mailbox;
    }

    // --- Constants ---
    bytes32 internal constant BATCH_TYPEHASH =
        keccak256(
            "PaymentBatch(bytes32 orgId,bytes32 batchId,address token,Payment[] payments)"
        );
    address public constant ETH_ADDRESS = address(0);

    address public immutable VAULT_CONFIGURATOR;
    address public immutable DEFAULT_STAKER_REWARDS_FACTORY;
    address public immutable OPERATOR_VAULT_OPT_IN_SERVICE;
    address public immutable OPERATOR_NETWORK_OPT_IN_SERVICE;
    address public immutable OPERATOR_REGISTRY;

    address public votingPowers;
    address public settlement;
    address public defaultCollateral;
    address public mailbox;
    uint48 public vaultEpochDuration;
    uint32 public messageExpiry;
    uint256 public protocolFeeBps;
    uint256 public expectedKeyTag;

    mapping(bytes32 => Organization) public organizations;
    mapping(bytes32 => mapping(address => uint256)) public orgBalances;
    mapping(address => uint256) public totalRecordedLiquidity;
    mapping(bytes32 => bool) public processedBatches;
    mapping(address => bool) public allowedTokens;

    // Token -> Destination chain Id -> Warp Route Address
    mapping(address => mapping(uint32 => address)) public warpRoutes;

    // Destination Verification: Chain ID -> Verifier Address on Dest Chain
    mapping(uint32 => bytes32) public destinationVerifiers;

    constructor(
        address vaultConfigurator,
        address operatorVaultOptInService,
        address operatorNetworkOptInService,
        address defaultStakerRewardsFactory,
        address operatorRegistry
    ) Ownable(msg.sender) {
        VAULT_CONFIGURATOR = vaultConfigurator;
        OPERATOR_VAULT_OPT_IN_SERVICE = operatorVaultOptInService;
        OPERATOR_NETWORK_OPT_IN_SERVICE = operatorNetworkOptInService;
        DEFAULT_STAKER_REWARDS_FACTORY = defaultStakerRewardsFactory;
        OPERATOR_REGISTRY = operatorRegistry;
    }

    function initialize(InitParams calldata initParams) external initializer {
        votingPowers = initParams.votingPowers;
        settlement = initParams.settlement;
        defaultCollateral = initParams.collateral;
        vaultEpochDuration = initParams.vaultEpochDuration;
        messageExpiry = initParams.messageExpiry;
        protocolFeeBps = initParams.protocolFeeBps;
        expectedKeyTag = initParams.expectedKeyTag;
        mailbox = initParams.mailbox;

        _transferOwnership(initParams.owner);

        allowedTokens[ETH_ADDRESS] = true;
        if (defaultCollateral != address(0)) {
            allowedTokens[defaultCollateral] = true;
        }
        emit TokenWhitelistUpdated(ETH_ADDRESS, true);

        __NetworkManager_init(
            INetworkManager.NetworkManagerInitParams({
                network: INetworkManager(votingPowers).NETWORK(),
                subnetworkId: INetworkManager(votingPowers)
                    .SUBNETWORK_IDENTIFIER()
            })
        );

        IOperatorRegistry(OPERATOR_REGISTRY).registerOperator();
        IOptInService(OPERATOR_NETWORK_OPT_IN_SERVICE).optIn(NETWORK());
    }

    function setWarpRoute(
        address token,
        uint32 destination,
        address route
    ) external onlyOwner {
        warpRoutes[token][destination] = route;
        emit WarpRouteSet(token, destination, route);
    }

    function setTokenWhitelist(
        address token,
        bool isAllowed
    ) external onlyOwner {
        allowedTokens[token] = isAllowed;
        emit TokenWhitelistUpdated(token, isAllowed);
    }

    function setDestinationVerifier(
        uint32 domain,
        bytes32 verifier
    ) external onlyOwner {
        destinationVerifiers[domain] = verifier;
    }

    // ==========================================
    //  Organization & Liquidity
    // ==========================================

    function registerOrganization(bytes32 orgId, address admin) external {
        if (organizations[orgId].exists) revert OrgAlreadyExists();

        (address vault, , ) = IVaultConfigurator(VAULT_CONFIGURATOR).create(
            IVaultConfigurator.InitParams({
                version: 1,
                owner: address(this),
                vaultParams: abi.encode(
                    IVault.InitParams({
                        collateral: defaultCollateral,
                        burner: address(this),
                        epochDuration: vaultEpochDuration,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: address(0),
                        depositWhitelistSetRoleHolder: address(0),
                        depositorWhitelistRoleHolder: address(0),
                        isDepositLimitSetRoleHolder: address(0),
                        depositLimitSetRoleHolder: address(0)
                    })
                ),
                delegatorIndex: uint64(
                    IVotingPowerProvider.DelegatorType.OPERATOR_NETWORK_SPECIFIC
                ),
                delegatorParams: abi.encode(
                    IOperatorNetworkSpecificDelegator.InitParams({
                        baseParams: IBaseDelegator.BaseParams({
                            defaultAdminRoleHolder: address(this),
                            hook: address(0),
                            hookSetRoleHolder: address(this)
                        }),
                        network: NETWORK(),
                        operator: address(this)
                    })
                ),
                withSlasher: true,
                slasherIndex: uint64(IVotingPowerProvider.SlasherType.INSTANT),
                slasherParams: abi.encode(
                    ISlasher.InitParams({
                        baseParams: IBaseSlasher.BaseParams({
                            isBurnerHook: false
                        })
                    })
                )
            })
        );

        IOptInService(OPERATOR_VAULT_OPT_IN_SERVICE).optIn(vault);
        VotingPowers(votingPowers).setMaxNetworkLimit(vault);

        address rewards = IDefaultStakerRewardsFactory(
            DEFAULT_STAKER_REWARDS_FACTORY
        ).create(
                IDefaultStakerRewards.InitParams({
                    vault: vault,
                    adminFee: 0,
                    defaultAdminRoleHolder: address(0),
                    adminFeeClaimRoleHolder: address(0),
                    adminFeeSetRoleHolder: address(0)
                })
            );

        organizations[orgId] = Organization({
            admin: admin,
            exists: true,
            activeVault: vault,
            rewardContract: rewards
        });

        emit OrganizationRegistered(orgId, admin, vault, rewards);
    }

    function depositETH(bytes32 orgId) external payable {
        if (!organizations[orgId].exists) revert OrgDoesNotExist();
        if (!allowedTokens[ETH_ADDRESS]) revert TokenNotAllowed();
        if (msg.value == 0) revert InvalidDepositAmount();

        orgBalances[orgId][ETH_ADDRESS] += msg.value;
        totalRecordedLiquidity[ETH_ADDRESS] += msg.value;
        emit LiquidityDeposited(orgId, ETH_ADDRESS, msg.value);
    }

    function depositLiquidity(
        bytes32 orgId,
        address token,
        uint256 amount
    ) external {
        if (!organizations[orgId].exists) revert OrgDoesNotExist();
        if (!allowedTokens[token]) revert TokenNotAllowed();
        if (token == ETH_ADDRESS) revert InvalidDepositAmount();

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        orgBalances[orgId][token] += amount;
        totalRecordedLiquidity[token] += amount;

        emit LiquidityDeposited(orgId, token, amount);
    }

    function batchDepositERC20Liquidity(
        bytes32 orgId,
        address[] calldata tokens,
        uint256[] calldata amounts
    ) external {
        if (!organizations[orgId].exists) revert OrgDoesNotExist();
        if (tokens.length != amounts.length) revert ArrayLengthMismatch();

        for (uint256 i = 0; i < tokens.length; i++) {
            address token = tokens[i];
            uint256 amount = amounts[i];

            if (!allowedTokens[token]) revert TokenNotAllowed();
            if (token == ETH_ADDRESS) revert InvalidDepositAmount();

            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
            orgBalances[orgId][token] += amount;
            totalRecordedLiquidity[token] += amount;

            emit LiquidityDeposited(orgId, token, amount);
        }
    }

    function withdrawLiquidity(
        bytes32 orgId,
        address token,
        uint256 amount
    ) external {
        if (msg.sender != organizations[orgId].admin) revert NotOrgAdmin();
        if (orgBalances[orgId][token] < amount)
            revert InsufficientOrgLiquidity();

        orgBalances[orgId][token] -= amount;
        totalRecordedLiquidity[token] -= amount;

        if (token == ETH_ADDRESS) {
            (bool success, ) = msg.sender.call{value: amount}("");
            if (!success) revert ETHTransferFailed();
        } else {
            IERC20(token).safeTransfer(msg.sender, amount);
        }

        emit LiquidityWithdrawn(orgId, token, amount);
    }

    function rescueSlashedFunds(address token, address to) external onlyOwner {
        uint256 currentBalance;
        if (token == ETH_ADDRESS) {
            currentBalance = address(this).balance;
        } else {
            currentBalance = IERC20(token).balanceOf(address(this));
        }

        uint256 legitLiquidity = totalRecordedLiquidity[token];
        if (currentBalance <= legitLiquidity) revert NoSlashedFundsToRescue();

        uint256 surplus = currentBalance - legitLiquidity;

        if (token == ETH_ADDRESS) {
            (bool success, ) = to.call{value: surplus}("");
            if (!success) revert ETHTransferFailed();
        } else {
            IERC20(token).safeTransfer(to, surplus);
        }

        emit SlashedFundsRescued(token, surplus);
    }

    /**
     * @notice Pushes current Validator Keys to destination chains for trust-minimized verification.
     */
    function syncValidatorSet(
        uint32 destinationDomain,
        uint256[4] calldata currentAggregateKey
    ) external payable {
        uint48 epoch = ISettlement(settlement).getLastCommittedHeaderEpoch();

        bytes memory message = abi.encode(epoch, currentAggregateKey);

        bytes32 recipient = destinationVerifiers[destinationDomain];
        require(recipient != bytes32(0), "Verifier not set");

        IMailbox(mailbox).dispatch{value: msg.value}(
            destinationDomain,
            recipient,
            message
        );
    }

    // ==========================================
    //  Execution
    // ==========================================

    function processPayoutBatch(
        bytes32 orgId,
        bytes32 batchId,
        address token,
        Payment[] calldata payments,
        uint48 epoch,
        bytes calldata proof
    ) external payable {
        if (processedBatches[batchId]) revert BatchAlreadyProcessed();
        Organization storage org = organizations[orgId];
        if (!org.exists) revert OrgDoesNotExist();
        if (!allowedTokens[token]) revert TokenNotAllowed();

        _verifyOrgSignature(orgId, batchId, token, payments, epoch, proof);

        uint256 totalPayment = 0;
        for (uint256 i = 0; i < payments.length; i++) {
            totalPayment += payments[i].amount;
        }

        uint256 feeAmount = (totalPayment * protocolFeeBps) / 10000;
        uint256 totalDeduction = totalPayment + feeAmount;

        if (orgBalances[orgId][token] < totalDeduction)
            revert InsufficientOrgLiquidity();
        orgBalances[orgId][token] -= totalDeduction;
        totalRecordedLiquidity[token] -= totalDeduction;

        processedBatches[batchId] = true;

        if (feeAmount > 0 && token != ETH_ADDRESS) {
            IERC20(token).safeTransfer(votingPowers, feeAmount);
            IBaseRewards(votingPowers).distributeStakerRewards(
                org.rewardContract,
                token,
                feeAmount,
                abi.encode(epoch, 10000, new bytes(0), new bytes(0))
            );
        } else if (feeAmount > 0 && token == ETH_ADDRESS) {
            (bool success, ) = owner().call{value: feeAmount}("");
            if (!success) revert FeeTransferFailed();
        }

        uint256 totalNativeFeeUsed = 0;

        for (uint256 i = 0; i < payments.length; i++) {
            Payment memory p = payments[i];

            if (p.destinationDomain == 0) {
                // LOCAL
                if (token == ETH_ADDRESS) {
                    (bool success, ) = p.recipient.call{value: p.amount}("");
                    if (!success) revert ETHTransferFailed();
                } else {
                    IERC20(token).safeTransfer(p.recipient, p.amount);
                }
            } else {
                // CROSS-CHAIN
                if (token == ETH_ADDRESS) {
                    revert("Native ETH bridging not yet supported");
                } else {
                    address route = warpRoutes[token][p.destinationDomain];
                    if (route == address(0)) revert RouteNotConfigured();
                    if (msg.value < totalNativeFeeUsed + p.bridgeFee)
                        revert InsufficientBridgeFee();

                    IERC20(token).forceApprove(route, p.amount);

                    ITokenRouter(route).transferRemote{value: p.bridgeFee}(
                        p.destinationDomain,
                        p.recipient.addressToBytes32(),
                        p.amount
                    );

                    totalNativeFeeUsed += p.bridgeFee;
                    emit CrossChainPayoutDispatched(
                        p.destinationDomain,
                        token,
                        p.recipient,
                        p.amount
                    );
                }
            }
        }

        emit PayoutProcessed(orgId, batchId, totalPayment, feeAmount);
    }

    function _verifyOrgSignature(
        bytes32 orgId,
        bytes32 batchId,
        address token,
        Payment[] calldata payments,
        uint48 epoch,
        bytes calldata proof
    ) internal view {
        uint8 tag = ISettlement(settlement).getRequiredKeyTagFromValSetHeaderAt(
            epoch
        );
        if (tag != uint8(expectedKeyTag)) {
            revert InvalidKeyTag();
        }

        bytes memory payload = abi.encode(
            keccak256(
                abi.encode(BATCH_TYPEHASH, orgId, batchId, token, payments)
            )
        );

        uint48 nextCaptureTimestamp = ISettlement(settlement)
            .getCaptureTimestampFromValSetHeaderAt(epoch + 1);
        if (
            nextCaptureTimestamp > 0 &&
            block.timestamp >= nextCaptureTimestamp + messageExpiry
        ) {
            revert InvalidEpoch();
        }

        bool valid = ISettlement(settlement).verifyQuorumSigAt(
            payload,
            ISettlement(settlement).getRequiredKeyTagFromValSetHeaderAt(epoch),
            ISettlement(settlement).getQuorumThresholdFromValSetHeaderAt(epoch),
            proof,
            epoch,
            new bytes(0)
        );

        if (!valid) revert SignatureVerificationFailed();
    }

    receive() external payable {}
}
