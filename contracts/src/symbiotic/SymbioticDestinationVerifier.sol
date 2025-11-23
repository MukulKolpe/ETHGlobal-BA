// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {TypeCasts} from "@hyperlane-xyz/libs/TypeCasts.sol";

interface IMailbox {
    function dispatch(
        uint32 _destinationDomain,
        bytes32 _recipientAddress,
        bytes calldata _messageBody
    ) external payable returns (bytes32);
}

/**
 * @title SymbioticDestinationVerifier
 * @notice Verifies Symbiotic BLS signatures on the destination chain.
 */
contract SymbioticDestinationVerifier is Ownable {
    using TypeCasts for address;

    address public hyperlaneMailbox;
    address public sourceContract;
    uint32 public sourceDomain;

    mapping(uint48 => uint256[4]) public epochKeys;

    error InvalidSource();
    error EpochNotSynced();
    error InvalidSignature();
    error PairingOpFailed();

    event ValidatorSetSynced(uint48 indexed epoch, uint256[4] key);

    constructor(
        address _mailbox,
        uint32 _sourceDomain,
        address _sourceContract
    ) Ownable(msg.sender) {
        hyperlaneMailbox = _mailbox;
        sourceDomain = _sourceDomain;
        sourceContract = _sourceContract;
    }

    function handle(
        uint32 _origin,
        bytes32 _sender,
        bytes calldata _body
    ) external {
        if (msg.sender != hyperlaneMailbox) revert InvalidSource();
        if (_origin != sourceDomain) revert InvalidSource();
        if (_sender != sourceContract.addressToBytes32())
            revert InvalidSource();

        (uint48 epoch, uint256[4] memory newKey) = abi.decode(
            _body,
            (uint48, uint256[4])
        );

        epochKeys[epoch] = newKey;
        emit ValidatorSetSynced(epoch, newKey);
    }

    function verifySymbioticProof(
        bytes32 messageHash,
        uint48 epoch,
        uint256[2] calldata signature
    ) external view returns (bool) {
        uint256[4] memory pk = epochKeys[epoch];
        if (pk[0] == 0 && pk[1] == 0) revert EpochNotSynced();

        uint256[2] memory messagePoint = _hashToG1(messageHash);
        uint256[4] memory negPk = _negateG2(pk);

        // G2 Generator
        uint256[4] memory g2 = [
            10857046999023057135944570762232829481370756359578518086990519993285655852781,
            11559732032986387107991004021392285783925812861821192530917403151452391805634,
            8495653923123431417604973247489272438418190587263600148770280649306958101930,
            4082367875863433681332203403145435568316851327593401208105741076214120093531
        ];

        uint256[12] memory input = [
            signature[0],
            signature[1],
            g2[1],
            g2[0],
            g2[3],
            g2[2],
            messagePoint[0],
            messagePoint[1],
            negPk[1],
            negPk[0],
            negPk[3],
            negPk[2]
        ];

        uint256[1] memory out;
        bool success;

        // ecPairing Precompile
        assembly {
            success := staticcall(sub(gas(), 2000), 0x08, input, 384, out, 32)
        }

        if (!success) revert PairingOpFailed();
        return out[0] == 1;
    }

    function _negateG2(
        uint256[4] memory point
    ) internal pure returns (uint256[4] memory) {
        uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        return [point[0], point[1], q - point[2], q - point[3]];
    }

    function _hashToG1(
        bytes32 message
    ) internal pure returns (uint256[2] memory) {
        return [uint256(message), 1];
    }
}
