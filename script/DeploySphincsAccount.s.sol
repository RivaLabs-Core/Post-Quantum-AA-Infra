// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {SphincsAccountFactory} from "../src/SphincsAccountFactory.sol";
import {SphincsAccount} from "../src/SphincsAccount.sol";
import {SphincsStandardVerifier, SPHINCS_STANDARD_SIG_LEN} from "../src/Verifiers/SphincsStandardVerifier.sol";
import {ISphincsVerifier} from "../src/Interfaces/ISphincsVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

/// @title DeploySphincsAccount — CREATE2 deploy of the SPHINCS--only account family
/// @notice Deploys `SphincsStandardVerifier` (8,400-byte standard-FORS / standard-WOTS+ blob) and
///         `SphincsAccountFactory`, whose constructor in turn deploys the `SphincsAccount`
///         implementation. Both go through the canonical CREATE2 deployer, so the addresses are
///         identical on every chain for the same salts and bytecode.
/// @dev    Touches NOTHING in the existing FORS-primary family — `SimpleAccountFactory`, its
///         implementation and every account derived from it are left exactly as deployed. This is
///         a parallel, independent account type.
///
///         The factory binds to the verifier address DERIVED from the verifier salt, and the script
///         asserts that address has code after the deploy step: binding the factory to an address
///         with no verifier behind it would produce accounts that can never validate anything.
///
///         Idempotent: an already-deployed verifier or factory is skipped.
contract DeploySphincsAccount is Script {
    address constant ENTRYPOINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    bytes32 constant DEFAULT_STANDARD_VERIFIER_SALT = keccak256("NiceTry.SphincsStandardVerifier.h20d4a7k29w4l68.v1");
    bytes32 constant DEFAULT_ACCOUNT_FACTORY_SALT = keccak256("NiceTry.SphincsAccountFactory.v1");

    function run() external {
        address entryPoint = vm.envOr("ENTRYPOINT", ENTRYPOINT_V07);
        bytes32 verifierSalt = vm.envOr("STANDARD_VERIFIER_SALT", DEFAULT_STANDARD_VERIFIER_SALT);
        bytes32 factorySalt = vm.envOr("SPHINCS_ACCOUNT_FACTORY_SALT", DEFAULT_ACCOUNT_FACTORY_SALT);

        require(CREATE2_DEPLOYER.code.length != 0, "Deploy: missing CREATE2 deployer");
        require(entryPoint.code.length != 0, "Deploy: EntryPoint has no code");

        bytes memory verifierInitCode = type(SphincsStandardVerifier).creationCode;
        address verifier = _predictDeterministicAddress(verifierSalt, verifierInitCode);

        bytes memory factoryInitCode = abi.encodePacked(
            type(SphincsAccountFactory).creationCode,
            abi.encode(IEntryPoint(entryPoint), ISphincsVerifier(verifier))
        );
        address predictedFactory = _predictDeterministicAddress(factorySalt, factoryInitCode);

        vm.startBroadcast();
        address deployedVerifier = _deployDeterministic(verifierSalt, verifierInitCode);
        address factoryAddr = _deployDeterministic(factorySalt, factoryInitCode);
        vm.stopBroadcast();

        require(deployedVerifier == verifier, "Deploy: verifier address drift");
        require(verifier.code.length != 0, "Deploy: standard verifier has no code");

        SphincsAccountFactory factory = SphincsAccountFactory(factoryAddr);

        console.log("CREATE2 deployer:                ", CREATE2_DEPLOYER);
        console.log("EntryPoint:                      ", entryPoint);
        console.log("SphincsStandardVerifier salt:    ");
        console.logBytes32(verifierSalt);
        console.log("SphincsStandardVerifier at:      ", verifier);
        console.log("SphincsAccountFactory salt:      ");
        console.logBytes32(factorySalt);
        console.log("SphincsAccountFactory at:        ", factoryAddr);
        console.log("SphincsAccount implementation:   ", factory.ACCOUNT_IMPL());
        console.log("SPHINCS_STANDARD_SIG_LEN:        ", SPHINCS_STANDARD_SIG_LEN);

        require(factoryAddr == predictedFactory, "Deploy: factory address drift");
        require(address(factory.ENTRY_POINT()) == entryPoint, "Deploy: EntryPoint mismatch");
        require(address(factory.VERIFIER()) == verifier, "Deploy: verifier mismatch");
        require(factory.ACCOUNT_IMPL().code.length != 0, "Deploy: impl has no code");

        // The implementation must be permanently locked against direct initialization.
        SphincsAccount impl = SphincsAccount(payable(factory.ACCOUNT_IMPL()));
        (bool ok,) = address(impl).call(abi.encodeCall(SphincsAccount.initialize, (bytes32(uint256(1)), bytes32(uint256(1)))));
        require(!ok, "Deploy: implementation is not locked");
    }

    function _deployDeterministic(bytes32 salt, bytes memory initCode) internal returns (address deployed) {
        deployed = _predictDeterministicAddress(salt, initCode);
        if (deployed.code.length != 0) return deployed;

        (bool ok, bytes memory data) = CREATE2_DEPLOYER.call(abi.encodePacked(salt, initCode));
        if (!ok) {
            assembly {
                revert(add(data, 0x20), mload(data))
            }
        }

        require(deployed.code.length != 0, "Deploy: CREATE2 deployment failed");
    }

    function _predictDeterministicAddress(bytes32 salt, bytes memory initCode) internal pure returns (address) {
        bytes32 digest = keccak256(abi.encodePacked(bytes1(0xff), CREATE2_DEPLOYER, salt, keccak256(initCode)));
        return address(uint160(uint256(digest)));
    }
}
