// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/SimpleAccountFactory.sol";
import "../src/Verifiers/ForsVerifier.sol";
import "../src/Verifiers/SphincsVerifier.sol";
import {ISignatureVerifier} from "../src/Interfaces/ISignatureVerifier.sol";
import {ISphincsVerifier} from "../src/Interfaces/ISphincsVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

contract Deploy is Script {
    address constant ENTRYPOINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    bytes32 constant DEFAULT_FORS_VERIFIER_SALT = keccak256("NiceTry.ForsVerifier.v1");
    bytes32 constant DEFAULT_SPHINCS_VERIFIER_SALT = keccak256("NiceTry.SphincsVerifier.v1");
    bytes32 constant DEFAULT_FACTORY_SALT = keccak256("NiceTry.SimpleAccountFactory.v1");

    function run() external {
        address entryPoint = vm.envOr("ENTRYPOINT", ENTRYPOINT_V07);
        bytes32 forsVerifierSalt = vm.envOr("FORS_VERIFIER_SALT", DEFAULT_FORS_VERIFIER_SALT);
        bytes32 sphincsVerifierSalt = vm.envOr("SPHINCS_VERIFIER_SALT", DEFAULT_SPHINCS_VERIFIER_SALT);
        bytes32 factorySalt = vm.envOr("FACTORY_SALT", DEFAULT_FACTORY_SALT);

        require(CREATE2_DEPLOYER.code.length != 0, "Deploy: missing CREATE2 deployer");

        bytes memory forsVerifierInitCode = type(ForsVerifier).creationCode;
        address predictedForsVerifier = _predictDeterministicAddress(forsVerifierSalt, forsVerifierInitCode);

        bytes memory sphincsVerifierInitCode = type(SphincsVerifier).creationCode;
        address predictedSphincsVerifier = _predictDeterministicAddress(sphincsVerifierSalt, sphincsVerifierInitCode);

        bytes memory factoryInitCode = abi.encodePacked(
            type(SimpleAccountFactory).creationCode,
            abi.encode(
                IEntryPoint(entryPoint),
                ISignatureVerifier(predictedForsVerifier),
                ISphincsVerifier(predictedSphincsVerifier)
            )
        );
        address predictedFactory = _predictDeterministicAddress(factorySalt, factoryInitCode);

        vm.startBroadcast();

        address forsVerifier = _deployDeterministic(forsVerifierSalt, forsVerifierInitCode);
        address sphincsVerifier = _deployDeterministic(sphincsVerifierSalt, sphincsVerifierInitCode);
        address factoryAddr = _deployDeterministic(factorySalt, factoryInitCode);

        vm.stopBroadcast();

        SimpleAccountFactory factory = SimpleAccountFactory(factoryAddr);

        console.log("CREATE2 deployer:           ", CREATE2_DEPLOYER);
        console.log("ForsVerifier salt:          ");
        console.logBytes32(forsVerifierSalt);
        console.log("SphincsVerifier salt:       ");
        console.logBytes32(sphincsVerifierSalt);
        console.log("Factory salt:               ");
        console.logBytes32(factorySalt);
        console.log("ForsVerifier deployed at:   ", forsVerifier);
        console.log("SphincsVerifier deployed at:", sphincsVerifier);
        console.log("Factory deployed at:        ", factoryAddr);
        console.log("Account implementation at: ", factory.ACCOUNT_IMPL());
        console.log("EntryPoint:                 ", entryPoint);

        require(forsVerifier == predictedForsVerifier, "Deploy: verifier address drift");
        require(sphincsVerifier == predictedSphincsVerifier, "Deploy: sphincs verifier address drift");
        require(factoryAddr == predictedFactory, "Deploy: factory address drift");
        require(factory.VERIFIER() == ISignatureVerifier(forsVerifier), "Deploy: verifier mismatch");
        require(factory.SPHINCS_VERIFIER() == ISphincsVerifier(sphincsVerifier), "Deploy: sphincs verifier mismatch");
        require(factory.ENTRY_POINT() == IEntryPoint(entryPoint), "Deploy: EntryPoint mismatch");
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
