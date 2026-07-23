// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/SimpleAccountFactory.sol";
import "../src/Verifiers/ForsVerifier.sol";
import "../src/Verifiers/SphincsParameterSetVerifiers.sol";
import {ISignatureVerifier} from "../src/Interfaces/ISignatureVerifier.sol";
import {ISphincsVerifier} from "../src/Interfaces/ISphincsVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

contract Deploy is Script {
    address constant ENTRYPOINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    bytes32 constant DEFAULT_FORS_VERIFIER_SALT = keccak256("NiceTry.ForsVerifier.v1");
    bytes32 constant DEFAULT_FAST_TRADE_PLUS_VERIFIER_SALT = keccak256("NiceTry.SphincsFastTradePlusVerifier.v1");
    bytes32 constant DEFAULT_DEFAULT_MINUS_VERIFIER_SALT = keccak256("NiceTry.SphincsDefaultMinusVerifier.v1");
    bytes32 constant DEFAULT_GAS_SAVER_VERIFIER_SALT = keccak256("NiceTry.SphincsGasSaverMinusQ18AggressiveVerifier.v1");
    bytes32 constant DEFAULT_SPHINCS_PLUS_128S_VERIFIER_SALT = keccak256("NiceTry.SphincsPlus128sVerifier.v1");
    bytes32 constant DEFAULT_FACTORY_SALT = keccak256("NiceTry.SimpleAccountFactory.v2");

    struct DeploymentPlan {
        address entryPoint;
        bytes32 forsSalt;
        bytes32[4] sphincsSalts;
        bytes32 factorySalt;
        bytes forsInitCode;
        bytes[4] sphincsInitCodes;
        address predictedFors;
        address[4] predictedSphincs;
        bytes factoryInitCode;
        address predictedFactory;
    }

    function run() external {
        DeploymentPlan memory plan;
        plan.entryPoint = vm.envOr("ENTRYPOINT", ENTRYPOINT_V07);
        plan.forsSalt = vm.envOr("FORS_VERIFIER_SALT", DEFAULT_FORS_VERIFIER_SALT);
        plan.sphincsSalts[0] = vm.envOr("FAST_TRADE_PLUS_VERIFIER_SALT", DEFAULT_FAST_TRADE_PLUS_VERIFIER_SALT);
        plan.sphincsSalts[1] = vm.envOr("DEFAULT_MINUS_VERIFIER_SALT", DEFAULT_DEFAULT_MINUS_VERIFIER_SALT);
        plan.sphincsSalts[2] = vm.envOr("GAS_SAVER_VERIFIER_SALT", DEFAULT_GAS_SAVER_VERIFIER_SALT);
        plan.sphincsSalts[3] = vm.envOr("SPHINCS_PLUS_128S_VERIFIER_SALT", DEFAULT_SPHINCS_PLUS_128S_VERIFIER_SALT);
        plan.factorySalt = vm.envOr("FACTORY_SALT", DEFAULT_FACTORY_SALT);

        require(CREATE2_DEPLOYER.code.length != 0, "Deploy: missing CREATE2 deployer");

        plan.forsInitCode = type(ForsVerifier).creationCode;
        plan.sphincsInitCodes[0] = type(SphincsFastTradePlusVerifier).creationCode;
        plan.sphincsInitCodes[1] = type(SphincsDefaultMinusVerifier).creationCode;
        plan.sphincsInitCodes[2] = type(SphincsGasSaverMinusQ18AggressiveVerifier).creationCode;
        plan.sphincsInitCodes[3] = type(SphincsPlus128sVerifier).creationCode;
        plan.predictedFors = _predictDeterministicAddress(plan.forsSalt, plan.forsInitCode);
        for (uint256 i = 0; i < 4; i++) {
            plan.predictedSphincs[i] = _predictDeterministicAddress(plan.sphincsSalts[i], plan.sphincsInitCodes[i]);
        }

        plan.factoryInitCode = abi.encodePacked(
            type(SimpleAccountFactory).creationCode,
            abi.encode(
                IEntryPoint(plan.entryPoint),
                ISignatureVerifier(plan.predictedFors),
                ISphincsVerifier(plan.predictedSphincs[0]),
                ISphincsVerifier(plan.predictedSphincs[1]),
                ISphincsVerifier(plan.predictedSphincs[2]),
                ISphincsVerifier(plan.predictedSphincs[3])
            )
        );
        plan.predictedFactory = _predictDeterministicAddress(plan.factorySalt, plan.factoryInitCode);

        vm.startBroadcast();

        address forsVerifier = _deployDeterministic(plan.forsSalt, plan.forsInitCode);
        address[4] memory sphincsVerifiers;
        for (uint256 i = 0; i < 4; i++) {
            sphincsVerifiers[i] = _deployDeterministic(plan.sphincsSalts[i], plan.sphincsInitCodes[i]);
        }
        address factoryAddr = _deployDeterministic(plan.factorySalt, plan.factoryInitCode);

        vm.stopBroadcast();

        SimpleAccountFactory factory = SimpleAccountFactory(factoryAddr);

        console.log("CREATE2 deployer:           ", CREATE2_DEPLOYER);
        console.log("ForsVerifier salt:          ");
        console.logBytes32(plan.forsSalt);
        console.log("FastTradePlus salt:         ");
        console.logBytes32(plan.sphincsSalts[0]);
        console.log("DefaultMinus salt:          ");
        console.logBytes32(plan.sphincsSalts[1]);
        console.log("GasSaver salt:              ");
        console.logBytes32(plan.sphincsSalts[2]);
        console.log("SphincsPlus128s salt:       ");
        console.logBytes32(plan.sphincsSalts[3]);
        console.log("Factory salt:               ");
        console.logBytes32(plan.factorySalt);
        console.log("ForsVerifier deployed at:   ", forsVerifier);
        console.log("FastTradePlus deployed at:  ", sphincsVerifiers[0]);
        console.log("DefaultMinus deployed at:   ", sphincsVerifiers[1]);
        console.log("GasSaver deployed at:       ", sphincsVerifiers[2]);
        console.log("SphincsPlus128s deployed at:", sphincsVerifiers[3]);
        console.log("Factory deployed at:        ", factoryAddr);
        console.log("Account implementation at: ", factory.ACCOUNT_IMPL());
        console.log("EntryPoint:                 ", plan.entryPoint);

        require(forsVerifier == plan.predictedFors, "Deploy: verifier address drift");
        for (uint256 i = 0; i < 4; i++) {
            require(sphincsVerifiers[i] == plan.predictedSphincs[i], "Deploy: sphincs verifier address drift");
        }
        require(factoryAddr == plan.predictedFactory, "Deploy: factory address drift");
        require(factory.VERIFIER() == ISignatureVerifier(forsVerifier), "Deploy: verifier mismatch");
        require(
            factory.FAST_TRADE_PLUS_VERIFIER() == ISphincsVerifier(sphincsVerifiers[0]),
            "Deploy: fast verifier mismatch"
        );
        require(
            factory.DEFAULT_MINUS_VERIFIER() == ISphincsVerifier(sphincsVerifiers[1]),
            "Deploy: default verifier mismatch"
        );
        require(
            factory.GAS_SAVER_MINUS_Q18_AGGRESSIVE_VERIFIER() == ISphincsVerifier(sphincsVerifiers[2]),
            "Deploy: gas saver verifier mismatch"
        );
        require(
            factory.SPHINCS_PLUS_128S_VERIFIER() == ISphincsVerifier(sphincsVerifiers[3]),
            "Deploy: plus verifier mismatch"
        );
        require(factory.ENTRY_POINT() == IEntryPoint(plan.entryPoint), "Deploy: EntryPoint mismatch");
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
