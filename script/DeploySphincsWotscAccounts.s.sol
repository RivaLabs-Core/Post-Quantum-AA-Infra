// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {SphincsWotscAccount} from "../src/SphincsWotscAccount.sol";
import {SphincsWotscAccountFactory} from "../src/SphincsWotscAccountFactory.sol";
import {SphincsAccountFactory_v5} from "../src/SphincsAccountFactory_v5.sol";
import {SphincsAccountFactory_v6} from "../src/SphincsAccountFactory_v6.sol";
import {SphincsVerifier_v5, SPHINCS_V5_SIG_LEN} from "../src/Verifiers/SphincsVerifier_v5.sol";
import {SphincsVerifier_v6, SPHINCS_V6_SIG_LEN} from "../src/Verifiers/SphincsVerifier_v6.sol";
import {ISphincsVerifier} from "../src/Interfaces/ISphincsVerifier.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

/// @title DeploySphincsWotscAccounts — CREATE2 deploy of the WOTS+C SPHINCS--only account families
/// @notice Deploys, for each of v5 and v6, the verifier (`SphincsVerifier_v5` / `_v6`) and its
///         factory (`SphincsAccountFactory_v5` / `_v6`), whose constructor in turn deploys the
///         account implementation. Everything goes through the canonical CREATE2 deployer, so the
///         addresses are identical on every chain for the same salts and bytecode.
/// @dev    Touches NOTHING in the existing families — `SimpleAccountFactory`, `SphincsAccountFactory`,
///         their implementations and every account derived from them are left exactly as deployed.
///
///         Each factory binds to the verifier address DERIVED from that verifier's salt, and the
///         script asserts that address has code after the deploy step, and that the verifier, the
///         factory and the implementation all agree on the signature length.
///
///         Idempotent: an already-deployed verifier or factory is skipped.
contract DeploySphincsWotscAccounts is Script {
    address constant ENTRYPOINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    bytes32 constant DEFAULT_V5_VERIFIER_SALT = keccak256("NiceTry.SphincsVerifier_v5.h26-8.8.10-w4-k24a10.v1");
    bytes32 constant DEFAULT_V5_FACTORY_SALT = keccak256("NiceTry.SphincsAccountFactory_v5.v1");
    bytes32 constant DEFAULT_V6_VERIFIER_SALT = keccak256("NiceTry.SphincsVerifier_v6.h24-7.7.10-w4-k19a9.v1");
    bytes32 constant DEFAULT_V6_FACTORY_SALT = keccak256("NiceTry.SphincsAccountFactory_v6.v1");

    function run() external {
        address entryPoint = vm.envOr("ENTRYPOINT", ENTRYPOINT_V07);

        require(CREATE2_DEPLOYER.code.length != 0, "Deploy: missing CREATE2 deployer");
        require(entryPoint.code.length != 0, "Deploy: EntryPoint has no code");

        _deployFamily(
            "v5",
            entryPoint,
            vm.envOr("V5_VERIFIER_SALT", DEFAULT_V5_VERIFIER_SALT),
            type(SphincsVerifier_v5).creationCode,
            vm.envOr("V5_ACCOUNT_FACTORY_SALT", DEFAULT_V5_FACTORY_SALT),
            type(SphincsAccountFactory_v5).creationCode,
            SPHINCS_V5_SIG_LEN
        );
        _deployFamily(
            "v6",
            entryPoint,
            vm.envOr("V6_VERIFIER_SALT", DEFAULT_V6_VERIFIER_SALT),
            type(SphincsVerifier_v6).creationCode,
            vm.envOr("V6_ACCOUNT_FACTORY_SALT", DEFAULT_V6_FACTORY_SALT),
            type(SphincsAccountFactory_v6).creationCode,
            SPHINCS_V6_SIG_LEN
        );
    }

    function _deployFamily(
        string memory tag,
        address entryPoint,
        bytes32 verifierSalt,
        bytes memory verifierInitCode,
        bytes32 factorySalt,
        bytes memory factoryCreationCode,
        uint256 sigLen
    ) internal {
        address verifier = _predictDeterministicAddress(verifierSalt, verifierInitCode);

        bytes memory factoryInitCode =
            abi.encodePacked(factoryCreationCode, abi.encode(IEntryPoint(entryPoint), ISphincsVerifier(verifier)));
        address predictedFactory = _predictDeterministicAddress(factorySalt, factoryInitCode);

        vm.startBroadcast();
        address deployedVerifier = _deployDeterministic(verifierSalt, verifierInitCode);
        address factoryAddr = _deployDeterministic(factorySalt, factoryInitCode);
        vm.stopBroadcast();

        require(deployedVerifier == verifier, "Deploy: verifier address drift");
        require(verifier.code.length != 0, "Deploy: verifier has no code");

        SphincsWotscAccountFactory factory = SphincsWotscAccountFactory(factoryAddr);

        console.log(string.concat("---- SPHINCS- WOTS+C family ", tag, " ----"));
        console.log("EntryPoint:               ", entryPoint);
        console.log("Verifier salt:            ");
        console.logBytes32(verifierSalt);
        console.log("Verifier at:              ", verifier);
        console.log("Account factory salt:     ");
        console.logBytes32(factorySalt);
        console.log("Account factory at:       ", factoryAddr);
        console.log("Account implementation:   ", factory.ACCOUNT_IMPL());
        console.log("Signature length:         ", sigLen);

        require(factoryAddr == predictedFactory, "Deploy: factory address drift");
        require(address(factory.ENTRY_POINT()) == entryPoint, "Deploy: EntryPoint mismatch");
        require(address(factory.VERIFIER()) == verifier, "Deploy: verifier mismatch");
        require(factory.ACCOUNT_IMPL().code.length != 0, "Deploy: impl has no code");

        // Verifier, factory and implementation must all accept exactly the same blob length.
        (bool lenOk, bytes memory lenRet) = verifier.staticcall(abi.encodeWithSignature("SIG_LEN()"));
        require(lenOk && abi.decode(lenRet, (uint256)) == sigLen, "Deploy: verifier SIG_LEN mismatch");
        require(factory.SIG_LEN() == sigLen, "Deploy: account SIG_LEN mismatch");

        // The implementation must be permanently locked against direct initialization.
        (bool ok,) = factory.ACCOUNT_IMPL().call(
            abi.encodeCall(SphincsWotscAccount.initialize, (bytes32(uint256(1) << 128), bytes32(uint256(1) << 128)))
        );
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
