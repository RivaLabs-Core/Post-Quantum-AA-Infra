// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {SphincsVerifier, SPHINCS_SIG_LEN} from "../src/Verifiers/SphincsVerifier.sol";
import {SphincsParamVerifier} from "../src/Verifiers/SphincsParamVerifier.sol";
import {SphincsParamsLib} from "../src/Verifiers/SphincsParamsLib.sol";
import {SphincsWotsPlusVerifier, SPHINCS_WOTSPLUS_SIG_LEN} from "../src/Verifiers/SphincsWotsPlusVerifier.sol";

/// @title DeployVerifiers — standalone CREATE2 deploy of the SPHINCS- verifiers
/// @notice Deploys ONLY the verifiers. It deliberately does NOT touch `SimpleAccountFactory` or
///         the `SimpleAccount` implementation, so the existing deterministic address family
///         (factory / impl / accounts) is left exactly as deployed. All contracts are stateless
///         and take no constructor arguments.
/// @dev    The retargeted `SphincsVerifier` gets a PARAM-DISTINGUISHING salt so the v1 salt keeps
///         pointing at the canonical (h=22 d=2 a=19 k=7 w=8 l=43) deployment and `addresses.json`
///         is unambiguous about which parameter set lives where.
///
///         Idempotent: an already-deployed address is skipped, mirroring `Deploy.s.sol`.
contract DeployVerifiers is Script {
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    bytes32 constant DEFAULT_SPHINCS_VERIFIER_SALT = keccak256("NiceTry.SphincsVerifier.h20d4a7k29w4.v2");
    bytes32 constant DEFAULT_SPHINCS_PARAM_VERIFIER_SALT = keccak256("NiceTry.SphincsParamVerifier.v1");
    bytes32 constant DEFAULT_WOTSPLUS_VERIFIER_SALT = keccak256("NiceTry.SphincsWotsPlusVerifier.h20d4a7k29w4l68.v1");

    function run() external {
        bytes32 sphincsSalt = vm.envOr("SPHINCS_VERIFIER_SALT", DEFAULT_SPHINCS_VERIFIER_SALT);
        bytes32 paramSalt = vm.envOr("SPHINCS_PARAM_VERIFIER_SALT", DEFAULT_SPHINCS_PARAM_VERIFIER_SALT);
        bytes32 wotsPlusSalt = vm.envOr("WOTSPLUS_VERIFIER_SALT", DEFAULT_WOTSPLUS_VERIFIER_SALT);

        require(CREATE2_DEPLOYER.code.length != 0, "Deploy: missing CREATE2 deployer");

        // Guard: the hardcoded verifier's length constant must equal the length the parameter
        // library derives for the set it claims to implement. Catches a constant/param drift
        // before it is written to chain.
        require(
            SphincsParamsLib.blobLen(SphincsParamsLib.retargeted()) == SPHINCS_SIG_LEN,
            "Deploy: SPHINCS_SIG_LEN does not match retargeted params"
        );

        bytes memory sphincsInitCode = type(SphincsVerifier).creationCode;
        address predictedSphincs = _predictDeterministicAddress(sphincsSalt, sphincsInitCode);

        bytes memory paramInitCode = type(SphincsParamVerifier).creationCode;
        address predictedParam = _predictDeterministicAddress(paramSalt, paramInitCode);

        bytes memory wotsPlusInitCode = type(SphincsWotsPlusVerifier).creationCode;
        address predictedWotsPlus = _predictDeterministicAddress(wotsPlusSalt, wotsPlusInitCode);

        vm.startBroadcast();

        address sphincsVerifier = _deployDeterministic(sphincsSalt, sphincsInitCode);
        address paramVerifier = _deployDeterministic(paramSalt, paramInitCode);
        address wotsPlusVerifier = _deployDeterministic(wotsPlusSalt, wotsPlusInitCode);

        vm.stopBroadcast();

        console.log("CREATE2 deployer:                ", CREATE2_DEPLOYER);
        console.log("SphincsVerifier salt:            ");
        console.logBytes32(sphincsSalt);
        console.log("SphincsParamVerifier salt:       ");
        console.logBytes32(paramSalt);
        console.log("SphincsVerifier deployed at:     ", sphincsVerifier);
        console.log("SphincsParamVerifier deployed at:", paramVerifier);
        console.log("WotsPlusVerifier salt:           ");
        console.logBytes32(wotsPlusSalt);
        console.log("SphincsWotsPlusVerifier at:      ", wotsPlusVerifier);
        console.log("SPHINCS_SIG_LEN (WOTS+C):        ", SPHINCS_SIG_LEN);
        console.log("SPHINCS_WOTSPLUS_SIG_LEN:        ", SPHINCS_WOTSPLUS_SIG_LEN);
        console.log("packed retargeted params:        ", SphincsParamsLib.pack(SphincsParamsLib.retargeted()));

        require(sphincsVerifier == predictedSphincs, "Deploy: sphincs verifier address drift");
        require(paramVerifier == predictedParam, "Deploy: param verifier address drift");
        require(wotsPlusVerifier == predictedWotsPlus, "Deploy: wots+ verifier address drift");
        require(wotsPlusVerifier.code.length != 0, "Deploy: wots+ verifier has no code");
        // The two SPHINCS blob lengths must stay distinct so a caller can never confuse the
        // constant-sum variant with the checksum variant by length alone.
        require(SPHINCS_WOTSPLUS_SIG_LEN != SPHINCS_SIG_LEN, "Deploy: variant length clash");
        require(sphincsVerifier.code.length != 0, "Deploy: sphincs verifier has no code");
        require(paramVerifier.code.length != 0, "Deploy: param verifier has no code");
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
