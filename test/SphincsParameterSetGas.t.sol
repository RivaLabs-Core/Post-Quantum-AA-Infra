// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ISphincsVerifier} from "../src/Interfaces/ISphincsVerifier.sol";
import {
    SphincsDefaultMinusVerifier,
    SphincsFastTradePlusVerifier,
    SphincsGasSaverMinusQ18AggressiveVerifier,
    SphincsPlus128sVerifier,
    SPHINCS_DEFAULT_MINUS_SIG_LEN,
    SPHINCS_FAST_TRADE_PLUS_SIG_LEN,
    SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN,
    SPHINCS_PLUS_128S_SIG_LEN
} from "../src/Verifiers/SphincsParameterSetVerifiers.sol";

/// @dev Gas benchmarks use deterministic, deliberately invalid signatures that
///      satisfy every FORS+C and WOTS+C filter. Verification therefore executes
///      the complete path and fails only at the final public-root comparison.
contract SphincsParameterSetGasTest is Test {
    bytes32 constant PK_SEED = bytes32(uint256(0x11111111111111111111111111111111) << 128);
    bytes32 constant PK_ROOT = bytes32(uint256(0x22222222222222222222222222222222) << 128);
    bytes32 constant MESSAGE = bytes32(uint256(0x3333333333333333333333333333333333333333333333333333333333333333));

    SphincsFastTradePlusVerifier fastTradePlus;
    SphincsDefaultMinusVerifier defaultMinus;
    SphincsGasSaverMinusQ18AggressiveVerifier gasSaver;
    SphincsPlus128sVerifier plus128s;

    function setUp() public {
        fastTradePlus = new SphincsFastTradePlusVerifier();
        defaultMinus = new SphincsDefaultMinusVerifier();
        gasSaver = new SphincsGasSaverMinusQ18AggressiveVerifier();
        plus128s = new SphincsPlus128sVerifier();
    }

    function test_gas_fastTradePlus_fullPath() public {
        bytes memory sig = new bytes(SPHINCS_FAST_TRADE_PLUS_SIG_LEN);
        _writeBytes16(sig, 0, 0x000000000000000000000000000000a2);
        _writeUint32(sig, 4176, 1072);
        _writeUint32(sig, 4948, 4334);
        _writeUint32(sig, 5720, 12334);

        _measure("fast_trade_plus", fastTradePlus, sig);
    }

    function test_gas_defaultMinus_fullPath() public {
        bytes memory sig = new bytes(SPHINCS_DEFAULT_MINUS_SIG_LEN);
        _writeBytes16(sig, 0, 0x00000000000000000000000000001365);
        _writeUint32(sig, 2960, 574443);
        _writeUint32(sig, 3812, 104692);

        _measure("default_minus", defaultMinus, sig);
    }

    function test_gas_gasSaverMinusQ18Aggressive_fullPath() public {
        bytes memory sig = new bytes(SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN);
        _writeBytes16(sig, 0, 0x000000000000000000000000002aeb99);
        _writeUint32(sig, 2736, 819149);

        _measure("gas_saver_minus_q18_aggressive", gasSaver, sig);
    }

    function test_gas_sphincsPlus128s_fullPath() public {
        bytes memory sig = new bytes(SPHINCS_PLUS_128S_SIG_LEN);
        _measure("sphincs_plus_128s", plus128s, sig);
    }

    function _measure(string memory name, ISphincsVerifier verifier, bytes memory sig) internal {
        vm.cool(address(verifier));
        uint256 beforeCold = gasleft();
        bool coldValid = verifier.verify(PK_SEED, PK_ROOT, MESSAGE, sig);
        uint256 coldGas = beforeCold - gasleft();

        uint256 beforeWarm = gasleft();
        bool warmValid = verifier.verify(PK_SEED, PK_ROOT, MESSAGE, sig);
        uint256 warmGas = beforeWarm - gasleft();

        assertFalse(coldValid, "crafted signature unexpectedly valid");
        assertFalse(warmValid, "crafted signature unexpectedly valid");
        console.log(string.concat(name, " cold gas:"), coldGas);
        console.log(string.concat(name, " warm gas:"), warmGas);
    }

    function _writeBytes16(bytes memory data, uint256 offset, bytes16 value) internal pure {
        assembly ("memory-safe") {
            mstore(add(add(data, 0x20), offset), value)
        }
    }

    function _writeUint32(bytes memory data, uint256 offset, uint32 value) internal pure {
        assembly ("memory-safe") {
            mstore(add(add(data, 0x20), offset), shl(224, value))
        }
    }
}
