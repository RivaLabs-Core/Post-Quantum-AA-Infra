// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
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

contract SphincsParameterSetVerifiersTest is Test {
    // Canonical top-128-bit-aligned dummy public-key words.
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

    function test_fastTradePlus_params() public view {
        assertEq(fastTradePlus.PARAMETER_SET(), "fast_trade_plus");
        assertEq(fastTradePlus.N(), 16);
        assertEq(fastTradePlus.H(), 15);
        assertEq(fastTradePlus.D(), 3);
        assertEq(fastTradePlus.SUBTREE_H(), 5);
        assertEq(fastTradePlus.A(), 8);
        assertEq(fastTradePlus.K(), 25);
        assertEq(fastTradePlus.W(), 8);
        assertEq(fastTradePlus.L(), 43);
        assertEq(fastTradePlus.TARGET_SUM(), 196);
        assertEq(fastTradePlus.SIG_LEN(), SPHINCS_FAST_TRADE_PLUS_SIG_LEN);
        assertEq(SPHINCS_FAST_TRADE_PLUS_SIG_LEN, 5804);
    }

    function test_defaultMinus_params() public view {
        assertEq(defaultMinus.PARAMETER_SET(), "default_minus");
        assertEq(defaultMinus.N(), 16);
        assertEq(defaultMinus.H(), 20);
        assertEq(defaultMinus.D(), 2);
        assertEq(defaultMinus.SUBTREE_H(), 10);
        assertEq(defaultMinus.A(), 13);
        assertEq(defaultMinus.K(), 11);
        assertEq(defaultMinus.W(), 8);
        assertEq(defaultMinus.L(), 43);
        assertEq(defaultMinus.TARGET_SUM(), 215);
        assertEq(defaultMinus.SIG_LEN(), SPHINCS_DEFAULT_MINUS_SIG_LEN);
        assertEq(SPHINCS_DEFAULT_MINUS_SIG_LEN, 3976);
    }

    function test_gasSaver_params() public view {
        assertEq(gasSaver.PARAMETER_SET(), "gas_saver_minus_q18_aggressive");
        assertEq(gasSaver.N(), 16);
        assertEq(gasSaver.H(), 18);
        assertEq(gasSaver.D(), 1);
        assertEq(gasSaver.SUBTREE_H(), 18);
        assertEq(gasSaver.A(), 20);
        assertEq(gasSaver.K(), 7);
        assertEq(gasSaver.W(), 8);
        assertEq(gasSaver.L(), 43);
        assertEq(gasSaver.TARGET_SUM(), 217);
        assertEq(gasSaver.SIG_LEN(), SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN);
        assertEq(SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN, 3028);
    }

    function test_plus128s_params() public view {
        assertEq(plus128s.PARAMETER_SET(), "sphincs_plus_128s");
        assertEq(plus128s.N(), 16);
        assertEq(plus128s.H(), 63);
        assertEq(plus128s.D(), 7);
        assertEq(plus128s.SUBTREE_H(), 9);
        assertEq(plus128s.A(), 12);
        assertEq(plus128s.K(), 14);
        assertEq(plus128s.W(), 16);
        assertEq(plus128s.L(), 35);
        assertEq(plus128s.SIG_LEN(), SPHINCS_PLUS_128S_SIG_LEN);
        assertEq(SPHINCS_PLUS_128S_SIG_LEN, 7856);
    }

    function test_wrongLength_reverts() public {
        vm.expectRevert(bytes("Invalid sig length"));
        fastTradePlus.verify(PK_SEED, PK_ROOT, MESSAGE, new bytes(SPHINCS_FAST_TRADE_PLUS_SIG_LEN - 1));

        vm.expectRevert(bytes("Invalid sig length"));
        defaultMinus.verify(PK_SEED, PK_ROOT, MESSAGE, new bytes(SPHINCS_DEFAULT_MINUS_SIG_LEN - 1));

        vm.expectRevert(bytes("Invalid sig length"));
        gasSaver.verify(PK_SEED, PK_ROOT, MESSAGE, new bytes(SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN - 1));

        vm.expectRevert(bytes("Invalid sig length"));
        plus128s.verify(PK_SEED, PK_ROOT, MESSAGE, new bytes(SPHINCS_PLUS_128S_SIG_LEN - 1));
    }

    function test_nonCanonicalPubkey_reverts() public {
        bytes32 bad = bytes32(uint256(1));

        vm.expectRevert(bytes("Invalid public key"));
        fastTradePlus.verify(bad, PK_ROOT, MESSAGE, new bytes(SPHINCS_FAST_TRADE_PLUS_SIG_LEN));

        vm.expectRevert(bytes("Invalid public key"));
        defaultMinus.verify(PK_SEED, bad, MESSAGE, new bytes(SPHINCS_DEFAULT_MINUS_SIG_LEN));

        vm.expectRevert(bytes("Invalid public key"));
        gasSaver.verify(bad, PK_ROOT, MESSAGE, new bytes(SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN));

        vm.expectRevert(bytes("Invalid public key"));
        plus128s.verify(PK_SEED, bad, MESSAGE, new bytes(SPHINCS_PLUS_128S_SIG_LEN));
    }

    function test_zeroSignaturesDoNotVerify() public view {
        assertFalse(
            fastTradePlus.verify(PK_SEED, PK_ROOT, MESSAGE, new bytes(SPHINCS_FAST_TRADE_PLUS_SIG_LEN)),
            "zero fast_trade_plus sig"
        );
        assertFalse(
            defaultMinus.verify(PK_SEED, PK_ROOT, MESSAGE, new bytes(SPHINCS_DEFAULT_MINUS_SIG_LEN)),
            "zero default_minus sig"
        );
        assertFalse(
            gasSaver.verify(PK_SEED, PK_ROOT, MESSAGE, new bytes(SPHINCS_GAS_SAVER_MINUS_Q18_AGGRESSIVE_SIG_LEN)),
            "zero gas_saver sig"
        );
        assertFalse(
            plus128s.verify(PK_SEED, PK_ROOT, MESSAGE, new bytes(SPHINCS_PLUS_128S_SIG_LEN)),
            "zero sphincs_plus_128s sig"
        );
    }
}
