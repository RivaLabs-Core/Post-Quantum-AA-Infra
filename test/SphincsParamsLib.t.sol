// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SphincsParamsLib} from "../src/Verifiers/SphincsParamsLib.sol";
import {FORS_SIG_LEN} from "../src/Verifiers/ForsVerifier.sol";
import {SPHINCS_SIG_LEN} from "../src/Verifiers/SphincsVerifier.sol";

/// @dev External wrapper so `vm.expectRevert` can observe reverts from the internal library.
contract ParamsHarness {
    function validate(SphincsParamsLib.Params calldata p) external pure {
        SphincsParamsLib.validate(p);
    }

    function blobLen(SphincsParamsLib.Params calldata p) external pure returns (uint256) {
        return SphincsParamsLib.blobLen(p);
    }
}

contract SphincsParamsLibTest is Test {
    ParamsHarness harness;

    function setUp() public {
        harness = new ParamsHarness();
    }

    function _canonical() internal pure returns (SphincsParamsLib.Params memory) {
        return SphincsParamsLib.canonical();
    }

    // ---- canonical set ----

    function test_canonical_isValid() public view {
        harness.validate(_canonical());
    }

    function test_canonical_blobLenMatchesFixedVerifier() public pure {
        assertEq(SphincsParamsLib.blobLen(SphincsParamsLib.canonical()), SPHINCS_SIG_LEN);
    }

    function test_canonical_packedWord() public pure {
        // h=0x16 d=0x02 k=0x07 a=0x13 logW=0x03 l=0x2B targetSum=0x00D0
        assertEq(SphincsParamsLib.pack(SphincsParamsLib.canonical()), 0x00D02B0313070216);
    }

    // ---- pack / unpack ----

    function testFuzz_packUnpackRoundtrip(uint8 h, uint8 d, uint8 k, uint8 a, uint8 logW, uint8 l, uint16 targetSum)
        public
        pure
    {
        SphincsParamsLib.Params memory p =
            SphincsParamsLib.Params({h: h, d: d, k: k, a: a, logW: logW, l: l, targetSum: targetSum});
        uint256 packed = SphincsParamsLib.pack(p);
        assertEq(packed >> 64, 0, "packed word must fit 64 bits");
        SphincsParamsLib.Params memory q = SphincsParamsLib.unpack(packed);
        assertEq(q.h, h);
        assertEq(q.d, d);
        assertEq(q.k, k);
        assertEq(q.a, a);
        assertEq(q.logW, logW);
        assertEq(q.l, l);
        assertEq(q.targetSum, targetSum);
    }

    // ---- validate: one violation per constraint ----

    function _expectInvalid(SphincsParamsLib.Params memory p, string memory reason) internal {
        vm.expectRevert(bytes(reason));
        harness.validate(p);
    }

    function test_validate_rejectsZeroParams() public {
        SphincsParamsLib.Params memory p = _canonical();
        p.h = 0;
        _expectInvalid(p, "SphincsParams: zero param");
        p = _canonical();
        p.d = 0;
        _expectInvalid(p, "SphincsParams: zero param");
        p = _canonical();
        p.k = 0;
        _expectInvalid(p, "SphincsParams: zero param");
        p = _canonical();
        p.a = 0;
        _expectInvalid(p, "SphincsParams: zero param");
        p = _canonical();
        p.l = 0;
        _expectInvalid(p, "SphincsParams: zero param");
    }

    function test_validate_rejectsLogWOutOfRange() public {
        SphincsParamsLib.Params memory p = _canonical();
        p.logW = 0;
        _expectInvalid(p, "SphincsParams: logW out of range");
        p = _canonical();
        p.logW = 9;
        _expectInvalid(p, "SphincsParams: logW out of range");
    }

    function test_validate_rejectsIndivisibleHeight() public {
        SphincsParamsLib.Params memory p = _canonical();
        p.h = 23; // 23 % 2 != 0
        _expectInvalid(p, "SphincsParams: h not multiple of d");
    }

    function test_validate_rejectsTallSubtree() public {
        SphincsParamsLib.Params memory p = _canonical();
        p.h = 66; // h/d = 33 > 32
        _expectInvalid(p, "SphincsParams: subtree too tall");
    }

    function test_validate_rejectsTreeAddressOverflow() public {
        // h=130 d=13 -> subtreeH=10 (<=32) but idxTree needs 120 bits > 96.
        SphincsParamsLib.Params memory p =
            SphincsParamsLib.Params({h: 130, d: 13, k: 1, a: 1, logW: 3, l: 43, targetSum: 208});
        _expectInvalid(p, "SphincsParams: tree address overflow");
    }

    function test_validate_rejectsDigestBitsExceeded() public {
        SphincsParamsLib.Params memory p = _canonical();
        p.k = 12;
        p.a = 20; // 12*20 + 22 = 262 > 256
        _expectInvalid(p, "SphincsParams: digest bits exceeded");
    }

    function test_validate_rejectsWotsDigitsExceeded() public {
        SphincsParamsLib.Params memory p = _canonical();
        p.l = 86; // 86*3 = 258 > 256
        _expectInvalid(p, "SphincsParams: wots digits exceeded");
    }

    function test_validate_rejectsBadTargetSum() public {
        SphincsParamsLib.Params memory p = _canonical();
        p.targetSum = 0;
        _expectInvalid(p, "SphincsParams: bad target sum");
        p = _canonical();
        p.targetSum = 43 * 7 + 1; // > l*(w-1)
        _expectInvalid(p, "SphincsParams: bad target sum");
    }

    function test_validate_rejectsTallForsTree() public {
        // k*a + h = 7*33 + 22 = 253 <= 256 passes the digest check, then a > 32 trips.
        SphincsParamsLib.Params memory p = _canonical();
        p.a = 33;
        _expectInvalid(p, "SphincsParams: fors tree too tall");
    }

    function test_validate_rejectsForsAdrsOverflow() public {
        // (2 << 32) = 2^33 > 2^32: FORS word3 would not fit the uint32 ADRS field.
        SphincsParamsLib.Params memory p = _canonical();
        p.k = 2;
        p.a = 32;
        _expectInvalid(p, "SphincsParams: fors adrs overflow");
    }

    // ---- length math ----

    function test_blobLen_secondHandComputedSet() public view {
        // R(16) + 10*16 secrets + 9*12*16 auth + 1*(16*64 + 4 + 16*8) = 1904 + 1156 = 3060
        SphincsParamsLib.Params memory p =
            SphincsParamsLib.Params({h: 8, d: 1, k: 10, a: 12, logW: 4, l: 64, targetSum: 480});
        harness.validate(p);
        assertEq(SphincsParamsLib.blobLen(p), 3060);
    }

    /// @dev This VALID param set's envelope (64 + 2384) collides with FORS_SIG_LEN — the account's
    ///      registration guard (not validate) must reject it. Pinned here so the guard test in
    ///      SimpleAccount.t.sol stays honest if the length formula ever changes.
    function test_blobLen_forsCollisionSet() public view {
        SphincsParamsLib.Params memory p =
            SphincsParamsLib.Params({h: 32, d: 4, k: 7, a: 6, logW: 3, l: 18, targetSum: 63});
        harness.validate(p);
        assertEq(64 + SphincsParamsLib.blobLen(p), FORS_SIG_LEN);
    }

    /// @dev Every valid set's envelope length is divisible by 4 (blob = 16x + 4d, header = 64),
    ///      while activation-envelope lengths are 2451 + 32p ≡ 3 (mod 4) — so a registered
    ///      SPHINCS- envelope can NEVER collide with an activation envelope. The account still
    ///      guards it belt-and-braces; this fuzz encodes the impossibility proof.
    function testFuzz_envelopeLen_neverInActivationClass(
        uint8 h,
        uint8 d,
        uint8 k,
        uint8 a,
        uint8 logW,
        uint8 l,
        uint16 targetSum
    ) public view {
        SphincsParamsLib.Params memory p =
            SphincsParamsLib.Params({h: h, d: d, k: k, a: a, logW: logW, l: l, targetSum: targetSum});
        try harness.validate(p) {}
        catch {
            return; // invalid set — not registrable, irrelevant
        }
        uint256 envLen = 64 + harness.blobLen(p);
        assertEq(envLen % 4, 0, "envelope length must be 0 mod 4");
        // Activation envelopes: 3 + 32p + FORS_SIG_LEN ≡ 3 (mod 4) since FORS_SIG_LEN % 4 == 0.
        assertEq(FORS_SIG_LEN % 4, 0);
    }
}
