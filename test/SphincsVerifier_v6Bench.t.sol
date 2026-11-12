// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SphincsVerifier_v6, SPHINCS_V6_SIG_LEN} from "../src/Verifiers/SphincsVerifier_v6.sol";

/// @dev Benchmark / regression harness for SphincsVerifier_v6, on signatures from an
///      off-repo signer.
contract SphincsVerifier_v6BenchTest is Test {
    SphincsVerifier_v6 verifier;

    function setUp() public {
        verifier = new SphincsVerifier_v6();
    }

    function _vector(uint256 n) internal view returns (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/sphincs-v6-bench-", vm.toString(n), ".json"));
        pkSeed = vm.parseJsonBytes32(json, ".pkSeed");
        pkRoot = vm.parseJsonBytes32(json, ".pkRoot");
        message = vm.parseJsonBytes32(json, ".message");
        sig = vm.parseJsonBytes(json, ".signature");
    }

    function test_bench_verifies() public view {
        for (uint256 n = 0; n < 2; n++) {
            (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _vector(n);
            assertEq(sig.length, SPHINCS_V6_SIG_LEN);
            assertTrue(verifier.verify(pkSeed, pkRoot, message, sig));
        }
    }

    function test_bench_wrongMessage_fails() public view {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _vector(0);
        assertFalse(verifier.verify(pkSeed, pkRoot, bytes32(uint256(message) ^ 1), sig));
    }

    /// @dev Flip one bit anywhere in the blob (16-byte elements and the 4-byte counters).
    function testFuzz_bench_tamper_fails(uint256 pos, uint8 bit) public view {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _vector(0);
        uint256 off = bound(pos, 0, SPHINCS_V6_SIG_LEN - 1);
        sig[off] = bytes1(uint8(sig[off]) ^ uint8(1 << (bit % 8)));
        assertFalse(verifier.verify(pkSeed, pkRoot, message, sig));
    }

    function testFuzz_bench1_tamper_fails(uint256 pos, uint8 bit) public view {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _vector(1);
        uint256 off = bound(pos, 0, SPHINCS_V6_SIG_LEN - 1);
        sig[off] = bytes1(uint8(sig[off]) ^ uint8(1 << (bit % 8)));
        assertFalse(verifier.verify(pkSeed, pkRoot, message, sig));
    }

    function test_bench_gas() public {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _vector(0);
        uint256 g = gasleft();
        verifier.verify(pkSeed, pkRoot, message, sig);
        emit log_named_uint("v6 verify gas", g - gasleft());

        (pkSeed, pkRoot, message, sig) = _vector(1);
        g = gasleft();
        verifier.verify(pkSeed, pkRoot, message, sig);
        emit log_named_uint("v6 verify gas (vector 1)", g - gasleft());

        // Flip the layer-0 counter: fails the first digit-sum gate right after FORS.
        sig[3056 + 1024 + 3] = bytes1(uint8(sig[3056 + 1024 + 3]) ^ 1);
        g = gasleft();
        verifier.verify(pkSeed, pkRoot, message, sig);
        emit log_named_uint("v6 gas to first gate (H_msg + FORS + 1 digest)", g - gasleft());
    }
}
