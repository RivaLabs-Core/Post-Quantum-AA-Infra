// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISignatureVerifier} from "./Interfaces/ISignatureVerifier.sol";
import {FORS_SIG_LEN} from "./Verifiers/ForsVerifier.sol";

/// @title FrameAccount
/// @notice EIP-8141 frame account that authenticates with the existing FORS verifier.
/// @dev This is intentionally separate from the ERC-4337 SimpleAccount.
///      The VERIFY frame checks the FORS signature and enforces that the
///      immediately following frame rotates the signer through a SENDER call.
///      The frame-introspection hooks are abstract because current Solidity
///      cannot compile the draft EIP-8141 opcodes directly.
abstract contract FrameAccount {
    uint256 internal constant FRAME_MODE_SENDER = 2;
    uint256 internal constant ATOMIC_BATCH_FLAG = 1 << 2;
    // selector(4) + currentKey(32) + nextOwner(32)
    uint256 internal constant ROTATE_OWNER_CALLDATA_LENGTH = 4 + 32 + 32;

    uint8 internal constant AUTH_NONE = 0; // never authorized
    uint8 internal constant AUTH_ACTIVE = 1; // authorized, may sign exactly one frame
    uint8 internal constant AUTH_BURNED = 2; // already used, never valid again

    /// @notice Per-signer authorization state. Each device runs its own key chain.
    mapping(address => uint8) public authState;
    ISignatureVerifier public immutable VERIFIER;

    event FrameAccountInitialized(address indexed owner, address indexed verifier);
    event OwnerRotated(address indexed previousOwner, address indexed newOwner);

    error FrameAccountZeroOwner();
    error FrameAccountZeroVerifier();
    error FrameAccountNotSelf();
    error FrameAccountBadSignatureLength(uint256 length);
    error FrameAccountInvalidSignature(address recovered);
    error FrameAccountKeyNotActive(address key);
    error FrameAccountNextOwnerNotFresh(address nextOwner);
    error FrameAccountMissingRotationFrame(uint256 currentFrame, uint256 frameCount);
    error FrameAccountRotationFrameWrongMode(uint256 frameIndex, uint256 mode);
    error FrameAccountRotationFrameWrongTarget(uint256 frameIndex, address target);
    error FrameAccountRotationFrameNonZeroValue(uint256 frameIndex, uint256 value);
    error FrameAccountRotationFrameAtomic(uint256 frameIndex);
    error FrameAccountRotationFrameWrongDataLength(uint256 frameIndex, uint256 length);
    error FrameAccountRotationFrameWrongSelector(uint256 frameIndex, bytes4 selector);
    error FrameAccountRotationFrameWrongCurrent(uint256 frameIndex, address currentKey);
    error FrameAccountRotationFrameZeroOwner(uint256 frameIndex);

    constructor(address initialOwner, ISignatureVerifier verifier) {
        if (initialOwner == address(0)) revert FrameAccountZeroOwner();
        if (address(verifier) == address(0)) revert FrameAccountZeroVerifier();

        authState[initialOwner] = AUTH_ACTIVE;
        VERIFIER = verifier;

        emit FrameAccountInitialized(initialOwner, address(verifier));
    }

    /// @notice VERIFY frame entry point. Calldata is the FORS signature blob.
    fallback() external {
        _validateFrameSignature(msg.data);
        _approveExecutionAndPayment();
    }

    /// @notice Dedicated rotation entry point to be called by the required SENDER frame.
    ///         Carries the current (signing) key so the burn binds to the signer that the
    ///         VERIFY frame authenticated; all state changes happen here, in the rotate frame.
    function rotateOwner(address currentKey, address nextOwner) external {
        _requireSelf();
        _rotateOwner(currentKey, nextOwner);
    }

    /// @notice Validation of the FORS signature + require the next frame to be exclusively a call to rotateOwner().
    /// @dev Side-effect-free: it only verifies the signer is active and that the next frame
    ///      will burn exactly that signer and activate a fresh key. State changes happen in
    ///      the SENDER rotateOwner frame.
    function _validateFrameSignature(bytes calldata signature) internal view virtual {
        if (signature.length != FORS_SIG_LEN) revert FrameAccountBadSignatureLength(signature.length);

        bytes32 sigHash = _txSigHash();
        address recovered = VERIFIER.recover(signature, sigHash);

        if (recovered == address(0) || authState[recovered] != AUTH_ACTIVE) {
            revert FrameAccountInvalidSignature(recovered);
        }

        _requireNextFrameRotatesOwner(recovered);
    }

    function _requireNextFrameRotatesOwner(address expectedCurrent)
        internal
        view
        virtual
        returns (address nextOwner)
    {
        uint256 currentFrame = _currentFrameIndex();
        uint256 frameCount = _frameCount();
        uint256 rotationFrame = currentFrame + 1;

        if (rotationFrame >= frameCount) {
            revert FrameAccountMissingRotationFrame(currentFrame, frameCount);
        }

        uint256 mode = _frameMode(rotationFrame);
        if (mode != FRAME_MODE_SENDER) {
            revert FrameAccountRotationFrameWrongMode(rotationFrame, mode);
        }

        address target = _frameTarget(rotationFrame);
        if (target != address(this)) {
            revert FrameAccountRotationFrameWrongTarget(rotationFrame, target);
        }

        uint256 value = _frameValue(rotationFrame);
        if (value != 0) {
            revert FrameAccountRotationFrameNonZeroValue(rotationFrame, value);
        }

        if (_frameAtomicBatch(rotationFrame)) {
            revert FrameAccountRotationFrameAtomic(rotationFrame);
        }

        uint256 dataLength = _frameDataLength(rotationFrame);
        if (dataLength != ROTATE_OWNER_CALLDATA_LENGTH) {
            revert FrameAccountRotationFrameWrongDataLength(rotationFrame, dataLength);
        }

        bytes32 word0 = _frameDataLoad(rotationFrame, 0);
        bytes4 selector = bytes4(word0);
        if (selector != this.rotateOwner.selector) {
            revert FrameAccountRotationFrameWrongSelector(rotationFrame, selector);
        }

        address currentKey = address(uint160(uint256(_frameDataLoad(rotationFrame, 4))));
        if (currentKey != expectedCurrent) {
            revert FrameAccountRotationFrameWrongCurrent(rotationFrame, currentKey);
        }

        nextOwner = address(uint160(uint256(_frameDataLoad(rotationFrame, 36))));
        if (nextOwner == address(0)) {
            revert FrameAccountRotationFrameZeroOwner(rotationFrame);
        }
    }

    /// @dev All authorization-state mutation lives here, in the rotate frame: burn the
    ///      signing key and activate the fresh next key.
    function _rotateOwner(address currentKey, address nextOwner) internal {
        if (nextOwner == address(0)) revert FrameAccountZeroOwner();
        if (authState[currentKey] != AUTH_ACTIVE) revert FrameAccountKeyNotActive(currentKey);
        if (authState[nextOwner] != AUTH_NONE) revert FrameAccountNextOwnerNotFresh(nextOwner);

        authState[currentKey] = AUTH_BURNED;
        authState[nextOwner] = AUTH_ACTIVE;

        emit OwnerRotated(currentKey, nextOwner);
    }

    function _requireSelf() internal view {
        if (msg.sender != address(this)) revert FrameAccountNotSelf();
    }

    function _txSigHash() internal view virtual returns (bytes32);

    function _frameCount() internal view virtual returns (uint256);

    function _currentFrameIndex() internal view virtual returns (uint256);

    function _frameTarget(uint256 frameIndex) internal view virtual returns (address);

    function _frameMode(uint256 frameIndex) internal view virtual returns (uint256);

    function _frameValue(uint256 frameIndex) internal view virtual returns (uint256);

    function _frameAtomicBatch(uint256 frameIndex) internal view virtual returns (bool);

    function _frameDataLength(uint256 frameIndex) internal view virtual returns (uint256);

    function _frameDataLoad(uint256 frameIndex, uint256 offset) internal view virtual returns (bytes32);

    function _approveExecutionAndPayment() internal virtual;

    receive() external payable {}
}
