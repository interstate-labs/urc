// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

/**
 * @title The interface for common signature utilities.
 */
interface ISignatureUtils {
    // @notice Struct that bundles together a signature and an expiration time for the signature.
    struct SignatureWithExpiry {
        // the signature itself, formatted as a single bytes object
        bytes signature;
        // the expiration timestamp (UTC) of the signature
        uint256 expiry;
    }

    // @notice Struct that bundles together a signature, a salt for uniqueness, and an expiration time for the signature.
    struct SignatureWithSaltAndExpiry {
        // the signature itself, formatted as a single bytes object
        bytes signature;
        // the salt used to generate the signature
        bytes32 salt;
        // the expiration timestamp (UTC) of the signature
        uint256 expiry;
    }
} 