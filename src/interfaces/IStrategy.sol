// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/**
 * @title Interface for strategies
 */
interface IStrategy {
    /**
     * @notice Returns the token underlying the strategy.
     */
    function underlyingToken() external view returns (IERC20);

    /**
     * @notice Calculates the amount of shares that should be minted for a given deposit.
     * @param amount The amount of tokens to be deposited.
     */
    function underlyingToShares(uint256 amount) external view returns (uint256);

    /**
     * @notice Calculates the amount of underlying tokens a user would receive for redeeming a given number of shares.
     * @param shares The amount of shares to be redeemed.
     */
    function sharesToUnderlyingView(uint256 shares) external view returns (uint256);
} 