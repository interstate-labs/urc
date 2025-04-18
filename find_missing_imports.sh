#!/bin/bash

# Find Time.sol actual location
TIME_LOC=$(find lib -name Time.sol)
echo "Time.sol is located at: $TIME_LOC"

# Find Checkpoints.sol actual location
CHECKPOINTS_LOC=$(find lib -name Checkpoints.sol)
echo "Checkpoints.sol is located at: $CHECKPOINTS_LOC"

# Find EnumerableMap.sol actual location
ENUMERABLE_MAP_LOC=$(find lib -name EnumerableMap.sol)
echo "EnumerableMap.sol is located at: $ENUMERABLE_MAP_LOC"

# Find EnumerableSet.sol actual location
ENUMERABLE_SET_LOC=$(find lib -name EnumerableSet.sol)
echo "EnumerableSet.sol is located at: $ENUMERABLE_SET_LOC"

# Find IERC20.sol actual location
IERC20_LOC=$(find lib -name IERC20.sol)
echo "IERC20.sol is located at: $IERC20_LOC"

# Find UUPSUpgradeable.sol actual location
UUPS_LOC=$(find lib -name UUPSUpgradeable.sol)
echo "UUPSUpgradeable.sol is located at: $UUPS_LOC"

# Find OwnableUpgradeable.sol actual location
OWNABLE_LOC=$(find lib -name OwnableUpgradeable.sol)
echo "OwnableUpgradeable.sol is located at: $OWNABLE_LOC" 