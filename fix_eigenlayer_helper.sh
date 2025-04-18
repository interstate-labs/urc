#!/bin/bash

# Fix imports in EigenlayerRestakingHelper.sol
HELPER_FILE=slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol

# Create a backup
cp $HELPER_FILE ${HELPER_FILE}.bak

# Update OpenZeppelin imports to use direct paths
sed -i '' 's|import {Time} from "openzeppelin-contracts/contracts/utils/types/Time.sol"|import {Time} from "@karak/node_modules/@openzeppelin/contracts/utils/types/Time.sol"|g' $HELPER_FILE
sed -i '' 's|import {OwnableUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol"|import {OwnableUpgradeable} from "@karak/node_modules/@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol"|g' $HELPER_FILE

echo "Fixed imports in EigenlayerRestakingHelper.sol" 