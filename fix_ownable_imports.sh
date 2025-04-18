#!/bin/bash

# Fix EigenlayerRestakingHelper.sol
echo "Fixing EigenlayerRestakingHelper.sol..."
sed -i '' 's|import {OwnableUpgradeable} from "lib/openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol"|import {OwnableUpgradeable} from "lib/karak/node_modules/@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol"|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol

# Fix EigenlayerRestaking.sol
echo "Fixing EigenlayerRestaking.sol..."
sed -i '' 's|import {UUPSUpgradeable} from "openzeppelin-contracts/contracts/proxy/utils/UUPSUpgradeable.sol"|import {UUPSUpgradeable} from "lib/openzeppelin-contracts/contracts/proxy/utils/UUPSUpgradeable.sol"|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestaking.sol
sed -i '' 's|import {OwnableUpgradeable} from|import {OwnableUpgradeable} from "lib/karak/node_modules/@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol" // Modified for initialOwner support\n// import {OwnableUpgradeable} from|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestaking.sol

echo "Done fixing imports" 