#!/bin/bash

# Check if symbiotic contract file exists
echo "Starting comprehensive Symbiotic fix..."
SYMBIOTIC_FILE=slashing/Restaking/SymbioticRestaking/SymbioticRestaking.sol
if [ ! -f "$SYMBIOTIC_FILE" ]; then
    echo "Symbiotic contract file not found at $SYMBIOTIC_FILE"
    exit 1
fi

# Create a backup of the original file
cp $SYMBIOTIC_FILE ${SYMBIOTIC_FILE}.bak

# Create new SymbioticRestaking.sol with direct paths
cat > $SYMBIOTIC_FILE << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Time} from "lib/karak/node_modules/@openzeppelin/contracts/utils/types/Time.sol";
import {EnumerableMap} from "lib/openzeppelin-contracts/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "lib/openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {OwnableUpgradeable} from "lib/karak/node_modules/@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "lib/openzeppelin-contracts/contracts/proxy/utils/UUPSUpgradeable.sol";

import {IBaseDelegator} from "lib/core/src/interfaces/delegator/IBaseDelegator.sol";
import {Subnetwork} from "lib/core/src/contracts/libraries/Subnetwork.sol";
import {IVault} from "lib/core/src/interfaces/vault/IVault.sol";
import {IRegistry} from "lib/core/src/interfaces/common/IRegistry.sol";
import {IOptInService} from "lib/core/src/interfaces/service/IOptInService.sol";
import {ISlasher} from "lib/core/src/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "lib/core/src/interfaces/slasher/IVetoSlasher.sol";
import {IEntity} from "lib/core/src/interfaces/common/IEntity.sol";

import {IConsensusRestaking} from "../IRestaking.sol";
EOF

# Append the rest of the file (after the imports)
tail -n +20 ${SYMBIOTIC_FILE}.bak >> $SYMBIOTIC_FILE

echo "Fixed SymbioticRestaking.sol imports with direct paths"

# Fix imports in core library files used by Symbiotic
echo "Fixing imports in core library files..."
find lib/core -name "*.sol" -type f -exec sed -i '' 's|import "@openzeppelin/contracts/|import "lib/openzeppelin-contracts/contracts/|g' {} \;
find lib/core -name "*.sol" -type f -exec sed -i '' 's|import "@openzeppelin/contracts-upgradeable/|import "lib/openzeppelin-contracts-upgradeable/contracts/|g' {} \;

echo "Completed comprehensive Symbiotic fix" 