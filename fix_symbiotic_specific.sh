#!/bin/bash

SYMBIOTIC_FILE=slashing/Restaking/SymbioticRestaking/SymbioticRestaking.sol

# Create a backup of the original file
cp $SYMBIOTIC_FILE ${SYMBIOTIC_FILE}.bak

# Replace imports to use node_modules paths directly
cat > $SYMBIOTIC_FILE << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

// Use direct paths to node_modules libraries
import {Time} from "@karak/node_modules/@openzeppelin/contracts/utils/types/Time.sol";
import {EnumerableMap} from "@karak/node_modules/@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "@karak/node_modules/@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "@karak/node_modules/@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OwnableUpgradeable} from "@karak/node_modules/@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@karak/node_modules/@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IRegistry} from "@symbiotic/interfaces/common/IRegistry.sol";
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {IEntity} from "@symbiotic/interfaces/common/IEntity.sol";

import {IConsensusRestaking} from "../IRestaking.sol";

// Copy rest of the file from backup
EOF

# Append the rest of the file (after the imports)
tail -n +20 ${SYMBIOTIC_FILE}.bak >> $SYMBIOTIC_FILE

echo "Fixed SymbioticRestaking.sol imports to use direct paths" 