#!/bin/bash

# Restore backup copies if they exist
if [ -f "slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol.bak" ]; then
    cp slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol.bak slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol
    echo "Restored original EigenlayerRestakingHelper.sol"
fi

if [ -f "slashing/Restaking/library/MapWithTimeData.sol.bak" ]; then
    cp slashing/Restaking/library/MapWithTimeData.sol.bak slashing/Restaking/library/MapWithTimeData.sol
    echo "Restored original MapWithTimeData.sol"
fi

if [ -f "slashing/Restaking/SymbioticRestaking/SymbioticRestaking.sol.bak" ]; then
    cp slashing/Restaking/SymbioticRestaking/SymbioticRestaking.sol.bak slashing/Restaking/SymbioticRestaking/SymbioticRestaking.sol
    echo "Restored original SymbioticRestaking.sol"
fi

# Now fix the imports to use the correct paths based on the new remappings
sed -i '' 's|import {Time} from "openzeppelin-contracts/contracts/utils/types/Time.sol"|import {Time} from "openzeppelin-contracts/utils/types/Time.sol"|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol
sed -i '' 's|import {OwnableUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol"|import {OwnableUpgradeable} from "openzeppelin-contracts-upgradeable/access/OwnableUpgradeable.sol"|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol

# Fix library imports
sed -i '' 's|import {Checkpoints} from "openzeppelin-contracts/contracts/utils/structs/Checkpoints.sol"|import {Checkpoints} from "openzeppelin-contracts/utils/structs/Checkpoints.sol"|g' slashing/Restaking/library/MapWithTimeData.sol
sed -i '' 's|import {Time} from "openzeppelin-contracts/contracts/utils/types/Time.sol"|import {Time} from "openzeppelin-contracts/utils/types/Time.sol"|g' slashing/Restaking/library/MapWithTimeData.sol
sed -i '' 's|import {EnumerableMap} from "openzeppelin-contracts/contracts/utils/structs/EnumerableMap.sol"|import {EnumerableMap} from "openzeppelin-contracts/utils/structs/EnumerableMap.sol"|g' slashing/Restaking/library/MapWithTimeData.sol

echo "Fixed imports in all files to use correct paths" 