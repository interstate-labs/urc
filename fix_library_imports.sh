#!/bin/bash

# Fix imports in MapWithTimeData.sol
MAP_FILE=slashing/Restaking/library/MapWithTimeData.sol

# Create a backup
cp $MAP_FILE ${MAP_FILE}.bak

# Update imports
sed -i '' 's|import {Checkpoints} from "openzeppelin-contracts/contracts/utils/structs/Checkpoints.sol"|import {Checkpoints} from "@karak/node_modules/@openzeppelin/contracts/utils/structs/Checkpoints.sol"|g' $MAP_FILE
sed -i '' 's|import {Time} from "openzeppelin-contracts/contracts/utils/types/Time.sol"|import {Time} from "@karak/node_modules/@openzeppelin/contracts/utils/types/Time.sol"|g' $MAP_FILE
sed -i '' 's|import {EnumerableMap} from "openzeppelin-contracts/contracts/utils/structs/EnumerableMap.sol"|import {EnumerableMap} from "@karak/node_modules/@openzeppelin/contracts/utils/structs/EnumerableMap.sol"|g' $MAP_FILE

echo "Fixed imports in MapWithTimeData.sol" 