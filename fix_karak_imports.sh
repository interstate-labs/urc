#!/bin/bash

# Fix imports in Karak contracts
find lib/karak -name "*.sol" -type f -exec sed -i '' 's|import {Create2} from "@openzeppelin/contracts/|import {Create2} from "lib/openzeppelin-contracts/contracts/|g' {} \;
find lib/karak -name "*.sol" -type f -exec sed -i '' 's|import "@openzeppelin/contracts/interfaces/|import "lib/openzeppelin-contracts/contracts/interfaces/|g' {} \;
find lib/karak -name "*.sol" -type f -exec sed -i '' 's|import {EnumerableSet} from "@openzeppelin/contracts/|import {EnumerableSet} from "lib/openzeppelin-contracts/contracts/|g' {} \;
find lib/karak -name "*.sol" -type f -exec sed -i '' 's|import {Math} from "@openzeppelin/contracts/|import {Math} from "lib/openzeppelin-contracts/contracts/|g' {} \;
find lib/karak -name "*.sol" -type f -exec sed -i '' 's|import "@openzeppelin/contracts/utils/structs/|import "lib/openzeppelin-contracts/contracts/utils/structs/|g' {} \;
find lib/karak -name "*.sol" -type f -exec sed -i '' 's|import {IERC20} from "@openzeppelin/contracts/|import {IERC20} from "lib/openzeppelin-contracts/contracts/|g' {} \;

# Fix imports in KarakRestaking.sol
echo "Fixing KarakRestaking.sol..."
find slashing/Restaking/KarakRestaking -name "*.sol" -type f -exec sed -i '' 's|import "@openzeppelin/contracts/|import "lib/openzeppelin-contracts/contracts/|g' {} \;
find slashing/Restaking/KarakRestaking -name "*.sol" -type f -exec sed -i '' 's|import {Create2} from "@openzeppelin/contracts/|import {Create2} from "lib/openzeppelin-contracts/contracts/|g' {} \;
find slashing/Restaking/KarakRestaking -name "*.sol" -type f -exec sed -i '' 's|import "@openzeppelin/contracts-upgradeable/|import "lib/openzeppelin-contracts-upgradeable/contracts/|g' {} \;

echo "Fixed imports in Karak contracts" 