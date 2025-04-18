#!/bin/bash

# Fix imports in EigenLayer contracts
find lib/eigenlayer-contracts -name "*.sol" -type f -exec sed -i '' 's|import "@openzeppelin/contracts/|import "lib/openzeppelin-contracts/contracts/|g' {} \;
find lib/eigenlayer-middleware -name "*.sol" -type f -exec sed -i '' 's|import "@openzeppelin/contracts/|import "lib/openzeppelin-contracts/contracts/|g' {} \;

# Fix imports for upgradeable contracts
find lib/eigenlayer-contracts -name "*.sol" -type f -exec sed -i '' 's|import "@openzeppelin/contracts-upgradeable/|import "lib/openzeppelin-contracts-upgradeable/contracts/|g' {} \;
find lib/eigenlayer-middleware -name "*.sol" -type f -exec sed -i '' 's|import "@openzeppelin/contracts-upgradeable/|import "lib/openzeppelin-contracts-upgradeable/contracts/|g' {} \;

echo "Fixed imports in EigenLayer contracts" 