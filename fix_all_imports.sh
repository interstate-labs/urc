#!/bin/bash

# Find all Solidity files and update OpenZeppelin imports
find slashing -name "*.sol" -type f -exec sed -i '' 's|@openzeppelin/contracts/|openzeppelin-contracts/contracts/|g' {} \;
find slashing -name "*.sol" -type f -exec sed -i '' 's|@openzeppelin/contracts-upgradeable/|openzeppelin-contracts-upgradeable/contracts/|g' {} \;

find src -name "*.sol" -type f -exec sed -i '' 's|@openzeppelin/contracts/|openzeppelin-contracts/contracts/|g' {} \;
find src -name "*.sol" -type f -exec sed -i '' 's|@openzeppelin/contracts-upgradeable/|openzeppelin-contracts-upgradeable/contracts/|g' {} \;

find test -name "*.sol" -type f -exec sed -i '' 's|@openzeppelin/contracts/|openzeppelin-contracts/contracts/|g' {} \;
find test -name "*.sol" -type f -exec sed -i '' 's|@openzeppelin/contracts-upgradeable/|openzeppelin-contracts-upgradeable/contracts/|g' {} \;

echo "Updated import paths in all Solidity files in the project" 