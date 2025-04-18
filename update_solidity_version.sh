#!/bin/bash

# Find all Solidity files with version 0.8.25 and update them to 0.8.29
find slashing -name "*.sol" -type f -exec sed -i '' 's/pragma solidity 0.8.25;/pragma solidity 0.8.29;/g' {} \;

echo "Updated Solidity version in all files from 0.8.25 to 0.8.29" 