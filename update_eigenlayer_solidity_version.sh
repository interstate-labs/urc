#!/bin/bash

# Find all Solidity files in eigenlayer-contracts and eigenlayer-middleware with exact version 0.8.12 and update them to 0.8.29
find lib/eigenlayer-contracts -name "*.sol" -type f -exec sed -i '' 's/pragma solidity =0.8.12;/pragma solidity 0.8.29;/g' {} \;
find lib/eigenlayer-middleware -name "*.sol" -type f -exec sed -i '' 's/pragma solidity =0.8.12;/pragma solidity 0.8.29;/g' {} \;

# Find any other version formats
find lib/eigenlayer-contracts -name "*.sol" -type f -exec sed -i '' 's/pragma solidity 0.8.12;/pragma solidity 0.8.29;/g' {} \;
find lib/eigenlayer-middleware -name "*.sol" -type f -exec sed -i '' 's/pragma solidity 0.8.12;/pragma solidity 0.8.29;/g' {} \;

echo "Updated Solidity version in EigenLayer contracts from 0.8.12 to 0.8.29" 