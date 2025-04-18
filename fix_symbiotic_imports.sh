#!/bin/bash

# Check if symbiotic contract file exists
SYMBIOTIC_FILE=slashing/Restaking/SymbioticRestaking/SymbioticRestaking.sol
if [ ! -f "$SYMBIOTIC_FILE" ]; then
    echo "Symbiotic contract file not found at $SYMBIOTIC_FILE"
    exit 1
fi

# Update OpenZeppelin import paths in the Symbiotic contract
sed -i '' 's|@openzeppelin/contracts/|openzeppelin-contracts/contracts/|g' $SYMBIOTIC_FILE
sed -i '' 's|@openzeppelin/contracts-upgradeable/|openzeppelin-contracts-upgradeable/contracts/|g' $SYMBIOTIC_FILE

echo "Updated import paths in $SYMBIOTIC_FILE"

# Also fix any imports in the library files related to Symbiotic
for FILE in slashing/Restaking/SymbioticRestaking/*.sol; do
    if [ -f "$FILE" ]; then
        sed -i '' 's|@openzeppelin/contracts/|openzeppelin-contracts/contracts/|g' $FILE
        sed -i '' 's|@openzeppelin/contracts-upgradeable/|openzeppelin-contracts-upgradeable/contracts/|g' $FILE
        echo "Updated import paths in $FILE"
    fi
done

echo "Finished updating import paths for Symbiotic contracts" 