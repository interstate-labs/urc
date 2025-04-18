#!/bin/bash

# Update imports in EigenlayerRestaking.sol
sed -i '' 's|@eigenlayer/src/contracts/interfaces/|@eigenlayer/interfaces/|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestaking.sol
sed -i '' 's|@eigenlayer/src/contracts/core/|@eigenlayer/core/|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestaking.sol

# Update imports in EigenlayerRestakingHelper.sol
sed -i '' 's|@eigenlayer/src/contracts/interfaces/|@eigenlayer/interfaces/|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol 
sed -i '' 's|@eigenlayer/src/contracts/core/|@eigenlayer/core/|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol

echo "Updated import paths in EigenlayerRestaking files" 