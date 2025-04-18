#!/bin/bash

# Update imports in EigenlayerRestaking.sol and EigenlayerRestakingHelper.sol to use direct paths

# EigenlayerRestaking.sol
sed -i '' 's|@eigenlayer-middleware/src/interfaces/IServiceManager.sol|../../../lib/eigenlayer-middleware/src/interfaces/IServiceManager.sol|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestaking.sol
sed -i '' 's|@eigenlayer/interfaces/IStrategyManager.sol|../../../lib/eigenlayer-contracts/src/contracts/interfaces/IStrategyManager.sol|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestaking.sol
sed -i '' 's|@eigenlayer/interfaces/ISignatureUtils.sol|../../../lib/eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestaking.sol
sed -i '' 's|@eigenlayer/interfaces/IStrategy.sol|../../../lib/eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestaking.sol
sed -i '' 's|@eigenlayer/core/AVSDirectoryStorage.sol|../../../lib/eigenlayer-contracts/src/contracts/core/AVSDirectoryStorage.sol|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestaking.sol

# EigenlayerRestakingHelper.sol
sed -i '' 's|@eigenlayer/interfaces/IAVSDirectory.sol|../../../lib/eigenlayer-contracts/src/contracts/interfaces/IAVSDirectory.sol|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol
sed -i '' 's|@eigenlayer/interfaces/IDelegationManager.sol|../../../lib/eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol
sed -i '' 's|@eigenlayer/core/DelegationManagerStorage.sol|../../../lib/eigenlayer-contracts/src/contracts/core/DelegationManagerStorage.sol|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol
sed -i '' 's|@eigenlayer/interfaces/IStrategy.sol|../../../lib/eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol
sed -i '' 's|@eigenlayer/core/StrategyManagerStorage.sol|../../../lib/eigenlayer-contracts/src/contracts/core/StrategyManagerStorage.sol|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol
sed -i '' 's|@eigenlayer/interfaces/ISignatureUtils.sol|../../../lib/eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol

echo "Updated import paths with direct paths in EigenlayerRestaking files" 