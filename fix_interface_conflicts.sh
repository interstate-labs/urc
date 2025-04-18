#!/bin/bash

# Update EigenlayerRestakingHelper.sol to use EigenLayer's interfaces directly instead of custom ones
sed -i '' 's|import {ISignatureUtils} from "../../../src/interfaces/ISignatureUtils.sol";|// Using EigenLayer interface directly|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol
sed -i '' 's|import {IStrategy} from "../../../src/interfaces/IStrategy.sol";|// Using EigenLayer interface directly|g' slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol

echo "Fixed interface conflicts in EigenlayerRestakingHelper.sol" 