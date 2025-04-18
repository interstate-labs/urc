#!/bin/bash

# Fix MapWithTimeData.sol
echo "Fixing MapWithTimeData.sol..."
cat > slashing/Restaking/library/MapWithTimeData.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

// Credits: Symbiotic contributors.
// Ref: https://github.com/symbioticfi/cosmos-sdk/blob/c25b6d5f320eb8ea4189584fa04d28c47362c2a7/middleware/src/libraries/MapWithTimeData.sol

import {Checkpoints} from "lib/openzeppelin-contracts/contracts/utils/Checkpoints.sol";
import {Time} from "lib/karak/node_modules/@openzeppelin/contracts/utils/types/Time.sol";
import {EnumerableMap} from "lib/openzeppelin-contracts/contracts/utils/structs/EnumerableMap.sol";

library MapWithTimeData {
    using EnumerableMap for EnumerableMap.AddressToUintMap;

    error AlreadyAdded();
    error NotEnabled();
    error AlreadyEnabled();

    uint256 private constant ENABLED_TIME_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 private constant DISABLED_TIME_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFF << 48;

    function add(EnumerableMap.AddressToUintMap storage self, address addr) internal {
        if (!self.set(addr, uint256(0))) {
            revert AlreadyAdded();
        }
    }

    function disable(EnumerableMap.AddressToUintMap storage self, address addr) internal {
        uint256 value = self.get(addr);

        if (uint48(value) == 0 || uint48(value >> 48) != 0) {
            revert NotEnabled();
        }

        value |= uint256(Time.timestamp()) << 48;
        self.set(addr, value);
    }

    function enable(EnumerableMap.AddressToUintMap storage self, address addr) internal {
        uint256 value = self.get(addr);

        if (uint48(value) != 0 && uint48(value >> 48) == 0) {
            revert AlreadyEnabled();
        }

        value = uint256(Time.timestamp());
        self.set(addr, value);
    }

    function atWithTimes(
        EnumerableMap.AddressToUintMap storage self,
        uint256 idx
    ) internal view returns (address key, uint48 enabledTime, uint48 disabledTime) {
        uint256 value;
        (key, value) = self.at(idx);
        enabledTime = uint48(value);
        disabledTime = uint48(value >> 48);
    }

    function getTimes(
        EnumerableMap.AddressToUintMap storage self,
        address addr
    ) internal view returns (uint48 enabledTime, uint48 disabledTime) {
        uint256 value = self.get(addr);
        enabledTime = uint48(value);
        disabledTime = uint48(value >> 48);
    }
}
EOF

# Fix EigenlayerRestakingHelper.sol
echo "Fixing EigenlayerRestakingHelper.sol..."
cat > slashing/Restaking/EigenlayerRestaking/EigenlayerRestakingHelper.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

// import {IValidatorRegistrySystem} from "../interfaces/IRegistry.sol";
import {IParameters} from "../IParameters.sol";
import {Time} from "lib/karak/node_modules/@openzeppelin/contracts/utils/types/Time.sol";
import {OwnableUpgradeable} from "lib/openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol";

// Import our simplified interfaces
// Using EigenLayer interface directly
// Using EigenLayer interface directly

// Import interfaces using direct paths
import {IAVSDirectory} from "../../../lib/eigenlayer-contracts/src/contracts/interfaces/IAVSDirectory.sol";
import {IDelegationManager} from "../../../lib/eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import {DelegationManagerStorage} from "../../../lib/eigenlayer-contracts/src/contracts/core/DelegationManagerStorage.sol";
import {StrategyManagerStorage} from "../../../lib/eigenlayer-contracts/src/contracts/core/StrategyManagerStorage.sol";
import {IStrategy} from "../../../lib/eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import {ISignatureUtils} from "../../../lib/eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";

contract RestakingHelper is OwnableUpgradeable {
    uint48 public START_TIMESTAMP;

    IParameters public parameters;
    // IValidatorRegistrySystem public registry;
    DelegationManagerStorage public DELEGATION_MANAGER;
    IAVSDirectory public AVS_DIRECTORY;

    StrategyManagerStorage public STRATEGY_MANAGER;
    bytes32 public PROTOCOL_IDENTIFIER;

    error NotRegistered();
    error OperationForbidden();

    function initialize(
        address _owner,
        address _parameters,
        address _eigenlayerAVSDirectory,
        address _eigenlayerDelegationManager,
        address _eigenlayerStrategyManager
    ) public initializer {
        __Ownable_init(_owner);
        parameters = IParameters(_parameters);
        // registry = IValidatorRegistrySystem(_registry);
        START_TIMESTAMP = Time.timestamp();

        AVS_DIRECTORY = IAVSDirectory(_eigenlayerAVSDirectory);
        DELEGATION_MANAGER = DelegationManagerStorage(
            _eigenlayerDelegationManager
        );
        STRATEGY_MANAGER = StrategyManagerStorage(_eigenlayerStrategyManager);
        PROTOCOL_IDENTIFIER = keccak256("CONSENSUS_PROTOCOL");
    }

    function _getStartTime() public view returns (uint48) {
        return START_TIMESTAMP;
    }

    function strategy_manager(address strategy) public view returns (bool) {
        // Call strategyIsWhitelistedForDeposit from STRATEGY_MANAGER and return the result
        return
            STRATEGY_MANAGER.strategyIsWhitelistedForDeposit(
                IStrategy(strategy)
            );
    }


    function _checkDelegationIsOperator(
        address Node
    ) public view returns (bool) {
        return DELEGATION_MANAGER.isOperator(Node);
    }


    function _operatorShares(
        address operator,
        IStrategy strategyImpl
    ) public view returns  (uint256) {
        return DELEGATION_MANAGER.operatorShares(operator, strategyImpl);
    }

    function getPeriodAtTime(uint48 periodIndex) public view returns (uint48) {
        return
            (periodIndex - START_TIMESTAMP) / parameters.VALIDATOR_EPOCH_TIME();
    }

    function getPeriodStartTime(
        uint48 epoch
    ) public view returns (uint48 periodIndex) {
        return START_TIMESTAMP + epoch * parameters.VALIDATOR_EPOCH_TIME();
    }

 

    function _avsURI(string calldata metadataURI) public {
        AVS_DIRECTORY.updateAVSMetadataURI(metadataURI);
    }

    function _avsDirector() public view returns (IAVSDirectory)
    {
        return AVS_DIRECTORY;
    }

    function _registerOperatorToAvs(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    ) public {
        AVS_DIRECTORY.registerOperatorToAVS(operator, operatorSignature);
    }

    function deregisterOperatorFromAVS(address operator) public {
        if (msg.sender != operator) {
            revert OperationForbidden();
        }
        AVS_DIRECTORY.deregisterOperatorFromAVS(operator);
    }
}
EOF

echo "Done fixing imports in all files" 