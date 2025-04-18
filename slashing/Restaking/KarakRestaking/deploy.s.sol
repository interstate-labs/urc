// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Script} from "forge-std/Script.sol";
import {TxnVerifier} from "./KarakRestaking.sol";
import {ICore} from "../../../lib/karak/src/interfaces/ICore.sol";

contract DeployTxnVerifier is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Replace these with actual addresses
        address aggregator = 0x1234567890123456789012345678901234567890; // Replace with actual aggregator address
        address core = 0x2345678901234567890123456789012345678901; // Replace with actual Core contract address
        address owner = 0x3456789012345678901234567890123456789012; // Replace with actual owner address

        TxnVerifier verifier = new TxnVerifier(aggregator, ICore(core), owner);
        
        vm.stopBroadcast();
    }
} 