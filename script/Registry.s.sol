// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "../src/Registry.sol";
import "../src/IRegistry.sol";

contract RegistryScript is Script {
    // forge script script/Registry.s.sol:RegistryScript --rpc-url $RPC_URL --broadcast
    function run() external {
        // Retrieve the private key from environment variable
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        // Start broadcasting transactions
        vm.startBroadcast(deployerPrivateKey);

        // Deploy the Registry contract
        Registry registry = new Registry(
            IRegistry.Config({
                minCollateralWei: 0.1 ether,
                fraudProofWindow: 7200,
                unregistrationDelay: 7200,
                slashWindow: 7200,
                optInDelay: 7200
            })
        );

        // Log the deployed address
        console.log("Registry deployed to:", address(registry));

        vm.stopBroadcast();
    }
}
