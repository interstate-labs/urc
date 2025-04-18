#!/bin/bash

# Set these to actual addresses
AGGREGATOR_ADDRESS="0x1234567890123456789012345678901234567890"  # Replace with actual aggregator address
CORE_ADDRESS="0x2345678901234567890123456789012345678901"       # Replace with actual Core contract address
OWNER_ADDRESS="0x3456789012345678901234567890123456789012"      # Replace with actual owner address

# Private key
PRIVATE_KEY="2cb26dcd8b503c3a708448fb27ebd2f725ef1a1305014ec0e44a9f89d204ee0e"

# RPC URL
RPC_URL="https://rpc.hoodi.ethpandaops.io/"

# Deploy the contract
forge create slashing/Restaking/KarakRestaking/KarakRestaking.sol:TxnVerifier \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --constructor-args $AGGREGATOR_ADDRESS $CORE_ADDRESS $OWNER_ADDRESS \
  --broadcast \
  --optimize 