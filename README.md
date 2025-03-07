All Interstate changes are in the README.md and the `/slasher` folder which has been renamed from `/example` all other files are the same as source: https://github.com/eth-fabric/urc/blob/main/src/Registry.sol

Notes for auditors: We would additionally prefer to have MIN_COLLATERAL Field here https://github.com/interstate-labs/urc/blob/main/src/Registry.sol#L21 set to 0 to allow operators to default to restaking only if they wish.

These contracts allow a validator to register collateral and enable proposer commitments, a subset of Interstate's functionality. Native Ether or a restaking protocol can be used as collateral. We support Karak, Eigenlayer, and Symbiotic
