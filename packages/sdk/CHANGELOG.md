# @beav3r/sdk

## 2.1.0-beta.4

### Patch Changes

- Align onchain execution inputs with contract-sized values by accepting bigint-safe numeric inputs (`string | number | bigint`) for chain and nonce fields, improve `keyId` handling to support pre-hashed `bytes32` values, and harden onchain authorization request serialization against unsafe JSON numeric overflow.

## 2.1.0-beta.3

### Patch Changes

- Add `provisionOnchainUser(...)` client method for `POST /v1/onchain/users/provision`.
- Align onchain provisioning response typing with server payload (`provisionedUserId`, `actorId`, `executorAddress`, `provisionTxHash`, and deployed contract addresses).

## 2.1.0-beta.2

### Patch Changes

- Republish RN-safe hashing updates for mobile APK build validation.
- Updated dependencies
  - @beav3r/protocol@2.0.1-beta.1

## 2.1.0-beta.1

### Patch Changes

- Fix React Native compatibility for onchain SDK/protocol path (remove Node-only crypto resolution path).
- Updated dependencies
  - @beav3r/protocol@2.0.1-beta.0

## 2.1.0-beta.0

### Minor Changes

- Add onchain support

## 1.2.1

### Patch Changes

- Guard SDK response parsing against empty HTTP bodies so mobile pairing and other requests do not fail with JSON parse errors when an endpoint returns no body.
