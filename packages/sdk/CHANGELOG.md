# @beav3r/sdk

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
