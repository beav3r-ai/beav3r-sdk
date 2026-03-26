# @beav3r/sdk

## 1.2.1

### Patch Changes

- Guard SDK response parsing against empty HTTP bodies so mobile pairing and other requests do not fail with JSON parse errors when an endpoint returns no body.
