# @beav3r/sdk

Beav3r client SDK for agent and client integrations.

Current responsibilities:

- submit action requests
- query action status
- list pending and recent actions

- mint and verify execution authorization artifacts
- redeem execution authorization artifacts once
- authorize executor callbacks after verification + redemption
- expose middleware-style guard methods

It is one of the intended public OSS packages in this monorepo.

## Permission And Spend

The offchain execution model has two phases:

1. `guardAndWait(...)`
   Ask Beav3r for permission for an exact action.
2. `authorizeAndExecute(...)`
   Spend that permission once, then run the real side effect.

That split matters because replay protection belongs to the spend phase, not just the approval phase.

## Execution Authorization Artifacts

Use `guardAndWait(..., { audience })` to mint a signed execution authorization artifact automatically on terminal allow (`approved`, `executed`, or `allow`-compatible server artifacts):

```ts
const result = await client.guardAndWait(actionInput, { audience: "executor" });
if (result.status === "approved" || result.status === "executed") {
  const artifact = result.executionAuthorizationArtifact;
}
```

You can also mint explicitly, verify locally, redeem once, and then execute:

```ts
const artifact = await client.mintExecutionAuthorization({
  actionId: "action-123",
  audience: "executor"
});

// canonical server artifact shape:
// {
//   payload: {
//     version, artifactId, actionId, actionHash, decision,
//     issuedAt, expiresAt, audience, keyId
//   },
//   signature,
//   keyId? // optional compatibility envelope field
// }

verifyExecutionAuthorization({
  artifact,
  action,
  audience: "executor",
  publicKeys: {
    "your-server-key-id": "BASE64_ED25519_PUBLIC_KEY"
  }
});

await client.redeemExecutionAuthorization({
  actionId: "action-123",
  artifact,
  audience: "executor",
  actionHash: hashAction(action)
});
```

`verifyExecutionAuthorization(...)` validates trusted key lookup (`payload.keyId` first, fallback top-level `keyId`), Ed25519 signature over canonicalized payload, expiry, audience, decision (`allow`/`approved`/`executed`), and recomputed `actionHash`. The verifier automatically ignores Beav3r display-only `payload.presentation` metadata so `getAction(actionId)` responses can be used directly in executor flows.  
`redeemExecutionAuthorization(...)` spends the signed artifact once against the Beav3r server.  
`isValidExecutionAuthorization(...)` returns `boolean` instead of throwing.

The `publicKeys` map must be keyed by the server signing `keyId` carried in the artifact payload, not by audience unless your deployment intentionally makes those values the same.

## Well-Known Verification Keys

For dynamic key discovery, Beav3r servers expose:

`GET /.well-known/execution-authorization-keys`

Expected response shape:

```json
{
  "items": [
    {
      "keyId": "exec-key-id",
      "algorithm": "Ed25519",
      "publicKey": "BASE64_ED25519_PUBLIC_KEY"
    }
  ]
}
```

You can convert this into the `publicKeys` map used by `verifyExecutionAuthorization(...)` and `authorizeAndExecute(...)`.

## Recommended Executor Flow

Most integrators should not wire verify -> redeem -> execute manually in every service. Use `authorizeAndExecute(...)`:

```ts
const result = await client.authorizeAndExecute({
  action,
  artifact,
  audience: "payments-executor",
  publicKeys: {
    "your-server-key-id": "BASE64_ED25519_PUBLIC_KEY"
  },
  execute: async ({ action, redemption }) => {
    return sendUsdt(action.payload, redemption.artifactId);
  }
});
```

This helper:

- verifies the artifact locally
- recomputes the exact `actionHash`
- redeems the artifact once with Beav3r
- only then runs the executor callback

If the callback fails after redemption, the authorization has still been spent. That is expected and should be reflected in your execution lifecycle.

## Onchain Authorization Helpers

The SDK exposes helpers for actor registration, `/onchain/*` authorization APIs, local digest verification, and `executeWithAuth(...)` transaction preparation:

```ts
const registered = await client.registerOnchainActor(
  {
    projectId: "proj_123",
    type: "smart_account",
    label: "Treasury Safe",
    chainId: 8453,
    accountAddress: "0x1111111111111111111111111111111111111111",
    executorAddress: "0x3333333333333333333333333333333333333333"
  },
  {
    keyId: "ops-key",
    signerAddress: "0x4444444444444444444444444444444444444444"
  }
);

const auth = await client.authorizeOnchainAction({
  projectId: "proj_123",
  actorId: registered.actor.id,
  account: registered.actor.accountAddress,
  to: "0x2222222222222222222222222222222222222222",
  value: "0",
  data: "0x1234",
  chainId: registered.actor.chainId,
  nonce: 7,
  executor: registered.actor.executorAddress
});

const loaded = await client.getOnchainAuthorization(auth.item.authorizationId);

const prepared = prepareOnchainExecution({
  actor: registered.actor,
  action: {
    to: auth.item.request.to,
    value: auth.item.request.value,
    data: auth.item.request.data,
    nonce: auth.item.request.nonce
  },
  artifact: loaded.item.artifact
});

verifyOnchainAuthorization({
  artifact: loaded.item.artifact,
  request: {
    account: registered.actor.accountAddress,
    to: auth.item.request.to,
    value: auth.item.request.value,
    data: auth.item.request.data,
    chainId: registered.actor.chainId,
    nonce: auth.item.request.nonce,
    executor: registered.actor.executorAddress
  }
});

const calldata = prepared.calldata;
```

## Compatibility note

As of the 2026-04-03 security hardening pass:

- `rejectApproval(...)` must send `signature` and `expiry`
- device-scoped reads use signed query parameters for:
  - `getActionStatusWithOptions`
  - `getActionWithOptions`
  - `listPendingActions`
  - `listRecentActions`
- `/actions/request` now requires an API key with `actions:relay`
- execution artifact mint/redeem flows require an API key with `actions:execute`

If you make server-side auth or approval-signing changes, review the sibling Beav3r integrations in the shared `~/beav3r` workspace before release.
