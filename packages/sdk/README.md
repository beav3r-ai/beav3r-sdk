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
