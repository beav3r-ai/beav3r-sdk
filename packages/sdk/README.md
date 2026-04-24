# @beav3r/sdk

Beav3r client SDK for agent and client integrations.

Current responsibilities:

- submit action requests
- query action status
- list pending and recent actions
- register devices
- submit approvals
- mint and verify execution authorization artifacts
- expose middleware-style guard methods

It is one of the intended public OSS packages in this monorepo.

## Execution Authorization Artifacts

Use `guardAndWait(..., { audience })` to mint a signed execution authorization artifact automatically on terminal allow (`approved` or `executed`):

```ts
const result = await client.guardAndWait(actionInput, { audience: "executor" });
if (result.status === "approved" || result.status === "executed") {
  const artifact = result.executionAuthorizationArtifact;
}
```

You can also mint explicitly and verify locally:

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
    "k-main": "BASE64_ED25519_PUBLIC_KEY"
  }
});
```

`verifyExecutionAuthorization(...)` validates trusted key lookup (`payload.keyId` first, fallback top-level `keyId`), Ed25519 signature over canonicalized payload, expiry, audience, decision (`approved`/`executed`), and recomputed `actionHash`.  
`isValidExecutionAuthorization(...)` returns `boolean` instead of throwing.

## Compatibility note

As of the 2026-04-03 security hardening pass:

- `rejectApproval(...)` must send `signature` and `expiry`
- device-scoped reads use signed query parameters for:
  - `getActionStatusWithOptions`
  - `getActionWithOptions`
  - `listPendingActions`
  - `listRecentActions`
- `/actions/request` now requires an API key with `actions:relay`

If you make server-side auth or approval-signing changes, review the sibling Beav3r integrations in the shared `~/beav3r` workspace before release.
