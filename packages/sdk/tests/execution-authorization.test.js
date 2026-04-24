const test = require("node:test");
const assert = require("node:assert/strict");
const { Buffer } = require("buffer");
const nacl = require("tweetnacl");

const { canonicalize, hashAction } = require("../../protocol/dist/index.js");
const {
  Beav3r,
  isValidExecutionAuthorization,
  verifyExecutionAuthorization
} = require("../dist/index.js");

const ACTION = {
  actionId: "action-123",
  agentId: "agent-prod",
  actionType: "exec.command",
  payload: { cmd: "ls", args: ["-la"] },
  attributes: { risk: "high" },
  timestamp: 1713907200,
  nonce: "nonce-123",
  expiry: 1713907800
};

test("verifyExecutionAuthorization accepts canonical payload and prefers payload keyId over top-level keyId", () => {
  const signingKeyPair = nacl.sign.keyPair();
  const topLevelKeyPair = nacl.sign.keyPair();

  const artifact = createArtifact({
    action: ACTION,
    keyPair: signingKeyPair,
    payloadOverrides: {
      version: "v1",
      artifactId: "art-100",
      audience: "executor",
      keyId: "k-payload",
      decision: "approved",
      issuedAt: 1899999900,
      expiresAt: 2000000000
    },
    topLevelKeyId: "k-top"
  });

  const payload = verifyExecutionAuthorization({
    artifact,
    action: ACTION,
    audience: "executor",
    publicKeys: {
      "k-payload": Buffer.from(signingKeyPair.publicKey).toString("base64"),
      "k-top": Buffer.from(topLevelKeyPair.publicKey).toString("base64")
    },
    now: 1900000000
  });

  assert.equal(payload.version, "v1");
  assert.equal(payload.artifactId, "art-100");
  assert.equal(payload.keyId, "k-payload");
  assert.equal(payload.actionHash, hashAction(ACTION));

  assert.equal(isValidExecutionAuthorization({
    artifact,
    action: ACTION,
    audience: "executor",
    publicKeys: {
      "k-payload": Buffer.from(signingKeyPair.publicKey).toString("base64"),
      "k-top": Buffer.from(topLevelKeyPair.publicKey).toString("base64")
    },
    now: 1900000000
  }), true);
});

test("verifyExecutionAuthorization supports legacy top-level keyId fallback", () => {
  const keyPair = nacl.sign.keyPair();
  const artifact = createArtifact({
    action: ACTION,
    keyPair,
    payloadOverrides: {
      audience: "executor",
      decision: "approved",
      expiresAt: 2000000000
    },
    omitPayloadKeyId: true,
    topLevelKeyId: "k-legacy"
  });

  const payload = verifyExecutionAuthorization({
    artifact,
    action: ACTION,
    audience: "executor",
    publicKeys: {
      "k-legacy": Buffer.from(keyPair.publicKey).toString("base64")
    },
    now: 1900000000
  });

  assert.equal(payload.audience, "executor");
  assert.equal(isValidExecutionAuthorization({
    artifact,
    action: ACTION,
    audience: "executor",
    publicKeys: {
      "k-legacy": Buffer.from(keyPair.publicKey).toString("base64")
    },
    now: 1900000000
  }), true);
});

test("verifyExecutionAuthorization fails on signature mismatch", () => {
  const keyPair = nacl.sign.keyPair();
  const artifact = createArtifact({
    action: ACTION,
    keyPair,
    payloadOverrides: {
      audience: "executor",
      decision: "executed",
      expiresAt: 2000000000
    }
  });
  artifact.payload.audience = "tampered";

  assert.throws(() => verifyExecutionAuthorization({
    artifact,
    action: ACTION,
    audience: "tampered",
    publicKeys: {
      [artifact.payload.keyId]: Buffer.from(keyPair.publicKey).toString("base64")
    },
    now: 1900000000
  }), /signature is invalid/i);
  assert.equal(isValidExecutionAuthorization({
    artifact,
    action: ACTION,
    audience: "tampered",
    publicKeys: {
      [artifact.payload.keyId]: Buffer.from(keyPair.publicKey).toString("base64")
    },
    now: 1900000000
  }), false);
});

test("verifyExecutionAuthorization fails on missing keyId, trust, expiry, audience, decision, actionHash, and algorithm", () => {
  const keyPair = nacl.sign.keyPair();
  const trustedPublicKey = Buffer.from(keyPair.publicKey).toString("base64");

  const baseArtifact = createArtifact({
    action: ACTION,
    keyPair,
    payloadOverrides: {
      audience: "executor",
      decision: "approved",
      expiresAt: 2000000000
    }
  });

  const noKeyIdArtifact = createArtifact({
    action: ACTION,
    keyPair,
    payloadOverrides: {
      audience: "executor",
      decision: "approved",
      expiresAt: 2000000000
    },
    omitPayloadKeyId: true,
    topLevelKeyId: null
  });
  assert.throws(() => verifyExecutionAuthorization({
    artifact: noKeyIdArtifact,
    action: ACTION,
    audience: "executor",
    publicKeys: {},
    now: 1900000000
  }), /keyId is missing/i);

  assert.throws(() => verifyExecutionAuthorization({
    artifact: baseArtifact,
    action: ACTION,
    audience: "executor",
    publicKeys: {},
    now: 1900000000
  }), /not trusted/i);

  const expiredArtifact = createArtifact({
    action: ACTION,
    keyPair,
    payloadOverrides: {
      audience: "executor",
      decision: "approved",
      expiresAt: 1800000000
    }
  });
  assert.throws(() => verifyExecutionAuthorization({
    artifact: expiredArtifact,
    action: ACTION,
    audience: "executor",
    publicKeys: { [expiredArtifact.keyId]: trustedPublicKey },
    now: 1900000000
  }), /expired/i);

  assert.throws(() => verifyExecutionAuthorization({
    artifact: baseArtifact,
    action: ACTION,
    audience: "wrong-audience",
    publicKeys: { [baseArtifact.keyId]: trustedPublicKey },
    now: 1900000000
  }), /audience mismatch/i);

  const deniedArtifact = createArtifact({
    action: ACTION,
    keyPair,
    payloadOverrides: {
      audience: "executor",
      decision: "denied",
      expiresAt: 2000000000
    }
  });
  assert.throws(() => verifyExecutionAuthorization({
    artifact: deniedArtifact,
    action: ACTION,
    audience: "executor",
    publicKeys: { [deniedArtifact.keyId]: trustedPublicKey },
    now: 1900000000
  }), /must be "approved" or "executed"/i);

  const wrongHashArtifact = createArtifact({
    action: ACTION,
    keyPair,
    payloadOverrides: {
      audience: "executor",
      decision: "approved",
      actionHash: hashAction({ ...ACTION, actionType: "exec.other" }),
      expiresAt: 2000000000
    }
  });
  assert.throws(() => verifyExecutionAuthorization({
    artifact: wrongHashArtifact,
    action: ACTION,
    audience: "executor",
    publicKeys: { [wrongHashArtifact.keyId]: trustedPublicKey },
    now: 1900000000
  }), /actionHash does not match/i);

  const wrongAlgorithm = createArtifact({
    action: ACTION,
    keyPair,
    payloadOverrides: {
      audience: "executor",
      decision: "approved",
      expiresAt: 2000000000
    }
  });
  wrongAlgorithm.algorithm = "rsa-pss";
  assert.throws(() => verifyExecutionAuthorization({
    artifact: wrongAlgorithm,
    action: ACTION,
    audience: "executor",
    publicKeys: { [wrongAlgorithm.payload.keyId]: trustedPublicKey },
    now: 1900000000
  }), /not supported/i);
});

test("guardAndWait mints and returns execution authorization artifact on allow path when audience is provided", async () => {
  const keyPair = nacl.sign.keyPair();
  const artifact = createArtifact({
    action: ACTION,
    keyPair,
    payloadOverrides: {
      actionId: "a-1",
      audience: "executor",
      decision: "approved",
      expiresAt: 2000000000
    }
  });

  const calls = [];
  const responses = [
    {
      status: "pending",
      actionId: "a-1",
      actionHash: "hash-a-1",
      reason: "awaiting signer",
      evaluation: {
        decision: "require_approval",
        severity: "critical",
        reason: "manual review required"
      }
    },
    {
      actionId: "a-1",
      status: "approved"
    },
    artifact
  ];

  const client = new Beav3r({
    baseUrl: "https://api.example.test",
    apiKey: "test-api-key",
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      const body = responses.shift();
      if (!body) {
        throw new Error(`No mock response left for ${url}`);
      }
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify(body);
        }
      };
    }
  });

  const result = await client.guardAndWait({
    actionId: "a-1",
    agentId: ACTION.agentId,
    actionType: ACTION.actionType,
    payload: ACTION.payload,
    attributes: ACTION.attributes,
    timestamp: ACTION.timestamp,
    nonce: ACTION.nonce,
    expiry: ACTION.expiry
  }, {
    audience: "executor",
    pollIntervalMs: 0,
    timeoutMs: 1000
  });

  assert.equal(result.status, "approved");
  assert.equal(result.actionId, "a-1");
  assert.equal(result.executionAuthorizationArtifact?.payload.audience, "executor");
  assert.equal(result.executionAuthorizationArtifact?.payload.version, "v1");
  assert.equal(result.executionAuthorizationArtifact?.payload.artifactId, "artifact-001");

  assert.equal(calls.length, 3);
  assert.equal(calls[2].url, "https://api.example.test/actions/a-1/execution-authorization");
  assert.equal(calls[2].init?.method, "POST");
  assert.equal(calls[2].init?.body, JSON.stringify({ audience: "executor" }));
});

function createArtifact({
  action,
  keyPair,
  payloadOverrides,
  omitPayloadKeyId = false,
  topLevelKeyId
}) {
  const payload = {
    version: "v1",
    artifactId: "artifact-001",
    actionId: action.actionId,
    actionHash: hashAction(action),
    audience: "executor",
    decision: "approved",
    issuedAt: 1900000000,
    expiresAt: 2000000000,
    keyId: "k-main",
    ...payloadOverrides
  };
  if (omitPayloadKeyId) {
    delete payload.keyId;
  }

  const signature = nacl.sign.detached(
    Buffer.from(canonicalize(payload), "utf8"),
    keyPair.secretKey
  );

  let resolvedTopLevelKeyId;
  if (topLevelKeyId === null) {
    resolvedTopLevelKeyId = undefined;
  } else if (typeof topLevelKeyId === "string") {
    resolvedTopLevelKeyId = topLevelKeyId;
  } else {
    resolvedTopLevelKeyId = typeof payload.keyId === "string" ? payload.keyId : "k-main";
  }

  return {
    ...(resolvedTopLevelKeyId ? { keyId: resolvedTopLevelKeyId } : {}),
    payload,
    signature: Buffer.from(signature).toString("base64")
  };
}
