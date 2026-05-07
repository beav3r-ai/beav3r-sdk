const test = require("node:test");
const assert = require("node:assert/strict");

const { Beav3r } = require("../dist/index.js");

function jsonResponse(status, payload) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(payload)
  };
}

test("authorizeOnchainAction sends POST /onchain/actions/authorize", async () => {
  const calls = [];
  const client = new Beav3r({
    baseUrl: "http://localhost:3000",
    apiKey: "key_test",
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return jsonResponse(200, {
        status: "authorized",
        item: { authorizationId: "onchain_auth_1" }
      });
    }
  });

  const res = await client.authorizeOnchainAction({
    account: "0x1111111111111111111111111111111111111111",
    to: "0x2222222222222222222222222222222222222222",
    value: "0",
    data: "0x1234",
    chainId: 8453,
    nonce: 7,
    expiresAt: 2000000000,
    executor: "0x3333333333333333333333333333333333333333",
    projectId: "project_test"
  });

  assert.equal(res.status, "authorized");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://localhost:3000/onchain/actions/authorize?projectId=project_test");
  assert.equal(calls[0].init.method, "POST");
});

test("getOnchainAuthorization sends GET /onchain/actions/{id}", async () => {
  const calls = [];
  const client = new Beav3r({
    baseUrl: "http://localhost:3000",
    apiKey: "key_test",
    fetchImpl: async (url) => {
      calls.push(url);
      return jsonResponse(200, {
        item: { authorizationId: "onchain_auth_1" }
      });
    }
  });

  const res = await client.getOnchainAuthorization("onchain_auth_1");
  assert.equal(res.item.authorizationId, "onchain_auth_1");
  assert.equal(calls[0], "http://localhost:3000/onchain/actions/onchain_auth_1");
});

test("provisionOnchainUser sends POST /v1/onchain/users/provision without projectId", async () => {
  const calls = [];
  const client = new Beav3r({
    baseUrl: "http://localhost:3000",
    apiKey: "key_test",
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return jsonResponse(200, {
        status: "provisioning_requested",
        item: {
          provisionedUserId: "onchain_user_1",
          actorId: "api_key_123",
          accountAddress: "0x1111111111111111111111111111111111111111",
          executorAddress: "0x2222222222222222222222222222222222222222",
          provisionTxHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          registryAddress: "0x3333333333333333333333333333333333333333",
          verifierAddress: "0x4444444444444444444444444444444444444444",
          chainId: 8453,
          status: "provisioned"
        }
      });
    }
  });

  const res = await client.provisionOnchainUser({
    chainId: 8453,
    intendedOwner: "0x1111111111111111111111111111111111111111",
    templateId: "template_a",
    metadata: { tier: "gold" }
  });

  assert.equal(res.status, "provisioning_requested");
  assert.equal(res.item.provisionedUserId, "onchain_user_1");
  assert.equal(res.item.status, "provisioned");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://localhost:3000/v1/onchain/users/provision");
  assert.equal(calls[0].init.method, "POST");
  const payload = JSON.parse(calls[0].init.body);
  assert.equal(payload.chainId, 8453);
  assert.equal(payload.intendedOwner, "0x1111111111111111111111111111111111111111");
  assert.equal(payload.templateId, "template_a");
  assert.deepEqual(payload.metadata, { tier: "gold" });
  assert.equal("projectId" in payload, false);
});

test("onchain account key helpers hit expected endpoints", async () => {
  const calls = [];
  const client = new Beav3r({
    baseUrl: "http://localhost:3000",
    apiKey: "key_test",
    fetchImpl: async (url, init = {}) => {
      calls.push({ url, method: init.method || "GET" });
      if ((init.method || "GET") === "DELETE") {
        return jsonResponse(200, { status: "deleted" });
      }
      if ((init.method || "GET") === "POST") {
        return jsonResponse(200, { status: "upserted", item: {} });
      }
      return jsonResponse(200, { items: [], configuredSigner: "0xSigner", configuredSignerId: "key_1" });
    }
  });

  await client.upsertOnchainAccountKey({
    account: "0x1111111111111111111111111111111111111111",
    signerAddress: "0x3333333333333333333333333333333333333333",
    keyId: "ops-key"
  });
  await client.listOnchainAccountKeys("0x1111111111111111111111111111111111111111");
  await client.deleteOnchainAccountKey("0x1111111111111111111111111111111111111111", "ops-key");

  assert.deepEqual(calls.map((c) => [c.method, c.url]), [
    ["POST", "http://localhost:3000/onchain/accounts/0x1111111111111111111111111111111111111111/keys"],
    ["GET", "http://localhost:3000/onchain/accounts/0x1111111111111111111111111111111111111111/keys"],
    ["DELETE", "http://localhost:3000/onchain/accounts/0x1111111111111111111111111111111111111111/keys/ops-key"]
  ]);
});

test("getExecutionAuthorizationKeys returns server key discovery payload", async () => {
  const client = new Beav3r({
    baseUrl: "http://localhost:3000",
    apiKey: "key_test",
    fetchImpl: async () =>
      jsonResponse(200, {
        items: [
          {
            keyId: "exec-key-1",
            algorithm: "Ed25519",
            publicKey: "BASE64_KEY"
          }
        ]
      })
  });

  const res = await client.getExecutionAuthorizationKeys();
  assert.equal(res.items.length, 1);
  assert.equal(res.items[0].keyId, "exec-key-1");
});
