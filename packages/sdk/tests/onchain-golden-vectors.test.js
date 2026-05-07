const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  computeOnchainActionHash,
  computeOnchainAuthorizationDigest,
  prepareExecuteWithAuthCall
} = require("../dist/index.js");

const GOLDEN_VECTORS_PATH = path.resolve(__dirname, "fixtures/onchain-v1-golden-vectors.json");

function lowerHex(value) {
  return String(value).toLowerCase();
}

function uintString(value) {
  return String(value);
}

function loadGoldenVectors() {
  const raw = fs.readFileSync(GOLDEN_VECTORS_PATH, "utf8");
  const spec = JSON.parse(raw);
  assert.equal(spec.protocolVersion, "onchain-v1");
  assert.ok(Array.isArray(spec.vectors), "golden-vectors.json must contain a vectors array");
  assert.ok(spec.vectors.length > 0, "golden-vectors.json must contain at least one vector");
  return spec.vectors;
}

for (const vector of loadGoldenVectors()) {
  test(`onchain-v1 golden vector parity: ${vector.name}`, () => {
    const { request, artifact, expected } = vector;

    assert.ok(request, `${vector.name} must include request`);
    assert.ok(artifact, `${vector.name} must include artifact`);
    assert.ok(expected, `${vector.name} must include expected`);

    const actionHash = computeOnchainActionHash({
      account: request.account,
      to: request.to,
      value: request.value,
      data: request.data,
      chainId: request.chainId,
      nonce: request.nonce,
      expiresAt: request.expiresAt,
      executor: request.executor
    });
    assert.equal(actionHash, lowerHex(expected.actionHash));
    assert.equal(actionHash, lowerHex(artifact.payload.actionHash));

    const digest = computeOnchainAuthorizationDigest(artifact);
    assert.equal(digest, lowerHex(expected.digest));
    assert.equal(digest, lowerHex(artifact.digest));

    const prepared = prepareExecuteWithAuthCall(
      {
        to: request.to,
        value: request.value,
        data: request.data
      },
      artifact
    );

    assert.equal(prepared.to, lowerHex(request.to));
    assert.equal(prepared.value.toString(), uintString(request.value));
    assert.equal(prepared.data, lowerHex(request.data));
    assert.equal(prepared.signature, lowerHex(artifact.signature));

    assert.equal(prepared.auth.actionHash, lowerHex(expected.actionHash));
    assert.equal(prepared.auth.account, lowerHex(request.account));
    assert.equal(prepared.auth.account, lowerHex(artifact.payload.account));
    assert.equal(prepared.auth.executor, lowerHex(request.executor));
    assert.equal(prepared.auth.executor, lowerHex(artifact.payload.executor));
    assert.equal(prepared.auth.chainId.toString(), uintString(request.chainId));
    assert.equal(prepared.auth.chainId.toString(), uintString(artifact.payload.chainId));
    assert.equal(prepared.auth.nonce.toString(), uintString(request.nonce));
    assert.equal(prepared.auth.nonce.toString(), uintString(artifact.payload.nonce));
    assert.equal(prepared.auth.expiresAt.toString(), uintString(request.expiresAt));
    assert.equal(prepared.auth.expiresAt.toString(), uintString(artifact.payload.expiresAt));
    assert.equal(prepared.auth.keyId, lowerHex(expected.keyIdHash));
  });
}
