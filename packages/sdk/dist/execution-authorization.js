"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeExecutionAuthorizationAction = normalizeExecutionAuthorizationAction;
exports.verifyExecutionAuthorization = verifyExecutionAuthorization;
exports.isValidExecutionAuthorization = isValidExecutionAuthorization;
const buffer_1 = require("buffer");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const protocol_1 = require("@beav3r/protocol");
function normalizeExecutionAuthorizationAction(action) {
    const normalizedPayload = action.payload && typeof action.payload === "object" && !Array.isArray(action.payload)
        ? { ...action.payload }
        : action.payload;
    if (normalizedPayload &&
        typeof normalizedPayload === "object" &&
        !Array.isArray(normalizedPayload) &&
        "presentation" in normalizedPayload) {
        delete normalizedPayload.presentation;
    }
    return {
        ...action,
        payload: normalizedPayload
    };
}
function verifyExecutionAuthorization(input) {
    if (input.artifact.algorithm && input.artifact.algorithm !== "ed25519") {
        throw new Error(`Execution authorization signature algorithm "${input.artifact.algorithm}" is not supported; expected "ed25519"`);
    }
    const keyId = resolveKeyId(input.artifact);
    if (!keyId) {
        throw new Error("Execution authorization keyId is missing from artifact payload and envelope");
    }
    const publicKey = getPublicKey(input.publicKeys, keyId);
    if (!publicKey) {
        throw new Error(`Execution authorization keyId "${keyId}" is not trusted`);
    }
    if (!verifyArtifactSignature(input.artifact, publicKey)) {
        throw new Error("Execution authorization signature is invalid");
    }
    const now = input.now ?? Math.floor(Date.now() / 1000);
    if (input.artifact.payload.expiresAt < now) {
        throw new Error("Execution authorization artifact is expired");
    }
    if (input.artifact.payload.audience !== input.audience) {
        throw new Error(`Execution authorization audience mismatch: expected "${input.audience}", got "${input.artifact.payload.audience}"`);
    }
    if (input.artifact.payload.decision !== "allow" &&
        input.artifact.payload.decision !== "approved" &&
        input.artifact.payload.decision !== "executed") {
        throw new Error(`Execution authorization decision must be "allow", "approved", or "executed", got "${input.artifact.payload.decision}"`);
    }
    const expectedActionHash = (0, protocol_1.hashAction)(normalizeExecutionAuthorizationAction(input.action));
    if (input.artifact.payload.actionHash !== expectedActionHash) {
        throw new Error("Execution authorization actionHash does not match the provided action input");
    }
    return input.artifact.payload;
}
function isValidExecutionAuthorization(input) {
    try {
        verifyExecutionAuthorization(input);
        return true;
    }
    catch {
        return false;
    }
}
function verifyArtifactSignature(artifact, publicKeyBase64) {
    const payloadCanonical = (0, protocol_1.canonicalize)(artifact.payload);
    const payloadBytes = buffer_1.Buffer.from(payloadCanonical, "utf8");
    const signatureBytes = buffer_1.Buffer.from(artifact.signature, "base64");
    const publicKeyBytes = buffer_1.Buffer.from(publicKeyBase64, "base64");
    return tweetnacl_1.default.sign.detached.verify(new Uint8Array(payloadBytes), new Uint8Array(signatureBytes), new Uint8Array(publicKeyBytes));
}
function getPublicKey(keySet, keyId) {
    if (Array.isArray(keySet)) {
        return keySet.find((item) => item.keyId === keyId)?.publicKey;
    }
    return keySet[keyId];
}
function resolveKeyId(artifact) {
    const payloadKeyId = normalizeString(artifact.payload.keyId);
    if (payloadKeyId) {
        return payloadKeyId;
    }
    return normalizeString(artifact.keyId);
}
function normalizeString(value) {
    if (typeof value !== "string") {
        return undefined;
    }
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
}
//# sourceMappingURL=execution-authorization.js.map