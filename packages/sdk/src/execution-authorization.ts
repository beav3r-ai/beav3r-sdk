import { Buffer } from "buffer";
import nacl from "tweetnacl";
import { canonicalize, hashAction, type ActionRequest } from "@beav3r/protocol";

export type ExecutionAuthorizationDecision = "allow" | "approved" | "executed" | string;

export type ExecutionAuthorizationArtifactPayload = {
  version: string;
  artifactId: string;
  actionId: string;
  actionHash: string;
  decision: ExecutionAuthorizationDecision;
  issuedAt: number;
  expiresAt: number;
  audience: string;
  keyId: string;
  [key: string]: unknown;
};

export type SignedExecutionAuthorizationArtifact = {
  payload: ExecutionAuthorizationArtifactPayload;
  signature: string;
  keyId?: string;
  algorithm?: "ed25519" | string;
};

export type ExecutionAuthorizationKey = {
  keyId: string;
  publicKey: string;
};

export type ExecutionAuthorizationKeySet = Record<string, string> | ExecutionAuthorizationKey[];

export type VerifyExecutionAuthorizationInput = {
  artifact: SignedExecutionAuthorizationArtifact;
  action: ActionRequest;
  audience: string;
  publicKeys: ExecutionAuthorizationKeySet;
  now?: number;
};

export function normalizeExecutionAuthorizationAction(action: ActionRequest): ActionRequest {
  const normalizedPayload =
    action.payload && typeof action.payload === "object" && !Array.isArray(action.payload)
      ? { ...action.payload }
      : action.payload;

  if (
    normalizedPayload &&
    typeof normalizedPayload === "object" &&
    !Array.isArray(normalizedPayload) &&
    "presentation" in normalizedPayload
  ) {
    delete (normalizedPayload as Record<string, unknown>).presentation;
  }

  return {
    ...action,
    payload: normalizedPayload
  };
}

export function verifyExecutionAuthorization(
  input: VerifyExecutionAuthorizationInput
): ExecutionAuthorizationArtifactPayload {
  if (input.artifact.algorithm && input.artifact.algorithm !== "ed25519") {
    throw new Error(
      `Execution authorization signature algorithm "${input.artifact.algorithm}" is not supported; expected "ed25519"`
    );
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
    throw new Error(
      `Execution authorization audience mismatch: expected "${input.audience}", got "${input.artifact.payload.audience}"`
    );
  }

  if (
    input.artifact.payload.decision !== "allow" &&
    input.artifact.payload.decision !== "approved" &&
    input.artifact.payload.decision !== "executed"
  ) {
    throw new Error(
      `Execution authorization decision must be "allow", "approved", or "executed", got "${input.artifact.payload.decision}"`
    );
  }

  const expectedActionHash = hashAction(normalizeExecutionAuthorizationAction(input.action));
  if (input.artifact.payload.actionHash !== expectedActionHash) {
    throw new Error("Execution authorization actionHash does not match the provided action input");
  }

  return input.artifact.payload;
}

export function isValidExecutionAuthorization(input: VerifyExecutionAuthorizationInput): boolean {
  try {
    verifyExecutionAuthorization(input);
    return true;
  } catch {
    return false;
  }
}

function verifyArtifactSignature(artifact: SignedExecutionAuthorizationArtifact, publicKeyBase64: string): boolean {
  const payloadCanonical = canonicalize(artifact.payload);
  const payloadBytes = Buffer.from(payloadCanonical, "utf8");
  const signatureBytes = Buffer.from(artifact.signature, "base64");
  const publicKeyBytes = Buffer.from(publicKeyBase64, "base64");
  return nacl.sign.detached.verify(
    new Uint8Array(payloadBytes),
    new Uint8Array(signatureBytes),
    new Uint8Array(publicKeyBytes)
  );
}

function getPublicKey(keySet: ExecutionAuthorizationKeySet, keyId: string): string | undefined {
  if (Array.isArray(keySet)) {
    return keySet.find((item) => item.keyId === keyId)?.publicKey;
  }
  return keySet[keyId];
}

function resolveKeyId(artifact: SignedExecutionAuthorizationArtifact): string | undefined {
  const payloadKeyId = normalizeString((artifact.payload as { keyId?: unknown }).keyId);
  if (payloadKeyId) {
    return payloadKeyId;
  }

  return normalizeString((artifact as { keyId?: unknown }).keyId);
}

function normalizeString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}
