import { Buffer } from "buffer";
import nacl from "tweetnacl";
import type {
  ActionRequest,
  ApprovalReject,
  ApprovalToken,
  DeviceInput,
  PolicyRule,
  QueueItem
} from "@beav3r/protocol";
import type { SignedExecutionAuthorizationArtifact } from "./execution-authorization";

type RegisterDeviceInput = DeviceInput & {
  secretKeyBase64?: string;
  pairingToken?: string;
};

export type Beav3rOptions = {
  baseUrl: string;
  agentId?: string;
  apiKey?: string;
  deviceId?: string;
  secretKeyBase64?: string;
  defaultExpirySeconds?: number;
  fetchImpl?: typeof fetch;
};

export type RequestActionInput = Omit<ActionRequest, "agentId" | "actionId" | "attributes" | "timestamp" | "nonce" | "expiry"> & {
  agentId?: string;
  actionId?: string;
  attributes?: ActionRequest["attributes"];
  timestamp?: number;
  nonce?: string;
  expiry?: number;
  callbackUrl?: string;
};

export type RelayActionInput = RequestActionInput & {
  reason: string;
};

export type ActionEvaluation = {
  decision: "allow" | "require_approval" | "deny";
  severity: "routine" | "elevated" | "critical";
  reason: string;
};

export type ExecutedActionResult = { status: "executed"; actionId: string; actionHash: string; evaluation: ActionEvaluation };
export type ApprovedActionResult = { status: "approved"; actionId: string; actionHash: string; evaluation: ActionEvaluation };
export type PendingActionResult = { status: "pending"; actionId: string; actionHash: string; reason: string; evaluation: ActionEvaluation };
export type DeniedActionResult = { status: "denied"; actionId: string; reason: string; evaluation: ActionEvaluation };

export type ActionRequestResult =
  | ExecutedActionResult
  | ApprovedActionResult
  | PendingActionResult
  | DeniedActionResult;

export type GuardResult = ActionRequestResult;

export type RelayActionResult =
  | ApprovedActionResult
  | PendingActionResult
  | DeniedActionResult;

export type ActionStatusResult =
  | { actionId: string; status: "pending"; reason?: string }
  | { actionId: string; status: "approved"; reason?: string }
  | { actionId: string; status: "executed"; reason?: string }
  | { actionId: string; status: "denied"; reason?: string }
  | { actionId: string; status: "rejected"; reason?: string }
  | { actionId: string; status: "expired"; reason?: string };

type GuardAndWaitAllowResult = {
  status: "approved" | "executed";
  actionId: string;
  actionHash: string;
  evaluation: ActionEvaluation;
  executionAuthorizationArtifact?: SignedExecutionAuthorizationArtifact;
};

export type GuardAndWaitResult =
  | GuardAndWaitAllowResult
  | { status: "denied"; actionId: string; reason?: string }
  | { status: "rejected"; actionId: string; reason?: string }
  | { status: "expired"; actionId: string; reason?: string }
  | { status: "pending"; actionId: string; actionHash: string; reason: string; pendingForMs: number };

export type GuardWaitOptions = {
  pollIntervalMs?: number;
  timeoutMs?: number;
  audience?: string;
};

export type MintExecutionAuthorizationInput = {
  actionId: string;
  audience: string;
};

export type ListPendingActionsOptions = {
  deviceId?: string;
  secretKeyBase64?: string;
  projectId?: string;
};

export type ListRecentActionsOptions = {
  deviceId?: string;
  secretKeyBase64?: string;
  projectId?: string;
};

export type ListPolicyRulesOptions = {
  agentId?: string;
  deviceId?: string;
  secretKeyBase64?: string;
};

export type ActionReadOptions = {
  actionHash?: string;
  deviceId?: string;
  secretKeyBase64?: string;
};

export class Beav3rDeniedError extends Error {
  readonly actionId: string;

  constructor(actionId: string, reason?: string) {
    super(reason ?? `Action ${actionId} was denied by Beav3r`);
    this.name = "Beav3rDeniedError";
    this.actionId = actionId;
  }
}

export class Beav3r {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: Beav3rOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async requestAction(input: RequestActionInput): Promise<ActionRequestResult> {
    this.requireAPIKey("requestAction");
    const action = this.buildAction(input);
    return this.request("/actions/request", {
      method: "POST",
      body: JSON.stringify(action)
    });
  }

  async relayAction(input: RelayActionInput): Promise<RelayActionResult> {
    this.requireAPIKey("relayAction");
    const action = this.buildAction(input);
    return this.request("/actions/relay", {
      method: "POST",
      body: JSON.stringify({
        action,
        reason: input.reason
      })
    });
  }

  async guard(input: RequestActionInput): Promise<GuardResult> {
    return this.requestAction(input);
  }

  async guardAndExit(input: RequestActionInput): Promise<GuardResult> {
    return this.guard(input);
  }

  async mintExecutionAuthorization(
    input: MintExecutionAuthorizationInput
  ): Promise<SignedExecutionAuthorizationArtifact> {
    this.requireAPIKey("mintExecutionAuthorization");
    const actionId = input.actionId.trim();
    const audience = input.audience.trim();
    if (!actionId) {
      throw new Error("mintExecutionAuthorization requires a non-empty actionId");
    }
    if (!audience) {
      throw new Error("mintExecutionAuthorization requires a non-empty audience");
    }

    return this.request(`/actions/${encodeURIComponent(actionId)}/execution-authorization`, {
      method: "POST",
      body: JSON.stringify({
        audience
      })
    });
  }

  private requireAPIKey(methodName: string): void {
    if (this.options.apiKey?.trim()) {
      return;
    }

    throw new Error(
      `Beav3r API key is required for ${methodName}. Configure apiKey when creating the client.`
    );
  }

  private buildAction(input: RequestActionInput): ActionRequest {
    const now = Math.floor(Date.now() / 1000);
    const payload = { ...input.payload } as ActionRequest["payload"];
    if (input.callbackUrl) {
      payload.callbackUrl = input.callbackUrl;
    }

    return {
      actionId: input.actionId ?? createUuid(),
      agentId: input.agentId ?? this.options.agentId ?? "agent_default",
      actionType: input.actionType,
      payload,
      attributes: input.attributes ?? {},
      timestamp: input.timestamp ?? now,
      nonce: input.nonce ?? createUuid(),
      expiry: input.expiry ?? now + (this.options.defaultExpirySeconds ?? 60)
    };
  }

  async guardAndWait(input: RequestActionInput, options?: GuardWaitOptions): Promise<GuardAndWaitResult> {
    const startedAt = Date.now();
    const initial = await this.guard(input);

    if (initial.status === "approved" || initial.status === "executed") {
      return this.attachExecutionAuthorizationIfNeeded(initial, options?.audience);
    }
    if (initial.status === "denied") {
      return initial;
    }

    const timeoutMs = options?.timeoutMs ?? 5 * 60 * 1000;
    const pollIntervalMs = options?.pollIntervalMs ?? 3000;

    while (Date.now() - startedAt < timeoutMs) {
      const status = await this.getActionStatus(initial.actionId);
      if (status.status === "approved" || status.status === "executed") {
        return this.attachExecutionAuthorizationIfNeeded({
          status: status.status === "approved" ? "approved" : "executed",
          actionId: initial.actionId,
          actionHash: initial.actionHash,
          evaluation: initial.evaluation
        }, options?.audience);
      }
      if (status.status === "denied" || status.status === "rejected" || status.status === "expired") {
        return {
          status: status.status,
          actionId: status.actionId,
          reason: status.reason
        };
      }

      await sleep(pollIntervalMs);
    }

    return {
      status: "pending",
      actionId: initial.actionId,
      actionHash: initial.actionHash,
      reason: initial.reason,
      pendingForMs: Date.now() - startedAt
    };
  }

  async guardOrThrow(input: RequestActionInput): Promise<Exclude<GuardResult, DeniedActionResult>> {
    const result = await this.guard(input);
    if (result.status === "denied") {
      throw new Beav3rDeniedError(result.actionId, result.reason);
    }
    return result;
  }

  async getActionStatus(actionId: string, options?: ActionReadOptions): Promise<ActionStatusResult> {
    return this.getActionStatusWithOptions(actionId, options);
  }

  async getAction(
    actionId: string,
    options?: ActionReadOptions
  ): Promise<ActionRequest & { actionHash: string; status: string; reason?: string; evaluation: ActionEvaluation }> {
    return this.getActionWithOptions(actionId, options);
  }

  async listPendingActions(options?: ListPendingActionsOptions): Promise<{ items: QueueItem[] }> {
    const query = {
      projectId: options?.projectId,
      ...this.buildSignedDeviceQuery("actions-pending", options?.deviceId, options?.secretKeyBase64)
    };
    return this.request(`/actions/pending${buildQueryString(query)}`);
  }

  async listRecentActions(options?: ListRecentActionsOptions): Promise<{
    items: Array<ActionRequest & { actionHash: string; status: string; reason?: string; evaluation: ActionEvaluation }>;
  }> {
    const query = {
      projectId: options?.projectId,
      ...this.buildSignedDeviceQuery("actions-recent", options?.deviceId, options?.secretKeyBase64)
    };
    return this.request(`/actions/recent${buildQueryString(query)}`);
  }

  async listPolicyRules(options?: ListPolicyRulesOptions): Promise<{ items: PolicyRule[] }> {
    const query = {
      agentId: options?.agentId,
      ...this.buildSignedDeviceQuery("policy-rules", options?.deviceId, options?.secretKeyBase64)
    };
    return this.request(`/policy-rules${buildQueryString(query)}`);
  }

  async registerDevice(device: RegisterDeviceInput): Promise<{ status: "registered" }> {
    if (!device.secretKeyBase64) {
      throw new Error("registerDevice now requires secretKeyBase64 to sign a registration challenge");
    }
    if (!device.pairingToken) {
      throw new Error("registerDevice now requires pairingToken from a project pairing session");
    }

    const challenge = await this.request<{ status: "ok"; challengeId: string; challenge: string; expiresAt: number }>(
      "/devices/register/challenge",
      {
        method: "POST",
        body: JSON.stringify({
          deviceId: device.deviceId,
          publicKey: device.publicKey,
          pairingToken: device.pairingToken
        })
      }
    );

    const message = Buffer.from(challenge.challenge, "utf8");
    const signature = nacl.sign.detached(message, new Uint8Array(Buffer.from(device.secretKeyBase64, "base64")));
    const challengeSignature = Buffer.from(signature).toString("base64");

    return this.request("/devices/register", {
      method: "POST",
      body: JSON.stringify({
        deviceId: device.deviceId,
        publicKey: device.publicKey,
        label: device.label,
        challengeId: challenge.challengeId,
        challengeSignature,
        pairingToken: device.pairingToken
      })
    });
  }

  async submitApproval(token: ApprovalToken): Promise<{ status: "approved" | "executed"; actionId: string }> {
    return this.request("/approvals/submit", {
      method: "POST",
      body: JSON.stringify(token)
    });
  }

  async rejectApproval(
    rejection: Omit<ApprovalReject, "signature" | "expiry"> & Partial<Pick<ApprovalReject, "signature" | "expiry">>
  ): Promise<{ status: "rejected"; actionId: string }> {
    const payload = this.completeRejection(rejection);
    return this.request("/approvals/reject", {
      method: "POST",
      body: JSON.stringify(payload)
    });
  }

  async getActionStatusWithOptions(actionId: string, options?: ActionReadOptions): Promise<ActionStatusResult> {
    const query = this.buildActionReadQuery(`action-status:${actionId}`, options);
    return this.request(`/actions/${actionId}/status${buildQueryString(query)}`);
  }

  async getActionWithOptions(
    actionId: string,
    options?: ActionReadOptions
  ): Promise<ActionRequest & { actionHash: string; status: string; reason?: string; evaluation: ActionEvaluation }> {
    const query = this.buildActionReadQuery(`action-read:${actionId}`, options);
    return this.request(`/actions/${actionId}${buildQueryString(query)}`);
  }

  private buildActionReadQuery(purpose: string, options?: ActionReadOptions): Record<string, string> {
    if (options?.actionHash) {
      return { actionHash: options.actionHash };
    }

    return this.buildSignedDeviceQuery(purpose, options?.deviceId, options?.secretKeyBase64);
  }

  private async attachExecutionAuthorizationIfNeeded(
    result: Omit<GuardAndWaitAllowResult, "executionAuthorizationArtifact">,
    audience?: string
  ): Promise<GuardAndWaitAllowResult> {
    if (!audience) {
      return result;
    }

    const executionAuthorizationArtifact = await this.mintExecutionAuthorization({
      actionId: result.actionId,
      audience
    });

    return {
      ...result,
      executionAuthorizationArtifact
    };
  }

  private buildSignedDeviceQuery(
    purpose: string,
    deviceId?: string,
    secretKeyBase64?: string
  ): Record<string, string> {
    const effectiveDeviceID = deviceId ?? this.options.deviceId;
    const effectiveSecretKey = secretKeyBase64 ?? this.options.secretKeyBase64;
    if (!effectiveDeviceID || !effectiveSecretKey) {
      return {};
    }

    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = createUuid();
    const signature = signUtf8Message(
      `${purpose}:${effectiveDeviceID}:${timestamp}:${nonce}`,
      effectiveSecretKey
    );

    return {
      deviceId: effectiveDeviceID,
      timestamp,
      nonce,
      signature
    };
  }

  private completeRejection(
    rejection: Omit<ApprovalReject, "signature" | "expiry"> & Partial<Pick<ApprovalReject, "signature" | "expiry">>
  ): ApprovalReject {
    if (rejection.signature && typeof rejection.expiry === "number") {
      return {
        actionHash: rejection.actionHash,
        deviceId: rejection.deviceId,
        signature: rejection.signature,
        expiry: rejection.expiry
      };
    }

    const effectiveDeviceID = rejection.deviceId || this.options.deviceId;
    const effectiveSecretKey = this.options.secretKeyBase64;
    if (!effectiveDeviceID || !effectiveSecretKey) {
      throw new Error("rejectApproval requires signature/expiry or signer device credentials");
    }

    return {
      ...rejection,
      deviceId: effectiveDeviceID,
      signature: signUtf8Message(rejection.actionHash, effectiveSecretKey),
      expiry: Math.floor(Date.now() / 1000) + (this.options.defaultExpirySeconds ?? 60)
    };
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const url = `${this.options.baseUrl}${path}`;

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        headers: {
          "content-type": "application/json",
          ...(this.options.apiKey ? { authorization: `Bearer ${this.options.apiKey}` } : {}),
          ...(init?.headers ?? {})
        },
        ...init
      });
    } catch (error) {
      const message = (error as Error).message;
      throw new Error(
        `Cannot reach Beav3r at ${this.options.baseUrl}. Make sure the server is running, bound to 0.0.0.0, and reachable from this machine. Original error: ${message}`
      );
    }

    const bodyText = await response.text();
    const body = (bodyText ? JSON.parse(bodyText) : {}) as T & { error?: string };
    if (!response.ok) {
      throw new Error(body.error ?? `Request to ${url} failed with status ${response.status}`);
    }
    return body;
  }
}

function signUtf8Message(message: string, secretKeyBase64: string): string {
  const signature = nacl.sign.detached(
    Buffer.from(message, "utf8"),
    new Uint8Array(Buffer.from(secretKeyBase64, "base64"))
  );
  return Buffer.from(signature).toString("base64");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createUuid(): string {
  const uuid = globalThis.crypto?.randomUUID?.();
  if (uuid) {
    return uuid;
  }

  return `beav3r-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function buildQueryString(values: Record<string, string | undefined>): string {
  const params = new URLSearchParams();

  for (const [key, value] of Object.entries(values)) {
    if (value) {
      params.set(key, value);
    }
  }

  const query = params.toString();
  return query ? `?${query}` : "";
}

export { Beav3r as BeaverClient, Beav3rDeniedError as BeaverDeniedError };
export type BeaverClientOptions = Beav3rOptions;
