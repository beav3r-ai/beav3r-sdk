import { randomUUID } from "node:crypto";
import nacl from "tweetnacl";
import type {
  ActionRequest,
  ApprovalReject,
  ApprovalToken,
  DeviceInput,
  PolicyRule,
  QueueItem
} from "@beav3r/protocol";

type RegisterDeviceInput = DeviceInput & {
  secretKeyBase64?: string;
  pairingToken?: string;
};

export type BeaverClientOptions = {
  baseUrl: string;
  agentId?: string;
  apiKey?: string;
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
export type PendingActionResult = { status: "pending"; actionId: string; actionHash: string; reason: string; evaluation: ActionEvaluation };
export type DeniedActionResult = { status: "denied"; actionId: string; reason: string; evaluation: ActionEvaluation };

export type ActionRequestResult =
  | ExecutedActionResult
  | PendingActionResult
  | DeniedActionResult;

export type GuardResult = ActionRequestResult;

export type ActionStatusResult =
  | { actionId: string; status: "pending"; reason?: string }
  | { actionId: string; status: "approved"; reason?: string }
  | { actionId: string; status: "executed"; reason?: string }
  | { actionId: string; status: "denied"; reason?: string }
  | { actionId: string; status: "rejected"; reason?: string }
  | { actionId: string; status: "expired"; reason?: string };

export type GuardAndWaitResult =
  | { status: "approved"; actionId: string; actionHash: string; evaluation: ActionEvaluation }
  | { status: "executed"; actionId: string; actionHash: string; evaluation: ActionEvaluation }
  | { status: "denied"; actionId: string; reason?: string }
  | { status: "rejected"; actionId: string; reason?: string }
  | { status: "expired"; actionId: string; reason?: string }
  | { status: "pending"; actionId: string; actionHash: string; reason: string; pendingForMs: number };

export type GuardWaitOptions = {
  pollIntervalMs?: number;
  timeoutMs?: number;
};

export class BeaverDeniedError extends Error {
  readonly actionId: string;

  constructor(actionId: string, reason?: string) {
    super(reason ?? `Action ${actionId} was denied by Beaver`);
    this.name = "BeaverDeniedError";
    this.actionId = actionId;
  }
}

export class BeaverClient {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: BeaverClientOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async requestAction(input: RequestActionInput): Promise<ActionRequestResult> {
    const action = this.buildAction(input);
    return this.request("/actions/request", {
      method: "POST",
      body: JSON.stringify(action)
    });
  }

  async relayAction(input: RelayActionInput): Promise<PendingActionResult> {
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

  private buildAction(input: RequestActionInput): ActionRequest {
    const now = Math.floor(Date.now() / 1000);
    return {
      actionId: input.actionId ?? randomUUID(),
      agentId: input.agentId ?? this.options.agentId ?? "agent_default",
      actionType: input.actionType,
      payload: input.payload,
      attributes: input.attributes ?? {},
      timestamp: input.timestamp ?? now,
      nonce: input.nonce ?? randomUUID(),
      expiry: input.expiry ?? now + (this.options.defaultExpirySeconds ?? 60)
    };
  }

  async guardAndWait(input: RequestActionInput, options?: GuardWaitOptions): Promise<GuardAndWaitResult> {
    const startedAt = Date.now();
    const initial = await this.guard(input);

    if (initial.status === "executed" || initial.status === "denied") {
      return initial;
    }

    const timeoutMs = options?.timeoutMs ?? 5 * 60 * 1000;
    const pollIntervalMs = options?.pollIntervalMs ?? 3000;

    while (Date.now() - startedAt < timeoutMs) {
      const status = await this.getActionStatus(initial.actionId);
      if (status.status === "approved" || status.status === "executed") {
        return {
          status: status.status === "approved" ? "approved" : "executed",
          actionId: initial.actionId,
          actionHash: initial.actionHash,
          evaluation: initial.evaluation
        };
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
      throw new BeaverDeniedError(result.actionId, result.reason);
    }
    return result;
  }

  async getActionStatus(actionId: string): Promise<ActionStatusResult> {
    return this.request(`/actions/${actionId}/status`);
  }

  async getAction(
    actionId: string
  ): Promise<ActionRequest & { actionHash: string; status: string; reason?: string; evaluation: ActionEvaluation }> {
    return this.request(`/actions/${actionId}`);
  }

  async listPendingActions(): Promise<{ items: QueueItem[] }> {
    return this.request("/actions/pending");
  }

  async listRecentActions(): Promise<{
    items: Array<ActionRequest & { actionHash: string; status: string; reason?: string; evaluation: ActionEvaluation }>;
  }> {
    return this.request("/actions/recent");
  }

  async listPolicyRules(): Promise<{ items: PolicyRule[] }> {
    return this.request("/policy-rules");
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

  async rejectApproval(rejection: ApprovalReject): Promise<{ status: "rejected"; actionId: string }> {
    return this.request("/approvals/reject", {
      method: "POST",
      body: JSON.stringify(rejection)
    });
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
        `Cannot reach Beaver at ${this.options.baseUrl}. Make sure the server is running, bound to 0.0.0.0, and reachable from this machine. Original error: ${message}`
      );
    }

    const body = (await response.json()) as T & { error?: string };
    if (!response.ok) {
      throw new Error(body.error ?? `Request to ${url} failed with status ${response.status}`);
    }
    return body;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
