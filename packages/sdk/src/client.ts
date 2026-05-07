import { Buffer } from "buffer";
import nacl from "tweetnacl";
import { keccak_256 } from "@noble/hashes/sha3";
import type {
  ActionRequest,
  ApprovalReject,
  ApprovalToken,
  DeviceInput,
  PolicyRule,
  QueueItem
} from "@beav3r/protocol";
import {
  verifyExecutionAuthorization,
  type ExecutionAuthorizationArtifactPayload,
  type ExecutionAuthorizationKeySet,
  type SignedExecutionAuthorizationArtifact
} from "./execution-authorization";

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

export type RedeemExecutionAuthorizationInput = {
  actionId?: string;
  artifact: SignedExecutionAuthorizationArtifact;
  audience: string;
  actionHash: string;
};

export type ExecutionAuthorizationRedemptionResult = {
  status: "redeemed";
  artifactId: string;
  actionId: string;
  redeemedAt: number;
};

export type ExecutionAuthorizationVerificationKey = {
  keyId: string;
  algorithm: string;
  publicKey: string;
};

export type AuthorizeAndExecuteInput<T> = {
  action: ActionRequest;
  artifact: SignedExecutionAuthorizationArtifact;
  audience: string;
  publicKeys: ExecutionAuthorizationKeySet;
  now?: number;
  execute: (context: {
    action: ActionRequest;
    actionHash: string;
    artifact: SignedExecutionAuthorizationArtifact;
    authorization: ExecutionAuthorizationArtifactPayload;
    redemption: ExecutionAuthorizationRedemptionResult;
  }) => Promise<T> | T;
};

export type AuthorizeAndExecuteResult<T> = {
  actionId: string;
  actionHash: string;
  artifactId: string;
  authorization: ExecutionAuthorizationArtifactPayload;
  redemption: ExecutionAuthorizationRedemptionResult;
  executionResult: T;
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

export type ActionRecord = ActionRequest & {
  actionHash: string;
  status: string;
  reason?: string;
  evaluation: ActionEvaluation;
};

type UintLike = string | number | bigint;

export type OnchainAuthorizeActionInput = {
  account: string;
  to: string;
  value: string;
  data: string;
  chainId: UintLike;
  nonce: UintLike;
  expiresAt?: UintLike;
  executor: string;
  projectId?: string;
  actorId?: string;
};

export type OnchainActorType = "wallet" | "smart_account";

export type ProvisionOnchainUserInput = {
  chainId: number;
  intendedOwner: string;
  templateId?: string;
  metadata?: Record<string, unknown>;
};

export type ProvisionOnchainUserResult = {
  status: "provisioning_requested";
  item: {
    provisionRequestId: string;
    /** @deprecated Use `provisionRequestId`. */
    provisionedUserId?: string;
    actorId: string;
    accountAddress: string;
    executorAddress: string;
    provisionTxHash: string;
    registryAddress: string;
    verifierAddress: string;
    chainId: number;
    status: "provisioned";
  };
};

export type OnchainActor = {
  id: string;
  projectId: string;
  type: OnchainActorType;
  label: string;
  chainId: number;
  accountAddress: string;
  executorAddress: string;
  metadataJson: string;
  createdAt: number;
  updatedAt: number;
};

export type CreateOnchainActorInput = {
  projectId: string;
  type: OnchainActorType;
  label: string;
  chainId: number;
  accountAddress: string;
  executorAddress: string;
  metadataJson?: string;
};

export type UpdateOnchainActorInput = {
  projectId: string;
  actorId: string;
  type: OnchainActorType;
  label: string;
  chainId: number;
  accountAddress: string;
  executorAddress: string;
  metadataJson?: string;
};

export type OnchainAuthorizationPayload = {
  version: string;
  actionHash: string;
  account: string;
  executor: string;
  chainId: UintLike;
  nonce: UintLike;
  expiresAt: UintLike;
  keyId: string;
};

export type OnchainAuthorizationArtifact = {
  authorizationId: string;
  payload: OnchainAuthorizationPayload;
  signature: string;
  digest: string;
  signerAddress: string;
};

export type OnchainAuthorizationRecord = {
  authorizationId: string;
  projectId?: string;
  actorId?: string;
  approver?: string;
  actionHash: string;
  keyId: string;
  request: {
    projectId?: string;
    actorId?: string;
    account: string;
    to: string;
    value: string;
    data: string;
    chainId: UintLike;
    nonce: UintLike;
    expiresAt: UintLike;
    executor: string;
  };
  artifact: OnchainAuthorizationArtifact;
  createdAt: number;
};

export type OnchainAccountKey = {
  account: string;
  keyId: string;
  onchainKeyId: string;
  signerAddress: string;
  createdAt: number;
  updatedAt: number;
};

export type UpsertOnchainAccountKeyInput = {
  account: string;
  keyId?: string;
  signerAddress: string;
};

export type VerifyOnchainAuthorizationInput = {
  artifact: OnchainAuthorizationArtifact;
  request: Pick<OnchainAuthorizeActionInput, "account" | "to" | "value" | "data" | "chainId" | "nonce" | "executor">;
};

export type PreparedExecuteWithAuthCall = {
  to: string;
  value: bigint;
  data: string;
  auth: {
    actionHash: string;
    account: string;
    executor: string;
    chainId: bigint;
    nonce: bigint;
    expiresAt: bigint;
    keyId: string;
  };
  signature: string;
};

export type PrepareOnchainExecutionInput = {
  actor: Pick<OnchainActor, "accountAddress" | "executorAddress" | "chainId">;
  action: Pick<OnchainAuthorizeActionInput, "to" | "value" | "data" | "nonce">;
  artifact: OnchainAuthorizationArtifact;
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

  async redeemExecutionAuthorization(
    input: RedeemExecutionAuthorizationInput
  ): Promise<ExecutionAuthorizationRedemptionResult> {
    this.requireAPIKey("redeemExecutionAuthorization");

    const actionId = input.actionId?.trim() || input.artifact?.payload?.actionId?.trim();
    const audience = input.audience?.trim();
    const actionHash = input.actionHash?.trim();

    if (!actionId) {
      throw new Error("redeemExecutionAuthorization requires a non-empty actionId");
    }
    if (!input.artifact || typeof input.artifact !== "object" || Array.isArray(input.artifact)) {
      throw new Error("redeemExecutionAuthorization requires a structured artifact object");
    }
    if (!audience) {
      throw new Error("redeemExecutionAuthorization requires a non-empty audience");
    }
    if (!actionHash) {
      throw new Error("redeemExecutionAuthorization requires a non-empty actionHash");
    }

    return this.request(`/actions/${encodeURIComponent(actionId)}/execution-authorization/redeem`, {
      method: "POST",
      body: JSON.stringify({
        artifact: input.artifact,
        audience,
        actionHash
      })
    });
  }

  async authorizeAndExecute<T>(
    input: AuthorizeAndExecuteInput<T>
  ): Promise<AuthorizeAndExecuteResult<T>> {
    this.requireAPIKey("authorizeAndExecute");

    if (!input.action || typeof input.action !== "object") {
      throw new Error("authorizeAndExecute requires an exact action object");
    }
    if (!input.artifact || typeof input.artifact !== "object" || Array.isArray(input.artifact)) {
      throw new Error("authorizeAndExecute requires a structured artifact object");
    }
    if (!input.audience?.trim()) {
      throw new Error("authorizeAndExecute requires a non-empty audience");
    }
    if (!input.publicKeys) {
      throw new Error("authorizeAndExecute requires trusted public keys");
    }
    if (typeof input.execute !== "function") {
      throw new Error("authorizeAndExecute requires an execute callback");
    }

    const authorization = verifyExecutionAuthorization({
      artifact: input.artifact,
      action: input.action,
      audience: input.audience.trim(),
      publicKeys: input.publicKeys,
      now: input.now
    });

    const redemption = await this.redeemExecutionAuthorization({
      actionId: authorization.actionId,
      artifact: input.artifact,
      audience: input.audience.trim(),
      actionHash: authorization.actionHash
    });

    const executionResult = await input.execute({
      action: input.action,
      actionHash: authorization.actionHash,
      artifact: input.artifact,
      authorization,
      redemption
    });

    return {
      actionId: authorization.actionId,
      actionHash: authorization.actionHash,
      artifactId: redemption.artifactId,
      authorization,
      redemption,
      executionResult
    };
  }

  async getExecutionAuthorizationKeys(): Promise<{ items: ExecutionAuthorizationVerificationKey[] }> {
    this.requireAPIKey("getExecutionAuthorizationKeys");
    return this.request("/.well-known/execution-authorization-keys");
  }

  async authorizeOnchainAction(
    input: OnchainAuthorizeActionInput
  ): Promise<{ status: "authorized"; item: OnchainAuthorizationRecord }> {
    this.requireAPIKey("authorizeOnchainAction");

    if (!input.account?.trim()) {
      throw new Error("authorizeOnchainAction requires a non-empty account");
    }
    if (!input.to?.trim()) {
      throw new Error("authorizeOnchainAction requires a non-empty to address");
    }
    if (!input.value?.trim()) {
      throw new Error("authorizeOnchainAction requires a non-empty value");
    }
    if (!input.data?.trim()) {
      throw new Error("authorizeOnchainAction requires non-empty calldata");
    }
    const chainId = parseUintLike(input.chainId, "authorizeOnchainAction chainId");
    if (chainId <= 0n) {
      throw new Error("authorizeOnchainAction requires chainId > 0");
    }
    const nonce = parseUintLike(input.nonce, "authorizeOnchainAction nonce");
    const expiresAt = parseUintLike(input.expiresAt ?? 0n, "authorizeOnchainAction expiresAt");
    if (!input.executor?.trim()) {
      throw new Error("authorizeOnchainAction requires a non-empty executor address");
    }

    const query = buildQueryString({ projectId: input.projectId?.trim(), actorId: input.actorId?.trim() });
    return this.request(`/onchain/actions/authorize${query}`, {
      method: "POST",
      body: JSON.stringify({
        account: input.account.trim(),
        to: input.to.trim(),
        value: input.value.trim(),
        data: input.data.trim(),
        chainId: toSafeJSONUint(chainId, "authorizeOnchainAction chainId"),
        nonce: toSafeJSONUint(nonce, "authorizeOnchainAction nonce"),
        expiresAt: toSafeJSONUint(expiresAt, "authorizeOnchainAction expiresAt"),
        executor: input.executor.trim()
      })
    });
  }

  /**
   * Provisions an onchain user profile via `POST /v1/onchain/users/provision`.
   * The request shape intentionally excludes `projectId`; project scoping is resolved server-side.
   */
  async provisionOnchainUser(input: ProvisionOnchainUserInput): Promise<ProvisionOnchainUserResult> {
    this.requireAPIKey("provisionOnchainUser");

    if (!Number.isFinite(input.chainId) || input.chainId <= 0) {
      throw new Error("provisionOnchainUser requires chainId > 0");
    }
    if (!input.intendedOwner?.trim()) {
      throw new Error("provisionOnchainUser requires a non-empty intendedOwner");
    }

    const templateId = input.templateId?.trim();
    if (typeof input.templateId !== "undefined" && !templateId) {
      throw new Error("provisionOnchainUser templateId must be non-empty when provided");
    }
    if (typeof input.metadata !== "undefined" && (input.metadata === null || Array.isArray(input.metadata))) {
      throw new Error("provisionOnchainUser metadata must be an object when provided");
    }

    return this.request("/v1/onchain/users/provision", {
      method: "POST",
      body: JSON.stringify({
        chainId: input.chainId,
        intendedOwner: input.intendedOwner.trim(),
        ...(templateId ? { templateId } : {}),
        ...(typeof input.metadata !== "undefined" ? { metadata: input.metadata } : {})
      })
    });
  }

  async getOnchainAuthorization(
    authorizationId: string,
    options?: { projectId?: string }
  ): Promise<{ item: OnchainAuthorizationRecord }> {
    this.requireAPIKey("getOnchainAuthorization");
    const trimmedAuthorizationID = authorizationId.trim();
    if (!trimmedAuthorizationID) {
      throw new Error("getOnchainAuthorization requires a non-empty authorizationId");
    }

    const query = buildQueryString({ projectId: options?.projectId?.trim() });
    return this.request(`/onchain/actions/${encodeURIComponent(trimmedAuthorizationID)}${query}`);
  }

  async upsertOnchainAccountKey(
    input: UpsertOnchainAccountKeyInput
  ): Promise<{ status: "upserted"; item: OnchainAccountKey }> {
    this.requireAPIKey("upsertOnchainAccountKey");

    const account = input.account?.trim() ?? "";
    const signerAddress = input.signerAddress?.trim() ?? "";
    const keyId = input.keyId?.trim();
    if (!account) {
      throw new Error("upsertOnchainAccountKey requires a non-empty account");
    }
    if (!signerAddress) {
      throw new Error("upsertOnchainAccountKey requires a non-empty signerAddress");
    }

    return this.request(`/onchain/accounts/${encodeURIComponent(account)}/keys`, {
      method: "POST",
      body: JSON.stringify({
        keyId,
        signerAddress
      })
    });
  }

  async listOnchainAccountKeys(
    account: string
  ): Promise<{ items: OnchainAccountKey[]; configuredSigner: string; configuredSignerId: string }> {
    this.requireAPIKey("listOnchainAccountKeys");
    const trimmedAccount = account.trim();
    if (!trimmedAccount) {
      throw new Error("listOnchainAccountKeys requires a non-empty account");
    }
    return this.request(`/onchain/accounts/${encodeURIComponent(trimmedAccount)}/keys`);
  }

  async deleteOnchainAccountKey(
    account: string,
    keyId: string
  ): Promise<{ status: "deleted" }> {
    this.requireAPIKey("deleteOnchainAccountKey");
    const trimmedAccount = account.trim();
    const trimmedKeyID = keyId.trim();
    if (!trimmedAccount) {
      throw new Error("deleteOnchainAccountKey requires a non-empty account");
    }
    if (!trimmedKeyID) {
      throw new Error("deleteOnchainAccountKey requires a non-empty keyId");
    }
    return this.request(`/onchain/accounts/${encodeURIComponent(trimmedAccount)}/keys/${encodeURIComponent(trimmedKeyID)}`, {
      method: "DELETE"
    });
  }

  async listOnchainActors(projectId: string): Promise<{ items: OnchainActor[] }> {
    this.requireAPIKey("listOnchainActors");
    const trimmedProjectID = projectId.trim();
    if (!trimmedProjectID) {
      throw new Error("listOnchainActors requires a non-empty projectId");
    }
    return this.request(`/onchain/actors/${encodeURIComponent(trimmedProjectID)}`);
  }

  async getOnchainActor(projectId: string, actorId: string): Promise<{ item: OnchainActor }> {
    this.requireAPIKey("getOnchainActor");
    const trimmedProjectID = projectId.trim();
    const trimmedActorID = actorId.trim();
    if (!trimmedProjectID) {
      throw new Error("getOnchainActor requires a non-empty projectId");
    }
    if (!trimmedActorID) {
      throw new Error("getOnchainActor requires a non-empty actorId");
    }
    return this.request(`/onchain/actors/${encodeURIComponent(trimmedProjectID)}/${encodeURIComponent(trimmedActorID)}`);
  }

  async createOnchainActor(input: CreateOnchainActorInput): Promise<{ status: "created"; item: OnchainActor }> {
    this.requireAPIKey("createOnchainActor");
    const payload = normalizeOnchainActorInput("createOnchainActor", input);
    return this.request(`/onchain/actors/${encodeURIComponent(payload.projectId)}`, {
      method: "POST",
      body: JSON.stringify(payload.body)
    });
  }

  async updateOnchainActor(input: UpdateOnchainActorInput): Promise<{ status: "updated"; item: OnchainActor }> {
    this.requireAPIKey("updateOnchainActor");
    const actorId = input.actorId?.trim() ?? "";
    if (!actorId) {
      throw new Error("updateOnchainActor requires a non-empty actorId");
    }
    const payload = normalizeOnchainActorInput("updateOnchainActor", input);
    return this.request(`/onchain/actors/${encodeURIComponent(payload.projectId)}/${encodeURIComponent(actorId)}`, {
      method: "PUT",
      body: JSON.stringify(payload.body)
    });
  }

  async deleteOnchainActor(projectId: string, actorId: string): Promise<{ status: "deleted" }> {
    this.requireAPIKey("deleteOnchainActor");
    const trimmedProjectID = projectId.trim();
    const trimmedActorID = actorId.trim();
    if (!trimmedProjectID) {
      throw new Error("deleteOnchainActor requires a non-empty projectId");
    }
    if (!trimmedActorID) {
      throw new Error("deleteOnchainActor requires a non-empty actorId");
    }
    return this.request(`/onchain/actors/${encodeURIComponent(trimmedProjectID)}/${encodeURIComponent(trimmedActorID)}`, {
      method: "DELETE"
    });
  }

  async registerOnchainActor(
    actor: CreateOnchainActorInput,
    options?: { keyId?: string; signerAddress?: string }
  ): Promise<{ actor: OnchainActor; key?: OnchainAccountKey }> {
    const created = await this.createOnchainActor(actor);
    if (!options?.signerAddress?.trim()) {
      return { actor: created.item };
    }

    const key = await this.upsertOnchainAccountKey({
      account: created.item.accountAddress,
      keyId: options.keyId,
      signerAddress: options.signerAddress
    });
    return { actor: created.item, key: key.item };
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
  ): Promise<ActionRecord> {
    return this.getActionWithOptions(actionId, options);
  }

  async getExactActionRequest(
    actionId: string,
    options?: ActionReadOptions
  ): Promise<ActionRequest> {
    return toExactActionRequest(await this.getActionWithOptions(actionId, options));
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
  ): Promise<ActionRecord> {
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

export function computeOnchainActionHash(input: Pick<OnchainAuthorizeActionInput, "account" | "to" | "value" | "data" | "chainId" | "nonce" | "expiresAt" | "executor">): string {
  const account = normalizeAddress(input.account, "computeOnchainActionHash account");
  const to = normalizeAddress(input.to, "computeOnchainActionHash to");
  const executor = normalizeAddress(input.executor, "computeOnchainActionHash executor");
  const value = parseUintString(input.value, "computeOnchainActionHash value");
  const chainID = parseUintLike(input.chainId, "computeOnchainActionHash chainId");
  const nonce = parseUintLike(input.nonce, "computeOnchainActionHash nonce");
  const expiresAt = parseUintLike(input.expiresAt ?? 0, "computeOnchainActionHash expiresAt");
  const data = normalizeHex(input.data, "computeOnchainActionHash data");

  return hexlify(
    keccak256Bytes(
      concatBytes(
        wordFromAddress(account),
        wordFromAddress(to),
        wordFromBigInt(value),
        keccak256Bytes(hexToBytes(data)),
        wordFromBigInt(chainID),
        wordFromBigInt(nonce),
        wordFromBigInt(expiresAt),
        wordFromAddress(executor)
      )
    )
  );
}

export function computeOnchainAuthorizationDigest(artifact: OnchainAuthorizationArtifact): string {
  const actionHash = normalizeBytes32(artifact.payload.actionHash, "computeOnchainAuthorizationDigest actionHash");
  const account = normalizeAddress(artifact.payload.account, "computeOnchainAuthorizationDigest account");
  const executor = normalizeAddress(artifact.payload.executor, "computeOnchainAuthorizationDigest executor");
  const chainID = parseUintLike(artifact.payload.chainId, "computeOnchainAuthorizationDigest chainId");
  const nonce = parseUintLike(artifact.payload.nonce, "computeOnchainAuthorizationDigest nonce");
  const expiresAt = parseUintLike(artifact.payload.expiresAt, "computeOnchainAuthorizationDigest expiresAt");
  const keyID = normalizeOnchainKeyId(artifact.payload.keyId, "computeOnchainAuthorizationDigest keyId");

  const domainTypeHash = keccak256Bytes(utf8Bytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"));
  const authTypeHash = keccak256Bytes(utf8Bytes("ExecutionAuthorization(bytes32 actionHash,address account,address executor,uint256 chainId,uint256 nonce,uint256 expiresAt,bytes32 keyId)"));
  const domainNameHash = keccak256Bytes(utf8Bytes("Beav3rExecutionAuthorization"));
  const domainVersionHash = keccak256Bytes(utf8Bytes("1"));
  const keyIDHash = normalizeBytes32OrHashKeyId(keyID);

  const domainSeparator = keccak256Bytes(
    concatBytes(
      domainTypeHash,
      domainNameHash,
      domainVersionHash,
      wordFromBigInt(chainID),
      wordFromAddress(executor)
    )
  );

  const structHash = keccak256Bytes(
    concatBytes(
      authTypeHash,
      hexToBytes(actionHash),
      wordFromAddress(account),
      wordFromAddress(executor),
      wordFromBigInt(chainID),
      wordFromBigInt(nonce),
      wordFromBigInt(expiresAt),
      keyIDHash
    )
  );

  return hexlify(keccak256Bytes(concatBytes(new Uint8Array([0x19, 0x01]), domainSeparator, structHash)));
}

export function verifyOnchainAuthorization(input: VerifyOnchainAuthorizationInput): {
  actionHash: string;
  digest: string;
} {
  const actionHash = computeOnchainActionHash({
    ...input.request,
    expiresAt: input.artifact.payload.expiresAt
  });
  if (normalizeBytes32(input.artifact.payload.actionHash, "verifyOnchainAuthorization artifact.payload.actionHash") !== actionHash) {
    throw new Error("Onchain authorization actionHash mismatch");
  }

  const digest = computeOnchainAuthorizationDigest(input.artifact);
  if (normalizeBytes32(input.artifact.digest, "verifyOnchainAuthorization artifact.digest") !== digest) {
    throw new Error("Onchain authorization digest mismatch");
  }

  return { actionHash, digest };
}

export function prepareExecuteWithAuthCall(
  request: Pick<OnchainAuthorizeActionInput, "to" | "value" | "data">,
  artifact: OnchainAuthorizationArtifact
): PreparedExecuteWithAuthCall {
  const to = normalizeAddress(request.to, "prepareExecuteWithAuthCall to");
  const value = parseUintString(request.value, "prepareExecuteWithAuthCall value");
  const data = normalizeHex(request.data, "prepareExecuteWithAuthCall data");

  const signature = normalizeHex(artifact.signature, "prepareExecuteWithAuthCall signature");
  const actionHash = normalizeBytes32(artifact.payload.actionHash, "prepareExecuteWithAuthCall actionHash");
  const account = normalizeAddress(artifact.payload.account, "prepareExecuteWithAuthCall account");
  const executor = normalizeAddress(artifact.payload.executor, "prepareExecuteWithAuthCall executor");
  const chainID = parseUintLike(artifact.payload.chainId, "prepareExecuteWithAuthCall chainId");
  const nonce = parseUintLike(artifact.payload.nonce, "prepareExecuteWithAuthCall nonce");
  const expiresAt = parseUintLike(artifact.payload.expiresAt, "prepareExecuteWithAuthCall expiresAt");
  const keyId = hexlify(
    normalizeBytes32OrHashKeyId(
      normalizeOnchainKeyId(artifact.payload.keyId, "prepareExecuteWithAuthCall keyId")
    )
  );

  return {
    to,
    value,
    data,
    auth: {
      actionHash,
      account,
      executor,
      chainId: chainID,
      nonce,
      expiresAt,
      keyId
    },
    signature
  };
}

export function encodeExecuteWithAuthCalldata(input: PreparedExecuteWithAuthCall): string {
  const selector = hexlify(keccak256Bytes(utf8Bytes("executeWithAuth(address,uint256,bytes,(bytes32,address,address,uint256,uint256,uint256,bytes32),bytes)"))).slice(0, 10);
  const dataBytes = hexToBytes(normalizeHex(input.data, "encodeExecuteWithAuthCalldata data"));
  const signatureBytes = hexToBytes(normalizeHex(input.signature, "encodeExecuteWithAuthCalldata signature"));

  const staticWords = 11n;
  const staticLength = staticWords * 32n;
  const dataOffset = staticLength;
  const dataTail = encodeDynamicBytes(dataBytes);
  const signatureOffset = staticLength + BigInt(dataTail.length);
  const signatureTail = encodeDynamicBytes(signatureBytes);

  const args = concatBytes(
    wordFromAddress(input.to),
    wordFromBigInt(input.value),
    wordFromBigInt(dataOffset),
    hexToBytes(normalizeBytes32(input.auth.actionHash, "encodeExecuteWithAuthCalldata auth.actionHash")),
    wordFromAddress(input.auth.account),
    wordFromAddress(input.auth.executor),
    wordFromBigInt(input.auth.chainId),
    wordFromBigInt(input.auth.nonce),
    wordFromBigInt(input.auth.expiresAt),
    hexToBytes(normalizeBytes32(input.auth.keyId, "encodeExecuteWithAuthCalldata auth.keyId")),
    wordFromBigInt(signatureOffset),
    dataTail,
    signatureTail
  );

  return `${selector}${toHexNoPrefix(args)}`;
}

export function prepareOnchainExecution(input: PrepareOnchainExecutionInput): PreparedExecuteWithAuthCall & { calldata: string } {
  verifyOnchainAuthorization({
    artifact: input.artifact,
    request: {
      account: input.actor.accountAddress,
      to: input.action.to,
      value: input.action.value,
      data: input.action.data,
      chainId: input.actor.chainId,
      nonce: input.action.nonce,
      executor: input.actor.executorAddress
    }
  });
  const call = prepareExecuteWithAuthCall(input.action, input.artifact);
  return {
    ...call,
    calldata: encodeExecuteWithAuthCalldata(call)
  };
}

function normalizeOnchainActorInput(
  methodName: string,
  input: CreateOnchainActorInput | UpdateOnchainActorInput
): {
  projectId: string;
  body: {
    type: OnchainActorType;
    label: string;
    chainId: number;
    accountAddress: string;
    executorAddress: string;
    metadataJson: string;
  };
} {
  const projectId = input.projectId?.trim() ?? "";
  const type = input.type?.trim() as OnchainActorType;
  const label = input.label?.trim() ?? "";
  const accountAddress = normalizeAddress(input.accountAddress, `${methodName} accountAddress`);
  const executorAddress = normalizeAddress(input.executorAddress, `${methodName} executorAddress`);
  const metadataJson = input.metadataJson?.trim() || "{}";

  if (!projectId) {
    throw new Error(`${methodName} requires a non-empty projectId`);
  }
  if (type !== "wallet" && type !== "smart_account") {
    throw new Error(`${methodName} requires type \"wallet\" or \"smart_account\"`);
  }
  if (!label) {
    throw new Error(`${methodName} requires a non-empty label`);
  }
  if (!Number.isFinite(input.chainId) || input.chainId <= 0) {
    throw new Error(`${methodName} requires chainId > 0`);
  }

  return {
    projectId,
    body: {
      type,
      label,
      chainId: input.chainId,
      accountAddress,
      executorAddress,
      metadataJson
    }
  };
}

function parseUintString(value: string, field: string): bigint {
  const text = normalizeNonEmptyString(value, field);
  if (!/^\d+$/.test(text)) {
    throw new Error(`${field} must be a base-10 unsigned integer string`);
  }
  return BigInt(text);
}

function parseUintLike(value: string | number | bigint, field: string): bigint {
  if (typeof value === "bigint") {
    if (value < 0n) {
      throw new Error(`${field} must be >= 0`);
    }
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value) || value < 0) {
      throw new Error(`${field} must be a non-negative integer`);
    }
    return BigInt(value);
  }
  return parseUintString(value, field);
}

function toSafeJSONUint(value: bigint, field: string): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${field} exceeds Number.MAX_SAFE_INTEGER and cannot be encoded in JSON number safely`);
  }
  return Number(value);
}

function normalizeOnchainKeyId(value: string, field: string): string {
  return normalizeNonEmptyString(value, field);
}

function normalizeBytes32OrHashKeyId(keyId: string): Uint8Array {
  if (/^0x[0-9a-f]{64}$/i.test(keyId)) {
    return hexToBytes(keyId.toLowerCase());
  }
  return keccak256Bytes(utf8Bytes(keyId));
}

function normalizeNonEmptyString(value: string, field: string): string {
  const text = value?.trim();
  if (!text) {
    throw new Error(`${field} is required`);
  }
  return text;
}

function normalizeHex(value: string, field: string): string {
  const text = normalizeNonEmptyString(value, field).toLowerCase();
  if (!/^0x[0-9a-f]*$/.test(text)) {
    throw new Error(`${field} must be a valid 0x-prefixed hex string`);
  }
  if ((text.length - 2) % 2 !== 0) {
    throw new Error(`${field} must contain an even number of hex characters`);
  }
  return text;
}

function normalizeBytes32(value: string, field: string): string {
  const text = normalizeHex(value, field);
  if (text.length !== 66) {
    throw new Error(`${field} must be a 32-byte hex string`);
  }
  return text;
}

function normalizeAddress(value: string, field: string): string {
  const text = normalizeHex(value, field);
  if (text.length !== 42) {
    throw new Error(`${field} must be a 20-byte address`);
  }
  return text;
}

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex.slice(2), "hex"));
}

function utf8Bytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "utf8"));
}

function hexlify(bytes: Uint8Array): string {
  return `0x${toHexNoPrefix(bytes)}`;
}

function toHexNoPrefix(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function keccak256Bytes(data: Uint8Array): Uint8Array {
  return Uint8Array.from(keccak_256(data));
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const totalLength = parts.reduce((sum, item) => sum + item.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;
  for (const item of parts) {
    output.set(item, offset);
    offset += item.length;
  }
  return output;
}

function wordFromBigInt(value: bigint): Uint8Array {
  if (value < 0n) {
    throw new Error("wordFromBigInt value must be non-negative");
  }
  const max = (1n << 256n) - 1n;
  if (value > max) {
    throw new Error("wordFromBigInt value exceeds uint256 range");
  }
  return hexToBytes(`0x${value.toString(16).padStart(64, "0")}`);
}

function wordFromAddress(address: string): Uint8Array {
  return hexToBytes(`0x${normalizeAddress(address, "address").slice(2).padStart(64, "0")}`);
}

function encodeDynamicBytes(value: Uint8Array): Uint8Array {
  const lengthWord = wordFromBigInt(BigInt(value.length));
  const padLength = (32 - (value.length % 32)) % 32;
  return concatBytes(lengthWord, value, new Uint8Array(padLength));
}

export function toExactActionRequest(action: ActionRequest | ActionRecord): ActionRequest {
  return {
    actionId: action.actionId,
    agentId: action.agentId,
    actionType: action.actionType,
    payload: {
      ...(action.payload ?? {})
    },
    attributes: action.attributes ?? {},
    timestamp: action.timestamp,
    nonce: action.nonce,
    expiry: action.expiry
  };
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
