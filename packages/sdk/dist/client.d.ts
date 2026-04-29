import type { ActionRequest, ApprovalReject, ApprovalToken, DeviceInput, PolicyRule, QueueItem } from "@beav3r/protocol";
import { type ExecutionAuthorizationArtifactPayload, type ExecutionAuthorizationKeySet, type SignedExecutionAuthorizationArtifact } from "./execution-authorization";
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
export type ExecutedActionResult = {
    status: "executed";
    actionId: string;
    actionHash: string;
    evaluation: ActionEvaluation;
};
export type ApprovedActionResult = {
    status: "approved";
    actionId: string;
    actionHash: string;
    evaluation: ActionEvaluation;
};
export type PendingActionResult = {
    status: "pending";
    actionId: string;
    actionHash: string;
    reason: string;
    evaluation: ActionEvaluation;
};
export type DeniedActionResult = {
    status: "denied";
    actionId: string;
    reason: string;
    evaluation: ActionEvaluation;
};
export type ActionRequestResult = ExecutedActionResult | ApprovedActionResult | PendingActionResult | DeniedActionResult;
export type GuardResult = ActionRequestResult;
export type RelayActionResult = ApprovedActionResult | PendingActionResult | DeniedActionResult;
export type ActionStatusResult = {
    actionId: string;
    status: "pending";
    reason?: string;
} | {
    actionId: string;
    status: "approved";
    reason?: string;
} | {
    actionId: string;
    status: "executed";
    reason?: string;
} | {
    actionId: string;
    status: "denied";
    reason?: string;
} | {
    actionId: string;
    status: "rejected";
    reason?: string;
} | {
    actionId: string;
    status: "expired";
    reason?: string;
};
type GuardAndWaitAllowResult = {
    status: "approved" | "executed";
    actionId: string;
    actionHash: string;
    evaluation: ActionEvaluation;
    executionAuthorizationArtifact?: SignedExecutionAuthorizationArtifact;
};
export type GuardAndWaitResult = GuardAndWaitAllowResult | {
    status: "denied";
    actionId: string;
    reason?: string;
} | {
    status: "rejected";
    actionId: string;
    reason?: string;
} | {
    status: "expired";
    actionId: string;
    reason?: string;
} | {
    status: "pending";
    actionId: string;
    actionHash: string;
    reason: string;
    pendingForMs: number;
};
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
export type OnchainAuthorizeActionInput = {
    account: string;
    to: string;
    value: string;
    data: string;
    chainId: number;
    nonce: number;
    expiresAt?: number;
    executor: string;
    projectId?: string;
    actorId?: string;
};
export type OnchainActorType = "wallet" | "smart_account";
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
    chainId: number;
    nonce: number;
    expiresAt: number;
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
        chainId: number;
        nonce: number;
        expiresAt: number;
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
export declare class Beav3rDeniedError extends Error {
    readonly actionId: string;
    constructor(actionId: string, reason?: string);
}
export declare class Beav3r {
    private readonly options;
    private readonly fetchImpl;
    constructor(options: Beav3rOptions);
    requestAction(input: RequestActionInput): Promise<ActionRequestResult>;
    relayAction(input: RelayActionInput): Promise<RelayActionResult>;
    guard(input: RequestActionInput): Promise<GuardResult>;
    guardAndExit(input: RequestActionInput): Promise<GuardResult>;
    mintExecutionAuthorization(input: MintExecutionAuthorizationInput): Promise<SignedExecutionAuthorizationArtifact>;
    redeemExecutionAuthorization(input: RedeemExecutionAuthorizationInput): Promise<ExecutionAuthorizationRedemptionResult>;
    authorizeAndExecute<T>(input: AuthorizeAndExecuteInput<T>): Promise<AuthorizeAndExecuteResult<T>>;
    getExecutionAuthorizationKeys(): Promise<{
        items: ExecutionAuthorizationVerificationKey[];
    }>;
    authorizeOnchainAction(input: OnchainAuthorizeActionInput): Promise<{
        status: "authorized";
        item: OnchainAuthorizationRecord;
    }>;
    getOnchainAuthorization(authorizationId: string, options?: {
        projectId?: string;
    }): Promise<{
        item: OnchainAuthorizationRecord;
    }>;
    upsertOnchainAccountKey(input: UpsertOnchainAccountKeyInput): Promise<{
        status: "upserted";
        item: OnchainAccountKey;
    }>;
    listOnchainAccountKeys(account: string): Promise<{
        items: OnchainAccountKey[];
        configuredSigner: string;
        configuredSignerId: string;
    }>;
    deleteOnchainAccountKey(account: string, keyId: string): Promise<{
        status: "deleted";
    }>;
    listOnchainActors(projectId: string): Promise<{
        items: OnchainActor[];
    }>;
    getOnchainActor(projectId: string, actorId: string): Promise<{
        item: OnchainActor;
    }>;
    createOnchainActor(input: CreateOnchainActorInput): Promise<{
        status: "created";
        item: OnchainActor;
    }>;
    updateOnchainActor(input: UpdateOnchainActorInput): Promise<{
        status: "updated";
        item: OnchainActor;
    }>;
    deleteOnchainActor(projectId: string, actorId: string): Promise<{
        status: "deleted";
    }>;
    registerOnchainActor(actor: CreateOnchainActorInput, options?: {
        keyId?: string;
        signerAddress?: string;
    }): Promise<{
        actor: OnchainActor;
        key?: OnchainAccountKey;
    }>;
    private requireAPIKey;
    private buildAction;
    guardAndWait(input: RequestActionInput, options?: GuardWaitOptions): Promise<GuardAndWaitResult>;
    guardOrThrow(input: RequestActionInput): Promise<Exclude<GuardResult, DeniedActionResult>>;
    getActionStatus(actionId: string, options?: ActionReadOptions): Promise<ActionStatusResult>;
    getAction(actionId: string, options?: ActionReadOptions): Promise<ActionRecord>;
    getExactActionRequest(actionId: string, options?: ActionReadOptions): Promise<ActionRequest>;
    listPendingActions(options?: ListPendingActionsOptions): Promise<{
        items: QueueItem[];
    }>;
    listRecentActions(options?: ListRecentActionsOptions): Promise<{
        items: Array<ActionRequest & {
            actionHash: string;
            status: string;
            reason?: string;
            evaluation: ActionEvaluation;
        }>;
    }>;
    listPolicyRules(options?: ListPolicyRulesOptions): Promise<{
        items: PolicyRule[];
    }>;
    registerDevice(device: RegisterDeviceInput): Promise<{
        status: "registered";
    }>;
    submitApproval(token: ApprovalToken): Promise<{
        status: "approved" | "executed";
        actionId: string;
    }>;
    rejectApproval(rejection: Omit<ApprovalReject, "signature" | "expiry"> & Partial<Pick<ApprovalReject, "signature" | "expiry">>): Promise<{
        status: "rejected";
        actionId: string;
    }>;
    getActionStatusWithOptions(actionId: string, options?: ActionReadOptions): Promise<ActionStatusResult>;
    getActionWithOptions(actionId: string, options?: ActionReadOptions): Promise<ActionRecord>;
    private buildActionReadQuery;
    private attachExecutionAuthorizationIfNeeded;
    private buildSignedDeviceQuery;
    private completeRejection;
    private request;
}
export declare function computeOnchainActionHash(input: Pick<OnchainAuthorizeActionInput, "account" | "to" | "value" | "data" | "chainId" | "nonce" | "expiresAt" | "executor">): string;
export declare function computeOnchainAuthorizationDigest(artifact: OnchainAuthorizationArtifact): string;
export declare function verifyOnchainAuthorization(input: VerifyOnchainAuthorizationInput): {
    actionHash: string;
    digest: string;
};
export declare function prepareExecuteWithAuthCall(request: Pick<OnchainAuthorizeActionInput, "to" | "value" | "data">, artifact: OnchainAuthorizationArtifact): PreparedExecuteWithAuthCall;
export declare function encodeExecuteWithAuthCalldata(input: PreparedExecuteWithAuthCall): string;
export declare function prepareOnchainExecution(input: PrepareOnchainExecutionInput): PreparedExecuteWithAuthCall & {
    calldata: string;
};
export declare function toExactActionRequest(action: ActionRequest | ActionRecord): ActionRequest;
export { Beav3r as BeaverClient, Beav3rDeniedError as BeaverDeniedError };
export type BeaverClientOptions = Beav3rOptions;
//# sourceMappingURL=client.d.ts.map