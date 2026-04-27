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
export declare function toExactActionRequest(action: ActionRequest | ActionRecord): ActionRequest;
export { Beav3r as BeaverClient, Beav3rDeniedError as BeaverDeniedError };
export type BeaverClientOptions = Beav3rOptions;
//# sourceMappingURL=client.d.ts.map