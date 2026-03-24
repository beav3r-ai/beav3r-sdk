import type { ActionRequest, ApprovalReject, ApprovalToken, DeviceInput, PolicyRule, QueueItem } from "@beav3r/protocol";
type RegisterDeviceInput = DeviceInput & {
    secretKeyBase64?: string;
    pairingToken?: string;
};
export type Beav3rOptions = {
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
export type ExecutedActionResult = {
    status: "executed";
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
export type ActionRequestResult = ExecutedActionResult | PendingActionResult | DeniedActionResult;
export type GuardResult = ActionRequestResult;
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
export type GuardAndWaitResult = {
    status: "approved";
    actionId: string;
    actionHash: string;
    evaluation: ActionEvaluation;
} | {
    status: "executed";
    actionId: string;
    actionHash: string;
    evaluation: ActionEvaluation;
} | {
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
};
export type ListPendingActionsOptions = {
    deviceId?: string;
};
export type ListRecentActionsOptions = {
    deviceId?: string;
};
export type ListPolicyRulesOptions = {
    agentId?: string;
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
    relayAction(input: RelayActionInput): Promise<PendingActionResult>;
    guard(input: RequestActionInput): Promise<GuardResult>;
    private buildAction;
    guardAndWait(input: RequestActionInput, options?: GuardWaitOptions): Promise<GuardAndWaitResult>;
    guardOrThrow(input: RequestActionInput): Promise<Exclude<GuardResult, DeniedActionResult>>;
    getActionStatus(actionId: string): Promise<ActionStatusResult>;
    getAction(actionId: string): Promise<ActionRequest & {
        actionHash: string;
        status: string;
        reason?: string;
        evaluation: ActionEvaluation;
    }>;
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
    rejectApproval(rejection: ApprovalReject): Promise<{
        status: "rejected";
        actionId: string;
    }>;
    private request;
}
export { Beav3r as BeaverClient, Beav3rDeniedError as BeaverDeniedError };
export type BeaverClientOptions = Beav3rOptions;
//# sourceMappingURL=client.d.ts.map