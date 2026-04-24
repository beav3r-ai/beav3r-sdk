import { type ActionRequest } from "@beav3r/protocol";
export type ExecutionAuthorizationDecision = "approved" | "executed" | string;
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
export declare function verifyExecutionAuthorization(input: VerifyExecutionAuthorizationInput): ExecutionAuthorizationArtifactPayload;
export declare function isValidExecutionAuthorization(input: VerifyExecutionAuthorizationInput): boolean;
//# sourceMappingURL=execution-authorization.d.ts.map