"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BeaverDeniedError = exports.BeaverClient = exports.Beav3r = exports.Beav3rDeniedError = void 0;
exports.toExactActionRequest = toExactActionRequest;
const buffer_1 = require("buffer");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const execution_authorization_1 = require("./execution-authorization");
class Beav3rDeniedError extends Error {
    actionId;
    constructor(actionId, reason) {
        super(reason ?? `Action ${actionId} was denied by Beav3r`);
        this.name = "Beav3rDeniedError";
        this.actionId = actionId;
    }
}
exports.Beav3rDeniedError = Beav3rDeniedError;
exports.BeaverDeniedError = Beav3rDeniedError;
class Beav3r {
    options;
    fetchImpl;
    constructor(options) {
        this.options = options;
        this.fetchImpl = options.fetchImpl ?? fetch;
    }
    async requestAction(input) {
        this.requireAPIKey("requestAction");
        const action = this.buildAction(input);
        return this.request("/actions/request", {
            method: "POST",
            body: JSON.stringify(action)
        });
    }
    async relayAction(input) {
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
    async guard(input) {
        return this.requestAction(input);
    }
    async guardAndExit(input) {
        return this.guard(input);
    }
    async mintExecutionAuthorization(input) {
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
    async redeemExecutionAuthorization(input) {
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
    async authorizeAndExecute(input) {
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
        const authorization = (0, execution_authorization_1.verifyExecutionAuthorization)({
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
    requireAPIKey(methodName) {
        if (this.options.apiKey?.trim()) {
            return;
        }
        throw new Error(`Beav3r API key is required for ${methodName}. Configure apiKey when creating the client.`);
    }
    buildAction(input) {
        const now = Math.floor(Date.now() / 1000);
        const payload = { ...input.payload };
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
    async guardAndWait(input, options) {
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
    async guardOrThrow(input) {
        const result = await this.guard(input);
        if (result.status === "denied") {
            throw new Beav3rDeniedError(result.actionId, result.reason);
        }
        return result;
    }
    async getActionStatus(actionId, options) {
        return this.getActionStatusWithOptions(actionId, options);
    }
    async getAction(actionId, options) {
        return this.getActionWithOptions(actionId, options);
    }
    async getExactActionRequest(actionId, options) {
        return toExactActionRequest(await this.getActionWithOptions(actionId, options));
    }
    async listPendingActions(options) {
        const query = {
            projectId: options?.projectId,
            ...this.buildSignedDeviceQuery("actions-pending", options?.deviceId, options?.secretKeyBase64)
        };
        return this.request(`/actions/pending${buildQueryString(query)}`);
    }
    async listRecentActions(options) {
        const query = {
            projectId: options?.projectId,
            ...this.buildSignedDeviceQuery("actions-recent", options?.deviceId, options?.secretKeyBase64)
        };
        return this.request(`/actions/recent${buildQueryString(query)}`);
    }
    async listPolicyRules(options) {
        const query = {
            agentId: options?.agentId,
            ...this.buildSignedDeviceQuery("policy-rules", options?.deviceId, options?.secretKeyBase64)
        };
        return this.request(`/policy-rules${buildQueryString(query)}`);
    }
    async registerDevice(device) {
        if (!device.secretKeyBase64) {
            throw new Error("registerDevice now requires secretKeyBase64 to sign a registration challenge");
        }
        if (!device.pairingToken) {
            throw new Error("registerDevice now requires pairingToken from a project pairing session");
        }
        const challenge = await this.request("/devices/register/challenge", {
            method: "POST",
            body: JSON.stringify({
                deviceId: device.deviceId,
                publicKey: device.publicKey,
                pairingToken: device.pairingToken
            })
        });
        const message = buffer_1.Buffer.from(challenge.challenge, "utf8");
        const signature = tweetnacl_1.default.sign.detached(message, new Uint8Array(buffer_1.Buffer.from(device.secretKeyBase64, "base64")));
        const challengeSignature = buffer_1.Buffer.from(signature).toString("base64");
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
    async submitApproval(token) {
        return this.request("/approvals/submit", {
            method: "POST",
            body: JSON.stringify(token)
        });
    }
    async rejectApproval(rejection) {
        const payload = this.completeRejection(rejection);
        return this.request("/approvals/reject", {
            method: "POST",
            body: JSON.stringify(payload)
        });
    }
    async getActionStatusWithOptions(actionId, options) {
        const query = this.buildActionReadQuery(`action-status:${actionId}`, options);
        return this.request(`/actions/${actionId}/status${buildQueryString(query)}`);
    }
    async getActionWithOptions(actionId, options) {
        const query = this.buildActionReadQuery(`action-read:${actionId}`, options);
        return this.request(`/actions/${actionId}${buildQueryString(query)}`);
    }
    buildActionReadQuery(purpose, options) {
        if (options?.actionHash) {
            return { actionHash: options.actionHash };
        }
        return this.buildSignedDeviceQuery(purpose, options?.deviceId, options?.secretKeyBase64);
    }
    async attachExecutionAuthorizationIfNeeded(result, audience) {
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
    buildSignedDeviceQuery(purpose, deviceId, secretKeyBase64) {
        const effectiveDeviceID = deviceId ?? this.options.deviceId;
        const effectiveSecretKey = secretKeyBase64 ?? this.options.secretKeyBase64;
        if (!effectiveDeviceID || !effectiveSecretKey) {
            return {};
        }
        const timestamp = String(Math.floor(Date.now() / 1000));
        const nonce = createUuid();
        const signature = signUtf8Message(`${purpose}:${effectiveDeviceID}:${timestamp}:${nonce}`, effectiveSecretKey);
        return {
            deviceId: effectiveDeviceID,
            timestamp,
            nonce,
            signature
        };
    }
    completeRejection(rejection) {
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
    async request(path, init) {
        const url = `${this.options.baseUrl}${path}`;
        let response;
        try {
            response = await this.fetchImpl(url, {
                headers: {
                    "content-type": "application/json",
                    ...(this.options.apiKey ? { authorization: `Bearer ${this.options.apiKey}` } : {}),
                    ...(init?.headers ?? {})
                },
                ...init
            });
        }
        catch (error) {
            const message = error.message;
            throw new Error(`Cannot reach Beav3r at ${this.options.baseUrl}. Make sure the server is running, bound to 0.0.0.0, and reachable from this machine. Original error: ${message}`);
        }
        const bodyText = await response.text();
        const body = (bodyText ? JSON.parse(bodyText) : {});
        if (!response.ok) {
            throw new Error(body.error ?? `Request to ${url} failed with status ${response.status}`);
        }
        return body;
    }
}
exports.Beav3r = Beav3r;
exports.BeaverClient = Beav3r;
function toExactActionRequest(action) {
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
function signUtf8Message(message, secretKeyBase64) {
    const signature = tweetnacl_1.default.sign.detached(buffer_1.Buffer.from(message, "utf8"), new Uint8Array(buffer_1.Buffer.from(secretKeyBase64, "base64")));
    return buffer_1.Buffer.from(signature).toString("base64");
}
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
function createUuid() {
    const uuid = globalThis.crypto?.randomUUID?.();
    if (uuid) {
        return uuid;
    }
    return `beav3r-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
function buildQueryString(values) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(values)) {
        if (value) {
            params.set(key, value);
        }
    }
    const query = params.toString();
    return query ? `?${query}` : "";
}
//# sourceMappingURL=client.js.map