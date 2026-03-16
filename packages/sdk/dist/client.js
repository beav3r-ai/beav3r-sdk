"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BeaverClient = exports.BeaverDeniedError = void 0;
const node_crypto_1 = require("node:crypto");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
class BeaverDeniedError extends Error {
    actionId;
    constructor(actionId, reason) {
        super(reason ?? `Action ${actionId} was denied by Beaver`);
        this.name = "BeaverDeniedError";
        this.actionId = actionId;
    }
}
exports.BeaverDeniedError = BeaverDeniedError;
class BeaverClient {
    options;
    fetchImpl;
    constructor(options) {
        this.options = options;
        this.fetchImpl = options.fetchImpl ?? fetch;
    }
    async requestAction(input) {
        const action = this.buildAction(input);
        return this.request("/actions/request", {
            method: "POST",
            body: JSON.stringify(action)
        });
    }
    async relayAction(input) {
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
    buildAction(input) {
        const now = Math.floor(Date.now() / 1000);
        return {
            actionId: input.actionId ?? (0, node_crypto_1.randomUUID)(),
            agentId: input.agentId ?? this.options.agentId ?? "agent_default",
            actionType: input.actionType,
            payload: input.payload,
            attributes: input.attributes ?? {},
            timestamp: input.timestamp ?? now,
            nonce: input.nonce ?? (0, node_crypto_1.randomUUID)(),
            expiry: input.expiry ?? now + (this.options.defaultExpirySeconds ?? 60)
        };
    }
    async guardAndWait(input, options) {
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
    async guardOrThrow(input) {
        const result = await this.guard(input);
        if (result.status === "denied") {
            throw new BeaverDeniedError(result.actionId, result.reason);
        }
        return result;
    }
    async getActionStatus(actionId) {
        return this.request(`/actions/${actionId}/status`);
    }
    async getAction(actionId) {
        return this.request(`/actions/${actionId}`);
    }
    async listPendingActions() {
        return this.request("/actions/pending");
    }
    async listRecentActions() {
        return this.request("/actions/recent");
    }
    async listPolicyRules() {
        return this.request("/policy-rules");
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
        const message = Buffer.from(challenge.challenge, "utf8");
        const signature = tweetnacl_1.default.sign.detached(message, new Uint8Array(Buffer.from(device.secretKeyBase64, "base64")));
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
    async submitApproval(token) {
        return this.request("/approvals/submit", {
            method: "POST",
            body: JSON.stringify(token)
        });
    }
    async rejectApproval(rejection) {
        return this.request("/approvals/reject", {
            method: "POST",
            body: JSON.stringify(rejection)
        });
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
            throw new Error(`Cannot reach Beaver at ${this.options.baseUrl}. Make sure the server is running, bound to 0.0.0.0, and reachable from this machine. Original error: ${message}`);
        }
        const body = (await response.json());
        if (!response.ok) {
            throw new Error(body.error ?? `Request to ${url} failed with status ${response.status}`);
        }
        return body;
    }
}
exports.BeaverClient = BeaverClient;
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
//# sourceMappingURL=client.js.map