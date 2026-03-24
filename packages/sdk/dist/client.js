"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BeaverDeniedError = exports.BeaverClient = exports.Beav3r = exports.Beav3rDeniedError = void 0;
const buffer_1 = require("buffer");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
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
            actionId: input.actionId ?? createUuid(),
            agentId: input.agentId ?? this.options.agentId ?? "agent_default",
            actionType: input.actionType,
            payload: input.payload,
            attributes: input.attributes ?? {},
            timestamp: input.timestamp ?? now,
            nonce: input.nonce ?? createUuid(),
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
            throw new Beav3rDeniedError(result.actionId, result.reason);
        }
        return result;
    }
    async getActionStatus(actionId) {
        return this.request(`/actions/${actionId}/status`);
    }
    async getAction(actionId) {
        return this.request(`/actions/${actionId}`);
    }
    async listPendingActions(options) {
        return this.request(`/actions/pending${buildQueryString({ deviceId: options?.deviceId })}`);
    }
    async listRecentActions(options) {
        return this.request(`/actions/recent${buildQueryString({ deviceId: options?.deviceId })}`);
    }
    async listPolicyRules(options) {
        return this.request(`/policy-rules${buildQueryString({ agentId: options?.agentId })}`);
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
            throw new Error(`Cannot reach Beav3r at ${this.options.baseUrl}. Make sure the server is running, bound to 0.0.0.0, and reachable from this machine. Original error: ${message}`);
        }
        const body = (await response.json());
        if (!response.ok) {
            throw new Error(body.error ?? `Request to ${url} failed with status ${response.status}`);
        }
        return body;
    }
}
exports.Beav3r = Beav3r;
exports.BeaverClient = Beav3r;
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