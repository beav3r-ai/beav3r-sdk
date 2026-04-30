"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BeaverDeniedError = exports.BeaverClient = exports.Beav3r = exports.Beav3rDeniedError = void 0;
exports.computeOnchainActionHash = computeOnchainActionHash;
exports.computeOnchainAuthorizationDigest = computeOnchainAuthorizationDigest;
exports.verifyOnchainAuthorization = verifyOnchainAuthorization;
exports.prepareExecuteWithAuthCall = prepareExecuteWithAuthCall;
exports.encodeExecuteWithAuthCalldata = encodeExecuteWithAuthCalldata;
exports.prepareOnchainExecution = prepareOnchainExecution;
exports.toExactActionRequest = toExactActionRequest;
const buffer_1 = require("buffer");
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const sha3_1 = require("@noble/hashes/sha3");
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
    async getExecutionAuthorizationKeys() {
        this.requireAPIKey("getExecutionAuthorizationKeys");
        return this.request("/.well-known/execution-authorization-keys");
    }
    async authorizeOnchainAction(input) {
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
    async provisionOnchainUser(input) {
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
    async getOnchainAuthorization(authorizationId, options) {
        this.requireAPIKey("getOnchainAuthorization");
        const trimmedAuthorizationID = authorizationId.trim();
        if (!trimmedAuthorizationID) {
            throw new Error("getOnchainAuthorization requires a non-empty authorizationId");
        }
        const query = buildQueryString({ projectId: options?.projectId?.trim() });
        return this.request(`/onchain/actions/${encodeURIComponent(trimmedAuthorizationID)}${query}`);
    }
    async upsertOnchainAccountKey(input) {
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
    async listOnchainAccountKeys(account) {
        this.requireAPIKey("listOnchainAccountKeys");
        const trimmedAccount = account.trim();
        if (!trimmedAccount) {
            throw new Error("listOnchainAccountKeys requires a non-empty account");
        }
        return this.request(`/onchain/accounts/${encodeURIComponent(trimmedAccount)}/keys`);
    }
    async deleteOnchainAccountKey(account, keyId) {
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
    async listOnchainActors(projectId) {
        this.requireAPIKey("listOnchainActors");
        const trimmedProjectID = projectId.trim();
        if (!trimmedProjectID) {
            throw new Error("listOnchainActors requires a non-empty projectId");
        }
        return this.request(`/onchain/actors/${encodeURIComponent(trimmedProjectID)}`);
    }
    async getOnchainActor(projectId, actorId) {
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
    async createOnchainActor(input) {
        this.requireAPIKey("createOnchainActor");
        const payload = normalizeOnchainActorInput("createOnchainActor", input);
        return this.request(`/onchain/actors/${encodeURIComponent(payload.projectId)}`, {
            method: "POST",
            body: JSON.stringify(payload.body)
        });
    }
    async updateOnchainActor(input) {
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
    async deleteOnchainActor(projectId, actorId) {
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
    async registerOnchainActor(actor, options) {
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
function computeOnchainActionHash(input) {
    const account = normalizeAddress(input.account, "computeOnchainActionHash account");
    const to = normalizeAddress(input.to, "computeOnchainActionHash to");
    const executor = normalizeAddress(input.executor, "computeOnchainActionHash executor");
    const value = parseUintString(input.value, "computeOnchainActionHash value");
    const chainID = parseUintLike(input.chainId, "computeOnchainActionHash chainId");
    const nonce = parseUintLike(input.nonce, "computeOnchainActionHash nonce");
    const expiresAt = parseUintLike(input.expiresAt ?? 0, "computeOnchainActionHash expiresAt");
    const data = normalizeHex(input.data, "computeOnchainActionHash data");
    return hexlify(keccak256Bytes(concatBytes(wordFromAddress(account), wordFromAddress(to), wordFromBigInt(value), keccak256Bytes(hexToBytes(data)), wordFromBigInt(chainID), wordFromBigInt(nonce), wordFromBigInt(expiresAt), wordFromAddress(executor))));
}
function computeOnchainAuthorizationDigest(artifact) {
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
    const domainSeparator = keccak256Bytes(concatBytes(domainTypeHash, domainNameHash, domainVersionHash, wordFromBigInt(chainID), wordFromAddress(executor)));
    const structHash = keccak256Bytes(concatBytes(authTypeHash, hexToBytes(actionHash), wordFromAddress(account), wordFromAddress(executor), wordFromBigInt(chainID), wordFromBigInt(nonce), wordFromBigInt(expiresAt), keyIDHash));
    return hexlify(keccak256Bytes(concatBytes(new Uint8Array([0x19, 0x01]), domainSeparator, structHash)));
}
function verifyOnchainAuthorization(input) {
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
function prepareExecuteWithAuthCall(request, artifact) {
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
    const keyId = hexlify(normalizeBytes32OrHashKeyId(normalizeOnchainKeyId(artifact.payload.keyId, "prepareExecuteWithAuthCall keyId")));
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
function encodeExecuteWithAuthCalldata(input) {
    const selector = hexlify(keccak256Bytes(utf8Bytes("executeWithAuth(address,uint256,bytes,(bytes32,address,address,uint256,uint256,uint256,bytes32),bytes)"))).slice(0, 10);
    const dataBytes = hexToBytes(normalizeHex(input.data, "encodeExecuteWithAuthCalldata data"));
    const signatureBytes = hexToBytes(normalizeHex(input.signature, "encodeExecuteWithAuthCalldata signature"));
    const staticWords = 11n;
    const staticLength = staticWords * 32n;
    const dataOffset = staticLength;
    const dataTail = encodeDynamicBytes(dataBytes);
    const signatureOffset = staticLength + BigInt(dataTail.length);
    const signatureTail = encodeDynamicBytes(signatureBytes);
    const args = concatBytes(wordFromAddress(input.to), wordFromBigInt(input.value), wordFromBigInt(dataOffset), hexToBytes(normalizeBytes32(input.auth.actionHash, "encodeExecuteWithAuthCalldata auth.actionHash")), wordFromAddress(input.auth.account), wordFromAddress(input.auth.executor), wordFromBigInt(input.auth.chainId), wordFromBigInt(input.auth.nonce), wordFromBigInt(input.auth.expiresAt), hexToBytes(normalizeBytes32(input.auth.keyId, "encodeExecuteWithAuthCalldata auth.keyId")), wordFromBigInt(signatureOffset), dataTail, signatureTail);
    return `${selector}${toHexNoPrefix(args)}`;
}
function prepareOnchainExecution(input) {
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
function normalizeOnchainActorInput(methodName, input) {
    const projectId = input.projectId?.trim() ?? "";
    const type = input.type?.trim();
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
function parseUintString(value, field) {
    const text = normalizeNonEmptyString(value, field);
    if (!/^\d+$/.test(text)) {
        throw new Error(`${field} must be a base-10 unsigned integer string`);
    }
    return BigInt(text);
}
function parseUintLike(value, field) {
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
function toSafeJSONUint(value, field) {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`${field} exceeds Number.MAX_SAFE_INTEGER and cannot be encoded in JSON number safely`);
    }
    return Number(value);
}
function normalizeOnchainKeyId(value, field) {
    return normalizeNonEmptyString(value, field);
}
function normalizeBytes32OrHashKeyId(keyId) {
    if (/^0x[0-9a-f]{64}$/i.test(keyId)) {
        return hexToBytes(keyId.toLowerCase());
    }
    return keccak256Bytes(utf8Bytes(keyId));
}
function normalizeNonEmptyString(value, field) {
    const text = value?.trim();
    if (!text) {
        throw new Error(`${field} is required`);
    }
    return text;
}
function normalizeHex(value, field) {
    const text = normalizeNonEmptyString(value, field).toLowerCase();
    if (!/^0x[0-9a-f]*$/.test(text)) {
        throw new Error(`${field} must be a valid 0x-prefixed hex string`);
    }
    if ((text.length - 2) % 2 !== 0) {
        throw new Error(`${field} must contain an even number of hex characters`);
    }
    return text;
}
function normalizeBytes32(value, field) {
    const text = normalizeHex(value, field);
    if (text.length !== 66) {
        throw new Error(`${field} must be a 32-byte hex string`);
    }
    return text;
}
function normalizeAddress(value, field) {
    const text = normalizeHex(value, field);
    if (text.length !== 42) {
        throw new Error(`${field} must be a 20-byte address`);
    }
    return text;
}
function hexToBytes(hex) {
    return Uint8Array.from(buffer_1.Buffer.from(hex.slice(2), "hex"));
}
function utf8Bytes(value) {
    return Uint8Array.from(buffer_1.Buffer.from(value, "utf8"));
}
function hexlify(bytes) {
    return `0x${toHexNoPrefix(bytes)}`;
}
function toHexNoPrefix(bytes) {
    return buffer_1.Buffer.from(bytes).toString("hex");
}
function keccak256Bytes(data) {
    return Uint8Array.from((0, sha3_1.keccak_256)(data));
}
function concatBytes(...parts) {
    const totalLength = parts.reduce((sum, item) => sum + item.length, 0);
    const output = new Uint8Array(totalLength);
    let offset = 0;
    for (const item of parts) {
        output.set(item, offset);
        offset += item.length;
    }
    return output;
}
function wordFromBigInt(value) {
    if (value < 0n) {
        throw new Error("wordFromBigInt value must be non-negative");
    }
    const max = (1n << 256n) - 1n;
    if (value > max) {
        throw new Error("wordFromBigInt value exceeds uint256 range");
    }
    return hexToBytes(`0x${value.toString(16).padStart(64, "0")}`);
}
function wordFromAddress(address) {
    return hexToBytes(`0x${normalizeAddress(address, "address").slice(2).padStart(64, "0")}`);
}
function encodeDynamicBytes(value) {
    const lengthWord = wordFromBigInt(BigInt(value.length));
    const padLength = (32 - (value.length % 32)) % 32;
    return concatBytes(lengthWord, value, new Uint8Array(padLength));
}
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