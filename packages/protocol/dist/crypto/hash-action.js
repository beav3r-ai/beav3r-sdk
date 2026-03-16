"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashAction = hashAction;
const node_crypto_1 = require("node:crypto");
const canonicalize_1 = require("./canonicalize");
function hashAction(action) {
    const canonicalPayload = (0, canonicalize_1.canonicalize)(action.payload);
    const canonicalAttributes = (0, canonicalize_1.canonicalize)(action.attributes);
    const input = [
        action.actionId,
        action.agentId,
        action.actionType,
        canonicalPayload,
        canonicalAttributes,
        String(action.timestamp),
        action.nonce,
        String(action.expiry)
    ].join("");
    return (0, node_crypto_1.createHash)("sha256").update(input, "utf8").digest("hex");
}
//# sourceMappingURL=hash-action.js.map