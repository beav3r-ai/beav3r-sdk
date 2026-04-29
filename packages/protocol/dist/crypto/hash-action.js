"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashAction = hashAction;
const sha2_1 = require("@noble/hashes/sha2");
const utils_1 = require("@noble/hashes/utils");
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
    return (0, utils_1.bytesToHex)((0, sha2_1.sha256)((0, utils_1.utf8ToBytes)(input)));
}
//# sourceMappingURL=hash-action.js.map