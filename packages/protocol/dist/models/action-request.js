"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.actionStatusSchema = exports.actionRequestSchema = exports.actionAttributesSchema = exports.actionAttributeValueSchema = void 0;
const zod_1 = require("zod");
exports.actionAttributeValueSchema = zod_1.z.union([zod_1.z.string(), zod_1.z.number(), zod_1.z.boolean(), zod_1.z.null()]);
exports.actionAttributesSchema = zod_1.z.record(zod_1.z.string(), exports.actionAttributeValueSchema).default({});
exports.actionRequestSchema = zod_1.z.object({
    actionId: zod_1.z.string().min(1),
    agentId: zod_1.z.string().min(1),
    actionType: zod_1.z.string().min(1),
    payload: zod_1.z.record(zod_1.z.string(), zod_1.z.unknown()),
    attributes: exports.actionAttributesSchema,
    timestamp: zod_1.z.number().int().nonnegative(),
    nonce: zod_1.z.string().min(1),
    expiry: zod_1.z.number().int().nonnegative()
});
exports.actionStatusSchema = zod_1.z.enum([
    "pending",
    "approved",
    "rejected",
    "expired",
    "executed",
    "denied"
]);
//# sourceMappingURL=action-request.js.map