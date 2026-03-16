"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.approvalRejectSchema = exports.approvalTokenSchema = void 0;
const zod_1 = require("zod");
exports.approvalTokenSchema = zod_1.z.object({
    actionHash: zod_1.z.string().min(1),
    deviceId: zod_1.z.string().min(1),
    signature: zod_1.z.string().min(1),
    expiry: zod_1.z.number().int().nonnegative()
});
exports.approvalRejectSchema = zod_1.z.object({
    actionHash: zod_1.z.string().min(1),
    deviceId: zod_1.z.string().min(1)
});
//# sourceMappingURL=approval-token.js.map