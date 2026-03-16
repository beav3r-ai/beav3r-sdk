"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.policyRuleSchema = exports.policyConditionSchema = exports.policyEffectSchema = void 0;
const zod_1 = require("zod");
exports.policyEffectSchema = zod_1.z.enum(["allow", "require_approval", "deny"]);
exports.policyConditionSchema = zod_1.z.object({
    field: zod_1.z.string().min(1),
    operator: zod_1.z.enum(["gt", "gte", "lt", "lte", "eq"]),
    value: zod_1.z.union([zod_1.z.number(), zod_1.z.string(), zod_1.z.boolean()])
});
exports.policyRuleSchema = zod_1.z.object({
    id: zod_1.z.string().min(1),
    actionType: zod_1.z.string().min(1),
    effect: exports.policyEffectSchema,
    reason: zod_1.z.string().min(1),
    condition: exports.policyConditionSchema.optional()
});
//# sourceMappingURL=policy-rule.js.map