import { z } from "zod";

export const policyEffectSchema = z.enum(["allow", "require_approval", "deny"]);
export type PolicyEffect = z.infer<typeof policyEffectSchema>;

export const policyConditionSchema = z.object({
  field: z.string().min(1),
  operator: z.enum(["gt", "gte", "lt", "lte", "eq"]),
  value: z.union([z.number(), z.string(), z.boolean()])
});

export const policyRuleSchema = z.object({
  id: z.string().min(1),
  actionType: z.string().min(1),
  effect: policyEffectSchema,
  reason: z.string().min(1),
  condition: policyConditionSchema.optional()
});

export type PolicyRule = z.infer<typeof policyRuleSchema>;
