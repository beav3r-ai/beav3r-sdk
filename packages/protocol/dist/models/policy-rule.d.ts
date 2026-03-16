import { z } from "zod";
export declare const policyEffectSchema: z.ZodEnum<["allow", "require_approval", "deny"]>;
export type PolicyEffect = z.infer<typeof policyEffectSchema>;
export declare const policyConditionSchema: z.ZodObject<{
    field: z.ZodString;
    operator: z.ZodEnum<["gt", "gte", "lt", "lte", "eq"]>;
    value: z.ZodUnion<[z.ZodNumber, z.ZodString, z.ZodBoolean]>;
}, "strip", z.ZodTypeAny, {
    value: string | number | boolean;
    field: string;
    operator: "gt" | "gte" | "lt" | "lte" | "eq";
}, {
    value: string | number | boolean;
    field: string;
    operator: "gt" | "gte" | "lt" | "lte" | "eq";
}>;
export declare const policyRuleSchema: z.ZodObject<{
    id: z.ZodString;
    actionType: z.ZodString;
    effect: z.ZodEnum<["allow", "require_approval", "deny"]>;
    reason: z.ZodString;
    condition: z.ZodOptional<z.ZodObject<{
        field: z.ZodString;
        operator: z.ZodEnum<["gt", "gte", "lt", "lte", "eq"]>;
        value: z.ZodUnion<[z.ZodNumber, z.ZodString, z.ZodBoolean]>;
    }, "strip", z.ZodTypeAny, {
        value: string | number | boolean;
        field: string;
        operator: "gt" | "gte" | "lt" | "lte" | "eq";
    }, {
        value: string | number | boolean;
        field: string;
        operator: "gt" | "gte" | "lt" | "lte" | "eq";
    }>>;
}, "strip", z.ZodTypeAny, {
    actionType: string;
    id: string;
    effect: "allow" | "require_approval" | "deny";
    reason: string;
    condition?: {
        value: string | number | boolean;
        field: string;
        operator: "gt" | "gte" | "lt" | "lte" | "eq";
    } | undefined;
}, {
    actionType: string;
    id: string;
    effect: "allow" | "require_approval" | "deny";
    reason: string;
    condition?: {
        value: string | number | boolean;
        field: string;
        operator: "gt" | "gte" | "lt" | "lte" | "eq";
    } | undefined;
}>;
export type PolicyRule = z.infer<typeof policyRuleSchema>;
//# sourceMappingURL=policy-rule.d.ts.map