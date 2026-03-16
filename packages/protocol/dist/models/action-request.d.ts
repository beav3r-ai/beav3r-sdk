import { z } from "zod";
export declare const actionAttributeValueSchema: z.ZodUnion<[z.ZodString, z.ZodNumber, z.ZodBoolean, z.ZodNull]>;
export declare const actionAttributesSchema: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodUnion<[z.ZodString, z.ZodNumber, z.ZodBoolean, z.ZodNull]>>>;
export declare const actionRequestSchema: z.ZodObject<{
    actionId: z.ZodString;
    agentId: z.ZodString;
    actionType: z.ZodString;
    payload: z.ZodRecord<z.ZodString, z.ZodUnknown>;
    attributes: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodUnion<[z.ZodString, z.ZodNumber, z.ZodBoolean, z.ZodNull]>>>;
    timestamp: z.ZodNumber;
    nonce: z.ZodString;
    expiry: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    actionId: string;
    agentId: string;
    actionType: string;
    payload: Record<string, unknown>;
    attributes: Record<string, string | number | boolean | null>;
    timestamp: number;
    nonce: string;
    expiry: number;
}, {
    actionId: string;
    agentId: string;
    actionType: string;
    payload: Record<string, unknown>;
    timestamp: number;
    nonce: string;
    expiry: number;
    attributes?: Record<string, string | number | boolean | null> | undefined;
}>;
export type ActionRequest = z.infer<typeof actionRequestSchema>;
export type ActionAttributes = z.infer<typeof actionAttributesSchema>;
export declare const actionStatusSchema: z.ZodEnum<["pending", "approved", "rejected", "expired", "executed", "denied"]>;
export type ActionStatus = z.infer<typeof actionStatusSchema>;
//# sourceMappingURL=action-request.d.ts.map