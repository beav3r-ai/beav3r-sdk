import { z } from "zod";

export const actionAttributeValueSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);
export const actionAttributesSchema = z.record(z.string(), actionAttributeValueSchema).default({});

export const actionRequestSchema = z.object({
  actionId: z.string().min(1),
  agentId: z.string().min(1),
  actionType: z.string().min(1),
  payload: z.record(z.string(), z.unknown()),
  attributes: actionAttributesSchema,
  timestamp: z.number().int().nonnegative(),
  nonce: z.string().min(1),
  expiry: z.number().int().nonnegative()
});

export type ActionRequest = z.infer<typeof actionRequestSchema>;
export type ActionAttributes = z.infer<typeof actionAttributesSchema>;

export const actionStatusSchema = z.enum([
  "pending",
  "approved",
  "rejected",
  "expired",
  "executed",
  "denied"
]);

export type ActionStatus = z.infer<typeof actionStatusSchema>;
