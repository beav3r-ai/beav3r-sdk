import { z } from "zod";

export const approvalTokenSchema = z.object({
  actionHash: z.string().min(1),
  deviceId: z.string().min(1),
  signature: z.string().min(1),
  expiry: z.number().int().nonnegative()
});

export type ApprovalToken = z.infer<typeof approvalTokenSchema>;

export const approvalRejectSchema = z.object({
  actionHash: z.string().min(1),
  deviceId: z.string().min(1),
  signature: z.string().min(1),
  expiry: z.number().int().nonnegative()
});

export type ApprovalReject = z.infer<typeof approvalRejectSchema>;
