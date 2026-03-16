import { z } from "zod";
export declare const approvalTokenSchema: z.ZodObject<{
    actionHash: z.ZodString;
    deviceId: z.ZodString;
    signature: z.ZodString;
    expiry: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    expiry: number;
    actionHash: string;
    deviceId: string;
    signature: string;
}, {
    expiry: number;
    actionHash: string;
    deviceId: string;
    signature: string;
}>;
export type ApprovalToken = z.infer<typeof approvalTokenSchema>;
export declare const approvalRejectSchema: z.ZodObject<{
    actionHash: z.ZodString;
    deviceId: z.ZodString;
}, "strip", z.ZodTypeAny, {
    actionHash: string;
    deviceId: string;
}, {
    actionHash: string;
    deviceId: string;
}>;
export type ApprovalReject = z.infer<typeof approvalRejectSchema>;
//# sourceMappingURL=approval-token.d.ts.map