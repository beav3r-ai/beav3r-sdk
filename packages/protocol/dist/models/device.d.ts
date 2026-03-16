import { z } from "zod";
export declare const deviceSchema: z.ZodObject<{
    deviceId: z.ZodString;
    publicKey: z.ZodString;
    label: z.ZodString;
}, "strip", z.ZodTypeAny, {
    deviceId: string;
    publicKey: string;
    label: string;
}, {
    deviceId: string;
    publicKey: string;
    label: string;
}>;
export type DeviceInput = z.infer<typeof deviceSchema>;
export type DeviceRecord = DeviceInput & {
    createdAt: number;
};
//# sourceMappingURL=device.d.ts.map