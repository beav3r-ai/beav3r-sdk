import { z } from "zod";

export const deviceSchema = z.object({
  deviceId: z.string().min(1),
  publicKey: z.string().min(1),
  label: z.string().min(1)
});

export type DeviceInput = z.infer<typeof deviceSchema>;

export type DeviceRecord = DeviceInput & {
  createdAt: number;
};
