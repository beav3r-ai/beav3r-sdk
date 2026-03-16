"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deviceSchema = void 0;
const zod_1 = require("zod");
exports.deviceSchema = zod_1.z.object({
    deviceId: zod_1.z.string().min(1),
    publicKey: zod_1.z.string().min(1),
    label: zod_1.z.string().min(1)
});
//# sourceMappingURL=device.js.map