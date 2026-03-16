import type { ActionStatus } from "./action-request";
export type QueueItem = {
    actionId: string;
    actionHash: string;
    status: ActionStatus;
    createdAt: number;
    updatedAt: number;
};
//# sourceMappingURL=queue-item.d.ts.map