import { createHash } from "node:crypto";

import type { ActionRequest } from "../models/action-request";
import { canonicalize } from "./canonicalize";

export function hashAction(action: ActionRequest): string {
  const canonicalPayload = canonicalize(action.payload);
  const canonicalAttributes = canonicalize(action.attributes);
  const input = [
    action.actionId,
    action.agentId,
    action.actionType,
    canonicalPayload,
    canonicalAttributes,
    String(action.timestamp),
    action.nonce,
    String(action.expiry)
  ].join("");

  return createHash("sha256").update(input, "utf8").digest("hex");
}
