import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";

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

  return bytesToHex(sha256(utf8ToBytes(input)));
}
