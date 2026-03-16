"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.canonicalize = canonicalize;
function sortValue(value) {
    if (value === null) {
        return null;
    }
    if (Array.isArray(value)) {
        return value.map(sortValue);
    }
    if (typeof value === "object") {
        const entries = Object.entries(value).sort(([a], [b]) => a.localeCompare(b));
        const sorted = {};
        for (const [key, nested] of entries) {
            sorted[key] = sortValue(nested);
        }
        return sorted;
    }
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
        return value;
    }
    return String(value);
}
function canonicalize(value) {
    return JSON.stringify(sortValue(value));
}
//# sourceMappingURL=canonicalize.js.map