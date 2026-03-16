export type CanonicalValue = null | boolean | number | string | CanonicalValue[] | {
    [key: string]: CanonicalValue;
};
export declare function canonicalize(value: unknown): string;
//# sourceMappingURL=canonicalize.d.ts.map