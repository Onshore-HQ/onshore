export interface VaultClientOptions {
    /** Base URL of your vault, for example https://vault.yourhost.ng */
    baseUrl: string;
    serviceAccountId: string;
    keyId: string;
    /** Base64 Ed25519 seed from `rv sa-keygen`. Keep it in your secret store. */
    privateKey: string;
    /** Attempts for retryable failures. Default 4. */
    maxAttempts?: number;
    /** Requests time out after this long. Default 10 seconds. */
    timeoutMs?: number;
    fetch?: typeof fetch;
}
export declare class VaultError extends Error {
    status: number;
    code: string;
    policy?: string | undefined;
    requestId?: string | undefined;
    constructor(status: number, code: string, message: string, policy?: string | undefined, requestId?: string | undefined);
}
export interface TokenizeItem {
    field: string;
    value: string;
    subject_ref?: string;
}
export interface TokenizeResult {
    index: number;
    token?: string;
    existing?: boolean;
    error?: {
        code: string;
        message: string;
    };
}
export interface DetokenizeResult {
    index: number;
    decision?: string;
    value?: string;
    policy?: string;
    error?: {
        code: string;
        message: string;
        policy?: string;
    };
}
/**
 * Checks a webhook from Onshore. Pass the body exactly as received, before any
 * JSON parsing, and the `x-rv-signature` header. During a secret rotation the header
 * holds two signatures, and either one is enough.
 */
export declare function verifyWebhook(secret: string, rawBody: string | Buffer, signatureHeader: string, opts?: {
    toleranceSeconds?: number;
    now?: number;
}): boolean;
export declare class VaultClient {
    private opts;
    private key;
    private token;
    private tokenExpiry;
    private fetchFn;
    private maxAttempts;
    private timeoutMs;
    constructor(opts: VaultClientOptions);
    private assertion;
    private bearer;
    private raw;
    private call;
    /** Stores values and returns tokens. Larger inputs are split into 500-item batches. */
    tokenize(vault: string, items: TokenizeItem[], opts?: {
        continueOnError?: boolean;
    }): Promise<TokenizeResult[]>;
    /**
     * Returns values as policy allows. Fails closed: when the vault cannot answer
     * this throws, and it never returns the token as if it were the value.
     */
    detokenize(vault: string, tokens: string[], purpose: string, opts?: {
        continueOnError?: boolean;
    }): Promise<DetokenizeResult[]>;
    insertRecord(vault: string, fields: Record<string, string>, subjectRef?: string): Promise<{
        id: string;
        tokens: Record<string, string>;
    }>;
    /** Finds a token without revealing a value. Rate-limited on the server. */
    lookup(vault: string, field: string, value: string): Promise<string>;
    /**
     * Mints a single-use token for a secure component in a browser. `collect` names fields;
     * `reveal` names tokens and needs a purpose. Call this from your server, never the browser.
     */
    createClientToken(vault: string, opts: {
        kind: "collect" | "reveal";
        origin: string;
        fields?: string[];
        tokens?: string[];
        purpose?: string;
        onBehalfOf?: string;
        subjectRef?: string;
        bindIp?: string;
        ttlSeconds?: number;
    }): Promise<{
        client_token: string;
        expires_at: string;
    }>;
    /** Custom entities apply when `vault` is named. `entities` limits to built-in or custom slugs. */
    /** Checks a batch before a job sends it somewhere Onshore cannot sit in the path. Only counts are kept. */
    checkFlow(vault: string, flow: string, text: string): Promise<{
        identifiers: number;
        tokens: number;
        clean: boolean;
        by_type: Record<string, number>;
    }>;
    detect(text: string, opts?: {
        tokenize?: boolean;
        vault?: string;
        entities?: string[];
        includeShadow?: boolean;
    }): Promise<{
        text?: string;
        entities: {
            type: string;
            start: number;
            end: number;
            score: number;
        }[];
    }>;
    /**
     * Runs a check in the country and returns only true or false, for example whether
     * a stored name matches one supplied. Needs the `compare` policy action.
     */
    residentCheck(vault: string, token: string, check: "equals" | "name_match" | "age_at_least" | "amount_at_least", arg: string, purpose: string): Promise<boolean>;
    eraseSubject(vault: string, subjectId: string, purpose: string): Promise<Record<string, unknown>>;
}
