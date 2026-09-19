export interface OperationDescription {
  name: string;
  permission?: string;
  assurance?: number;
  auth: "none" | "required";
  mutating: boolean;
  maximum_body_bytes: number;
  maximum_response_bytes: number;
}

export interface CatalogResponse { api_version: string; operations: OperationDescription[] }
export interface ResponseEnvelope<T> { api_version: string; request_id: string; operation: string; result: T; generation?: number; completed_at: string }
export interface Problem { type: string; title: string; status: number; code: string; detail?: string; request_id?: string; retry_after_seconds?: number }

export class APIProblem extends Error {
  readonly problem: Problem;
  constructor(problem: Problem) { super(problem.detail || problem.title); this.name = "APIProblem"; this.problem = problem; }
}

const encoder = new TextEncoder();

export class APIClient {
  private csrfToken = "";
  private catalog = new Map<string, OperationDescription>();
  private readonly baseURL: string;

  constructor(baseURL = "") { this.baseURL = baseURL.replace(/\/$/, ""); }

  async loadCatalog(signal?: AbortSignal): Promise<OperationDescription[]> {
    const response = await fetch(`${this.baseURL}/api/v1/catalog`, { credentials: "same-origin", headers: { Accept: "application/json" }, signal: signal ?? null });
    if (!response.ok) throw await this.problem(response);
    const body = await response.json() as CatalogResponse;
    if (body.api_version !== "panel.cyberpanel.io/v1" || !Array.isArray(body.operations)) throw new Error("The API catalog is incompatible with this console.");
    this.catalog.clear();
    body.operations.forEach((operation) => this.catalog.set(operation.name, operation));
    return body.operations;
  }

  operation(name: string): OperationDescription | undefined { return this.catalog.get(name); }
  available(name: string): boolean { return this.catalog.has(name); }

  async invoke<T>(operation: string, options: { tenantId?: string | undefined; resourceId?: string | undefined; expectedGeneration?: number | undefined; payload?: unknown; idempotencyKey?: string; signal?: AbortSignal | undefined } = {}): Promise<ResponseEnvelope<T>> {
    const requestID = opaqueID("req");
    const description = this.catalog.get(operation);
    if (!description) throw new Error(`Operation ${operation} is not available on this node.`);
    const headers = new Headers({ "Content-Type": "application/json", Accept: "application/json", "X-Request-ID": requestID });
    if (description.mutating) {
      headers.set("Idempotency-Key", options.idempotencyKey || opaqueID("idem"));
      if (this.csrfToken) headers.set("X-CSRF-Token", this.csrfToken);
    }
    const response = await fetch(`${this.baseURL}/api/v1/operations`, {
      method: "POST", credentials: "same-origin", headers, signal: options.signal ?? null,
      body: JSON.stringify({ api_version: "panel.cyberpanel.io/v1", request_id: requestID, operation, tenant_id: options.tenantId || undefined, resource_id: options.resourceId || undefined, expected_generation: options.expectedGeneration || undefined, payload: options.payload ?? {} })
    });
    const deliveredCSRF = response.headers.get("X-CSRF-Token");
    if (deliveredCSRF) this.csrfToken = deliveredCSRF;
    if (!response.ok) throw await this.problem(response);
    return await response.json() as ResponseEnvelope<T>;
  }

  async invokePublic<T>(operation: string, payload: unknown, signal?: AbortSignal): Promise<ResponseEnvelope<T>> {
    const description = this.catalog.get(operation);
    if (!description || description.auth !== "none") throw new Error(`Public operation ${operation} is not available on this node.`);
    const requestID = opaqueID("req");
    const headers = new Headers({ "Content-Type": "application/json", Accept: "application/json", "X-Request-ID": requestID });
    if (description.mutating) headers.set("Idempotency-Key", opaqueID("idem"));
    const response = await fetch(`${this.baseURL}/api/v1/operations`, {
      method: "POST", credentials: "omit", headers, signal: signal ?? null,
      body: JSON.stringify({ api_version:"panel.cyberpanel.io/v1", request_id:requestID, operation, payload })
    });
    if (!response.ok) throw await this.problem(response);
    return await response.json() as ResponseEnvelope<T>;
  }

  async exchangeContainerExec<T>(grantID: string, token: string, signal?: AbortSignal): Promise<ResponseEnvelope<T>> {
    if (!this.catalog.has("container.exec.exchange")) throw new Error("Container exec exchange is not available on this node.");
    const requestID = opaqueID("req");
    const response = await fetch(`${this.baseURL}/api/v1/containers/exec/exchange`, {
      method: "POST", credentials: "omit", signal: signal ?? null,
      headers: { "Content-Type": "application/json", Accept: "application/json", "X-Request-ID": requestID },
      body: JSON.stringify({ grant_id: grantID, token })
    });
    if (!response.ok) throw await this.problem(response);
    return await response.json() as ResponseEnvelope<T>;
  }

  setCSRF(token: string): void { this.csrfToken = token; }
  clearSession(): void { this.csrfToken = ""; }

  private async problem(response: Response): Promise<APIProblem> {
    try { return new APIProblem(await response.json() as Problem); }
    catch { return new APIProblem({ type: "about:blank", title: "Request failed", status: response.status, code: "http_error" }); }
  }
}

function opaqueID(prefix: string): string {
  const bytes = new Uint8Array(24); crypto.getRandomValues(bytes);
  const value = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${prefix}_${value}`;
}

export function oneTimeToken(): string {
  const bytes = new Uint8Array(32); crypto.getRandomValues(bytes);
  let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function approximatePayloadBytes(value: unknown): number { return encoder.encode(JSON.stringify(value)).byteLength; }
