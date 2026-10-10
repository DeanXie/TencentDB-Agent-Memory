import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { IMemoryStore, L1RecordRow } from "../core/store/types.js";
import { VectorStore } from "../core/store/sqlite.js";
import * as gatewayEnv from "../utils/env.js";
import { TdaiGateway } from "./server.js";

const CMG_VECTOR_PATH = "F:\\AI\\CodexMemoryGovernance\\tests\\fixtures\\explicit-memory-contract-vectors.json";
const API_KEY = "synthetic-direct-writer-key";
const AUTHORITY = Object.freeze({
  serviceId: "memory-v1-10",
  projectId: "project:ef611ea17d747c59",
  scope: "project",
  scopeId: "cmg-v1-10-run-20260926-01a0cf43",
  isolation: Object.freeze({
    teamId: "codex-memory-governance-v1-10",
    userId: "v1-10-user",
    agentId: "codex-desktop-v1-10",
  }),
});

function stable(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stable(record[key])}`).join(",")}}`;
}

function digest(domain: string, value: unknown): string {
  return `sha256:${createHash("sha256").update(`${domain}\0${stable(value)}`, "utf8").digest("hex")}`;
}

function without(value: Record<string, unknown>, key: string): Record<string, unknown> {
  const copy = { ...value };
  delete copy[key];
  return copy;
}

function directFixture(): any {
  const vector = JSON.parse(readFileSync(CMG_VECTOR_PATH, "utf8")).vectors[0];
  return structuredClone({ admission: vector.admission, record: vector.writePayload });
}

function legacyFixture(): any {
  const body = {
    content: "Preserve the reviewed legacy contract.", memory_kind: "architecture_decision",
    scope: "project", scope_id: "legacy-project", allowed_project_ids: [], status: "current",
    candidate_digest: `sha256:${"a".repeat(64)}`, candidate_version: 1,
    expected_version: null, supersedes: [],
  };
  const record = { memory_id: `wm_sha256_${digest("cmg/working-memory-write-payload/v1/identity", body).slice(7)}`, ...body };
  const admission: any = {
    contract: "cmg/human-approved-memory-admission/v1",
    candidate_id: `wmc_sha256_${"b".repeat(64)}`, candidate_version: 1,
    candidate_digest: record.candidate_digest, governance_digest: `sha256:${"c".repeat(64)}`,
    approval_request_id: `wmar_sha256_${"d".repeat(64)}`, approval_request_digest: `sha256:${"e".repeat(64)}`,
    approval_decision_digest: `sha256:${"f".repeat(64)}`, scope: record.scope, scope_id: record.scope_id,
    allowed_project_ids: [], write_payload_digest: digest("cmg/working-memory-write-payload/v1/snapshot", record),
    idempotency_key: "", admitted: true, reasons: [], evaluated_at: "2026-10-07T01:00:00.000Z",
  };
  admission.idempotency_key = digest("cmg/human-approved-memory-admission/v1/idempotency", {
    candidate_id: admission.candidate_id, candidate_version: admission.candidate_version,
    candidate_digest: admission.candidate_digest, governance_digest: admission.governance_digest,
    approval_request_id: admission.approval_request_id, approval_request_digest: admission.approval_request_digest,
    approval_decision_digest: admission.approval_decision_digest, scope: admission.scope, scope_id: admission.scope_id,
    allowed_project_ids: admission.allowed_project_ids, write_payload_digest: admission.write_payload_digest,
  });
  admission.admission_digest = digest("cmg/human-approved-memory-admission/v1/admission", admission);
  return { admission, record };
}

function rehashDirectAdmission(value: any): any {
  const admission = structuredClone(value);
  admission.safety_digest = digest("cmg/human-approved-memory-admission/v2/safety", admission.safety);
  admission.idempotency_key = digest("cmg/human-approved-memory-admission/v2/idempotency", {
    command_id: admission.command_id,
    source_digest: admission.source_digest,
    authorization_digest: admission.authorization_digest,
    scope: admission.scope,
    scope_id: admission.scope_id,
    allowed_project_ids: admission.allowed_project_ids,
    safety_digest: admission.safety_digest,
    write_payload_digest: admission.write_payload_digest,
  });
  admission.admission_digest = digest("cmg/human-approved-memory-admission/v2/admission",
    without(admission, "admission_digest"));
  return admission;
}

function rehashDirectRequest(value: any): any {
  const request = structuredClone(value);
  request.record.memory_id = `wm_sha256_${digest("cmg/working-memory-write-payload/v2/identity",
    without(request.record, "memory_id")).slice(7)}`;
  request.admission.write_payload_digest = digest("cmg/working-memory-write-payload/v2/snapshot", request.record);
  request.admission = rehashDirectAdmission(request.admission);
  return request;
}

type TestStore = {
  store: IMemoryStore;
  calls: () => number;
  rows: L1RecordRow[];
};

function testStore(): TestStore {
  const rows: L1RecordRow[] = [];
  let calls = 0;
  const store = {
    readL1RecordExact: async (recordId: string) => {
      calls += 1;
      const matches = rows.filter((row) => row.record_id === recordId);
      return matches.length === 1 ? { status: "found" as const, row: matches[0] } :
        matches.length === 0 ? { status: "not_found" as const } : { status: "read_failed" as const };
    },
    queryL1Records: async () => { calls += 1; return rows; },
    upsertL1: async (record: any) => {
      calls += 1;
      rows.push({
        record_id: record.id, content: record.content, type: record.type, priority: record.priority,
        scene_name: record.scene_name, session_key: record.sessionKey, session_id: record.sessionId,
        team_id: record.teamId, task_id: record.taskId ?? "", user_id: record.userId, agent_id: record.agentId,
        version: record.version, timestamp_str: record.timestamps[0], timestamp_start: "", timestamp_end: "",
        created_time: record.createdAt, updated_time: record.updatedAt, metadata_json: JSON.stringify(record.metadata),
      });
      return true;
    },
  } as unknown as IMemoryStore;
  return { store, calls: () => calls, rows };
}

type Harness = {
  trackStore: (store: VectorStore) => void;
  baseUrl: string;
  requests: Array<{ method: string | undefined; path: string | undefined; status?: number }>;
  post: (path: string, body: unknown, headers?: Record<string, string>) => Promise<{ status: number; text: string; json: any }>;
  get: (path: string, headers?: Record<string, string>) => Promise<{ status: number; text: string; json: any }>;
  store: TestStore;
  storeResolutions: () => number;
  logs: string[];
  close: () => Promise<void>;
};

type HarnessOptions = { apiKey?: string; authority?: unknown; getStore?: () => IMemoryStore; dataDir?: string };

const activeResources: Array<{ server: Server; stores: Set<VectorStore>; initializeCalls: () => number }> = [];
const completedResourceAudits: Array<{ servers: number; sqliteStores: number }> = [];
function assertResourcesClosed() {
  for (const resource of activeResources) {
    expect(resource.server.listening).toBe(false);
    expect(resource.initializeCalls()).toBe(0);
    for (const store of resource.stores) {
      const open = store.getRawDb().isOpen;
      expect(typeof open).toBe("boolean");
      expect(open).toBe(false);
    }
  }
}
// This applies to E1–E7 and the original authority tests, after their own
// finally blocks. It checks real resource state, not calls to a cleanup mock.
afterEach(() => {
  assertResourcesClosed();
  completedResourceAudits.push({ servers: activeResources.length,
    sqliteStores: activeResources.reduce((count, resource) => count + resource.stores.size, 0) });
  activeResources.length = 0;
});

async function harness(options: HarnessOptions = {}): Promise<Harness> {
  const trackedStore = testStore();
  const requests: Harness["requests"] = [];
  let storeResolutions = 0;
  const logs: string[] = [];
  const gateway = new TdaiGateway({
    deployMode: "standalone",
    server: {
      host: "127.0.0.1", port: 0, corsOrigins: [], apiKey: options.apiKey,
      directWriterAuthority: options.authority,
    } as any,
    data: { baseDir: options.dataDir ?? join(tmpdir(), "memorycore-direct-authority-test") } as any,
  });
  const core = (gateway as any).core;
  const stores = new Set<VectorStore>();
  let initializeCalls = 0;
  const actualInitialize = core.initialize.bind(core);
  vi.spyOn(core, "initialize").mockImplementation(async (...args: unknown[]) => {
    initializeCalls += 1;
    return actualInitialize(...args);
  });
  core.getVectorStore = () => {
    storeResolutions += 1;
    const store = options.getStore ? options.getStore() : trackedStore.store;
    if (store instanceof VectorStore) stores.add(store);
    return store;
  };
  core.getEmbeddingService = () => undefined;
  core.getStorage = () => undefined;
  (gateway as any).logger = {
    info: (...args: unknown[]) => logs.push(args.join(" ")),
    warn: (...args: unknown[]) => logs.push(args.join(" ")),
    error: (...args: unknown[]) => logs.push(args.join(" ")),
    debug: (...args: unknown[]) => logs.push(args.join(" ")),
  };

  const server: Server = createServer((req, res) => {
    const observation = { method: req.method, path: req.url, status: undefined as number | undefined };
    requests.push(observation);
    res.once("finish", () => { observation.status = res.statusCode; });
    void (gateway as any).handleRequest(req, res).catch((error: unknown) => {
      res.statusCode = 500;
      res.end(error instanceof Error ? error.message : "test server error");
    });
  });
  activeResources.push({ server, stores, initializeCalls: () => initializeCalls });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test listener unavailable");
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const send = async (method: string, path: string, body: unknown, headers: Record<string, string> = {}) => {
    const response = await fetch(`${baseUrl}${path}`, {
      method,
      headers: { ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    let json: any = null;
    try { json = JSON.parse(text); } catch { /* non-JSON response */ }
    return { status: response.status, text, json };
  };
  return {
    trackStore: store => { stores.add(store); },
    baseUrl,
    requests,
    post: (path, body, headers) => send("POST", path, body, headers),
    get: (path, headers) => send("GET", path, undefined, headers),
    store: trackedStore,
    storeResolutions: () => storeResolutions,
    logs,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

function headers(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    authorization: `Bearer ${API_KEY}`,
    "x-tdai-service-id": AUTHORITY.serviceId,
    "x-tdai-team-id": AUTHORITY.isolation.teamId,
    "x-tdai-user-id": AUTHORITY.isolation.userId,
    "x-tdai-agent-id": AUTHORITY.isolation.agentId,
    "x-tdai-session-id": "vector-session",
    ...overrides,
  };
}

async function withHarness<T>(options: HarnessOptions, run: (value: Harness) => Promise<T>): Promise<T> {
  const value = await harness(options);
  try { return await run(value); } finally { await value.close(); }
}

// Reuse E1's existing HTTP harness and CMG fixture contracts. Faults use the
// injected exact reader or this fixture's SQLite rows; normal IO stays real.
async function withCmgSqliteScenario(run: (context: any) => Promise<void>) {
  const loadCmg = (path: string) => import(/* @vite-ignore */ pathToFileURL(join("F:\\AI\\CodexMemoryGovernance", path)).href);
  const dependencyPaths = ["tests/helpers/explicit-memory-command-fixture.js", "src/v1/user-memory-command-source.js",
    "src/v1/product-runtime-compatibility.js", "src/v1/human-memory-approval.js", "src/v1/human-approved-admission.js",
    "src/v1/explicit-memory-command-store.js", "src/v1/explicit-memory-command-flow.js", "src/integration/tencentdb-client.js"];
  const [fixtureModule, sourceModule, runtimeModule, approvalModule, admissionModule, storeModule, flowModule, clientModule] =
    await Promise.all(dependencyPaths.map(loadCmg));
  const root = await mkdtemp(join(tmpdir(), "memorycore-cmg-e234-"));
  expect(relative(tmpdir(), root).startsWith("..")).toBe(false);
  const cleanup: Array<() => Promise<void>> = [];
  let sqlite: VectorStore | undefined;
  let app: Harness | undefined;
  try {
    const fixture = await fixtureModule.explicitMemoryCommandFixture({ after: (fn: () => Promise<void>) => cleanup.push(fn) });
    expect(fixture.fields.runtime_implementation.desktop_package_identity).toBe("OpenAI.Codex_test");
    expect(JSON.stringify(fixture.compatibilityAssessment).includes("fixture_only_verified")).toBe(true);
    let validations = 0;
    const revalidate = async (_previous?: unknown, options: { signal?: AbortSignal } = {}) => {
      validations += 1;
      return sourceModule.verifyUserMemoryCommandSource({ hookInput: fixture.hookInput,
        expectedWorkspace: fixture.projectIdentity.workspace, projectIdentity: fixture.projectIdentity,
        referenceFingerprint: fixture.referenceFingerprint, compatibilityAssessment: fixture.compatibilityAssessment,
        rolloutResolver: fixture.resolver, expectedHookScript: fixture.expectedHookScript, signal: options.signal }, {
        verifyCapability: (assessment: unknown, capability: string) => runtimeModule.gateProductRuntimeCapability(assessment, capability),
        verifyCurrentRuntime: async () => ({ status: "verified", current_fingerprint_digest: fixture.referenceFingerprint.fingerprint_digest }),
      });
    };
    const source = await revalidate();
    expect(source.status).toBe("verified");
    const details = sourceModule.trustedUserMemoryCommandSource(source.trustedSource);
    const resolution = approvalModule.resolveExplicitMemoryAuthorization({ trustedSource: source.trustedSource,
      projectIdentity: fixture.projectIdentity });
    expect(resolution.status).toBe("authorized");
    const record = approvalModule.buildExplicitWorkingMemoryWritePayload(resolution);
    const evaluation = admissionModule.evaluateExplicitMemoryAdmission({ trustedResolution: resolution,
      writePayload: record, projectIdentity: fixture.projectIdentity });
    expect(evaluation.admitted).toBe(true);
    const admission = evaluation.admission;
    expect(record.memory_id).toBe(`wm_sha256_${digest("cmg/working-memory-write-payload/v2/identity", without(record, "memory_id")).slice(7)}`);
    const directory = join(fixture.root, "commands");
    const slot = join(directory, details.slot_id);
    const resultPath = join(slot, "result.json");
    const commandStore = new storeModule.ExplicitMemoryCommandStore(directory,
      { sourceRevalidator: revalidate, projectIdentity: fixture.projectIdentity });
    const exactInput = { memory_id: record.memory_id, idempotency_key: admission.idempotency_key,
      scope: record.scope, scope_id: record.scope_id };
    const credential = "synthetic-contract-e234-writer-key";
    const sensitiveFailure = "synthetic-store-sensitive-error-marker";
    const authority = { serviceId: "contract-e234-test", projectId: fixture.projectIdentity.project_id,
      scope: fixture.projectIdentity.scope, scopeId: fixture.projectIdentity.scope_id,
      isolation: { teamId: "e234-test-team", userId: "e234-test-user", agentId: "e234-test-agent" } };
    const configPath = join(root, "gateway-test.json");
    await writeFile(configPath, JSON.stringify({ deployMode: "standalone", data: { baseDir: root },
      llm: { baseUrl: "http://127.0.0.1:1", apiKey: "" } }));
    const testEnv: Record<string, string> = { TDAI_GATEWAY_CONFIG: configPath, TDAI_DATA_DIR: root };
    vi.spyOn(gatewayEnv, "getEnv").mockImplementation((key: string) => testEnv[key]);
    vi.stubEnv("V3_STRICT_ISOLATION", "true");
    const start = vi.spyOn(TdaiGateway.prototype, "start");
    let fault: "none" | "read_failed" | "throw" = "none";
    let rowTransform: ((row: L1RecordRow) => L1RecordRow) | undefined;
    let concurrent = false;
    let writes = 0;
    let committedWrites = 0;
    let databaseIndex = 0;
    let database = "";
    const storeReads: Array<{ path: string | undefined; id: string; status: string; injected: boolean }> = [];
    const openFreshStore = () => {
      sqlite?.close();
      database = join(root, `memory-${databaseIndex++}.sqlite`);
      sqlite = new VectorStore(database, 0);
      sqlite.init();
      expect(sqlite.isDegraded()).toBe(false);
      expect(sqlite.readL1RecordExact(record.memory_id)).toEqual({ status: "not_found" });
      const exact = sqlite.readL1RecordExact.bind(sqlite);
      vi.spyOn(sqlite, "readL1RecordExact").mockImplementation((id) => {
        const path = app?.requests.at(-1)?.path;
        if (fault !== "none" && path === "/v3/approved-memory/get") {
          storeReads.push({ path, id, status: fault, injected: true });
          if (fault === "throw") throw new Error(sensitiveFailure);
          return { status: "read_failed" };
        }
        const value = exact(id);
        if (value.status === "found" && rowTransform) {
          storeReads.push({ path, id, status: "found", injected: true });
          return { status: "found", row: rowTransform(structuredClone(value.row)) };
        }
        storeReads.push({ path, id, status: value.status, injected: false });
        return value;
      });
      const upsert = sqlite.upsertL1.bind(sqlite);
      vi.spyOn(sqlite, "upsertL1").mockImplementation((value, embedding) => {
        writes += 1;
        const committed = upsert(value, embedding); // Real SQLite returns true only after COMMIT.
        if (committed === true) committedWrites += 1;
        return committed;
      });
    };
    openFreshStore();
    // Independent SQLite connection bypasses the injected reader fault only for
    // test inspection. No Gateway or CMG response is supplied from these rows.
    const inspectDatabase = (operation: (store: VectorStore) => unknown) => {
      const independent = new VectorStore(database, 0);
      app?.trackStore(independent);
      try { independent.init(); expect(independent.isDegraded()).toBe(false); return operation(independent); }
      finally { independent.close(); }
    };
    const realFetch = globalThis.fetch;
    let allowedOrigin: string | undefined;
    const http: any[] = [];
    const clientErrors: any[] = [];
    let afterReceipt: ((observation: any) => Promise<void>) | undefined;
    let afterHttp: ((observation: any) => Promise<void>) | undefined;
    let actualNetworkCalls = 0;
    let logStart = 0;
    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
      expect(url.protocol).toBe("http:"); expect(url.hostname).toBe("127.0.0.1"); expect(url.origin).toBe(allowedOrigin);
      expect(["/v3/approved-memory/get", "/v3/approved-memory/write"]).toContain(url.pathname);
      expect(init?.method).toBe("POST"); expect(init?.redirect).toBe("error");
      const sentHeaders = new Headers(init?.headers);
      expect(sentHeaders.get("authorization") === `Bearer ${credential}`).toBe(true);
      expect(sentHeaders.get("x-tdai-service-id")).toBe(authority.serviceId);
      expect(sentHeaders.get("x-tdai-team-id")).toBe(authority.isolation.teamId);
      expect(sentHeaders.get("x-tdai-user-id")).toBe(authority.isolation.userId);
      expect(sentHeaders.get("x-tdai-agent-id")).toBe(authority.isolation.agentId);
      expect(sentHeaders.get("x-tdai-session-id")).toBe(details.source.session_id);
      const body = JSON.parse(String(init?.body));
      expect(body).toEqual(url.pathname.endsWith("/write") ? { admission, record } : exactInput);
      actualNetworkCalls += 1;
      const response = await realFetch(input, init);
      const text = await response.clone().text();
      const envelope = JSON.parse(text);
      const observation = { path: url.pathname, status: response.status, envelope, text, validations };
      http.push(observation);
      if (url.pathname.endsWith("/write") && afterReceipt) await afterReceipt(observation);
      if (afterHttp) await afterHttp(observation);
      return response;
    });
    app = await harness({ apiKey: credential, authority, dataDir: root, getStore: () => sqlite! });
    allowedOrigin = new URL(app.baseUrl).origin;
    expect(new URL(app.baseUrl).hostname).toBe("127.0.0.1");
    expect(Number(new URL(app.baseUrl).port)).toBeGreaterThan(0);
    const transport = (input: string | URL | Request, init?: RequestInit) => globalThis.fetch(input, { ...init, redirect: "error" });
    const client = new clientModule.TencentDbClient({ baseUrl: app.baseUrl, token: credential,
      serviceId: authority.serviceId, isolation: { team_id: authority.isolation.teamId,
        user_id: authority.isolation.userId, agent_id: authority.isolation.agentId }, fetchImpl: transport });
    const actualGet = client.getApprovedMemoryDirect.bind(client);
    vi.spyOn(client, "getApprovedMemoryDirect").mockImplementation(async (...args: any[]) => {
      try { return await actualGet(...args); }
      catch (error: any) {
        clientErrors.push({ name: error.name, status: error.status, code: error.gateway_code,
          message: error.message, string: String(error), json: JSON.stringify(error) });
        throw error;
      }
    });
    await run({ record, admission, resolution, details, resultPath, slot, http, storeReads, clientErrors,
      baseUrl: app.baseUrl, root, fixtureRoot: fixture.root, databasePath: () => database, dependencyPaths,
      fixtureRuntime: fixture.fields.runtime_implementation.desktop_package_identity,
      networkCalls: () => actualNetworkCalls,
      guardFetch: (input: string, init: RequestInit) => globalThis.fetch(input, init),
      concurrentMode: () => { concurrent = true; },
      afterHttp: (callback: (observation: any) => Promise<void>) => { afterHttp = callback; },
      restoreExactReader: () => { fault = "none"; rowTransform = undefined; afterReceipt = undefined; },
      transformExactRow: (transform: (row: L1RecordRow) => L1RecordRow) => { rowTransform = transform; },
      patchPersistedRow: (patch: Record<string, unknown>) => {
        const allowed = ["team_id", "user_id", "agent_id", "metadata_json", "version", "content"];
        expect(Object.keys(patch).every(key => allowed.includes(key))).toBe(true);
        const result = sqlite!.getRawDb().prepare(`UPDATE l1_records SET ${Object.keys(patch).map(key => `${key} = ?`).join(", ")} WHERE record_id = ?`)
          .run(...(Object.values(patch) as any[]), record.memory_id);
        expect(Number(result.changes)).toBe(1);
      },
      attemptOutput: (result: unknown) => JSON.stringify({ result, http, clientErrors, logs: app!.logs.slice(logStart) }),
      runFlow: () => flowModule.runExplicitMemoryCommandFlow({ trustedSource: source.trustedSource,
        store: commandStore, projectIdentity: fixture.projectIdentity, client, resultDirectory: directory,
        deadlineAt: 45_000 }, { clock: () => 0 }),
      validations: () => validations, writes: () => writes, committedWrites: () => committedWrites,
      injectReadFailure: (mode: "read_failed" | "throw") => { fault = mode; },
      afterWriteReceipt: (callback: (observation: any) => Promise<void>) => { afterReceipt = callback; },
      readCommitted: () => inspectDatabase(store => store.readL1RecordExact(record.memory_id)),
      recordCount: () => inspectDatabase(store => store.queryL1Records({}).length),
      freshStoreKeepingTerminal: openFreshStore,
      resetObservations: () => { http.length = 0; storeReads.length = 0; clientErrors.length = 0;
        app!.requests.length = 0; writes = 0; committedWrites = 0; logStart = app!.logs.length; },
      assertNoLeak: async (result: unknown) => {
        const artifacts = await Promise.all((await readdir(slot)).map(name => readFile(join(slot, name), "utf8")));
        const output = JSON.stringify({ result, http, clientErrors, logs: app!.logs, artifacts });
        expect(output.includes(sensitiveFailure)).toBe(false);
        expect(output.includes(credential)).toBe(false);
      },
    });
    expect(app.store.calls()).toBe(0);
    const observedRequests = http.map(({ path, status }) => ({ method: "POST", path, status }));
    if (concurrent) {
      // Request arrival and response completion can differ under concurrency.
      expect(app.requests.map(value => JSON.stringify(value)).sort()).toEqual(observedRequests.map(value => JSON.stringify(value)).sort());
    } else expect(app.requests).toEqual(observedRequests);
    expect(start).not.toHaveBeenCalled();
  } finally {
    if (app) await app.close();
    sqlite?.close();
    vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs();
    for (const fn of cleanup.reverse()) await fn();
    await rm(root, { recursive: true, force: true });
  }
}

describe("direct approved-memory server authority", () => {
  it("Contract E1 real CMG trusted flow persists through HTTP Gateway and reopens SQLite exact readback", async () => {
    // Cross-repository test imports only. No production dependency on CMG is added.
    const cmgRoot = "F:\\AI\\CodexMemoryGovernance";
    const loadCmg = (path: string) => import(/* @vite-ignore */ pathToFileURL(join(cmgRoot, path)).href);
    const [fixtureModule, sourceModule, runtimeModule, approvalModule, admissionModule, storeModule, flowModule, clientModule] =
      await Promise.all([
        loadCmg("tests/helpers/explicit-memory-command-fixture.js"),
        loadCmg("src/v1/user-memory-command-source.js"),
        loadCmg("src/v1/product-runtime-compatibility.js"),
        loadCmg("src/v1/human-memory-approval.js"),
        loadCmg("src/v1/human-approved-admission.js"),
        loadCmg("src/v1/explicit-memory-command-store.js"),
        loadCmg("src/v1/explicit-memory-command-flow.js"),
        loadCmg("src/integration/tencentdb-client.js"),
      ]);
    const root = await mkdtemp(join(tmpdir(), "memorycore-cmg-e1-"));
    expect(relative(tmpdir(), root).startsWith("..")).toBe(false);
    const cleanup: Array<() => Promise<void>> = [];
    let sqlite: VectorStore | undefined;
    let app: Harness | undefined;
    try {
      const fixture = await fixtureModule.explicitMemoryCommandFixture({ after: (fn: () => Promise<void>) => cleanup.push(fn) });
      // Same Runtime dependency seam as the existing CMG fixture tests. This is
      // fixture-only capability evidence, not live Desktop qualification.
      expect(fixture.fields.runtime_implementation.desktop_package_identity).toBe("OpenAI.Codex_test");
      expect(JSON.stringify(fixture.compatibilityAssessment).includes("fixture_only_verified")).toBe(true);
      let validations = 0;
      const revalidate = async (_previous?: unknown, options: { signal?: AbortSignal } = {}) => {
        validations += 1;
        return sourceModule.verifyUserMemoryCommandSource({
          hookInput: fixture.hookInput, expectedWorkspace: fixture.projectIdentity.workspace,
          projectIdentity: fixture.projectIdentity, referenceFingerprint: fixture.referenceFingerprint,
          compatibilityAssessment: fixture.compatibilityAssessment, rolloutResolver: fixture.resolver,
          expectedHookScript: fixture.expectedHookScript, signal: options.signal,
        }, {
          verifyCapability: (assessment: unknown, capability: string) => runtimeModule.gateProductRuntimeCapability(assessment, capability),
          verifyCurrentRuntime: async () => ({ status: "verified", current_fingerprint_digest: fixture.referenceFingerprint.fingerprint_digest }),
        });
      };
      const source = await revalidate();
      expect(source.status).toBe("verified");
      const details = sourceModule.trustedUserMemoryCommandSource(source.trustedSource);
      const resolution = approvalModule.resolveExplicitMemoryAuthorization({ trustedSource: source.trustedSource,
        projectIdentity: fixture.projectIdentity });
      expect(resolution.status).toBe("authorized");
      const record = approvalModule.buildExplicitWorkingMemoryWritePayload(resolution);
      const evaluation = admissionModule.evaluateExplicitMemoryAdmission({ trustedResolution: resolution,
        writePayload: record, projectIdentity: fixture.projectIdentity });
      expect(evaluation.admitted).toBe(true);
      const admission = evaluation.admission;
      const memoryId = `wm_sha256_${digest("cmg/working-memory-write-payload/v2/identity", without(record, "memory_id")).slice(7)}`;
      expect(record.memory_id).toBe(memoryId);
      expect(admission.write_payload_digest).toBe(digest("cmg/working-memory-write-payload/v2/snapshot", record));
      expect(admission.safety.provenance).toMatchObject({ project_id: fixture.projectIdentity.project_id,
        session_id: fixture.hookInput.session_id, source_contract: details.source.contract,
        content_digest: `sha256:${createHash("sha256").update(record.content, "utf8").digest("hex")}` });

      const directory = join(fixture.root, "commands");
      const commandStore = new storeModule.ExplicitMemoryCommandStore(directory,
        { sourceRevalidator: revalidate, projectIdentity: fixture.projectIdentity });
      const resultPath = join(directory, details.slot_id, "result.json");
      const exactInput = { memory_id: memoryId, idempotency_key: admission.idempotency_key,
        scope: record.scope, scope_id: record.scope_id };
      const database = join(root, "memory.sqlite");
      sqlite = new VectorStore(database, 0);
      sqlite.init();
      expect(sqlite.isDegraded()).toBe(false);
      expect(sqlite.readL1RecordExact(memoryId)).toEqual({ status: "not_found" });

      // Prevent the config loader from consulting deployment files or credential
      // environment values. Authentication itself remains the real server/router.
      const configPath = join(root, "gateway-test.json");
      await writeFile(configPath, JSON.stringify({ deployMode: "standalone", data: { baseDir: root },
        llm: { baseUrl: "http://127.0.0.1:1", apiKey: "" } }));
      const testEnv: Record<string, string> = { TDAI_GATEWAY_CONFIG: configPath, TDAI_DATA_DIR: root };
      vi.spyOn(gatewayEnv, "getEnv").mockImplementation((key: string) => testEnv[key]);
      vi.stubEnv("V3_STRICT_ISOLATION", "true");
      const start = vi.spyOn(TdaiGateway.prototype, "start");
      const credential = "synthetic-contract-e1-writer-key";
      const authority = { serviceId: "contract-e1-test", projectId: fixture.projectIdentity.project_id,
        scope: fixture.projectIdentity.scope, scopeId: fixture.projectIdentity.scope_id,
        isolation: { teamId: "e1-test-team", userId: "e1-test-user", agentId: "e1-test-agent" } };
      const sqliteReads: Array<{ memoryId: string; status: string }> = [];
      let sqliteWrites = 0;
      const listReads: Array<{ path: string | undefined; options: unknown }> = [];
      const observeStore = (store: VectorStore) => {
        const exact = store.readL1RecordExact.bind(store);
        vi.spyOn(store, "readL1RecordExact").mockImplementation((id) => {
          const value = exact(id);
          sqliteReads.push({ memoryId: id, status: value.status });
          return value;
        });
        const upsert = store.upsertL1.bind(store);
        vi.spyOn(store, "upsertL1").mockImplementation((value, embedding) => {
          sqliteWrites += 1;
          return upsert(value, embedding);
        });
        const query = store.queryL1Records.bind(store);
        vi.spyOn(store, "queryL1Records").mockImplementation((options) => {
          listReads.push({ path: app?.requests.at(-1)?.path, options });
          return query(options);
        });
      };
      observeStore(sqlite);

      const realFetch = globalThis.fetch;
      let allowedOrigin: string | undefined;
      const http: Array<{ path: string; status: number; body: any; data: any; code: number; validations: number }> = [];
      vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
        const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
        expect(url.protocol).toBe("http:");
        expect(url.hostname).toBe("127.0.0.1");
        expect(url.origin).toBe(allowedOrigin);
        expect(["/v3/approved-memory/get", "/v3/approved-memory/write"]).toContain(url.pathname);
        expect(init?.method).toBe("POST");
        expect(init?.redirect).toBe("error");
        const sentHeaders = new Headers(init?.headers);
        // Boolean assertion avoids printing a credential even on failure.
        expect(sentHeaders.get("authorization") === `Bearer ${credential}`).toBe(true);
        expect(sentHeaders.get("x-tdai-service-id")).toBe(authority.serviceId);
        expect(sentHeaders.get("x-tdai-session-id")).toBe(details.source.session_id);
        expect(sentHeaders.get("x-tdai-team-id")).toBe(authority.isolation.teamId);
        expect(sentHeaders.get("x-tdai-user-id")).toBe(authority.isolation.userId);
        expect(sentHeaders.get("x-tdai-agent-id")).toBe(authority.isolation.agentId);
        const body = JSON.parse(String(init?.body));
        if (url.pathname.endsWith("/write")) expect(body).toEqual({ admission, record });
        else expect(body).toEqual(exactInput);
        if (http.length < 3) await expect(readFile(resultPath)).rejects.toMatchObject({ code: "ENOENT" });
        const response = await realFetch(input, init);
        const envelope = await response.clone().json();
        http.push({ path: url.pathname, status: response.status, code: envelope.code, data: envelope.data, body, validations });
        // The successful write receipt must still leave local success unpublished.
        if (http.length <= 3) await expect(readFile(resultPath)).rejects.toMatchObject({ code: "ENOENT" });
        return response;
      });
      app = await harness({ apiKey: credential, authority, dataDir: root, getStore: () => sqlite! });
      allowedOrigin = new URL(app.baseUrl).origin;
      expect(new URL(app.baseUrl).hostname).toBe("127.0.0.1");
      expect(Number(new URL(app.baseUrl).port)).toBeGreaterThan(0);
      // A transport observer only: every request delegates to the actual fetch.
      // Reject redirects before they could escape the approved loopback origin.
      const transport = (input: string | URL | Request, init?: RequestInit) => globalThis.fetch(input, { ...init, redirect: "error" });
      const client = new clientModule.TencentDbClient({ baseUrl: app.baseUrl, token: credential,
        serviceId: authority.serviceId, isolation: { team_id: authority.isolation.teamId,
          user_id: authority.isolation.userId, agent_id: authority.isolation.agentId }, fetchImpl: transport });
      const actualGet = client.getApprovedMemoryDirect.bind(client);
      let classified404: { name: string; status: number; code: number } | undefined;
      vi.spyOn(client, "getApprovedMemoryDirect").mockImplementation(async (...args: any[]) => {
        try { return await actualGet(...args); }
        catch (error: any) {
          classified404 = { name: error.name, status: error.status, code: error.gateway_code };
          throw error;
        }
      });
      const saved = await flowModule.runExplicitMemoryCommandFlow({ trustedSource: source.trustedSource,
        store: commandStore, projectIdentity: fixture.projectIdentity, client, resultDirectory: directory,
        deadlineAt: 45_000 }, { clock: () => 0 });
      expect(classified404).toEqual({ name: "TencentDbGatewayError", status: 404, code: 404 });
      expect(http.map(({ path, status, code }) => ({ path, status, code }))).toEqual([
        { path: "/v3/approved-memory/get", status: 404, code: 404 },
        { path: "/v3/approved-memory/write", status: 200, code: 0 },
        { path: "/v3/approved-memory/get", status: 200, code: 0 },
      ]);
      expect(http[1].validations).toBeGreaterThan(http[0].validations);
      expect(app.requests).toEqual(http.map(({ path, status }) => ({ method: "POST", path, status })));
      expect(app.store.calls()).toBe(0); // The harness's legacy in-memory fixture was never used.
      expect(sqliteWrites).toBe(1);
      // The writer checks isolated conflicts after exact NOT_FOUND. Neither
      // external exact GET may substitute that list query for the exact reader.
      expect(listReads).toEqual([{ path: "/v3/approved-memory/write", options: {
        teamId: authority.isolation.teamId, userId: authority.isolation.userId, agentId: authority.isolation.agentId,
      } }]);
      expect(sqliteReads).toEqual([
        { memoryId, status: "not_found" }, { memoryId, status: "not_found" },
        { memoryId, status: "found" }, { memoryId, status: "found" },
      ]);
      const creationHttp = http.slice();
      const creationStoreExactReads = sqliteReads.length;
      const remote = http[2].data;
      expect(remote).toMatchObject({ record, admission_digest: admission.admission_digest,
        write_payload_digest: admission.write_payload_digest, idempotency_key: admission.idempotency_key,
        currentness: "current", lineage_status: "valid", readback_status: "verified", record_version: 1 });
      expect(http[1].data).toMatchObject({ status: "created", memory_id: memoryId,
        readback_status: "verified", readback_digest: admission.write_payload_digest });
      expect(saved).toMatchObject({ status: "MEMORY_SAVED", persistence_status: "created", memory_id: memoryId,
        remote_binding: { project_id: details.source.project_id, scope: record.scope, scope_id: record.scope_id,
          session_id: details.source.session_id, idempotency_key: admission.idempotency_key,
          admission_digest: admission.admission_digest, write_payload_digest: admission.write_payload_digest } });
      const terminal = JSON.parse(await readFile(resultPath, "utf8"));
      expect(terminal).toEqual(saved.result);
      expect(terminal).toMatchObject({ status: "MEMORY_SAVED", memory_id: memoryId,
        source_digest: details.source.source_digest, authorization_digest: admission.authorization_digest });
      const persisted = sqlite.readL1RecordExact(memoryId);
      expect(persisted.status).toBe("found");
      if (persisted.status !== "found") throw new Error("E1 SQLite record unavailable");
      expect(persisted.row).toMatchObject({ record_id: memoryId, content: record.content,
        team_id: authority.isolation.teamId, user_id: authority.isolation.userId,
        agent_id: authority.isolation.agentId, session_id: details.source.session_id, version: 1 });
      expect(JSON.parse(persisted.row.metadata_json)).toMatchObject({ approved_payload: record,
        source_digest: record.source_digest, authorization_digest: record.authorization_digest,
        admission_digest: admission.admission_digest, idempotency_key: admission.idempotency_key });
      expect((await stat(database)).size).toBeGreaterThan(0);

      // Reopen the physical database and let the SAME real HTTP reader use the
      // NEW Store instance. Neither the receipt nor local result is consulted.
      const closed = sqlite;
      closed.close();
      expect(closed.readL1RecordExact(memoryId)).toEqual({ status: "read_failed" });
      sqlite = new VectorStore(database, 0);
      sqlite.init();
      // Do not format native finalized Statement objects in an assertion.
      expect(sqlite === closed).toBe(false);
      expect(sqlite.isDegraded()).toBe(false);
      observeStore(sqlite);
      const readsBeforeReopenGet = sqliteReads.length;
      const reopened = await client.getApprovedMemoryDirect(exactInput, { sessionId: details.source.session_id });
      expect(reopened).toEqual(remote);
      expect(reopened.record).not.toBe(remote.record);
      expect(sqliteReads.slice(readsBeforeReopenGet)).toEqual([{ memoryId, status: "found" }]);
      expect(sqliteWrites).toBe(1);
      expect(listReads).toHaveLength(1);
      expect(http).toHaveLength(4);
      expect(http[3]).toMatchObject({ path: "/v3/approved-memory/get", status: 200, code: 0 });
      expect(app.requests).toHaveLength(4);
      expect(start).not.toHaveBeenCalled();
      expect(JSON.stringify({ terminal, remote, reopened, logs: app.logs }).includes(credential)).toBe(false);
      console.info("Contract E1 evidence", JSON.stringify({ initialGet: creationHttp[0].status,
        write: creationHttp[1].status, readbackGet: creationHttp[2].status,
        initialExactGet: creationHttp.slice(0, 1).filter(value => value.path.endsWith("/get")).length,
        writePost: creationHttp.filter(value => value.path.endsWith("/write")).length,
        postWriteExactGet: creationHttp.slice(2).filter(value => value.path.endsWith("/get")).length,
        creationGatewayRequests: creationHttp.length, creationStoreExactReads, creationWriterConflictQueries: listReads.length,
        sqliteWrites, reopenVerificationGet: 1, totalIncludingReopen: http.length }));
    } finally {
      if (app) await app.close();
      sqlite?.close();
      vi.restoreAllMocks();
      vi.unstubAllGlobals();
      vi.unstubAllEnvs();
      for (const fn of cleanup.reverse()) await fn();
      await rm(root, { recursive: true, force: true });
    }
  });

  it("Contract E2 existing SQLite FOUND is reused with current authority and zero write POST", async () => {
    await withCmgSqliteScenario(async ctx => {
      const first = await ctx.runFlow();
      expect(first.status).toBe("MEMORY_SAVED");
      expect(first.persistence_status).toBe("created");
      expect(ctx.writes()).toBe(1);
      expect(ctx.recordCount()).toBe(1);
      const bytes = await readFile(ctx.resultPath);
      ctx.resetObservations();
      const validationsBefore = ctx.validations();
      const reused = await ctx.runFlow();
      expect(ctx.http.map((value: any) => ({ path: value.path, status: value.status, code: value.envelope.code })))
        .toEqual([{ path: "/v3/approved-memory/get", status: 200, code: 0 }]);
      expect(ctx.storeReads).toEqual([{ path: "/v3/approved-memory/get", id: ctx.record.memory_id, status: "found", injected: false }]);
      expect(ctx.writes()).toBe(0);
      expect(ctx.recordCount()).toBe(1);
      // The real flow performs fresh source/auth/admission validation AFTER its
      // authenticated FOUND response, not just before entering the flow.
      expect(ctx.validations()).toBeGreaterThan(ctx.http[0].validations);
      expect(ctx.http[0].validations).toBeGreaterThan(validationsBefore);
      expect(JSON.parse(await readFile(join(ctx.slot, "source.json"), "utf8"))).toEqual(ctx.details.source);
      expect(JSON.parse(await readFile(join(ctx.slot, "authorization.json"), "utf8"))).toEqual(ctx.resolution.authorization);
      expect(JSON.parse(await readFile(join(ctx.slot, "admission.json"), "utf8"))).toEqual(ctx.admission);
      expect(ctx.http[0].envelope.data).toMatchObject({ record: ctx.record,
        admission_digest: ctx.admission.admission_digest, write_payload_digest: ctx.admission.write_payload_digest,
        idempotency_key: ctx.admission.idempotency_key, currentness: "current", lineage_status: "valid",
        readback_status: "verified", record_version: 1 });
      const committed = ctx.readCommitted();
      expect(committed.status).toBe("found");
      expect(committed.row).toMatchObject({ record_id: ctx.record.memory_id,
        content: ctx.record.content, session_id: ctx.details.source.session_id });
      expect(JSON.parse(committed.row.metadata_json)).toMatchObject({ approved_payload: ctx.record,
        source_digest: ctx.record.source_digest, authorization_digest: ctx.admission.authorization_digest,
        admission_digest: ctx.admission.admission_digest, idempotency_key: ctx.admission.idempotency_key });
      expect(ctx.admission.safety.provenance).toMatchObject({ project_id: ctx.details.source.project_id,
        session_id: ctx.details.source.session_id, source_contract: ctx.details.source.contract });
      expect(reused).toMatchObject({ status: "MEMORY_SAVED", persistence_status: "exact_replay",
        memory_id: ctx.record.memory_id, remote_binding: { project_id: ctx.details.source.project_id,
          session_id: ctx.details.source.session_id, scope: ctx.record.scope, scope_id: ctx.record.scope_id } });
      expect(reused.result).toEqual(first.result);
      expect(await readFile(ctx.resultPath)).toEqual(bytes);
      await ctx.assertNoLeak(reused);
      console.info("Contract E2 evidence", JSON.stringify({ foundGetStatus: ctx.http[0].status,
        reuseWritePosts: ctx.http.filter((value: any) => value.path.endsWith("/write")).length,
        storeRecordCount: ctx.recordCount(), currentAuthorityValidation: true, memorySaved: reused.status === "MEMORY_SAVED" }));
    });
  });

  it.each(["absent", "existing"] as const)("Contract E3 Store exact failure fails closed with %s terminal", async terminal => {
    await withCmgSqliteScenario(async ctx => {
      let bytes: Buffer | undefined;
      if (terminal === "existing") {
        expect((await ctx.runFlow()).status).toBe("MEMORY_SAVED");
        bytes = await readFile(ctx.resultPath);
      } else await expect(readFile(ctx.resultPath)).rejects.toMatchObject({ code: "ENOENT" });
      const countBefore = ctx.recordCount();
      ctx.resetObservations();
      // Exercise both supported Store failure outcomes. The thrown exception
      // carries a synthetic sensitive marker that must not reach any output.
      const mode = terminal === "absent" ? "throw" : "read_failed";
      ctx.injectReadFailure(mode);
      const failed = await ctx.runFlow();
      expect(ctx.http.map((value: any) => ({ path: value.path, status: value.status, code: value.envelope.code })))
        .toEqual([{ path: "/v3/approved-memory/get", status: 503, code: 503 }]);
      expect(ctx.storeReads).toEqual([{ path: "/v3/approved-memory/get", id: ctx.record.memory_id, status: mode, injected: true }]);
      expect(ctx.clientErrors).toHaveLength(1);
      expect(ctx.clientErrors[0]).toMatchObject({ name: "TencentDbGatewayError", status: 503, code: 503 });
      expect(ctx.writes()).toBe(0);
      expect(ctx.recordCount()).toBe(countBefore);
      expect(failed).toMatchObject({ status: "persistence_unknown", reason_code: "exact_gateway_get_unavailable", remote_binding: null });
      expect(failed.result).toBeUndefined();
      if (bytes) expect(await readFile(ctx.resultPath)).toEqual(bytes);
      else await expect(readFile(ctx.resultPath)).rejects.toMatchObject({ code: "ENOENT" });
      await ctx.assertNoLeak(failed);
      console.info("Contract E3 evidence", JSON.stringify({ terminal, httpStatus: ctx.http[0].status,
        gatewayCode: ctx.http[0].envelope.code, writePosts: ctx.writes(), memorySaved: failed.status === "MEMORY_SAVED",
        terminalBytesPreserved: bytes !== undefined, absentTerminalRemainsAbsent: bytes === undefined }));
    });
  });

  it.each(["absent", "existing"] as const)("Contract E4 real writer receipt precedes failed independent readback with %s terminal", async terminal => {
    await withCmgSqliteScenario(async ctx => {
      let bytes: Buffer | undefined;
      if (terminal === "existing") {
        expect((await ctx.runFlow()).status).toBe("MEMORY_SAVED");
        bytes = await readFile(ctx.resultPath);
        // Keep the genuine success artifact and old database. The active Store
        // is now another empty test database, so local success cannot supply
        // authority for this attempt's GET-first or post-write exact readback.
        ctx.freshStoreKeepingTerminal();
      }
      expect(ctx.recordCount()).toBe(0);
      expect(ctx.readCommitted()).toEqual({ status: "not_found" });
      ctx.resetObservations();
      let receiptWindow: any;
      ctx.afterWriteReceipt(async (observation: any) => {
        // This callback runs only after the REAL HTTP response has arrived and
        // its body has been read. The writer's internal Store readback is over.
        receiptWindow = { observation, storeReads: structuredClone(ctx.storeReads),
          committed: ctx.readCommitted(), writes: ctx.writes(),
          terminalBytes: bytes ? await readFile(ctx.resultPath) : undefined };
        if (!bytes) await expect(readFile(ctx.resultPath)).rejects.toMatchObject({ code: "ENOENT" });
        ctx.injectReadFailure("read_failed");
      });
      const failed = await ctx.runFlow();
      expect(receiptWindow).toBeDefined();
      expect(receiptWindow.observation).toMatchObject({ path: "/v3/approved-memory/write", status: 200,
        envelope: { code: 0, data: { status: "created", memory_id: ctx.record.memory_id,
          readback_status: "verified", readback_digest: ctx.admission.write_payload_digest } } });
      const receipt = receiptWindow.observation.envelope.data;
      expect(receipt.receipt_digest).toBe(digest("cmg/approved-working-memory-persistence-result/v1/receipt", without(receipt, "receipt_digest")));
      expect(receiptWindow.writes).toBe(1);
      expect(receiptWindow.storeReads).toEqual([
        { path: "/v3/approved-memory/get", id: ctx.record.memory_id, status: "not_found", injected: false },
        { path: "/v3/approved-memory/write", id: ctx.record.memory_id, status: "not_found", injected: false },
        { path: "/v3/approved-memory/write", id: ctx.record.memory_id, status: "found", injected: false },
      ]);
      expect(receiptWindow.committed.status).toBe("found");
      expect(receiptWindow.committed.row).toMatchObject({ record_id: ctx.record.memory_id,
        content: ctx.record.content, session_id: ctx.details.source.session_id });
      expect(JSON.parse(receiptWindow.committed.row.metadata_json)).toMatchObject({ approved_payload: ctx.record,
        admission_digest: ctx.admission.admission_digest, idempotency_key: ctx.admission.idempotency_key });
      expect(ctx.http.map((value: any) => ({ path: value.path, status: value.status, code: value.envelope.code })))
        .toEqual([
          { path: "/v3/approved-memory/get", status: 404, code: 404 },
          { path: "/v3/approved-memory/write", status: 200, code: 0 },
          { path: "/v3/approved-memory/get", status: 503, code: 503 },
        ]);
      expect(ctx.storeReads.at(-1)).toEqual({ path: "/v3/approved-memory/get",
        id: ctx.record.memory_id, status: "read_failed", injected: true });
      expect(ctx.clientErrors.map((value: any) => ({ status: value.status, code: value.code })))
        .toEqual([{ status: 404, code: 404 }, { status: 503, code: 503 }]);
      expect(failed).toMatchObject({ status: "persistence_unknown", reason_code: "write_outcome_or_readback_unknown", remote_binding: null });
      expect(failed.result).toBeUndefined();
      expect(ctx.writes()).toBe(1);
      expect(ctx.recordCount()).toBe(1);
      expect(ctx.readCommitted().row).toEqual(receiptWindow.committed.row);
      if (bytes) {
        expect(receiptWindow.terminalBytes).toEqual(bytes);
        expect(await readFile(ctx.resultPath)).toEqual(bytes);
      } else await expect(readFile(ctx.resultPath)).rejects.toMatchObject({ code: "ENOENT" });
      await ctx.assertNoLeak(failed);
      console.info("Contract E4 evidence", JSON.stringify({ terminal, storeCommitted: true,
        writerHttpStatus: receiptWindow.observation.status, writerReadback: receipt.readback_status,
        cmgReadbackHttpStatus: ctx.http[2].status, writePosts: ctx.writes(),
        memorySaved: failed.status === "MEMORY_SAVED", terminalBytesPreserved: bytes !== undefined,
        absentTerminalRemainsAbsent: bytes === undefined }));
    });
  });

  it.each(["team_id", "user_id", "agent_id"])("Contract E5 foreign isolation changes only %s and rejects without content leakage", async column => {
    await withCmgSqliteScenario(async ctx => {
      const positive = await ctx.runFlow();
      expect(positive.status).toBe("MEMORY_SAVED");
      const bytes = await readFile(ctx.resultPath);
      const original = ctx.readCommitted().row;
      ctx.patchPersistedRow({ [column]: "e5-foreign-isolation" });
      // Every other column, including metadata/version/identity, stays valid.
      expect(ctx.readCommitted().row).toEqual({ ...original, [column]: "e5-foreign-isolation" });
      ctx.resetObservations();
      const rejected = await ctx.runFlow();
      expect(ctx.http.map((value: any) => ({ status: value.status, code: value.envelope.code }))).toEqual([{ status: 503, code: 503 }]);
      expect(ctx.http[0].path).toBe("/v3/approved-memory/get");
      expect(ctx.storeReads).toEqual([{ path: "/v3/approved-memory/get", id: ctx.record.memory_id, status: "found", injected: false }]);
      expect(ctx.writes()).toBe(0);
      expect(rejected).toMatchObject({ status: "persistence_unknown", remote_binding: null });
      expect(rejected.result).toBeUndefined();
      expect(ctx.attemptOutput(rejected).includes(ctx.record.content)).toBe(false);
      expect(ctx.attemptOutput(rejected).includes(original.metadata_json)).toBe(false);
      expect(await readFile(ctx.resultPath)).toEqual(bytes);
      await ctx.assertNoLeak(rejected);
      console.info("Contract E5 isolation evidence", JSON.stringify({ column, gatewayReject: ctx.http[0].status,
        writePosts: ctx.writes(), contentLeaked: false }));
      ctx.patchPersistedRow({ [column]: original[column] });
      ctx.resetObservations();
      expect((await ctx.runFlow()).status).toBe("MEMORY_SAVED");
      expect(ctx.http[0].status).toBe(200);
      expect(ctx.writes()).toBe(0);
      expect(await readFile(ctx.resultPath)).toEqual(bytes);
    });
  });

  it.each(["wrong memory ID", "wrong deterministic binding", "wrong idempotency key",
    "invalid metadata", "invalid version", "wrong scope", "invalid stored provenance"])(
    "Contract E5 %s from Store is rejected by real Gateway before CMG success", async anomaly => {
      await withCmgSqliteScenario(async ctx => {
        expect((await ctx.runFlow()).status).toBe("MEMORY_SAVED");
        const bytes = await readFile(ctx.resultPath);
        const original = ctx.readCommitted().row;
        const metadata = JSON.parse(original.metadata_json);
        if (anomaly === "wrong memory ID") {
          // Adapter fault seam: real SQLite returns the valid row first; only
          // the exact reader's reported ID is changed before the real handler.
          ctx.transformExactRow((row: L1RecordRow) => ({ ...row, record_id: `wm_sha256_${"0".repeat(64)}` }));
        } else if (anomaly === "wrong deterministic binding") {
          metadata.approved_payload.content += " Synthetic changed binding.";
          metadata.write_payload_digest = digest("cmg/working-memory-write-payload/v2/snapshot", metadata.approved_payload);
          ctx.patchPersistedRow({ content: metadata.approved_payload.content, metadata_json: JSON.stringify(metadata) });
        } else if (anomaly === "wrong idempotency key") {
          metadata.idempotency_key = `sha256:${"0".repeat(64)}`;
          ctx.patchPersistedRow({ metadata_json: JSON.stringify(metadata) });
        } else if (anomaly === "invalid metadata") {
          ctx.patchPersistedRow({ metadata_json: "{invalid-json" });
        } else if (anomaly === "invalid version") {
          ctx.patchPersistedRow({ version: 0 });
        } else if (anomaly === "wrong scope") {
          metadata.approved_payload.scope_id = "e5-other-scope";
          ctx.patchPersistedRow({ metadata_json: JSON.stringify(metadata) });
        } else {
          // Stored direct provenance is command/source/authorization digest
          // binding, not an independent Desktop rollout qualification proof.
          metadata.source_digest = `sha256:${"0".repeat(64)}`;
          ctx.patchPersistedRow({ metadata_json: JSON.stringify(metadata) });
        }
        ctx.resetObservations();
        const rejected = await ctx.runFlow();
        expect(ctx.http.map((value: any) => ({ path: value.path, status: value.status, code: value.envelope.code })))
          .toEqual([{ path: "/v3/approved-memory/get", status: 503, code: 503 }]);
        expect(ctx.storeReads[0].status).toBe("found");
        expect(ctx.clientErrors[0]).toMatchObject({ name: "TencentDbGatewayError", status: 503, code: 503 });
        expect(ctx.writes()).toBe(0);
        expect(ctx.recordCount()).toBe(1);
        expect(rejected).toMatchObject({ status: "persistence_unknown", remote_binding: null });
        expect(rejected.result).toBeUndefined();
        expect(ctx.attemptOutput(rejected).includes(ctx.record.content)).toBe(false);
        expect(ctx.attemptOutput(rejected).includes("Synthetic changed binding.")).toBe(false);
        expect(await readFile(ctx.resultPath)).toEqual(bytes);
        await ctx.assertNoLeak(rejected);
        console.info("Contract E5 anomaly evidence", JSON.stringify({ anomaly, gatewayReject: ctx.http[0].status,
          cmgRecordValidationReached: false, writePosts: ctx.writes(), contentLeaked: false }));
        ctx.restoreExactReader();
        ctx.patchPersistedRow({ content: original.content, version: original.version, metadata_json: original.metadata_json });
        ctx.resetObservations();
        expect((await ctx.runFlow()).status).toBe("MEMORY_SAVED");
        expect(ctx.writes()).toBe(0);
        expect(await readFile(ctx.resultPath)).toEqual(bytes);
      });
    });

  it("Contract E6 sequential duplicates preserve one SQLite record and terminal bytes", async () => {
    await withCmgSqliteScenario(async ctx => {
      const first = await ctx.runFlow();
      expect(first.status).toBe("MEMORY_SAVED");
      const bytes = await readFile(ctx.resultPath);
      for (let index = 0; index < 2; index += 1) {
        const validations = ctx.validations();
        const reused = await ctx.runFlow();
        expect(reused).toMatchObject({ status: "MEMORY_SAVED", persistence_status: "exact_replay", result: first.result });
        expect(ctx.http.at(-1)).toMatchObject({ path: "/v3/approved-memory/get", status: 200 });
        expect(ctx.validations()).toBeGreaterThan(validations);
        expect(await readFile(ctx.resultPath)).toEqual(bytes);
      }
      expect(ctx.recordCount()).toBe(1);
      expect(ctx.http.filter((value: any) => value.path.endsWith("/write"))).toHaveLength(1);
      expect(ctx.writes()).toBe(1);
      expect(ctx.committedWrites()).toBe(1);
      await ctx.assertNoLeak(first);
      console.info("Contract E6 sequential evidence", JSON.stringify({ gatewayWritePosts: 1, storeWrites: ctx.writes(),
        storeCommittedWrites: ctx.committedWrites(),
        logicalRecords: ctx.recordCount(), verifiedReuses: 2, terminalBytesUnchanged: true }));
    });
  });

  it("Contract E6 concurrent same-identity workers commit once through real Gateway and SQLite", async () => {
    await withCmgSqliteScenario(async ctx => {
      ctx.concurrentMode();
      let release!: () => void;
      const firstGetBarrier = new Promise<void>(resolve => { release = resolve; });
      let arrived = 0;
      ctx.afterHttp(async (observation: any) => {
        if (observation.path.endsWith("/get") && observation.status === 404) {
          arrived += 1;
          await firstGetBarrier; // Delay delivery only; the real HTTP 404 is unchanged.
        }
      });
      const pending = [ctx.runFlow(), ctx.runFlow()];
      let barrierError: unknown;
      try { await vi.waitFor(() => expect(arrived).toBe(2), { timeout: 5_000, interval: 10 }); }
      catch (error) { barrierError = error; }
      finally { release(); }
      const results = await Promise.all(pending);
      if (barrierError) throw barrierError;
      expect(results.map(value => value.status)).toEqual(["MEMORY_SAVED", "MEMORY_SAVED"]);
      expect(results[0].result).toEqual(results[1].result);
      const gatewayWritePosts = ctx.http.filter((value: any) => value.path.endsWith("/write")).length;
      expect(gatewayWritePosts).toBe(2);
      expect(ctx.writes()).toBe(1);
      const storeCommittedWrites = ctx.committedWrites();
      expect(storeCommittedWrites).toBe(1);
      expect(ctx.recordCount()).toBe(1);
      expect(ctx.http.filter((value: any) => value.path.endsWith("/write")).map((value: any) => value.envelope.data.status).sort())
        .toEqual(["created", "exact_replay"]);
      expect(ctx.readCommitted().row.record_id).toBe(ctx.record.memory_id);
      const bytes = await readFile(ctx.resultPath);
      expect(JSON.parse(bytes.toString("utf8"))).toEqual(results[0].result);
      ctx.resetObservations();
      const reuses = await Promise.all([ctx.runFlow(), ctx.runFlow()]);
      expect(reuses.every(value => value.status === "MEMORY_SAVED" && value.persistence_status === "exact_replay")).toBe(true);
      expect(ctx.http).toHaveLength(2);
      expect(ctx.http.every((value: any) => value.path.endsWith("/get") && value.status === 200)).toBe(true);
      expect(ctx.writes()).toBe(0);
      expect(ctx.recordCount()).toBe(1);
      expect(await readFile(ctx.resultPath)).toEqual(bytes);
      await ctx.assertNoLeak(reuses);
      console.info("Contract E6 concurrent evidence", JSON.stringify({ gatewayWritePosts, storeCommittedWrites,
        logicalRecords: ctx.recordCount(), concurrentVerifiedResults: results.length, terminalBytesUnchanged: true }));
    });
  });

  it("Contract E6 committed unknown outcome retries by authoritative FOUND without another write", async () => {
    await withCmgSqliteScenario(async ctx => {
      ctx.afterWriteReceipt(async (observation: any) => {
        expect(observation).toMatchObject({ status: 200, envelope: { code: 0, data: { readback_status: "verified" } } });
        ctx.injectReadFailure("read_failed");
      });
      const unknown = await ctx.runFlow();
      expect(unknown.status).toBe("persistence_unknown");
      expect(ctx.http.map((value: any) => value.status)).toEqual([404, 200, 503]);
      expect(ctx.writes()).toBe(1);
      const storeCommittedWrites = ctx.committedWrites();
      expect(storeCommittedWrites).toBe(1);
      expect(ctx.recordCount()).toBe(1);
      await expect(readFile(ctx.resultPath)).rejects.toMatchObject({ code: "ENOENT" });
      const committed = ctx.readCommitted().row;
      ctx.restoreExactReader();
      ctx.resetObservations();
      const retry = await ctx.runFlow();
      expect(ctx.http).toHaveLength(1);
      expect(ctx.http[0]).toMatchObject({ path: "/v3/approved-memory/get", status: 200 });
      expect(ctx.http[0].envelope.data).toMatchObject({ record: ctx.record, readback_status: "verified",
        idempotency_key: ctx.admission.idempotency_key, admission_digest: ctx.admission.admission_digest,
        currentness: "current", lineage_status: "valid" });
      expect(ctx.validations()).toBeGreaterThan(ctx.http[0].validations);
      expect(retry).toMatchObject({ status: "MEMORY_SAVED", persistence_status: "exact_replay",
        remote_binding: { memory_id: ctx.record.memory_id, scope: ctx.record.scope, scope_id: ctx.record.scope_id,
          session_id: ctx.details.source.session_id, project_id: ctx.details.source.project_id } });
      expect(ctx.writes()).toBe(0);
      expect(ctx.readCommitted().row).toEqual(committed);
      const bytes = await readFile(ctx.resultPath);
      expect(JSON.parse(bytes.toString("utf8"))).toEqual(retry.result);
      ctx.resetObservations();
      expect((await ctx.runFlow()).status).toBe("MEMORY_SAVED");
      expect(ctx.http).toHaveLength(1);
      expect(ctx.http[0].status).toBe(200);
      expect(ctx.writes()).toBe(0);
      expect(ctx.recordCount()).toBe(1);
      expect(await readFile(ctx.resultPath)).toEqual(bytes);
      await ctx.assertNoLeak(retry);
      console.info("Contract E6 retry evidence", JSON.stringify({ initialStatus: unknown.status, retryStatus: retry.status,
        initialGatewayWrites: 1, retryGatewayWrites: 0, storeCommittedWrites,
        logicalRecords: ctx.recordCount(), terminalBytesUnchanged: true }));
    });
  });

  it("Contract E7 explicit test configuration ignores inherited token and URL and closes real resources", async () => {
    vi.stubEnv("TDAI_GATEWAY_TOKEN", "synthetic-e7-inherited-token-trap");
    vi.stubEnv("TDAI_GATEWAY_URL", "https://contract-e7.invalid");
    await withCmgSqliteScenario(async ctx => {
      expect(new URL(ctx.baseUrl).hostname).toBe("127.0.0.1");
      expect(relative(ctx.root, ctx.databasePath()).startsWith("..")).toBe(false);
      expect(ctx.databasePath().startsWith(ctx.root)).toBe(true);
      expect(relative(tmpdir(), ctx.fixtureRoot).startsWith("..")).toBe(false);
      expect(ctx.fixtureRuntime).toBe("OpenAI.Codex_test");
      expect(ctx.dependencyPaths).toEqual(["tests/helpers/explicit-memory-command-fixture.js", "src/v1/user-memory-command-source.js",
        "src/v1/product-runtime-compatibility.js", "src/v1/human-memory-approval.js", "src/v1/human-approved-admission.js",
        "src/v1/explicit-memory-command-store.js", "src/v1/explicit-memory-command-flow.js", "src/integration/tencentdb-client.js"]);
      const result = await ctx.runFlow();
      expect(result.status).toBe("MEMORY_SAVED");
      expect(ctx.networkCalls()).toBe(3);
      expect(ctx.recordCount()).toBe(1);
      expect(ctx.attemptOutput(result).includes("synthetic-e7-inherited-token-trap")).toBe(false);
      expect(ctx.attemptOutput(result).includes("contract-e7.invalid")).toBe(false);
      await ctx.assertNoLeak(result);
    });
    // The helper has returned through its real finally block; the suite hook
    // independently applies the same check to every E1–E6 test as well.
    assertResourcesClosed();
    expect(activeResources.length).toBe(1);
    expect(activeResources[0].stores.size).toBeGreaterThan(0);
    console.info("Contract E7 lifecycle evidence", JSON.stringify({ serversClosed: true, sqliteConnectionsClosed: true,
      previousFixtureAudits: completedResourceAudits.length,
      productionInitializationCalls: activeResources[0].initializeCalls(), productionQualification: false }));
  });

  it("Contract E7 loopback origin guard rejects external origin, other port and redirects before network", async () => {
    await withCmgSqliteScenario(async ctx => {
      const result = await ctx.runFlow();
      expect(result.status).toBe("MEMORY_SAVED");
      const networkBefore = ctx.networkCalls();
      const body = JSON.stringify({ memory_id: ctx.record.memory_id, idempotency_key: ctx.admission.idempotency_key,
        scope: ctx.record.scope, scope_id: ctx.record.scope_id });
      for (const [url, redirect] of [["https://contract-e7.invalid/v3/approved-memory/get", "error"],
        ["http://127.0.0.1:1/v3/approved-memory/get", "error"], [`${ctx.baseUrl}/v3/approved-memory/get`, "follow"]]) {
        await expect(ctx.guardFetch(url, { method: "POST", body, redirect })).rejects.toThrow();
      }
      expect(ctx.networkCalls()).toBe(networkBefore);
      expect(ctx.http).toHaveLength(3);
      expect(ctx.recordCount()).toBe(1);
      await ctx.assertNoLeak(result);
      console.info("Contract E7 origin evidence", JSON.stringify({ rejectedBeforeNetwork: 3,
        actualNetworkCalls: ctx.networkCalls(), productionResourcesUsed: false }));
    });
  });

  it("fails direct v2 closed when the server API key is not configured", async () => {
    await withHarness({ authority: AUTHORITY }, async (app) => {
      const result = await app.post("/v3/approved-memory/write", directFixture(), headers());
      expect(result).toMatchObject({ status: 403, json: { code: 403 } });
      expect(app.storeResolutions()).toBe(0);
      expect(app.store.calls()).toBe(0);
    });
  });

  it("rejects missing and wrong credentials before resolving the Store", async () => {
    await withHarness({ apiKey: API_KEY, authority: AUTHORITY }, async (app) => {
      const missing = headers(); delete missing.authorization;
      const missingResult = await app.post("/v3/approved-memory/write", directFixture(), missing);
      const wrongResult = await app.post("/v3/approved-memory/write", directFixture(), headers({ authorization: "Bearer wrong" }));
      expect(missingResult).toMatchObject({ status: 401, json: { code: 401 } });
      expect(wrongResult).toMatchObject({ status: 401, json: { code: 401 } });
      expect(app.storeResolutions()).toBe(0);
      expect(app.store.calls()).toBe(0);
    });
  });

  it("rejects absent and incomplete server-side direct authority", async () => {
    for (const authority of [undefined, { serviceId: AUTHORITY.serviceId }]) {
      await withHarness({ apiKey: API_KEY, authority }, async (app) => {
        const result = await app.post("/v3/approved-memory/write", directFixture(), headers());
        expect(result).toMatchObject({ status: 403, json: { code: 403 } });
        expect(app.storeResolutions()).toBe(0);
        expect(app.store.calls()).toBe(0);
      });
    }
  });

  it("rejects a spoofed service id after valid API-key authentication", async () => {
    await withHarness({ apiKey: API_KEY, authority: AUTHORITY }, async (app) => {
      const result = await app.post("/v3/approved-memory/write", directFixture(), headers({ "x-tdai-service-id": "spoofed" }));
      expect(result).toMatchObject({ status: 403, json: { code: 403 } });
      expect(app.storeResolutions()).toBe(0);
      expect(app.store.calls()).toBe(0);
    });
  });

  it("rejects a self-consistent forged project before resolving the Store", async () => {
    const forged = directFixture();
    const forgedWorkspace = "F:\\AI\\ForgedProject";
    const forgedWorkspaceDigest = `sha256:${createHash("sha256").update(forgedWorkspace, "utf8").digest("hex")}`;
    forged.admission.safety.provenance.workspace = forgedWorkspace;
    forged.admission.safety.provenance.workspace_digest = forgedWorkspaceDigest;
    forged.admission.safety.provenance.project_id = `project:${forgedWorkspaceDigest.slice(7, 23)}`;
    forged.admission = rehashDirectAdmission(forged.admission);
    await withHarness({ apiKey: API_KEY, authority: AUTHORITY }, async (app) => {
      const result = await app.post("/v3/approved-memory/write", forged, headers());
      expect(result).toMatchObject({ status: 403, json: { code: 403 } });
      expect(app.storeResolutions()).toBe(0);
      expect(app.store.calls()).toBe(0);
    });
  });

  it("rejects a self-consistent forged scope and scope id", async () => {
    const forged = directFixture();
    forged.record.scope_id = "forged-scope";
    forged.admission.scope_id = "forged-scope";
    const selfConsistent = rehashDirectRequest(forged);
    await withHarness({ apiKey: API_KEY, authority: AUTHORITY }, async (app) => {
      const result = await app.post("/v3/approved-memory/write", selfConsistent, headers());
      expect(result).toMatchObject({ status: 403, json: { code: 403 } });
      expect(app.storeResolutions()).toBe(0);
      expect(app.store.calls()).toBe(0);
    });
  });

  it("rejects stable isolation mismatches", async () => {
    await withHarness({ apiKey: API_KEY, authority: AUTHORITY }, async (app) => {
      const mismatches: Array<Record<string, string>> = [
        { "x-tdai-team-id": "other-team" },
        { "x-tdai-user-id": "other-user" },
        { "x-tdai-agent-id": "other-agent" },
      ];
      for (const mismatch of mismatches) {
        const result = await app.post("/v3/approved-memory/write", directFixture(), headers(mismatch));
        expect(result).toMatchObject({ status: 403, json: { code: 403 } });
      }
      expect(app.storeResolutions()).toBe(0);
      expect(app.store.calls()).toBe(0);
    });
  });

  it("requires an explicit session matching direct provenance without fixing it in server config", async () => {
    await withHarness({ apiKey: API_KEY, authority: AUTHORITY }, async (app) => {
      const missing = headers(); delete missing["x-tdai-session-id"];
      const missingResult = await app.post("/v3/approved-memory/write", directFixture(), missing);
      const mismatchResult = await app.post("/v3/approved-memory/write", directFixture(),
        headers({ "x-tdai-session-id": "another-session" }));
      expect(missingResult).toMatchObject({ status: 403, json: { code: 403 } });
      expect(mismatchResult).toMatchObject({ status: 403, json: { code: 403 } });
      expect(app.storeResolutions()).toBe(0);
      expect(app.store.calls()).toBe(0);
    });
  });

  it("allows exact authority into the existing typed writer", async () => {
    await withHarness({ apiKey: API_KEY, authority: AUTHORITY }, async (app) => {
      const result = await app.post("/v3/approved-memory/write", directFixture(), headers());
      expect(result).toMatchObject({ status: 200, json: { code: 0, data: { status: "created" } } });
      expect(app.storeResolutions()).toBe(1);
      expect(app.store.calls()).toBeGreaterThan(0);
      expect(app.store.rows).toHaveLength(1);
    });
  });

  it("lets typed validation reject malformed direct v2 without a Store method call", async () => {
    const malformed = directFixture();
    delete malformed.record.source_digest;
    await withHarness({ apiKey: API_KEY, authority: AUTHORITY }, async (app) => {
      const result = await app.post("/v3/approved-memory/write", malformed, headers());
      expect(result).toMatchObject({ status: 400, json: { code: 400 } });
      expect(app.store.calls()).toBe(0);
    });
  });

  it("does not expose credentials or expected authority in errors or logs", async () => {
    await withHarness({ apiKey: API_KEY, authority: AUTHORITY }, async (app) => {
      const wrongCredential = "synthetic-wrong-credential";
      const unauthorized = await app.post("/v3/approved-memory/write", directFixture(),
        headers({ authorization: `Bearer ${wrongCredential}` }));
      const forbidden = await app.post("/v3/approved-memory/write", directFixture(),
        headers({ "x-tdai-service-id": "spoofed" }));
      const publicEvidence = `${unauthorized.text}\n${forbidden.text}\n${app.logs.join("\n")}`;
      for (const secretOrBinding of [
        API_KEY, wrongCredential, AUTHORITY.serviceId, AUTHORITY.projectId, AUTHORITY.scopeId,
        AUTHORITY.isolation.teamId, AUTHORITY.isolation.userId, AUTHORITY.isolation.agentId,
      ]) {
        expect(publicEvidence).not.toContain(secretOrBinding);
      }
    });
  });

  it("preserves legacy v1 default-open behavior without direct authority", async () => {
    await withHarness({}, async (app) => {
      const result = await app.post("/v3/approved-memory/write", legacyFixture(),
        headers({ authorization: "Bearer local-standalone" }));
      expect(result).toMatchObject({ status: 200, json: { code: 0, data: { status: "created" } } });
      expect(app.store.rows).toHaveLength(1);
    });
  });

  it("does not apply direct-write authority policy to approved reads or health", async () => {
    await withHarness({}, async (app) => {
      const search = await app.post("/v3/approved-memory/search", { scope: "project", scope_id: AUTHORITY.scopeId },
        headers({ authorization: "Bearer local-standalone" }));
      const health = await app.get("/health");
      expect(search).toMatchObject({ status: 200, json: { code: 0, data: { total: 0 } } });
      expect(health.status).toBe(200);
    });
  });
});
