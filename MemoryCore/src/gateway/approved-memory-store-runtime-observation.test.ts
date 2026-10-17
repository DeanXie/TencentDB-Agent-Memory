import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import type http from "node:http";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseConfig } from "../config.js";
import { StorePool } from "../core/store/store-pool.js";
import { InstanceConfigProvider } from "../core/instance-config-provider.js";
import { TdaiGateway } from "./server.js";
import { handleV2Route } from "./v2-router.js";

// Real Pool/cache/init, Gateway, Router and Approved Memory handlers. Only
// Store construction/I/O boundaries are synthetic; no Gateway.start or socket.
const io = vi.hoisted(() => {
  const stores: any[] = [], initPlans: Array<() => Promise<void>> = [];
  const construct = (backend: string) => {
    const plan = initPlans.shift() ?? (() => Promise.resolve());
    const store: any = { backend, rows: [], calls: [], degraded: false, attempt: 0, status: "UNKNOWN",
      hold: null, entered: null, onRead: null, onWrite: null, onQuery: null, onDegraded: null,
      async init() {
        store.calls.push("init"); store.attempt++; store.status = "UNKNOWN";
        try { await plan(); store.status = "SUCCEEDED"; return { needsReindex: false }; }
        catch (error) { store.status = "FAILED"; store.degraded = true; throw error; }
      },
      getInitializationObservation() { return Object.freeze({ attempt: store.attempt, status: store.status }); },
      isDegraded() { store.onDegraded?.(); return store.degraded; },
      close() { store.calls.push("close"); store.degraded = true; },
      async readL1RecordExact(id: string) {
        store.calls.push("read"); store.onRead?.(store); store.entered?.(); await store.hold;
        const rows = store.rows.filter((row: any) => row.record_id === id);
        return rows.length === 1 ? { status: "found", row: rows[0] } : { status: "not_found" };
      },
      async queryL1Records() { store.calls.push("query"); store.onQuery?.(store); return store.rows; },
      async upsertL1(record: any) {
        store.calls.push("write"); store.onWrite?.(store);
        store.rows.push({ record_id: record.id, content: record.content, type: record.type, priority: record.priority,
          scene_name: record.scene_name, session_key: record.sessionKey, session_id: record.sessionId,
          team_id: record.teamId, user_id: record.userId, agent_id: record.agentId, task_id: record.taskId ?? "",
          version: record.version, timestamp_str: record.timestamps[0], timestamp_start: "", timestamp_end: "",
          created_time: record.createdAt, updated_time: record.updatedAt, metadata_json: JSON.stringify(record.metadata) });
        return true;
      },
    };
    stores.push(store); return store;
  };
  return { stores, initPlans, construct };
});
vi.mock("../core/store/tcvdb.js", async original => {
  const actual = await original<typeof import("../core/store/tcvdb.js")>();
  return { ...actual, TcvdbMemoryStore: class { constructor() { return io.construct("tcvdb"); } } };
});
vi.mock("../core/store/sqlite.js", async original => {
  const actual = await original<typeof import("../core/store/sqlite.js")>();
  return { ...actual, VectorStore: class { constructor() { return io.construct("sqlite"); } } };
});

const logger = { info() {}, warn() {}, error() {}, debug() {} };
const key = "synthetic-binding-key", instanceId = "synthetic-instance";
const identity = { team_id: "synthetic-team", user_id: "synthetic-user", agent_id: "synthetic-agent" };
const unknown = { selectionSource: "UNKNOWN", poolMatch: "UNKNOWN", constructedBackend: "UNKNOWN", generation: null, initStatus: "UNKNOWN" };
const matched = { selectionSource: "STOREPOOL", poolMatch: "MATCHED", constructedBackend: "tcvdb", generation: 1, initStatus: "SUCCEEDED" };
function deferred() {
  let resolve!: () => void; const promise = new Promise<void>(yes => { resolve = yes; });
  return { promise, resolve };
}
class Response extends EventEmitter {
  statusCode = 200; writableEnded = false; destroyed = false; headersSent = false; body = "";
  setHeader() { return this; }
  writeHead(status: number) { this.statusCode = status; this.headersSent = true; return this; }
  end(body?: string) { this.body += body ?? ""; this.writableEnded = true; this.emit("finish"); return this; }
}
const vector = JSON.parse(readFileSync("F:/AI/CodexMemoryGovernance/tests/fixtures/explicit-memory-contract-vectors.json", "utf8")).vectors[0];
const payload = () => structuredClone({ admission: vector.admission, record: vector.writePayload });
const getBody = () => ({ memory_id: vector.writePayload.memory_id, idempotency_key: vector.admission.idempotency_key,
  scope: vector.writePayload.scope, scope_id: vector.writePayload.scope_id });
function request(path = "/v3/approved-memory/get", body: unknown = getBody(), id = instanceId) {
  const bytes = Buffer.from(JSON.stringify(body)); const req = Readable.from([bytes]) as unknown as http.IncomingMessage;
  req.method = "POST"; req.url = path;
  req.headers = { authorization: `Bearer ${key}`, "x-tdai-service-id": id, "content-type": "application/json",
    "content-length": String(bytes.length), "x-tdai-team-id": identity.team_id, "x-tdai-user-id": identity.user_id,
    "x-tdai-agent-id": identity.agent_id, "x-tdai-session-id": vector.admission.safety.provenance.session_id };
  return req;
}
const pools: StorePool[] = []; const dirs: string[] = [];
function newPool() {
  const dir = mkdtempSync(join(tmpdir(), "approved-store-fixture-")); dirs.push(dir);
  const pool = new StorePool({ mode: "tcvdb", memoryCfg: parseConfig({ embedding: { provider: "none", enabled: false }, bm25: { enabled: false } }),
    dataDir: dir, kafka: { enabled: false, brokers: [] }, logger });
  pool.setGraceCloseDelay(0); pools.push(pool); return pool;
}
async function fixture({ prefetch = true, core = false } = {}) {
  const pool = newPool(); const config = { url: "http://synthetic.invalid", user: "synthetic-user", apiKey: "synthetic-not-a-secret", database: "synthetic-db" };
  const provider = new InstanceConfigProvider({ source: { async fetchVdb() { return { ...config }; }, async fetchCos() { return null; } }, vdbTtlMs: 0, logger });
  const authority = { serviceId: instanceId, projectId: vector.admission.safety.provenance.project_id, scope: "project",
    scopeId: vector.writePayload.scope_id, isolation: { teamId: identity.team_id, userId: identity.user_id, agentId: identity.agent_id } };
  const gateway = new TdaiGateway({ deployMode: "standalone", data: { baseDir: dirs.at(-1)! },
    server: { host: "127.0.0.1", port: 0, corsOrigins: [], apiKey: key, directWriterAuthority: authority } as any });
  const internal = gateway as any; internal.logger = logger;
  internal.core.getStorage = () => undefined; internal.core.getEmbeddingService = () => undefined;
  internal.resolveStorageForInstance = async () => undefined;
  internal.storePool = core ? null : pool; internal.configProvider = core ? null : provider;
  const selected: any = core ? io.construct("sqlite") : prefetch ? (await pool.getStore(instanceId, config)).store : undefined;
  internal.core.getVectorStore = () => selected;
  const observe = (req: http.IncomingMessage) => internal.getApprovedMemoryStoreObservation?.(req) ?? Object.freeze({ ...unknown });
  const start = (req: http.IncomingMessage) => { const res = new Response(); const done: Promise<void> = internal.handleRequest(req, res); return { res, done }; };
  return { pool, config, provider, internal, selected, observe, start };
}
async function pending(f: Awaited<ReturnType<typeof fixture>>, req = request()) {
  const entered = deferred(), hold = deferred(); f.selected.entered = entered.resolve; f.selected.hold = hold.promise;
  const running = f.start(req); await Promise.race([entered.promise, running.done]);
  return { ...running, req, release: hold.resolve };
}
beforeEach(() => {
  io.stores.length = 0; io.initPlans.length = 0; vi.stubEnv("V3_STRICT_ISOLATION", "true");
  const dir = mkdtempSync(join(tmpdir(), "approved-store-config-")); dirs.push(dir);
  const path = join(dir, "empty.json"); writeFileSync(path, "{}"); vi.stubEnv("TDAI_GATEWAY_CONFIG", path);
});
afterEach(async () => {
  for (const pool of pools.splice(0)) await pool.closeAll();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks(); vi.unstubAllEnvs();
});

describe("Approved Memory request Store binding", () => {
  it("stays UNKNOWN before a Handler actually gets its resolved Store", async () => {
    const f = await fixture(); expect(f.observe(request())).toEqual(unknown);
  });
  it("binds the actual GET Store and performs no extra read or initialization", async () => {
    const f = await fixture(); const run = await pending(f);
    try {
      expect(f.observe(run.req)).toEqual(matched);
      for (let i = 0; i < 3; i++) f.observe(run.req);
      expect(f.selected.calls).toEqual(["init", "read"]);
    } finally { run.release(); await run.done; }
    expect(run.res.statusCode).toBe(404); expect(f.observe(run.req)).toEqual(unknown);
  });
  it("does not match an old resolved Store to a rebuilt Entry", async () => {
    const f = await fixture(); const entered = deferred(), hold = deferred();
    f.internal.resolveStorageForInstance = async () => { entered.resolve(); await hold.promise; return undefined; };
    let observed: any; const req = request(); f.selected.onDegraded = () => { observed = f.observe(req); };
    const run = f.start(req); await entered.promise;
    await f.pool.evict(instanceId); await f.pool.getStore(instanceId, f.config); hold.resolve(); await run.done;
    expect(observed).toEqual({ ...unknown, selectionSource: "STOREPOOL" });
    // Immediate close makes the old object degraded; the original Handler refuses before I/O.
    expect(f.selected.calls).toEqual(["init", "close"]); expect(run.res.statusCode).toBe(503);
  });
  it("invalidates a match immediately on eviction without mutating held snapshots", async () => {
    const f = await fixture(); const run = await pending(f);
    try { const old = f.observe(run.req); expect(old).toEqual(matched); await f.pool.evict(instanceId);
      expect(f.observe(run.req)).toEqual({ ...unknown, selectionSource: "STOREPOOL" }); expect(old).toEqual(matched);
    } finally { run.release(); await run.done; }
  });
  it("fails closed when the entire Pool is replaced even if its generation restarts at one", async () => {
    const f = await fixture(); const run = await pending(f);
    try { const replacement = newPool(); await replacement.getStore(instanceId, f.config); f.internal.storePool = replacement;
      expect(f.observe(run.req)).toEqual({ ...unknown, selectionSource: "STOREPOOL" });
    } finally { run.release(); await run.done; }
  });
  it("fails closed when the Provider associated with a selected Pool is replaced", async () => {
    const f = await fixture(); const run = await pending(f);
    try { f.internal.configProvider = {}; expect(f.observe(run.req)).toEqual({ ...unknown, selectionSource: "STOREPOOL" }); }
    finally { run.release(); await run.done; }
  });
  it("observes UNKNOWN initialization on a real concurrent cache hit", async () => {
    const gate = deferred(); io.initPlans.push(() => gate.promise); const f = await fixture({ prefetch: false });
    const initializing = f.pool.getStore(instanceId, f.config); const selected = io.stores[0];
    const run = await pending({ ...f, selected });
    try { expect(f.observe(run.req)).toEqual({ ...matched, initStatus: "UNKNOWN" }); gate.resolve(); await initializing;
      expect(f.observe(run.req)).toEqual(matched);
    } finally { gate.resolve(); run.release(); await run.done; }
  });
  it("retains FAILED initialization as a diagnostic while the Handler returns 503", async () => {
    io.initPlans.push(() => Promise.reject(new Error("synthetic-init-failure"))); const f = await fixture();
    const req = request(); let snapshot: any; f.selected.onDegraded = () => { snapshot = f.observe(req); };
    const run = f.start(req); await run.done;
    expect(snapshot).toEqual({ ...matched, initStatus: "FAILED" }); expect(run.res.statusCode).toBe(503);
    expect(f.selected.calls).toEqual(["init"]); expect(f.observe(req)).toEqual(unknown);
  });
  it("keeps two concurrent instances bound to distinct actual Stores", async () => {
    const f = await fixture(); const other: any = (await f.pool.getStore("synthetic-other", f.config)).store;
    const gate = deferred(), entered = deferred(); let reads = 0;
    for (const store of [f.selected, other]) { store.hold = gate.promise; store.entered = () => { if (++reads === 2) entered.resolve(); }; }
    const aReq = request(), bReq = request(undefined, undefined, "synthetic-other"); const a = f.start(aReq), b = f.start(bReq); await entered.promise;
    try { expect(f.observe(aReq)).toEqual(matched); expect(f.observe(bReq)).toEqual({ ...matched, generation: 2 }); }
    finally { gate.resolve(); await Promise.all([a.done, b.done]); }
    expect(f.selected.calls).toEqual(["init", "read"]); expect(other.calls).toEqual(["init", "read"]);
  });
  it("allows two request contexts to reuse the same current Entry independently", async () => {
    const f = await fixture(); const a = await pending(f), b = await pending(f);
    try { expect(f.observe(a.req)).toEqual(matched); expect(f.observe(b.req)).toEqual(matched);
      b.release(); await b.done; expect(f.observe(b.req)).toEqual(unknown); expect(f.observe(a.req)).toEqual(matched);
    } finally { a.release(); b.release(); await Promise.all([a.done, b.done]); }
    expect(f.selected.calls).toEqual(["init", "read", "read"]);
  });
  it.each(["close", "aborted"])("invalidates an active request on %s", async event => {
    const f = await fixture(); const run = await pending(f);
    try { expect(f.observe(run.req)).toEqual(matched); if (event === "close") run.res.emit(event); else run.req.emit(event);
      expect(f.observe(run.req)).toEqual(unknown);
    } finally { run.release(); await run.done; }
    expect(f.observe(run.req)).toEqual(unknown); expect(run.req.listenerCount("aborted")).toBe(0);
  });
  it("rejects late resolution after close while another request uses the cached Store", async () => {
    const gate = deferred(); io.initPlans.push(() => gate.promise); const f = await fixture({ prefetch: false });
    const oldReq = request(), old = f.start(oldReq); await vi.waitFor(() => expect(io.stores).toHaveLength(1)); old.res.emit("close");
    const selected = io.stores[0], current = await pending({ ...f, selected });
    try { expect(f.observe(current.req)).toEqual({ ...matched, initStatus: "UNKNOWN" }); gate.resolve();
      await vi.waitFor(() => expect(selected.calls.filter((c: string) => c === "read")).toHaveLength(2));
      expect(f.observe(oldReq)).toEqual(unknown); expect(f.observe(current.req)).toEqual(matched);
    } finally { gate.resolve(); current.release(); await Promise.all([old.done, current.done]); }
  });
  it.each(["sqlite", "tcvdb"])("reports Core fallback with UNKNOWN backend despite configured %s", async backend => {
    const f = await fixture({ core: true }); f.internal.config.memory.storeBackend = backend; const run = await pending(f);
    try { expect(f.observe(run.req)).toEqual({ ...unknown, selectionSource: "CORE_FALLBACK" }); }
    finally { run.release(); await run.done; }
    expect(run.res.statusCode).toBe(404); expect(f.selected.calls).toEqual(["read"]);
  });
  it("observes the actual WRITE object and preserves exact pre-read/write/readback counts", async () => {
    const f = await fixture(); const req = request("/v3/approved-memory/write", payload()); const snapshots: any[] = [];
    f.selected.onRead = (store: unknown) => { expect(store).toBe(f.selected); snapshots.push(f.observe(req)); };
    f.selected.onWrite = (store: unknown) => { expect(store).toBe(f.selected); snapshots.push(f.observe(req)); };
    f.selected.onQuery = (store: unknown) => { expect(store).toBe(f.selected); snapshots.push(f.observe(req)); };
    const run = f.start(req); await run.done;
    expect(run.res.statusCode).toBe(200); expect(snapshots).toEqual([matched, matched, matched, matched]);
    expect(f.selected.calls).toEqual(["init", "read", "query", "write", "read"]); expect(f.observe(req)).toEqual(unknown);
  });
  it("permits GET, WRITE and final GET to select independent generations", async () => {
    const f = await fixture(); const snapshots: any[] = [];
    for (const [index, path] of ["get", "write", "get"].entries()) {
      f.config.database = `synthetic-db-${index}`;
      const selected: any = (await f.pool.getStore(instanceId, f.config)).store;
      const req = request(`/v3/approved-memory/${path}`, path === "write" ? payload() : getBody());
      selected.onRead = () => snapshots.push(f.observe(req)); const run = f.start(req); await run.done;
      expect(run.res.statusCode).toBe(path === "write" ? 200 : 404);
      expect(snapshots.at(-1)).toEqual({ ...matched, generation: index + 2 });
    }
    expect(snapshots.map(s => s.generation)).toEqual([2, 3, 3, 4]);
  });
  it("covers SEARCH through its actual queryL1Records use", async () => {
    const f = await fixture(); const req = request("/v3/approved-memory/search", { scope: vector.writePayload.scope, scope_id: vector.writePayload.scope_id });
    let observed: any; f.selected.onQuery = () => { observed = f.observe(req); };
    const run = f.start(req); await run.done;
    expect(run.res.statusCode).toBe(200); expect(observed).toEqual(matched); expect(f.selected.calls).toEqual(["init", "query"]);
  });
  it("returns frozen scalar snapshots without identity, credentials, fingerprints or Store references", async () => {
    const f = await fixture(); const run = await pending(f);
    try { const snap = f.observe(run.req); expect(snap).toEqual(matched); expect(Object.isFrozen(snap)).toBe(true);
      expect(Object.values(snap).every(v => v === null || ["string", "number"].includes(typeof v))).toBe(true);
      expect(JSON.stringify(snap)).not.toMatch(/synthetic|http|apiKey|fingerprint|instanceId|team_id|content|storeObject/);
      expect(Reflect.set(snap, "poolMatch", "forged")).toBe(false);
    } finally { run.release(); await run.done; }
  });
  it("isolates throwing observation callbacks from actual Router/Handler behavior", async () => {
    const f = await fixture(); const req = request(), res = new Response(); let observed: any;
    const deps: any = { deployMode: "standalone", getStore: () => f.selected, getStorage: () => undefined, getEmbedding: () => undefined, logger,
      observeApprovedMemoryStoreSelection(store: unknown) { observed = store; throw new Error("synthetic-observer-failure"); } };
    await handleV2Route(req, res as any, req.url!, "POST", async <T>() => getBody() as T,
      (response, code, body) => { response.writeHead(code); response.end(JSON.stringify(body)); }, deps);
    expect(observed).toBe(f.selected); expect(res.statusCode).toBe(404); expect(f.selected.calls).toEqual(["init", "read"]);
  });
  it("preserves wrong-key rejection before Store resolution", async () => {
    const f = await fixture({ prefetch: false }); const req = request(); req.headers.authorization = "Bearer synthetic-wrong-key";
    const run = f.start(req); await run.done; expect(run.res.statusCode).toBe(401); expect(io.stores).toHaveLength(0); expect(f.observe(req)).toEqual(unknown);
  });
  it("preserves Direct authority failure before Store resolution", async () => {
    const f = await fixture({ prefetch: false }); delete f.internal.config.server.directWriterAuthority;
    const req = request("/v3/approved-memory/write", payload()); const run = f.start(req); await run.done;
    expect(run.res.statusCode).toBe(403); expect(io.stores).toHaveLength(0); expect(f.observe(req)).toEqual(unknown);
  });
  it("clears observation after a Handler read failure without leaking its error", async () => {
    const f = await fixture(); const req = request(); let observed: any;
    f.selected.readL1RecordExact = async () => { observed = f.observe(req); throw new Error("synthetic-private-error"); };
    const run = f.start(req); await run.done;
    expect(observed).toEqual(matched); expect(run.res.statusCode).toBe(503); expect(run.res.body).not.toContain("synthetic-private-error"); expect(f.observe(req)).toEqual(unknown);
  });
  it("does not attach Approved Memory observation listeners to Profile routes", async () => {
    const f = await fixture(); const req = request("/v3/core/count", identity); const run = f.start(req);
    await run.done; expect(f.observe(req)).toEqual(unknown); expect(req.listenerCount("aborted")).toBe(0);
  });
});
