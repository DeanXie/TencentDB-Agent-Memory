import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type http from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { TdaiGateway } from "./server.js";
import { handleV2Route } from "./v2-router.js";
import { StorageAdapter } from "../core/storage/adapter.js";
import { LocalStorageBackend } from "../core/storage/local-backend.js";

// Real Gateway -> Router -> Profile Handler -> ScopedStorageBackend. Only
// storage I/O is synthetic. No start(), socket, cloud client or database.
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(yes => { resolve = yes; });
  return { promise, resolve };
}

class Response extends EventEmitter {
  statusCode = 200;
  headersSent = false;
  writableEnded = false;
  destroyed = false;
  body = "";
  setHeader() { return this; }
  writeHead(status: number) { this.statusCode = status; this.headersSent = true; return this; }
  end(body?: string) { this.body += body ?? ""; this.writableEnded = true; this.emit("finish"); return this; }
}

function request(path = "/v2/core/read", body: Record<string, unknown> = {}, instance = "synthetic-instance") {
  const bytes = Buffer.from(JSON.stringify(body));
  const req = Readable.from([bytes]) as unknown as http.IncomingMessage;
  req.method = "POST";
  req.url = path;
  req.headers = { authorization: "Bearer synthetic-test-key", "x-tdai-service-id": instance,
    "content-type": "application/json", "content-length": String(bytes.length) };
  return req;
}

function memoryBackend(type: "local" | "cos" = "local") {
  const keys: string[] = [];
  const entered = deferred();
  const release = deferred();
  const state = { pause: true, failure: null as Error | null, reads: 0 };
  const backend = {
    type,
    async getObject(key: string) {
      state.reads++; keys.push(key); entered.resolve();
      if (state.pause) await release.promise;
      if (state.failure) throw state.failure;
      return null;
    },
    async putObject(key: string) { keys.push(key); },
    async appendObject(key: string) { keys.push(key); },
    async exists() { return false; },
    async listObjects(key: string) { keys.push(key); entered.resolve(); if (state.pause) await release.promise; return { entries: [], total: 0 }; },
    async deleteObject(key: string) { keys.push(key); },
    async deleteByPrefix(key: string) { keys.push(key); return 0; },
  };
  return { backend, adapter: new StorageAdapter(backend), keys, entered, release, state };
}

function fixture(mode: "standalone" | "service" = "standalone") {
  vi.stubEnv("V3_STRICT_ISOLATION", "true");
  const storage = memoryBackend();
  const gateway = new TdaiGateway({ deployMode: mode,
    server: { apiKey: "synthetic-test-key", corsOrigins: [], host: "127.0.0.1", port: 0 } as any,
    data: { baseDir: join(tmpdir(), "profile-observation-unused") } as any,
  });
  const internals = gateway as any;
  const store: any = {};
  const base = { current: storage.adapter as StorageAdapter | undefined, reads: 0 };
  internals.core.getStorage = () => { base.reads++; return base.current; };
  internals.core.getVectorStore = () => store;
  internals.core.getEmbeddingService = () => undefined;
  internals.logger = { info() {}, warn() {}, error() {}, debug() {} };
  const observe = (req: http.IncomingMessage) => internals.getProfileStorageObservation(req);
  const start = (req: http.IncomingMessage) => {
    const res = new Response();
    const done: Promise<void> = internals.handleRequest(req, res);
    return { res, done };
  };
  return { gateway, internals, storage, store, base, observe, start };
}

const identity = { team_id: "synthetic-team", user_id: "synthetic-user", agent_id: "synthetic-agent", session_id: "synthetic-session" };
const scopeKey = "profiles/team%3Asynthetic-team%7Cagent%3Asynthetic-agent/persona.md";
const accepted = { configuredStorageTarget: "LOCAL_DEFAULT", baseAdapterStatus: "RESOLVED",
  selectedAdapterKind: "SCOPED_WRAPPER", backendImplementationIdentity: "UNKNOWN",
  scopeShape: "TEAM_AGENT", selectionStatus: "ACCEPTED" };

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });

describe("ScopeShape accuracy on actual Profile scope branches", () => {
  const cases: Array<{ name: string; body: Record<string, unknown>; shape: string; key: string }> = [
    { name: "numeric team remains the business team branch", body: { ...identity, team_id: 7 }, shape: "UNKNOWN", key: "profiles/team%3A7%7Cagent%3Asynthetic-agent/persona.md" },
    { name: "boolean team is not user fallback", body: { ...identity, team_id: true }, shape: "UNKNOWN", key: "profiles/team%3Atrue%7Cagent%3Asynthetic-agent/persona.md" },
    { name: "array team is not missing team", body: { ...identity, team_id: [] }, shape: "UNKNOWN", key: "profiles/team%3A%7Cagent%3Asynthetic-agent/persona.md" },
    { name: "object team is not missing team", body: { ...identity, team_id: {} }, shape: "UNKNOWN", key: "profiles/team%3A%5Bobject%20Object%5D%7Cagent%3Asynthetic-agent/persona.md" },
    { name: "valid team string remains classified", body: identity, shape: "TEAM_AGENT", key: scopeKey },
    { name: "missing team uses the valid user branch", body: { user_id: "synthetic-user", agent_id: "synthetic-agent" }, shape: "USER_AGENT_FALLBACK", key: "profiles/team%3Asynthetic-user%7Cagent%3Asynthetic-agent/persona.md" },
    ...["", null, undefined, false, 0].map((team, index) => ({ name: `falsy team ${index} retains resolver user fallback`, body: { ...identity, team_id: team }, shape: "USER_AGENT_FALLBACK", key: "profiles/team%3Asynthetic-user%7Cagent%3Asynthetic-agent/persona.md" })),
    { name: "numeric user is not a validated user fallback", body: { user_id: 7, agent_id: "synthetic-agent" }, shape: "UNKNOWN", key: "profiles/team%3A7%7Cagent%3Asynthetic-agent/persona.md" },
    { name: "boolean user is not a validated user fallback", body: { user_id: true, agent_id: "synthetic-agent" }, shape: "UNKNOWN", key: "profiles/team%3Atrue%7Cagent%3Asynthetic-agent/persona.md" },
    { name: "array user is not a validated user fallback", body: { user_id: [], agent_id: "synthetic-agent" }, shape: "UNKNOWN", key: "profiles/team%3A%7Cagent%3Asynthetic-agent/persona.md" },
    { name: "object user is not a validated user fallback", body: { user_id: {}, agent_id: "synthetic-agent" }, shape: "UNKNOWN", key: "profiles/team%3A%5Bobject%20Object%5D%7Cagent%3Asynthetic-agent/persona.md" },
    { name: "numeric agent prevents a team shape claim", body: { ...identity, agent_id: 7 }, shape: "UNKNOWN", key: "profiles/team%3Asynthetic-team%7Cagent%3A7/persona.md" },
    { name: "boolean agent prevents a team shape claim", body: { ...identity, agent_id: true }, shape: "UNKNOWN", key: "profiles/team%3Asynthetic-team%7Cagent%3Atrue/persona.md" },
    { name: "array agent prevents a team shape claim", body: { ...identity, agent_id: [] }, shape: "UNKNOWN", key: "profiles/team%3Asynthetic-team%7Cagent%3A/persona.md" },
    { name: "object agent prevents a user shape claim", body: { user_id: "synthetic-user", agent_id: {} }, shape: "UNKNOWN", key: "profiles/team%3Asynthetic-user%7Cagent%3A%5Bobject%20Object%5D/persona.md" },
  ];

  it.each(cases)("$name", async ({ body, shape, key }) => {
    const f = fixture(); const req = request("/v2/core/read", body); const running = f.start(req);
    // A counterexample must actually reach Storage; an early response is a failure.
    await Promise.race([f.storage.entered.promise, running.done]);
    try {
      expect(f.storage.keys).toEqual([key]);
      const snapshot = f.observe(req);
      expect(snapshot).toEqual({ ...accepted, scopeShape: shape });
      expect(Object.keys(snapshot)).toHaveLength(6); expect(Object.isFrozen(snapshot)).toBe(true);
      expect(JSON.stringify(snapshot)).not.toMatch(/synthetic|profiles\/|persona|token|bucket/);
      const reads = f.storage.state.reads; expect(f.observe(req)).toBe(snapshot); expect(f.storage.state.reads).toBe(reads);
    } finally { f.storage.release.resolve(); await running.done; }
    expect(running.res.statusCode).toBe(200); expect(JSON.parse(running.res.body).data.content).toBeNull();
    expect(f.observe(req).selectionStatus).toBe("UNKNOWN");
  });

  it.each(["", null, undefined, false, 0])("keeps the actual default branch UNKNOWN for empty legacy identity %s", async value => {
    const storage = memoryBackend(); storage.state.pause = false; const res = new Response(); let captured: any;
    const body = { team_id: value, user_id: value, agent_id: "synthetic-agent" };
    const deps: any = { deployMode: "standalone", isolationConfig: { legacyCompatMode: true, legacyPlaceholder: "" },
      getStore: () => ({}), getStorage: () => storage.adapter, getEmbedding: () => undefined,
      logger: { info() {}, warn() {}, error() {}, debug() {} }, observeProfileStorageSelection(snapshot: any) { captured = snapshot; } };
    const req = request("/v2/core/read", body);
    await handleV2Route(req, res as any, req.url!, "POST", async () => body as any,
      (response, code, data) => { response.writeHead(code); response.end(JSON.stringify(data)); }, deps);
    expect(storage.keys).toEqual(["profiles/team%3Adefault%7Cagent%3Asynthetic-agent/persona.md"]);
    expect(captured).toEqual({ ...accepted, scopeShape: "UNKNOWN" }); expect(res.statusCode).toBe(200);
  });

  it.each(["team_id", "user_id", "agent_id"])("preserves V3 strict rejection of nonstring %s", async field => {
    const f = fixture(); const req = request("/v3/core/read", { ...identity, [field]: 7 }); const running = f.start(req);
    await running.done;
    expect(running.res.statusCode).toBe(422); expect(f.storage.keys).toEqual([]);
    expect(f.observe(req).selectionStatus).toBe("UNKNOWN");
  });

  it("does not let an unknown team shape contaminate a concurrent valid user fallback", async () => {
    const f = fixture(); const entered = deferred(); let reads = 0;
    const original = f.storage.backend.getObject;
    f.storage.backend.getObject = key => { const result = original(key); if (++reads === 2) entered.resolve(); return result; };
    const reqA = request("/v2/core/read", { ...identity, team_id: 7 });
    const reqB = request("/v2/core/read", { user_id: "synthetic-user", agent_id: "synthetic-agent" });
    const a = f.start(reqA), b = f.start(reqB);
    await Promise.race([entered.promise, Promise.all([a.done, b.done])]);
    try {
      expect(f.storage.keys).toHaveLength(2);
      expect(new Set(f.storage.keys)).toEqual(new Set(["profiles/team%3A7%7Cagent%3Asynthetic-agent/persona.md", "profiles/team%3Asynthetic-user%7Cagent%3Asynthetic-agent/persona.md"]));
      expect(f.observe(reqA)).toEqual({ ...accepted, scopeShape: "UNKNOWN" });
      expect(f.observe(reqB)).toEqual({ ...accepted, scopeShape: "USER_AGENT_FALLBACK" });
      expect(f.observe(reqA)).not.toBe(f.observe(reqB));
    } finally { f.storage.release.resolve(); await Promise.all([a.done, b.done]); }
    expect(a.res.statusCode).toBe(200); expect(b.res.statusCode).toBe(200);
    expect(f.observe(reqA).selectionStatus).toBe("UNKNOWN"); expect(f.observe(reqB).selectionStatus).toBe("UNKNOWN");
  });
});

describe("V2/V3 Profile request-bound nonauthoritative Storage observation", () => {
  it("has no final selection before request execution and its getter performs no storage work", () => {
    const f = fixture(); const req = request();
    expect(f.observe(req).selectionStatus).toBe("UNKNOWN");
    expect(f.observe(req).selectedAdapterKind).toBe("UNKNOWN");
    expect(f.base.reads).toBe(0); expect(f.storage.state.reads).toBe(0);
  });

  it("does not attach Profile observation lifecycle listeners to unrelated Gateway requests", async () => {
    const f = fixture(); const req = request("/v2/no-profile-route", identity); const running = f.start(req);
    try { expect(req.listenerCount("aborted")).toBe(0); }
    finally { await running.done; }
    expect(running.res.statusCode).toBe(404);
    expect(f.observe(req).selectionStatus).toBe("UNKNOWN");
  });

  it.each(["v2", "v3"])("observes the real %s Profile Handler scoped adapter while its read is in flight", async version => {
    const f = fixture(); const req = request(`/${version}/core/read`, identity); const running = f.start(req);
    await f.storage.entered.promise;
    try {
      expect(f.observe(req)).toEqual(accepted);
      expect(f.storage.keys).toEqual([scopeKey]);
      expect(f.storage.state.reads).toBe(1);
    } finally { f.storage.release.resolve(); await running.done; }
    expect(running.res.statusCode).toBe(200);
    expect(JSON.parse(running.res.body).data.content).toBeNull();
    expect(f.observe(req).selectionStatus).toBe("UNKNOWN");
    expect(req.listenerCount("aborted")).toBe(0);
    expect(running.res.listenerCount("close")).toBe(0);
  });

  it("keeps an accepted Core Local adapter distinct from the final scoped wrapper", async () => {
    const f = fixture(); const backend = new LocalStorageBackend(join(tmpdir(), "unused-local-profile"));
    const actualDefault = new StorageAdapter(backend);
    f.internals.core.setStorage(actualDefault); f.base.current = actualDefault;
    vi.spyOn(backend, "getObject").mockImplementation(async key => {
      expect(key).toBe(scopeKey); f.storage.entered.resolve(); await f.storage.release.promise; return null;
    });
    const req = request("/v2/core/read", identity); const running = f.start(req);
    await f.storage.entered.promise;
    try { expect(f.observe(req).selectedAdapterKind).toBe("SCOPED_WRAPPER"); expect(f.base.current).toBe(actualDefault); }
    finally { f.storage.release.resolve(); await running.done; }
  });

  it("keeps a service COS target separate from an actually local base adapter", async () => {
    const f = fixture("service"); const req = request("/v2/core/read", identity); const running = f.start(req);
    await f.storage.entered.promise;
    try {
      expect(f.observe(req)).toMatchObject({ configuredStorageTarget: "COS_DEFAULT", selectedAdapterKind: "SCOPED_WRAPPER", backendImplementationIdentity: "UNKNOWN" });
      expect(f.storage.backend.type).toBe("local"); expect(f.storage.keys).toEqual([scopeKey]);
    } finally { f.storage.release.resolve(); await running.done; }
  });

  it("does not trust a synthetic cos type label as implementation identity", async () => {
    const f = fixture("service"); const cos = memoryBackend("cos"); f.base.current = cos.adapter;
    const req = request("/v2/core/read", identity); const running = f.start(req); await cos.entered.promise;
    try { expect(f.observe(req).backendImplementationIdentity).toBe("UNKNOWN"); expect(cos.keys).toEqual([scopeKey]); }
    finally { cos.release.resolve(); await running.done; }
  });

  it("uses the original user-plus-agent fallback when v2 has no team", async () => {
    const f = fixture(); const { team_id: _team, ...body } = identity;
    const req = request("/v2/core/read", body); const running = f.start(req); await f.storage.entered.promise;
    try {
      expect(f.observe(req).scopeShape).toBe("USER_AGENT_FALLBACK");
      expect(f.storage.keys).toEqual(["profiles/team%3Asynthetic-user%7Cagent%3Asynthetic-agent/persona.md"]);
    } finally { f.storage.release.resolve(); await running.done; }
  });

  it("does not add session isolation to the existing Profile storage formula", async () => {
    const f = fixture(); f.storage.state.pause = false;
    const reqA = request("/v2/core/read", identity), reqB = request("/v2/core/read", { ...identity, session_id: "other-session" });
    const snapshots: any[] = [];
    const original = f.storage.backend.getObject;
    f.storage.backend.getObject = async key => { snapshots.push(f.observe(snapshots.length ? reqB : reqA)); return original(key); };
    await f.start(reqA).done; await f.start(reqB).done;
    expect(snapshots.map(s => s.scopeShape)).toEqual(["TEAM_AGENT", "TEAM_AGENT"]);
    expect(f.storage.keys).toEqual([scopeKey, scopeKey]);
  });

  it("keeps two concurrent same-instance Profile scopes bound to their own request objects", async () => {
    const f = fixture(); const reqA = request("/v2/core/read", identity);
    const reqB = request("/v2/core/read", { user_id: "other-user", agent_id: "other-agent" });
    const a = f.start(reqA), b = f.start(reqB); await f.storage.entered.promise;
    while (f.storage.state.reads < 2) await Promise.resolve();
    try {
      const snapA = f.observe(reqA), snapB = f.observe(reqB);
      expect(snapA.scopeShape).toBe("TEAM_AGENT"); expect(snapB.scopeShape).toBe("USER_AGENT_FALLBACK");
      expect(snapA).not.toBe(snapB); expect(f.observe(reqA)).toBe(snapA);
      expect(new Set(f.storage.keys)).toEqual(new Set([scopeKey, "profiles/team%3Aother-user%7Cagent%3Aother-agent/persona.md"]));
    } finally { f.storage.release.resolve(); await Promise.all([a.done, b.done]); }
    expect(f.observe(reqA).selectionStatus).toBe("UNKNOWN"); expect(f.observe(reqB).selectionStatus).toBe("UNKNOWN");
  });

  it("observes actual instance-cache reuse without claiming physical instance isolation", async () => {
    const f = fixture(); const a = await f.internals.resolveStorageForInstance("instance-a");
    const aAgain = await f.internals.resolveStorageForInstance("instance-a");
    const b = await f.internals.resolveStorageForInstance("instance-b");
    expect(aAgain).toBe(a); expect(b).not.toBe(a);
    const seen: string[] = []; const hold = deferred(); const entered = deferred();
    let reads = 0;
    for (const adapter of [a, b]) vi.spyOn(adapter.getBackend(), "getObject").mockImplementation(async (key: any) => {
      seen.push(key); reads++; if (reads === 2) entered.resolve(); await hold.promise; return null;
    });
    f.internals.storePool = { mode: "sqlite", async getStore() { return { store: f.store, embedding: undefined }; } };
    f.internals.configProvider = {};
    const reqA = request("/v2/core/read", identity, "instance-a"), reqB = request("/v2/core/read", identity, "instance-b");
    const runA = f.start(reqA), runB = f.start(reqB); await entered.promise;
    try {
      expect(f.observe(reqA).selectionStatus).toBe("ACCEPTED"); expect(f.observe(reqB).selectionStatus).toBe("ACCEPTED");
      expect(f.observe(reqA)).not.toBe(f.observe(reqB)); expect(seen).toEqual([scopeKey, scopeKey]);
      expect(f.internals.cosStorageCache.get("instance-a")).toBe(a);
    } finally { hold.resolve(); await Promise.all([runA.done, runB.done]); }
  });

  it("does not invalidate request A when concurrent request B completes first", async () => {
    const f = fixture(); const entered = deferred(), releaseA = deferred(), releaseB = deferred(); let reads = 0;
    f.storage.state.pause = false;
    const original = f.storage.backend.getObject;
    f.storage.backend.getObject = async key => {
      const value = await original(key); if (++reads === 2) entered.resolve();
      await (key.includes("synthetic-team") ? releaseA.promise : releaseB.promise); return value;
    };
    const reqA = request("/v2/core/read", identity), reqB = request("/v2/core/read", { user_id: "other-user", agent_id: "other-agent" });
    const a = f.start(reqA), b = f.start(reqB); await entered.promise;
    try {
      const snapshotA = f.observe(reqA); releaseB.resolve(); await b.done;
      expect(f.observe(reqA)).toBe(snapshotA); expect(snapshotA.selectionStatus).toBe("ACCEPTED");
      expect(f.observe(reqB).selectionStatus).toBe("UNKNOWN");
    } finally { releaseA.resolve(); releaseB.resolve(); await Promise.all([a.done, b.done]); }
  });

  it("does not publish a late scoped selection after a request closed during base resolution", async () => {
    const f = fixture(); const entered = deferred(), hold = deferred(); f.storage.state.pause = false;
    f.internals.storePool = { mode: "sqlite", async getStore() { entered.resolve(); await hold.promise; return { store: f.store, embedding: undefined }; } };
    f.internals.configProvider = {};
    f.internals.cosStorageCache = new Map([["synthetic-instance", f.storage.adapter]]);
    const req = request("/v2/core/read", identity); const running = f.start(req); await entered.promise;
    let observedDuringRead: any;
    const original = f.storage.backend.getObject;
    f.storage.backend.getObject = async key => { observedDuringRead = f.observe(req); return original(key); };
    try { running.res.emit("close"); hold.resolve(); await running.done; }
    finally { hold.resolve(); }
    expect(f.storage.keys).toEqual([scopeKey]);
    expect(observedDuringRead.selectionStatus).toBe("UNKNOWN"); expect(f.observe(req).selectionStatus).toBe("UNKNOWN");
  });

  it("reuses a cached base adapter but creates a fresh selection snapshot for the next request", async () => {
    const f = fixture(); f.storage.state.pause = false; const captured: any[] = [];
    const original = f.storage.backend.getObject;
    let current: http.IncomingMessage;
    f.storage.backend.getObject = async key => { captured.push(f.observe(current)); return original(key); };
    for (const session of ["first", "second"]) { current = request("/v2/core/read", { ...identity, session_id: session }); await f.start(current).done; }
    expect(captured).toHaveLength(2); expect(captured[0]).not.toBe(captured[1]); expect(captured[0]).toEqual(captured[1]);
    expect(f.base.current).toBe(f.storage.adapter); expect(f.storage.state.reads).toBe(2);
  });

  it("does not publish a final selection when the scoped constructor fails", async () => {
    const f = fixture(); const failure = new Error("synthetic-scoped-construction-failure");
    f.base.current = { getBackend() { throw failure; } } as any;
    const req = request("/v2/core/read", identity); const running = f.start(req); await running.done;
    expect(running.res.statusCode).toBe(500); expect(f.observe(req).selectionStatus).toBe("UNKNOWN"); expect(f.storage.state.reads).toBe(0);
  });

  it.each(["missing-auth", "missing-team", "unknown-route"])("keeps final selection UNKNOWN after %s early exit", async kind => {
    const f = fixture(); const body: any = { ...identity }; if (kind === "missing-team") delete body.team_id;
    const req = request(kind === "unknown-route" ? "/v3/no-profile-route" : "/v3/core/read", body);
    if (kind === "missing-auth") delete req.headers.authorization;
    const running = f.start(req); await running.done;
    expect(running.res.statusCode).toBe(kind === "missing-auth" ? 401 : kind === "missing-team" ? 422 : 404);
    expect(f.observe(req).selectionStatus).toBe("UNKNOWN"); expect(f.storage.state.reads).toBe(0);
  });

  it("does not invent Storage selection on the real store-only count branch", async () => {
    const f = fixture(); f.store.countProfiles = async () => 7;
    const req = request("/v3/core/count", identity); const running = f.start(req); await running.done;
    expect(JSON.parse(running.res.body).data.total).toBe(7);
    expect(f.observe(req).selectionStatus).toBe("UNKNOWN"); expect(f.storage.state.reads).toBe(0);
  });

  it("observes the real storage fallback of the v3 count handler", async () => {
    const f = fixture(); const req = request("/v3/scenario/count", identity); const running = f.start(req); await f.storage.entered.promise;
    try { expect(f.observe(req)).toEqual(accepted); expect(f.storage.keys).toEqual(["profiles/team%3Asynthetic-team%7Cagent%3Asynthetic-agent/scene_blocks/"]); }
    finally { f.storage.release.resolve(); await running.done; }
    expect(JSON.parse(running.res.body).data.total).toBe(0);
  });

  it("keeps a missing base adapter unavailable rather than claiming scoped acceptance", async () => {
    const f = fixture(); f.base.current = undefined; const req = request("/v2/core/read", identity); const running = f.start(req); await running.done;
    expect(running.res.statusCode).toBe(503); expect(f.observe(req).selectionStatus).toBe("UNKNOWN");
  });

  it("invalidates the active observation on response close while storage I/O is still pending", async () => {
    const f = fixture(); const req = request("/v2/core/read", identity); const running = f.start(req); await f.storage.entered.promise;
    try {
      expect(f.observe(req).selectionStatus).toBe("ACCEPTED"); running.res.emit("close");
      expect(f.observe(req).selectionStatus).toBe("UNKNOWN");
    } finally { f.storage.release.resolve(); await running.done; }
  });

  it("invalidates on request abort without allowing late completion to republish selection", async () => {
    const f = fixture(); const req = request("/v2/core/read", identity); const running = f.start(req); await f.storage.entered.promise;
    try {
      expect(f.observe(req).selectionStatus).toBe("ACCEPTED"); req.emit("aborted");
      expect(f.observe(req).selectionStatus).toBe("UNKNOWN");
    } finally { f.storage.release.resolve(); await running.done; }
    expect(f.observe(req).selectionStatus).toBe("UNKNOWN");
  });

  it("preserves the original failed-I/O response and clears its completed observation", async () => {
    const f = fixture(); f.storage.state.failure = new Error("synthetic-backend-read-failure");
    const req = request("/v2/core/read", identity); const running = f.start(req); await f.storage.entered.promise;
    try { expect(f.observe(req).selectionStatus).toBe("ACCEPTED"); }
    finally { f.storage.release.resolve(); await running.done; }
    expect(running.res.statusCode).toBe(500); expect(f.observe(req).selectionStatus).toBe("UNKNOWN");
    expect(running.res.body).not.toContain("synthetic-backend-read-failure");
  });

  it("returns frozen scalar snapshots without identities, paths, credentials or additional reads", async () => {
    const f = fixture(); const req = request("/v2/core/read", identity); const running = f.start(req); await f.storage.entered.promise;
    try {
      const before = f.base.reads; const snapshot = f.observe(req);
      expect(snapshot).toEqual(accepted); expect(Object.isFrozen(snapshot)).toBe(true);
      expect(Object.values(snapshot).every(value => typeof value === "string")).toBe(true);
      expect(() => { snapshot.selectionStatus = "forged"; }).toThrow();
      expect(JSON.stringify(snapshot)).not.toMatch(/synthetic|profiles\/|persona|http|token|bucket/i);
      expect(f.base.reads).toBe(before); expect(f.storage.state.reads).toBe(1);
    } finally { f.storage.release.resolve(); await running.done; }
  });

  it("isolates optional observer failures from the real Router and Profile return contract", async () => {
    const storage = memoryBackend(); storage.state.pause = false; const res = new Response(); let observations = 0; let captured: any;
    const deps: any = { deployMode: "standalone", getStore: () => ({}), getEmbedding: () => undefined, getStorage: () => storage.adapter,
      logger: { info() {}, warn() {}, error() {}, debug() {} },
      observeProfileStorageSelection(snapshot: any) { observations++; captured = snapshot; throw new Error("synthetic-observer-failure"); },
    };
    const req = request("/v2/core/read", identity);
    const handled = await handleV2Route(req, res as any, req.url!, "POST", async () => identity as any,
      (response, code, body) => { response.writeHead(code); response.end(JSON.stringify(body)); }, deps);
    expect(handled).toBe(true); expect(observations).toBe(1); expect(res.statusCode).toBe(200);
    expect(captured).toEqual(accepted);
    expect(storage.keys).toEqual([scopeKey]);
  });
});

describe("Profile Router and Scoped Storage compatibility without an observer", () => {
  const cases = ["v2", "v3"].flatMap(version => [
    { path: `/${version}/scenario/ls`, body: {}, status: 200, key: "scene_blocks/" },
    { path: `/${version}/scenario/read`, body: { path: "synthetic.md" }, status: 200, key: "scene_blocks/synthetic.md" },
    { path: `/${version}/scenario/write`, body: { path: "synthetic.md", content: "replacement" }, status: 404, key: "scene_blocks/synthetic.md" },
    { path: `/${version}/scenario/rm`, body: { path: "synthetic.md" }, status: 200, key: "scene_blocks/synthetic.md" },
    { path: `/${version}/core/read`, body: {}, status: 200, key: "persona.md" },
    { path: `/${version}/core/write`, body: { content: " synthetic " }, status: 200, key: "persona.md" },
  ]).concat([
    { path: "/v3/scenario/count", body: {}, status: 200, key: "scene_blocks/" },
    { path: "/v3/core/count", body: {}, status: 200, key: "persona.md" },
  ]);

  it.each(cases)("preserves $path response and existing scoped storage operations", async ({ path, body, status, key }) => {
    const storage = memoryBackend(); storage.state.pause = false; const res = new Response();
    const writes: Array<{ key: string; content: string }> = [];
    (storage.backend as any).putObject = async (objectKey: string, value: string | Buffer) => {
      storage.keys.push(objectKey); writes.push({ key: objectKey, content: value.toString() });
    };
    const deps: any = { deployMode: "standalone", getStore: () => ({}), getEmbedding: () => undefined,
      getStorage: () => storage.adapter, logger: { info() {}, warn() {}, error() {}, debug() {} } };
    const req = request(path, { ...identity, ...body });
    const handled = await handleV2Route(req, res as any, path, "POST", async () => ({ ...identity, ...body }) as any,
      (response, code, value) => { response.writeHead(code); response.end(JSON.stringify(value)); }, deps);
    expect(handled).toBe(true); expect(res.statusCode).toBe(status);
    expect(JSON.parse(res.body).code).toBe(status === 200 ? 0 : status);
    expect(storage.keys).toContain(`profiles/team%3Asynthetic-team%7Cagent%3Asynthetic-agent/${key}`);
    if (path.endsWith("/core/write")) expect(writes).toContainEqual({ key: scopeKey, content: "synthetic" });
    if (path.endsWith("/scenario/write")) expect(writes).toHaveLength(0);
  });
});
