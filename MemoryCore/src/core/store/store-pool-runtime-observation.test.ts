import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MemoryTdaiConfig } from "../../config.js";
import type { VdbConfig } from "../instance-config-provider.js";
import { StorePool } from "./store-pool.js";
import { TcvdbMemoryStore } from "./tcvdb.js";
import { TcvdbApiError } from "./tcvdb-client.js";

// Mock only I/O boundaries. StorePool's construction, cache, init and close
// control flow runs unchanged; no real database, filesystem or service is used.
const boundary = vi.hoisted(() => {
  const plans: Array<() => Promise<void>> = [];
  const stores: Array<{
    backend: string;
    init: ReturnType<typeof vi.fn>;
    close: ReturnType<typeof vi.fn>;
    degraded: boolean;
    missingInitResult: boolean;
    isDegraded: ReturnType<typeof vi.fn>;
    getInitializationObservation: ReturnType<typeof vi.fn>;
  }> = [];
  const construct = (backend: string) => {
    const init = plans.shift() ?? (() => Promise.resolve());
    let attempt = 0;
    let status = "UNKNOWN";
    const store = {
      backend, degraded: false, missingInitResult: false,
      init: vi.fn(() => {
        attempt++;
        status = "UNKNOWN";
        return init().then(() => {
          status = "SUCCEEDED";
          return store.missingInitResult ? undefined : { needsReindex: false };
        });
      }),
      close: vi.fn(async () => {}),
      isDegraded: vi.fn((): boolean => store.degraded),
      getInitializationObservation: vi.fn(() => Object.freeze({ attempt, status })),
    };
    stores.push(store);
    return store;
  };
  return {
    plans, stores, construct,
    realTcvdb: false,
    databasePlans: [] as Array<() => Promise<boolean>>,
    collectionPlans: [] as Array<() => Promise<void>>,
    clients: [] as Array<{
      createDatabase: ReturnType<typeof vi.fn>;
      createCollection: ReturnType<typeof vi.fn>;
    }>,
    constructorError: null as Error | null,
    embedding: vi.fn(() => { throw new Error("Unexpected external embedding"); }),
    kafka: vi.fn(() => { throw new Error("Unexpected Kafka connection"); }),
    mkdir: vi.fn(() => { throw new Error("Unexpected filesystem write"); }),
  };
});

vi.mock("./sqlite.js", () => ({ VectorStore: class {
  constructor() {
    if (boundary.constructorError) throw boundary.constructorError;
    return boundary.construct("sqlite");
  }
} }));
vi.mock("./tcvdb.js", async importOriginal => {
  const actual = await importOriginal<typeof import("./tcvdb.js")>();
  return { TcvdbMemoryStore: class {
    constructor(...args: ConstructorParameters<typeof actual.TcvdbMemoryStore>) {
      if (boundary.constructorError) throw boundary.constructorError;
      if (boundary.realTcvdb) return new actual.TcvdbMemoryStore(...args);
      return boundary.construct("tcvdb");
    }
  } };
});
vi.mock("./tcvdb-client.js", () => ({
  TcvdbApiError: class extends Error {
    readonly apiCode: number;
    constructor(_path: string, code: number, message: string) {
      super(message); this.apiCode = code;
    }
  },
  TcvdbClient: class {
    createDatabase = vi.fn(() => (boundary.databasePlans.shift() ?? (() => Promise.resolve(false)))());
    createCollection = vi.fn((_params: Record<string, unknown>) =>
      (boundary.collectionPlans.shift() ?? (() => Promise.resolve()))());
    getDatabase() { return "fixture-database"; }
    constructor() { boundary.clients.push(this); }
  },
}));
vi.mock("./tcvdb-skill-store.js", () => ({ TcvdbSkillStore: class {
  constructor() { throw new Error("Unexpected skill store"); }
} }));
vi.mock("./embedding.js", () => ({
  NoopEmbeddingService: class {}, createEmbeddingService: boundary.embedding,
}));
vi.mock("./bm25-local.js", () => ({ createBM25Encoder: () => undefined }));
vi.mock("../report/kafka-metric-producer.js", () => ({
  metricProducer: { initialize: boundary.kafka },
}));
vi.mock("node:fs", () => ({ existsSync: () => true, mkdirSync: boundary.mkdir }));

const vdb: VdbConfig = {
  url: "http://synthetic.invalid", user: "fixture-user",
  apiKey: "synthetic-key-not-a-credential", database: "fixture-database",
};
const pools: StorePool[] = [];
function pool(mode: "sqlite" | "tcvdb" = "tcvdb", maxStores = 100) {
  const instance = new StorePool({
    mode, maxStores, dataDir: "synthetic-data-directory",
    memoryCfg: {
      embedding: { enabled: false, provider: "none", dimensions: 0 },
      bm25: { enabled: false }, tcvdb: {},
    } as MemoryTdaiConfig,
    kafka: { enabled: false, brokers: [] },
    logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  });
  instance.setGraceCloseDelay(0);
  pools.push(instance);
  return instance;
}
function deferred() {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

// Optional lookup makes the initial RED an observation assertion failure rather
// than a missing-method TypeError. All store operations still run for real.
interface Observation {
  readonly instanceId: string;
  readonly generation: number;
  readonly configuredMode: "sqlite" | "tcvdb";
  readonly constructedBackend: "sqlite" | "tcvdb";
  readonly initStatus: "UNKNOWN" | "SUCCEEDED" | "FAILED";
}
function observe(instance: StorePool, id: string): Readonly<Observation> | null | undefined {
  return (instance as StorePool & {
    getStoreObservation?: (id: string) => Readonly<Observation> | null;
  }).getStoreObservation?.(id);
}

beforeEach(() => {
  boundary.plans.length = 0;
  boundary.stores.length = 0;
  boundary.constructorError = null;
  boundary.realTcvdb = false;
  boundary.databasePlans.length = 0;
  boundary.collectionPlans.length = 0;
  boundary.clients.length = 0;
});

interface InitializationObservation {
  readonly attempt: number;
  readonly status: "UNKNOWN" | "SUCCEEDED" | "FAILED";
}
function initialization(store: object): Readonly<InitializationObservation> | undefined {
  return (store as {
    getInitializationObservation?: () => Readonly<InitializationObservation>;
  }).getInitializationObservation?.();
}
function realTcvdb() {
  boundary.realTcvdb = true;
  return new TcvdbMemoryStore({
    url: vdb.url, username: vdb.user, apiKey: vdb.apiKey,
    database: vdb.database, embeddingModel: "fixture-model", timeout: 1000,
  });
}
const collections = [
  "l1_memories", "l0_conversations", "profiles", "memory_audit", "knowledge",
  "memory_prompts", "memory_prompt_settings", "memory_prompt_setting_logs",
  "memory_generation_refs",
].map(suffix => `fixture-database_${suffix}`);

describe("initialization completion evidence", () => {
  it("requires all nine real TCVDB initialization steps before success", async () => {
    boundary.realTcvdb = true;
    const last = deferred();
    for (let i = 0; i < 8; i++) boundary.collectionPlans.push(() => Promise.resolve());
    boundary.collectionPlans.push(() => last.promise);
    const instance = pool();
    const pending = instance.getStore("real", vdb);
    try {
      await vi.waitFor(() => expect(boundary.clients[0].createCollection).toHaveBeenCalledTimes(9));
      const cached = await instance.getStore("real", vdb);
      const before = initialization(cached.store);
      expect(before).toEqual({ attempt: 1, status: "UNKNOWN" });
      expect(observe(instance, "real")).toMatchObject({ initStatus: "UNKNOWN" });
      last.resolve();
      expect(await pending).toBe(cached);
      expect(initialization(cached.store)).toEqual({ attempt: 1, status: "SUCCEEDED" });
      expect(before?.status).toBe("UNKNOWN");
      expect(Object.isFrozen(before)).toBe(true);
      expect(Reflect.set(before!, "status", "FAILED")).toBe(false);
      expect(observe(instance, "real")).toMatchObject({ initStatus: "SUCCEEDED" });
      expect(boundary.clients[0].createCollection.mock.calls.map(call => call[0].collection)).toEqual(collections);
    } finally { last.resolve(); await pending; }
  });

  it("preserves the database-created delay and then the full initialization order", async () => {
    vi.useFakeTimers();
    boundary.databasePlans.push(() => Promise.resolve(true));
    const store = realTcvdb();
    expect(initialization(store)).toEqual({ attempt: 0, status: "UNKNOWN" });
    const pending = store.init();
    try {
      await Promise.resolve();
      expect(boundary.clients[0].createCollection).not.toHaveBeenCalled();
      expect(initialization(store)).toEqual({ attempt: 1, status: "UNKNOWN" });
    } finally { await vi.advanceTimersByTimeAsync(5000); await pending; }
    expect(await pending).toEqual({ needsReindex: false });
    expect(initialization(store)).toEqual({ attempt: 1, status: "SUCCEEDED" });
    expect(boundary.clients[0].createCollection.mock.calls.map(call => call[0].collection)).toEqual(collections);
  });

  it("keeps the real 15201 early return UNKNOWN without extra collection operations", async () => {
    boundary.realTcvdb = true;
    boundary.databasePlans.push(() => Promise.reject(new TcvdbApiError("/database/create", 15201, "synthetic race")));
    const instance = pool();
    const result = await instance.getStore("early", vdb);
    expect(result.store.isDegraded()).toBe(false);
    expect(boundary.clients[0].createCollection).not.toHaveBeenCalled();
    expect(initialization(result.store)).toEqual({ attempt: 1, status: "UNKNOWN" });
    expect(observe(instance, "early")).toMatchObject({ initStatus: "UNKNOWN" });
    expect(await instance.getStore("early", vdb)).toBe(result);
    expect(boundary.clients[0].createDatabase).toHaveBeenCalledTimes(1);
  });

  it.each([0, 1, 9])("records real internal TCVDB failure at initialization step %i", async step => {
    boundary.realTcvdb = true;
    const failure = () => Promise.reject(new Error("synthetic initialization failure"));
    if (step === 0) boundary.databasePlans.push(failure);
    else {
      for (let i = 1; i < step; i++) boundary.collectionPlans.push(() => Promise.resolve());
      boundary.collectionPlans.push(failure);
    }
    const instance = pool();
    const result = await instance.getStore("degraded", vdb);
    expect(result.store.isDegraded()).toBe(true);
    expect(initialization(result.store)).toEqual({ attempt: 1, status: "FAILED" });
    expect(observe(instance, "degraded")).toMatchObject({ initStatus: "FAILED" });
    expect(boundary.clients[0].createCollection).toHaveBeenCalledTimes(step);
    expect(await instance.getStore("degraded", vdb)).toBe(result);
  });

  it("maps SQLite normal-return internal degradation to FAILED without changing its return", async () => {
    boundary.plans.push(() => {
      boundary.stores[0].degraded = true;
      return Promise.resolve();
    });
    const instance = pool("sqlite");
    const result = await instance.getStore("sqlite", null);
    expect(result.store).toBe(boundary.stores[0]);
    expect(result.store.isDegraded()).toBe(true);
    expect(observe(instance, "sqlite")).toMatchObject({ initStatus: "FAILED" });
    expect(await instance.getStore("sqlite", null)).toBe(result);
  });

  it.each(["missing", "nonboolean", "throws", "missing result"])("keeps insufficient SQLite initialization evidence UNKNOWN: %s", async kind => {
    const init = deferred();
    boundary.plans.push(() => init.promise);
    const instance = pool("sqlite");
    const pending = instance.getStore("sqlite", null);
    const store = boundary.stores[0];
    if (kind === "missing") Object.defineProperty(store, "isDegraded", { value: undefined });
    if (kind === "nonboolean") store.isDegraded.mockReturnValue(undefined);
    if (kind === "throws") store.isDegraded.mockImplementation(() => { throw new Error("synthetic observer error"); });
    if (kind === "missing result") {
      store.missingInitResult = true;
    }
    init.resolve();
    expect((await pending).store).toBe(store);
    expect(observe(instance, "sqlite")).toMatchObject({ initStatus: "UNKNOWN" });
  });

  it.each(["missing", "throws", "invalid status", "invalid attempt"])("keeps insufficient TCVDB completion evidence UNKNOWN: %s", async kind => {
    const init = deferred();
    boundary.plans.push(() => init.promise);
    const instance = pool();
    const pending = instance.getStore("tenant", vdb);
    const store = boundary.stores[0];
    if (kind === "missing") Object.defineProperty(store, "getInitializationObservation", { value: undefined });
    if (kind === "throws") store.getInitializationObservation.mockImplementation(() => { throw new Error("synthetic observer error"); });
    if (kind === "invalid status") store.getInitializationObservation.mockReturnValue({ attempt: 1, status: "READY" });
    if (kind === "invalid attempt") store.getInitializationObservation.mockReturnValue({ attempt: 0, status: "SUCCEEDED" });
    init.resolve();
    expect((await pending).store).toBe(store);
    expect(observe(instance, "tenant")).toMatchObject({ initStatus: "UNKNOWN" });
  });

  it("resets repeated real initialization and retains UNKNOWN after a later 15201", async () => {
    const store = realTcvdb();
    expect(await store.init()).toEqual({ needsReindex: false });
    const previous = initialization(store);
    expect(previous).toEqual({ attempt: 1, status: "SUCCEEDED" });
    const next = deferred();
    boundary.databasePlans.push(async () => {
      await next.promise;
      throw new TcvdbApiError("/database/create", 15201, "synthetic race");
    });
    const pending = store.init();
    try { expect(initialization(store)).toEqual({ attempt: 2, status: "UNKNOWN" }); }
    finally { next.resolve(); await pending; }
    expect(initialization(store)).toEqual({ attempt: 2, status: "UNKNOWN" });
    expect(previous).toEqual({ attempt: 1, status: "SUCCEEDED" });
    expect(store.isDegraded()).toBe(false);
    expect(boundary.clients[0].createCollection).toHaveBeenCalledTimes(9);
  });

  it.each(["success", "failure", "early return"])("isolates a late old real initialization %s from a newer attempt", async outcome => {
    const old = deferred();
    boundary.databasePlans.push(async () => {
      await old.promise;
      if (outcome === "failure") throw new Error("old initialization failure");
      if (outcome === "early return") throw new TcvdbApiError("/database/create", 15201, "synthetic race");
      return false;
    });
    const store = realTcvdb();
    const first = store.init();
    try {
      await store.init();
      expect(initialization(store)).toEqual({ attempt: 2, status: "SUCCEEDED" });
    } finally { old.resolve(); await first; }
    expect(initialization(store)).toEqual({ attempt: 2, status: "SUCCEEDED" });
    expect(store.isDegraded()).toBe(outcome === "failure");
  });

  it("does not reuse a pool snapshot's old success when its real store is initialized again", async () => {
    boundary.realTcvdb = true;
    const instance = pool();
    const result = await instance.getStore("repeat", vdb);
    const prior = observe(instance, "repeat");
    expect(prior).toMatchObject({ initStatus: "SUCCEEDED", generation: 1 });
    const next = deferred();
    boundary.databasePlans.push(async () => { await next.promise; return false; });
    const pending = result.store.init();
    try { expect(observe(instance, "repeat")).toMatchObject({ initStatus: "UNKNOWN", generation: 1 }); }
    finally { next.resolve(); await pending; }
    expect(observe(instance, "repeat")).toMatchObject({ initStatus: "UNKNOWN", generation: 1 });
    expect(prior).toMatchObject({ initStatus: "SUCCEEDED" });
    expect(await instance.getStore("repeat", vdb)).toBe(result);
  });

  it("does not bind another initialization attempt's success to an older pool init", async () => {
    boundary.realTcvdb = true;
    const old = deferred();
    boundary.databasePlans.push(async () => { await old.promise; return false; });
    const instance = pool();
    const first = instance.getStore("repeat", vdb);
    try {
      const cached = await instance.getStore("repeat", vdb);
      await cached.store.init();
      expect(initialization(cached.store)).toEqual({ attempt: 2, status: "SUCCEEDED" });
    } finally { old.resolve(); await first; }
    expect(observe(instance, "repeat")).toMatchObject({ initStatus: "UNKNOWN" });
  });

  it("separates a completed new attempt from a sticky prior degraded flag", async () => {
    boundary.databasePlans.push(() => Promise.reject(new Error("first initialization failure")));
    const store = realTcvdb();
    await store.init();
    expect(initialization(store)).toEqual({ attempt: 1, status: "FAILED" });
    await store.init();
    expect(initialization(store)).toEqual({ attempt: 2, status: "SUCCEEDED" });
    expect(store.isDegraded()).toBe(true);
  });

  it("ignores a replaced real store's late degraded result", async () => {
    boundary.realTcvdb = true;
    const old = deferred();
    boundary.databasePlans.push(async () => { await old.promise; throw new Error("old store initialization failed"); });
    const instance = pool();
    const first = instance.getStore("replace", vdb);
    try {
      const replacement = await instance.getStore("replace", { ...vdb, apiKey: "synthetic-rotation" });
      expect(initialization(replacement.store)).toEqual({ attempt: 1, status: "SUCCEEDED" });
      expect(observe(instance, "replace")).toMatchObject({ generation: 2, initStatus: "SUCCEEDED" });
    } finally { old.resolve(); await first; }
    expect(observe(instance, "replace")).toMatchObject({ generation: 2, initStatus: "SUCCEEDED" });
  });
});
afterEach(async () => {
  await Promise.all(pools.splice(0).map(instance => instance.closeAll()));
  expect(boundary.embedding).not.toHaveBeenCalled();
  expect(boundary.kafka).not.toHaveBeenCalled();
  expect(boundary.mkdir).not.toHaveBeenCalled();
  vi.useRealTimers();
});

describe("StorePool nonauthoritative runtime observation", () => {
  it("observes the existing TCVDB-null fallback as SQLite, not configured mode", async () => {
    const instance = pool();
    const result = await instance.getStore("fallback", null);
    expect(result.store).toBe(boundary.stores[0]);
    expect(boundary.stores[0].backend).toBe("sqlite");
    expect(observe(instance, "fallback")).toEqual({
      instanceId: "fallback", generation: 1, configuredMode: "tcvdb",
      constructedBackend: "sqlite", initStatus: "SUCCEEDED",
    });
    expect(Object.keys(result).sort()).toEqual(["bm25Encoder", "embedding", "store"]);
  });

  it("observes the real TCVDB construction branch with supplied config", async () => {
    const instance = pool();
    const result = await instance.getStore("tenant", vdb);
    expect(result.store).toBe(boundary.stores[0]);
    expect(boundary.stores[0].backend).toBe("tcvdb");
    expect(observe(instance, "tenant")).toMatchObject({
      instanceId: "tenant", configuredMode: "tcvdb",
      constructedBackend: "tcvdb", initStatus: "SUCCEEDED",
    });
  });

  it("retains SQLite selection even when VDB config is supplied", async () => {
    const instance = pool("sqlite");
    const result = await instance.getStore("tenant", vdb);
    expect(boundary.stores[0].backend).toBe("sqlite");
    expect(result.store).toBe(boundary.stores[0]);
    expect(observe(instance, "tenant")).toMatchObject({
      configuredMode: "sqlite", constructedBackend: "sqlite", initStatus: "SUCCEEDED",
    });
  });

  it("keeps concurrent cache hits UNKNOWN and preserves early cached return identity", async () => {
    const init = deferred();
    boundary.plans.push(() => init.promise);
    const instance = pool();
    const first = instance.getStore("tenant", vdb);
    try {
      const cached = await instance.getStore("tenant", vdb);
      expect(cached.store).toBe(boundary.stores[0]);
      expect(boundary.stores).toHaveLength(1);
      expect(boundary.stores[0].init).toHaveBeenCalledTimes(1);
      const pending = observe(instance, "tenant");
      expect(pending).toMatchObject({ initStatus: "UNKNOWN", generation: 1 });
      init.resolve();
      expect(await first).toBe(cached);
      expect(observe(instance, "tenant")).toMatchObject({ initStatus: "SUCCEEDED", generation: 1 });
      expect(pending?.initStatus).toBe("UNKNOWN");
    } finally { init.resolve(); await first; }
  });

  it.each(["async rejection", "synchronous throw"])("records FAILED after %s without changing swallowed-init behavior", async kind => {
    boundary.plans.push(() => {
      if (kind === "synchronous throw") throw new Error("synthetic init failure");
      return Promise.reject(new Error("synthetic init failure"));
    });
    const instance = pool();
    const result = await instance.getStore("tenant", vdb);
    expect(result.store).toBe(boundary.stores[0]);
    expect(await instance.getStore("tenant", vdb)).toBe(result);
    expect(boundary.stores[0].init).toHaveBeenCalledTimes(1);
    expect(observe(instance, "tenant")).toMatchObject({ initStatus: "FAILED" });
  });

  it("leaves no observation when construction throws and preserves the same rejection", async () => {
    const instance = pool();
    const error = new Error("synthetic constructor failure");
    boundary.constructorError = error;
    await expect(instance.getStore("tenant", vdb)).rejects.toBe(error);
    expect(instance.has("tenant")).toBe(false);
    expect(observe(instance, "tenant")).toBeNull();
  });

  it("does not create an entry or synthesize identity for a missing query", () => {
    const instance = pool();
    expect(observe(instance, "absent")).toBeNull();
    expect(instance.size).toBe(0);
    expect(boundary.stores).toHaveLength(0);
  });

  it("advances generation only on reconstruction, retaining the existing fingerprint rules", async () => {
    const instance = pool();
    const first = await instance.getStore("tenant", vdb);
    const before = observe(instance, "tenant");
    // Username is deliberately not part of the existing fingerprint.
    expect(await instance.getStore("tenant", { ...vdb, user: "changed-user" })).toBe(first);
    expect(observe(instance, "tenant")).toEqual(before);
    const replacement = await instance.getStore("tenant", { ...vdb, apiKey: "synthetic-rotated-key" });
    expect(replacement).not.toBe(first);
    expect(boundary.stores[0].close).toHaveBeenCalledTimes(1);
    expect(observe(instance, "tenant")).toMatchObject({ generation: 2, initStatus: "SUCCEEDED" });
  });

  it.each(["success", "failure"])("ignores old generation async %s after replacement", async outcome => {
    const old = deferred();
    const next = deferred();
    boundary.plans.push(() => old.promise, () => next.promise);
    const instance = pool();
    const first = instance.getStore("tenant", vdb);
    const replacement = instance.getStore("tenant", { ...vdb, apiKey: "synthetic-rotated-key" });
    try {
      // Existing replacement path awaits closeEntry before inserting the new entry.
      await Promise.resolve();
      expect(observe(instance, "tenant")).toMatchObject({ generation: 2, initStatus: "UNKNOWN" });
      if (outcome === "success") old.resolve(); else old.reject(new Error("old init failure"));
      await first;
      expect(observe(instance, "tenant")).toMatchObject({ generation: 2, initStatus: "UNKNOWN" });
      if (outcome === "success") next.reject(new Error("new init failure")); else next.resolve();
      await replacement;
      expect(observe(instance, "tenant")).toMatchObject({
        generation: 2, initStatus: outcome === "success" ? "FAILED" : "SUCCEEDED",
      });
    } finally { old.resolve(); next.resolve(); await Promise.all([first, replacement]); }
  });

  it("removes pending entries on eviction and never resurrects them on late completion", async () => {
    const init = deferred();
    boundary.plans.push(() => init.promise);
    const instance = pool();
    const pending = instance.getStore("tenant", vdb);
    try {
      await instance.evict("tenant");
      expect(observe(instance, "tenant")).toBeNull();
      init.resolve(); await pending;
      expect(observe(instance, "tenant")).toBeNull();
      await instance.getStore("tenant", vdb);
      expect(observe(instance, "tenant")).toMatchObject({ generation: 2 });
    } finally { init.resolve(); await pending; }
  });

  it("preserves LRU refresh and eviction while retiring the matching observation", async () => {
    const instance = pool("sqlite", 2);
    const now = vi.spyOn(Date, "now");
    now.mockReturnValue(1); const a = await instance.getStore("a", null);
    now.mockReturnValue(2); await instance.getStore("b", null);
    now.mockReturnValue(3); expect(await instance.getStore("a", null)).toBe(a);
    now.mockReturnValue(4); await instance.getStore("c", null);
    expect(instance.size).toBe(2);
    expect(observe(instance, "a")).toMatchObject({ generation: 1 });
    expect(observe(instance, "b")).toBeNull();
    expect(observe(instance, "c")).toMatchObject({ generation: 3 });
    expect(boundary.stores[1].close).toHaveBeenCalledTimes(1);
  });

  it("invalidates observation immediately while preserving delayed close and shutdown waiting", async () => {
    vi.useFakeTimers();
    const instance = pool();
    instance.setGraceCloseDelay(100);
    await instance.getStore("tenant", vdb);
    await instance.evict("tenant");
    const closing = instance.closeAll();
    let closed = false;
    void closing.then(() => { closed = true; });
    try {
      expect(observe(instance, "tenant")).toBeNull();
      expect(boundary.stores[0].close).not.toHaveBeenCalled();
      expect(closed).toBe(false);
    } finally { await vi.advanceTimersByTimeAsync(100); await closing; }
    expect(closed).toBe(true);
    expect(boundary.stores[0].close).toHaveBeenCalledTimes(1);
  });

  it("clears all current observations on shutdown without recycling generations", async () => {
    const init = deferred();
    boundary.plans.push(() => init.promise);
    const instance = pool();
    const first = instance.getStore("tenant", vdb);
    try {
      await instance.closeAll();
      init.resolve(); await first;
      expect(observe(instance, "tenant")).toBeNull();
      await instance.getStore("tenant", vdb);
      expect(observe(instance, "tenant")).toMatchObject({ generation: 2 });
    } finally { init.resolve(); await first; }
  });

  it("returns frozen detached scalar snapshots without sensitive or authority fields", async () => {
    const instance = pool();
    await instance.getStore("tenant", vdb);
    const snapshot = observe(instance, "tenant");
    expect(snapshot).toEqual({
      instanceId: "tenant", generation: 1, configuredMode: "tcvdb",
      constructedBackend: "tcvdb", initStatus: "SUCCEEDED",
    });
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Reflect.set(snapshot!, "initStatus", "FAILED")).toBe(false);
    expect(observe(instance, "tenant")).toEqual(snapshot);
    expect(observe(instance, "tenant")).not.toBe(snapshot);
    const serialized = JSON.stringify(snapshot);
    for (const sensitive of [vdb.url, vdb.user, vdb.apiKey, vdb.database,
      "configFingerprint", "store", "embedding", "issuer", "verified", "qualification"]) {
      expect(serialized).not.toContain(sensitive);
    }
  });

  it("keeps observations scoped to their actual pool rather than another pool's cache key", async () => {
    const first = pool();
    const second = pool("sqlite");
    await first.getStore("tenant", vdb);
    expect(observe(second, "tenant")).toBeNull();
    await second.getStore("tenant", null);
    await first.evict("tenant");
    expect(observe(first, "tenant")).toBeNull();
    expect(observe(second, "tenant")).toMatchObject({ configuredMode: "sqlite", generation: 1 });
  });
});
