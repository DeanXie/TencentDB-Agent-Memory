import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import { describe, expect, it } from "vitest";

// Execute complete current Gateway, State Factory, LocalStateBackend and
// InstanceConfigProvider sources. Only private Redis/client and unrelated
// service boundaries are synthetic; no Gateway.start(), sockets or real I/O.
function evaluate(relative: string, dependencies: Record<string, unknown>) {
  const filename = fileURLToPath(new URL(relative, import.meta.url));
  const compiled = ts.transpileModule(readFileSync(filename, "utf8"), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true },
    fileName: filename,
  }).outputText;
  const module = { exports: {} as any };
  const load = (id: string) => {
    if (!Object.prototype.hasOwnProperty.call(dependencies, id)) return Object.freeze({});
    const value = dependencies[id];
    if (value instanceof Error) throw value;
    return value;
  };
  runInNewContext("(function(exports, require, module, process) {" + compiled + "\n})",
    { Error, console, setTimeout, clearTimeout }, { filename })(module.exports, load, module,
    { env: { STORE_MODE: "sqlite" }, argv: [] });
  return module.exports;
}

function deferred() {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fixture(mode: "standalone" | "service" = "standalone", backend?: "local" | "redis") {
  const calls = { stateImports: 0, factory: 0, redisImports: 0, clients: 0, initialized: 0,
    destroyed: 0, adapters: 0, stores: 0, scanners: 0, workers: 0, coreDestroyed: 0 };
  const order: string[] = [];
  const factoryArguments: any[] = [];
  const instances: any[] = [];
  const control = {
    stateModuleError: null as Error | null,
    redisModuleError: null as Error | null,
    adapterError: null as Error | null,
    initialize: (() => Promise.resolve()) as () => Promise<void>,
    destroy: (() => Promise.resolve()) as () => Promise<void>,
    returnInstance: undefined as object | undefined,
  };
  const stateTypes = evaluate("../core/state/types.ts", {});
  const local = evaluate("../core/state/local-backend.ts", { "./types.js": stateTypes });
  class SyntheticRedisClient {
    constructor(readonly options: unknown) { calls.clients++; order.push("client"); }
  }
  class SyntheticRedisStateBackend {
    readonly secret = "synthetic-redis-secret";
    constructor(readonly options: unknown) {
      instances.push(this); order.push("redis-constructed");
      if (control.returnInstance) return control.returnInstance as SyntheticRedisStateBackend;
    }
    async initialize() { calls.initialized++; order.push("initialize"); await control.initialize(); }
    async destroy() { calls.destroyed++; order.push("destroy"); await control.destroy(); }
  }
  const factoryDependencies: Record<string, unknown> = {
    "./types.js": stateTypes, "./local-backend.js": local, ioredis: SyntheticRedisClient,
  };
  Object.defineProperty(factoryDependencies, "../../integrations/redis/index.js", { get() {
    calls.redisImports++;
    if (control.redisModuleError) throw control.redisModuleError;
    return { RedisStateBackend: SyntheticRedisStateBackend };
  } });
  const realFactory = evaluate("../core/state/index.ts", factoryDependencies);
  const provider = evaluate("../core/instance-config-provider.ts", {
    "../utils/env-config.js": { readVdbEnvConfig: () => { throw new Error("Unexpected VDB read"); }, readCosEnvConfig: () => null },
  });
  const config = {
    deployMode: mode, stateBackend: backend, data: { baseDir: "unused-state-fixture" }, llm: {},
    memory: { capture: { excludeAgents: [] } }, worker: { concurrency: 1, pollMs: 50 },
    scanner: { instances: "synthetic-instance", intervalMs: 50 },
    redis: { host: "synthetic.invalid", port: 6379, password: "synthetic-password", db: 2, keyPrefix: "synthetic" },
    shark: { baseUrl: "https://synthetic.invalid", vdbTtlMs: 10_000, cosBufferMs: 10, maxInstances: 5 },
    observability: { kafka: { brokers: "", topic: "", enabled: false } },
  };
  const logger = { debug() {}, info() {}, warn() {}, error() {} };
  const dependencies: Record<string, unknown> = {
    "./config.js": { loadGatewayConfig: () => config, parseBrokers: () => [] },
    "../core/tdai-core.js": { TdaiCore: class { async destroy() { calls.coreDestroyed++; } } },
    "../adapters/standalone/host-adapter.js": { StandaloneHostAdapter: class {} },
    "../services/worker-permit-pool.js": { WorkerPermitPool: class {} },
    "../utils/session-filter.js": { SessionFilter: class {} },
    "../utils/env-config.js": { resolveMaxBodyBytes: () => 1024 },
    "../core/instance-config-provider.js": provider,
    "../integrations/factory.js": { createAdapterDeps() {
      calls.adapters++; order.push("adapter");
      if (control.adapterError) throw control.adapterError;
      return { configSource: { async fetchVdb() { throw new Error("Unexpected source read"); }, async fetchCos() { return null; } }, quotaReporter: {} };
    } },
    "../core/quota/index.js": { QuotaManager: class {} },
    "../core/store/store-pool.js": { StorePool: class {
      mode = "sqlite";
      constructor() { calls.stores++; order.push("store"); }
      setGraceCloseDelay() {}
      async closeAll() {}
    } },
    "../utils/pipeline-factory.js": { createStatefulPipelineManager: () => ({ advanceL2TimerAfterL1() {}, armL2MaxInterval() {} }) },
    "../services/timer-scanner.js": { TimerScanner: class {
      async start() { calls.scanners++; order.push("scanner"); }
      async stop() {}
    } },
    "../services/pipeline-worker.js": { PipelineWorker: class {
      async start() { calls.workers++; order.push("worker"); }
      async stop() {}
    } },
    "../core/report/traced-task-executor.js": { TracedTaskExecutor: class {} },
    "../core/report/otel-sdk-init.js": { async shutdownOTelSDK() {} },
  };
  Object.defineProperty(dependencies, "../core/state/index.js", { get() {
    calls.stateImports++;
    if (control.stateModuleError) throw control.stateModuleError;
    return { ...realFactory, createStateBackend(options: unknown) {
      calls.factory++; factoryArguments.push(options); order.push("factory");
      return realFactory.createStateBackend(options);
    } };
  } });
  const { TdaiGateway } = evaluate("./server.ts", dependencies);
  const gateway = new TdaiGateway();
  gateway.logger = logger;
  gateway.initSharedCosClient = async () => {};
  return { gateway, calls, order, factoryArguments, instances, control, local, config,
    select: () => gateway.startIntegratedServices() as Promise<void>,
    observe: () => gateway.getStateBackendObservation(),
  };
}

async function waitForInitialization(f: ReturnType<typeof fixture>, count = 1) {
  for (let i = 0; i < 60 && f.calls.initialized < count; i++) await Promise.resolve();
  expect(f.calls.initialized).toBe(count);
}

describe("State Backend nonauthoritative runtime observation", () => {
  it("does not infer a constructed local instance before selection or invoke the factory from its getter", () => {
    const f = fixture();
    expect(f.observe()).toEqual({ configuredStateBackend: "UNKNOWN", constructedStateBackend: "UNKNOWN", selectionStatus: "UNKNOWN" });
    expect(f.calls.factory).toBe(0); expect(f.calls.stateImports).toBe(0);
  });
  it("observes the standalone default through the real local factory and preserves downstream order", async () => {
    const f = fixture(); await f.select();
    expect(f.observe()).toEqual({ configuredStateBackend: "local", constructedStateBackend: "local", selectionStatus: "ACCEPTED" });
    expect(f.gateway.stateBackend).toBeInstanceOf(f.local.LocalStateBackend);
    expect(f.factoryArguments[0].type).toBe("local");
    expect(typeof f.factoryArguments[0].local.onTimerExpired).toBe("function");
    expect(f.factoryArguments[0].redis).toBeUndefined();
    expect(f.order).toEqual(["factory", "adapter", "store", "scanner", "worker"]);
    expect(f.calls.factory).toBe(1); expect(f.calls.clients).toBe(0);
  });
  it("uses the service redis default without presenting the private implementation as proven", async () => {
    const f = fixture("service"); await f.select();
    expect(f.observe()).toEqual({ configuredStateBackend: "redis", constructedStateBackend: "UNKNOWN", selectionStatus: "ACCEPTED" });
    expect(f.gateway.stateBackend).toBe(f.instances[0]);
    expect(f.order).toEqual(["factory", "client", "redis-constructed", "initialize", "adapter", "store", "scanner", "worker"]);
    expect(f.calls.clients).toBe(1); expect(f.calls.initialized).toBe(1);
  });
  it("honors explicit local in service mode and does not construct a redis client", async () => {
    const f = fixture("service", "local"); await f.select();
    expect(f.observe()).toMatchObject({ configuredStateBackend: "local", constructedStateBackend: "local", selectionStatus: "ACCEPTED" });
    expect(f.gateway.stateBackend).toBeInstanceOf(f.local.LocalStateBackend);
    expect(f.calls.redisImports).toBe(0); expect(f.calls.clients).toBe(0);
  });
  it("honors explicit redis in standalone without silently substituting local", async () => {
    const f = fixture("standalone", "redis"); await f.select();
    expect(f.observe()).toMatchObject({ configuredStateBackend: "redis", constructedStateBackend: "UNKNOWN", selectionStatus: "ACCEPTED" });
    expect(f.gateway.stateBackend).toBe(f.instances[0]);
    expect(f.factoryArguments[0].local).toBeUndefined();
    expect(f.factoryArguments[0].redis).toEqual(f.config.redis);
  });
  it("does not copy the redis request label when the actual accepted result is a built-in local instance", async () => {
    const f = fixture("standalone", "redis");
    const actualLocal = new f.local.LocalStateBackend(); f.control.returnInstance = actualLocal;
    await f.select();
    expect(f.gateway.stateBackend).toBe(actualLocal);
    expect(f.observe()).toMatchObject({ configuredStateBackend: "redis", constructedStateBackend: "local", selectionStatus: "ACCEPTED" });
  });
  it("keeps an already constructed redis boundary instance UNKNOWN while real factory initialization awaits", async () => {
    const f = fixture("standalone", "redis"); const hold = deferred(); f.control.initialize = () => hold.promise;
    const running = f.select(); await waitForInitialization(f);
    expect(f.instances).toHaveLength(1); expect(f.gateway.stateBackend).toBeNull();
    const pending = f.observe();
    expect(pending).toEqual({ configuredStateBackend: "redis", constructedStateBackend: "UNKNOWN", selectionStatus: "UNKNOWN" });
    expect(f.calls.adapters).toBe(0);
    hold.resolve(); await running;
    expect(f.gateway.stateBackend).toBe(f.instances[0]); expect(f.observe().selectionStatus).toBe("ACCEPTED");
    expect(pending.selectionStatus).toBe("UNKNOWN");
  });
  it("preserves the original initialization rejection and never starts downstream services", async () => {
    const f = fixture("standalone", "redis"); const failure = new Error("synthetic-initialization-rejection");
    f.control.initialize = () => Promise.reject(failure);
    await expect(f.select()).rejects.toBe(failure);
    expect(f.observe()).toMatchObject({ configuredStateBackend: "redis", constructedStateBackend: "UNKNOWN", selectionStatus: "UNKNOWN" });
    expect(f.gateway.stateBackend).toBeNull(); expect(f.calls.adapters).toBe(0);
    expect(f.calls.stores).toBe(0); expect(f.calls.workers).toBe(0);
  });
  it.each(["standalone", "service"] as const)("keeps the real missing-redis fail-fast in %s rather than adding fallback", async mode => {
    const f = fixture(mode, "redis"); f.control.redisModuleError = new Error("synthetic-module-unavailable");
    await expect(f.select()).rejects.toThrow("Redis integration is not available");
    expect(f.observe()).toMatchObject({ configuredStateBackend: "redis", constructedStateBackend: "UNKNOWN", selectionStatus: "UNKNOWN" });
    expect(f.gateway.stateBackend).toBeNull(); expect(f.calls.clients).toBe(0); expect(f.calls.adapters).toBe(0);
  });
  it("does not reinterpret a factory module loading failure as a successful selection", async () => {
    const f = fixture(); const failure = new Error("synthetic-state-module-error"); f.control.stateModuleError = failure;
    await expect(f.select()).rejects.toBe(failure);
    expect(f.observe()).toMatchObject({ configuredStateBackend: "local", constructedStateBackend: "UNKNOWN", selectionStatus: "UNKNOWN" });
    expect(f.calls.factory).toBe(0); expect(f.calls.adapters).toBe(0);
  });
  it("preserves rejection of a private constructor result without the required initialize method", async () => {
    const f = fixture("standalone", "redis"); f.control.returnInstance = {};
    await expect(f.select()).rejects.toThrow();
    expect(f.observe().selectionStatus).toBe("UNKNOWN");
    expect(f.gateway.stateBackend).toBeNull(); expect(f.calls.adapters).toBe(0);
  });
  it("does not promote factory acceptance of a minimally shaped object into implementation or health proof", async () => {
    const f = fixture("standalone", "redis"); const value = { async initialize() {} }; f.control.returnInstance = value;
    await f.select(); expect(f.gateway.stateBackend).toBe(value);
    expect(f.observe()).toEqual({ configuredStateBackend: "redis", constructedStateBackend: "UNKNOWN", selectionStatus: "ACCEPTED" });
  });
  it("does not make failed identity inspection a new business exception", async () => {
    const f = fixture("standalone", "redis");
    const value = new Proxy({ async initialize() {} }, { getPrototypeOf() { throw new Error("synthetic-inspection-denied"); } });
    f.control.returnInstance = value; await f.select();
    expect(f.gateway.stateBackend).toBe(value);
    expect(f.observe()).toMatchObject({ constructedStateBackend: "UNKNOWN", selectionStatus: "ACCEPTED" });
    expect(f.calls.workers).toBe(1);
  });
  it("replaces a previous acceptance with UNKNOWN when a later real factory attempt fails", async () => {
    const f = fixture(); await f.select(); const previous = f.observe(); const backend = f.gateway.stateBackend;
    f.config.stateBackend = "redis"; f.control.redisModuleError = new Error("synthetic-retry-failure");
    await expect(f.select()).rejects.toThrow("Redis integration is not available");
    expect(f.gateway.stateBackend).toBe(backend);
    expect(f.observe()).toEqual({ configuredStateBackend: "redis", constructedStateBackend: "UNKNOWN", selectionStatus: "UNKNOWN" });
    expect(previous.selectionStatus).toBe("ACCEPTED"); expect(f.calls.factory).toBe(2);
  });
  it("follows actual repeated-startup instance replacement without changing prior snapshots", async () => {
    const f = fixture(); await f.select(); const previous = f.observe(); const backend = f.gateway.stateBackend;
    await f.select();
    expect(f.gateway.stateBackend).not.toBe(backend); expect(f.observe()).not.toBe(previous);
    expect(f.observe()).toEqual(previous); expect(f.calls.factory).toBe(2);
  });
  it("follows the original concurrent assignment order instead of inventing stale-result suppression", async () => {
    const f = fixture("standalone", "redis"); const hold = deferred(); f.control.initialize = () => hold.promise;
    const first = f.select(); await waitForInitialization(f);
    f.control.initialize = () => Promise.resolve(); await f.select();
    const newer = f.gateway.stateBackend; const newerSnapshot = f.observe();
    hold.resolve(); await first;
    expect(f.gateway.stateBackend).toBe(f.instances[0]); expect(f.gateway.stateBackend).not.toBe(newer);
    expect(f.observe()).not.toBe(newerSnapshot); expect(f.observe().selectionStatus).toBe("ACCEPTED");
    expect(f.calls.factory).toBe(2);
  });
  it("does not reuse an observation after an unobserved backend reference replacement", async () => {
    const f = fixture(); await f.select(); f.gateway.stateBackend = new f.local.LocalStateBackend();
    expect(f.observe()).toEqual({ configuredStateBackend: "UNKNOWN", constructedStateBackend: "UNKNOWN", selectionStatus: "UNKNOWN" });
  });
  it("invalidates acceptance before the original asynchronous destroy finishes", async () => {
    const f = fixture("standalone", "redis"); await f.select();
    const hold = deferred(); f.control.destroy = () => hold.promise;
    const stopping = f.gateway.stop();
    for (let i = 0; i < 30 && !f.calls.destroyed; i++) await Promise.resolve();
    expect(f.calls.destroyed).toBe(1); expect(f.observe().selectionStatus).toBe("UNKNOWN");
    hold.resolve(); await stopping;
    expect(f.observe().selectionStatus).toBe("UNKNOWN"); expect(f.calls.coreDestroyed).toBe(1);
  });
  it("preserves destroy rejection without retaining accepted observation", async () => {
    const f = fixture("standalone", "redis"); await f.select(); const failure = new Error("synthetic-destroy-error");
    f.control.destroy = () => Promise.reject(failure);
    await expect(f.gateway.stop()).rejects.toBe(failure);
    expect(f.observe().selectionStatus).toBe("UNKNOWN"); expect(f.calls.coreDestroyed).toBe(0);
  });
  it("keeps State acceptance separate from a later ConfigProvider failure", async () => {
    const f = fixture("service", "local"); f.control.adapterError = new Error("synthetic-adapter-rejection");
    await expect(f.select()).rejects.toThrow("deployMode=service requires src/integrations/");
    expect(f.observe()).toEqual({ configuredStateBackend: "local", constructedStateBackend: "local", selectionStatus: "ACCEPTED" });
    expect(f.gateway.getConfigProviderObservation().selectionStatus).toBe("UNKNOWN");
    expect(f.calls.stores).toBe(0);
  });
  it("observes one Gateway-wide backend while real LocalStateBackend retains scope isolation", async () => {
    const f = fixture(); await f.select(); const backend = f.gateway.stateBackend;
    await backend.appendBuffer("instance", "session", "synthetic-a", "team-a", "agent");
    await backend.appendBuffer("instance", "session", "synthetic-b", "team-b", "agent");
    expect(await backend.getBufferLength("instance", "session", "team-a", "agent")).toBe(1);
    expect(await backend.getBufferLength("instance", "session", "team-b", "agent")).toBe(1);
    expect(f.gateway.stateBackend).toBe(backend); expect(f.calls.factory).toBe(1);
    expect(f.observe().constructedStateBackend).toBe("local");
  });
  it("returns only frozen scalar diagnostics without reading backend secrets or triggering new work", async () => {
    const f = fixture(); await f.select(); let reads = 0;
    for (const key of ["password", "host", "constructor"]) Object.defineProperty(f.gateway.stateBackend, key, {
      get() { reads++; throw new Error("Unexpected sensitive property read"); },
    });
    const snapshot = f.observe();
    expect(Object.keys(snapshot).sort()).toEqual(["configuredStateBackend", "constructedStateBackend", "selectionStatus"]);
    expect(Object.values(snapshot).every(value => typeof value === "string")).toBe(true);
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(() => { snapshot.constructedStateBackend = "redis"; }).toThrow();
    expect(JSON.stringify(snapshot)).not.toContain("synthetic");
    expect(reads).toBe(0); expect(f.calls.factory).toBe(1);
  });
});
