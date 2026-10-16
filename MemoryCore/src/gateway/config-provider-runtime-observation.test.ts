import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import { describe, expect, it } from "vitest";

// Execute the complete current source, not a copied selection algorithm. A
// closed CommonJS loader isolates imports (including the absent private
// integrations submodule). Actual Gateway constructor/selection and actual
// InstanceConfigProvider/LocalConfigSource run; no HTTP/start() or real I/O.
function evaluate(relative: string, dependencies: Record<string, unknown>) {
  const filename = fileURLToPath(new URL(relative, import.meta.url));
  const source = readFileSync(filename, "utf8");
  const compiled = ts.transpileModule(source, { compilerOptions: {
    target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS,
    esModuleInterop: true,
  }, fileName: filename }).outputText;
  const module = { exports: {} as any };
  const load = (id: string) => {
    if (id in dependencies) {
      const value = dependencies[id];
      if (value instanceof Error) throw value;
      return value;
    }
    // Unused imports have no capabilities; unexpected use throws naturally.
    return Object.freeze({});
  };
  runInNewContext("(function(exports, require, module, process) {" + compiled + "\n})",
    { Error, console }, { filename })(module.exports, load, module,
    { env: { STORE_MODE: "sqlite" }, argv: [] });
  return module.exports;
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
class SyntheticSource {
  readonly secret = "synthetic-do-not-observe";
  fetches = 0;
  async fetchVdb() {
    this.fetches++;
    return { url: "https://synthetic.invalid", user: "fixture", apiKey: this.secret, database: "fixture" };
  }
  async fetchCos() { return null; }
}
function fixture(mode: "standalone" | "service" = "standalone") {
  const calls = { imports: 0, factory: 0, stores: 0, scanners: 0, workers: 0, providerLogs: 0 };
  const source = new SyntheticSource();
  const reporter = {};
  const state = { plan: (() => ({ configSource: source, quotaReporter: reporter })) as () => any,
    importError: null as Error | null, factoryArguments: [] as any[] };
  const logger = { debug() {}, info(message: string) {
    if (message.includes("InstanceConfigProvider initialized")) calls.providerLogs++;
  }, warn() {}, error() {} };
  const actualProvider = evaluate("../core/instance-config-provider.ts", {
    "../utils/env-config.js": {
      readVdbEnvConfig: () => ({ url: "https://local.invalid", user: "local", apiKey: "local-fixture-secret", database: "local" }),
      readCosEnvConfig: () => null,
    },
  });
  const config = { deployMode: mode, stateBackend: "local", data: { baseDir: "unused-fixture" },
    llm: {}, memory: { capture: { excludeAgents: [] } }, worker: { concurrency: 1, pollMs: 50 },
    scanner: { instances: "fixture", intervalMs: 50 },
    shark: { baseUrl: "https://sensitive.invalid", vdbTtlMs: 10_000, cosBufferMs: 10, maxInstances: 5 },
    observability: { kafka: { brokers: "", topic: "", enabled: false } } };
  const dependencies: Record<string, unknown> = {
    "./config.js": { loadGatewayConfig: () => config, parseBrokers: () => [] },
    "../core/tdai-core.js": { TdaiCore: class {} },
    "../adapters/standalone/host-adapter.js": { StandaloneHostAdapter: class {} },
    "../services/worker-permit-pool.js": { WorkerPermitPool: class {} },
    "../utils/session-filter.js": { SessionFilter: class {} },
    "../utils/env-config.js": { resolveMaxBodyBytes: () => 1024 },
    "../core/instance-config-provider.js": actualProvider,
    "../core/state/index.js": { createStateBackend: async () => ({}) },
    "../core/quota/noop-quota-reporter.js": { NoopQuotaReporter: class {} },
    "../core/quota/index.js": { QuotaManager: class {} },
    "../core/store/store-pool.js": { StorePool: class { mode = "sqlite"; constructor() { calls.stores++; } } },
    "../utils/pipeline-factory.js": { createStatefulPipelineManager: () => ({
      advanceL2TimerAfterL1() {}, armL2MaxInterval() {},
    }) },
    "../services/timer-scanner.js": { TimerScanner: class { async start() { calls.scanners++; } } },
    "../services/pipeline-worker.js": { PipelineWorker: class { async start() { calls.workers++; } } },
    "../core/report/traced-task-executor.js": { TracedTaskExecutor: class {} },
  };
  Object.defineProperty(dependencies, "../integrations/factory.js", { enumerable: true, get() {
    calls.imports++;
    if (state.importError) throw state.importError;
    return { createAdapterDeps: (args: any) => {
      calls.factory++; state.factoryArguments.push(args); return state.plan();
    } };
  } });
  const { TdaiGateway } = evaluate("./server.ts", dependencies);
  const gateway = new TdaiGateway();
  gateway.logger = logger;
  // This method crosses into COS I/O after provider acceptance in service mode.
  gateway.initSharedCosClient = async () => {};
  return { gateway, calls, source, state, actualProvider, config,
    select: () => gateway.startIntegratedServices() as Promise<void>,
    observe: () => gateway.getConfigProviderObservation(),
  };
}
async function waitForFactory(f: ReturnType<typeof fixture>, count = 1) {
  for (let i = 0; i < 30 && f.calls.factory < count; i++) await Promise.resolve();
  expect(f.calls.factory).toBe(count);
}
const acceptedFactory = { factoryStatus: "RETURNED", selectionStatus: "ACCEPTED", selectedSource: "FACTORY_UNVERIFIED" };
const acceptedFallback = { factoryStatus: "THREW", selectionStatus: "ACCEPTED", selectedSource: "BUILTIN_LOCAL_FALLBACK" };

describe("ConfigProvider nonauthoritative runtime observation", () => {
  it("keeps an unattempted selection UNKNOWN without loading a factory", () => {
    const f = fixture();
    expect(f.observe()).toEqual({ configuredDeployMode: "standalone", factoryCallAttempted: false, factoryStatus: "UNKNOWN",
      selectionStatus: "UNKNOWN", selectedSource: "UNKNOWN" });
    expect(f.calls.imports).toBe(0);
  });
  it("records the factory source only after the real provider accepts it", async () => {
    const f = fixture(); await f.select();
    expect(f.observe()).toEqual({ configuredDeployMode: "standalone", factoryCallAttempted: true, ...acceptedFactory });
    expect(f.gateway.configProvider).toBeInstanceOf(f.actualProvider.InstanceConfigProvider);
    expect((await f.gateway.configProvider.resolveVdb("fixture")).database).toBe("fixture");
    expect(f.source.fetches).toBe(1);
    expect(f.calls).toMatchObject({ imports: 1, factory: 1, providerLogs: 1, stores: 1, scanners: 1, workers: 1 });
    expect(f.state.factoryArguments[0]).toMatchObject({ deployMode: "standalone", sharkBaseUrl: "https://sensitive.invalid" });
  });
  it("leaves an asynchronous factory UNKNOWN until it resolves", async () => {
    const f = fixture(); const hold = deferred<any>(); f.state.plan = () => hold.promise;
    const running = f.select(); await waitForFactory(f);
    const before = f.observe();
    expect(before).toMatchObject({ factoryStatus: "PENDING", selectionStatus: "UNKNOWN", selectedSource: "UNKNOWN" });
    expect(f.gateway.configProvider).toBeNull();
    hold.resolve({ configSource: f.source, quotaReporter: {} }); await running;
    expect(f.observe()).toMatchObject(acceptedFactory);
    expect(before.selectionStatus).toBe("UNKNOWN");
  });
  it("falls back to the real LocalConfigSource only after standalone factory rejection", async () => {
    const f = fixture(); f.state.plan = async () => { throw new Error("fixture-rejection"); };
    await f.select(); expect(f.observe()).toMatchObject(acceptedFallback);
    expect(f.gateway.configProvider.source).toBeInstanceOf(f.actualProvider.LocalConfigSource);
    expect((await f.gateway.configProvider.resolveVdb("fixture")).database).toBe("local");
    expect(f.calls.factory).toBe(1); expect(f.source.fetches).toBe(0);
  });
  it("records import failure separately from a factory call and accepts standalone fallback", async () => {
    const f = fixture(); f.state.importError = new Error("fixture-module-unavailable");
    await f.select(); expect(f.observe()).toMatchObject(acceptedFallback);
    expect(f.calls.imports).toBe(1); expect(f.calls.factory).toBe(0);
  });
  it("preserves service fail-fast after factory rejection without provider or downstream creation", async () => {
    const f = fixture("service"); f.state.plan = async () => { throw new Error("fixture-rejection"); };
    await expect(f.select()).rejects.toThrow("deployMode=service requires src/integrations/");
    expect(f.observe()).toEqual({ configuredDeployMode: "service", factoryCallAttempted: true, factoryStatus: "THREW", selectionStatus: "UNKNOWN", selectedSource: "UNKNOWN" });
    expect(f.gateway.configProvider).toBeNull();
    expect(f.calls).toMatchObject({ factory: 1, providerLogs: 0, stores: 0, scanners: 0, workers: 0 });
  });
  it("preserves service fail-fast on module loading failure without calling the factory", async () => {
    const f = fixture("service"); f.state.importError = new Error("fixture-module-unavailable");
    await expect(f.select()).rejects.toThrow("fixture-module-unavailable");
    expect(f.observe()).toMatchObject({ factoryStatus: "THREW", selectedSource: "UNKNOWN" });
    expect(f.calls.factory).toBe(0); expect(f.calls.providerLogs).toBe(0);
  });
  it("does not infer builtin Local from the standalone deployment target", async () => {
    const f = fixture(); await f.select();
    expect(f.observe()).toMatchObject({ configuredDeployMode: "standalone", selectedSource: "FACTORY_UNVERIFIED" });
    expect(f.gateway.configProvider.source).toBe(f.source);
  });
  it("does not label factory-provided LocalConfigSource as fallback", async () => {
    const f = fixture(); const local = new f.actualProvider.LocalConfigSource({ info() {} });
    f.state.plan = () => ({ configSource: local, quotaReporter: {} });
    await f.select(); expect(f.observe()).toMatchObject(acceptedFactory);
    expect(f.gateway.configProvider.source).toBe(local);
  });
  it("does not turn an invalid factory return into a new standalone fallback rule", async () => {
    const f = fixture(); f.state.plan = () => undefined;
    await expect(f.select()).rejects.toThrow();
    expect(f.observe()).toMatchObject({ factoryStatus: "RETURNED", selectionStatus: "UNKNOWN", selectedSource: "UNKNOWN" });
    expect(f.calls.providerLogs).toBe(0); expect(f.gateway.configProvider).toBeNull();
  });
  it("preserves constructor rejection of a null source outside the factory catch", async () => {
    const f = fixture(); f.state.plan = () => ({ configSource: null, quotaReporter: {} });
    await expect(f.select()).rejects.toThrow();
    expect(f.observe()).toMatchObject({ factoryStatus: "RETURNED", selectionStatus: "UNKNOWN", selectedSource: "UNKNOWN" });
    expect(f.calls.factory).toBe(1); expect(f.gateway.configProvider).toBeNull();
  });
  it("does not upgrade constructor acceptance of a malformed source into evidence of usability", async () => {
    const f = fixture(); f.state.plan = () => ({ configSource: {}, quotaReporter: {} });
    await f.select(); expect(f.observe()).toMatchObject(acceptedFactory);
    await expect(f.gateway.configProvider.resolveVdb("fixture")).rejects.toThrow();
    expect(f.calls.factory).toBe(1);
  });
  it("retains real source and selection on cache invalidation and refresh", async () => {
    const f = fixture(); await f.select(); const provider = f.gateway.configProvider;
    await provider.resolveVdb("fixture"); provider.evictVdb("fixture");
    await provider.resolveVdb("fixture"); await provider.refreshCosNow(); provider.clear();
    expect(f.gateway.configProvider).toBe(provider); expect(f.calls.factory).toBe(1);
    expect(f.source.fetches).toBe(2); expect(f.observe()).toMatchObject(acceptedFactory);
  });
  it("observes a real repeated startup replacement without changing earlier snapshots", async () => {
    const f = fixture(); await f.select(); const previous = f.observe(); const provider = f.gateway.configProvider;
    f.state.plan = () => { throw new Error("next-attempt"); };
    await f.select(); expect(f.gateway.configProvider).not.toBe(provider);
    expect(f.observe()).toMatchObject(acceptedFallback); expect(previous).toMatchObject(acceptedFactory);
    expect(f.calls.factory).toBe(2);
  });
  it("follows actual assignment order for concurrent startup completions, not invented generations", async () => {
    const f = fixture(); const old = deferred<any>(); f.state.plan = () => old.promise;
    const first = f.select(); await waitForFactory(f);
    const newerSource = new SyntheticSource(); f.state.plan = () => ({ configSource: newerSource, quotaReporter: {} });
    await f.select(); const newerProvider = f.gateway.configProvider; const snapshot = f.observe();
    old.resolve({ configSource: f.source, quotaReporter: {} }); await first;
    expect(f.gateway.configProvider).not.toBe(newerProvider);
    expect(f.gateway.configProvider.source).toBe(f.source);
    expect(f.observe()).toMatchObject(acceptedFactory); expect(snapshot).toMatchObject(acceptedFactory);
    expect(f.calls.factory).toBe(2);
  });
  it("does not report an externally replaced provider as the previously observed instance", async () => {
    const f = fixture(); await f.select(); f.gateway.configProvider = {};
    expect(f.observe()).toMatchObject({ selectionStatus: "UNKNOWN", selectedSource: "UNKNOWN" });
  });
  it("returns frozen scalar snapshots without configuration, secrets, errors or authority fields", async () => {
    const f = fixture(); await f.select(); const snapshot = f.observe();
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.keys(snapshot).sort()).toEqual(["configuredDeployMode", "factoryCallAttempted", "factoryStatus", "selectedSource", "selectionStatus"]);
    expect(Object.values(snapshot).every(value => typeof value === "string" || typeof value === "boolean")).toBe(true);
    expect(JSON.stringify(snapshot)).not.toContain("synthetic-do-not-observe");
    expect(JSON.stringify(snapshot)).not.toContain("sensitive.invalid");
    expect(() => { snapshot.selectedSource = "BUILTIN_LOCAL_FALLBACK"; }).toThrow();
    expect(f.observe()).toMatchObject(acceptedFactory);
  });
  it("factory call boundary records no invocation when module loading fails", async () => {
    const f = fixture(); f.state.importError = new Error("fixture-load-failure");
    await f.select();
    expect(f.observe().factoryCallAttempted).toBe(false);
    expect(f.calls.factory).toBe(0);
  });
  it("factory call boundary records invocation before asynchronous rejection", async () => {
    const f = fixture(); const hold = deferred<any>(); f.state.plan = () => hold.promise;
    const running = f.select(); await waitForFactory(f);
    expect(f.observe().factoryCallAttempted).toBe(true);
    hold.reject(new Error("fixture-call-failure")); await running;
    expect(f.observe()).toMatchObject({ factoryStatus: "THREW", factoryCallAttempted: true });
  });
  it("factory call boundary preserves successful service selection without fallback", async () => {
    const f = fixture("service"); await f.select();
    expect(f.observe()).toMatchObject({ configuredDeployMode: "service", ...acceptedFactory, factoryCallAttempted: true });
    expect(f.gateway.configProvider.source).toBe(f.source);
    expect(f.calls).toMatchObject({ imports: 1, factory: 1, providerLogs: 1, stores: 1, scanners: 1, workers: 1 });
  });

});
