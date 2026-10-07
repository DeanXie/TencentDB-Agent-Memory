import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { IMemoryStore, L1RecordRow } from "../core/store/types.js";
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
  post: (path: string, body: unknown, headers?: Record<string, string>) => Promise<{ status: number; text: string; json: any }>;
  get: (path: string, headers?: Record<string, string>) => Promise<{ status: number; text: string; json: any }>;
  store: TestStore;
  storeResolutions: () => number;
  logs: string[];
  close: () => Promise<void>;
};

async function harness(options: { apiKey?: string; authority?: unknown } = {}): Promise<Harness> {
  const trackedStore = testStore();
  let storeResolutions = 0;
  const logs: string[] = [];
  const gateway = new TdaiGateway({
    server: {
      host: "127.0.0.1", port: 0, corsOrigins: [], apiKey: options.apiKey,
      directWriterAuthority: options.authority,
    } as any,
    data: { baseDir: join(tmpdir(), "memorycore-direct-authority-test") } as any,
  });
  const core = (gateway as any).core;
  core.getVectorStore = () => { storeResolutions += 1; return trackedStore.store; };
  core.getEmbeddingService = () => undefined;
  core.getStorage = () => undefined;
  (gateway as any).logger = {
    info: (...args: unknown[]) => logs.push(args.join(" ")),
    warn: (...args: unknown[]) => logs.push(args.join(" ")),
    error: (...args: unknown[]) => logs.push(args.join(" ")),
    debug: (...args: unknown[]) => logs.push(args.join(" ")),
  };

  const server: Server = createServer((req, res) => {
    void (gateway as any).handleRequest(req, res).catch((error: unknown) => {
      res.statusCode = 500;
      res.end(error instanceof Error ? error.message : "test server error");
    });
  });
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

async function withHarness<T>(options: { apiKey?: string; authority?: unknown }, run: (value: Harness) => Promise<T>): Promise<T> {
  const value = await harness(options);
  try { return await run(value); } finally { await value.close(); }
}

describe("direct approved-memory server authority", () => {
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
