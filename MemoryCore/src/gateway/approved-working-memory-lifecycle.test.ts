import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { IMemoryStore } from "../core/store/types.js";
import { VectorStore } from "../core/store/sqlite.js";
import { TcvdbMemoryStore } from "../core/store/tcvdb.js";
import {
  handleApprovedMemoryGet,
  handleApprovedMemorySearch,
  handleApprovedMemoryWrite
} from "./approved-working-memory.js";

const CMG_DIRECT_VECTOR_PATH = "F:\\AI\\CodexMemoryGovernance\\tests\\fixtures\\explicit-memory-contract-vectors.json";

function directFixture() {
  const fixture = JSON.parse(readFileSync(CMG_DIRECT_VECTOR_PATH, "utf8")).vectors[0];
  return structuredClone({ admission: fixture.admission, record: fixture.writePayload });
}

function without(value: Record<string, unknown>, key: string) {
  const copy = { ...value };
  delete copy[key];
  return copy;
}

function rehashDirectAdmission(value: any) {
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

function stable(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stable(record[key])}`).join(",")}}`;
}

function digest(domain: string, value: unknown): string {
  return `sha256:${createHash("sha256").update(`${domain}\0${stable(value)}`, "utf8").digest("hex")}`;
}

function approvedFixture({ content = "Use immutable publication.", marker = "a", scopeId = "project:test",
  supersedes = [] as string[], expectedVersion = supersedes.length === 0 ? null : 1 } = {}) {
  const body = {
    content, memory_kind: "architecture_decision", scope: "project", scope_id: scopeId,
    allowed_project_ids: [], status: "current", candidate_digest: `sha256:${marker.repeat(64)}`,
    candidate_version: 1, expected_version: expectedVersion, supersedes,
  };
  const record = { memory_id: `wm_sha256_${digest("cmg/working-memory-write-payload/v1/identity", body).slice(7)}`, ...body };
  const base = {
    contract: "cmg/human-approved-memory-admission/v1", candidate_id: `wmc_sha256_${marker.repeat(64)}`,
    candidate_version: 1, candidate_digest: record.candidate_digest, governance_digest: `sha256:${"c".repeat(64)}`,
    approval_request_id: `wmar_sha256_${marker.repeat(64)}`, approval_request_digest: `sha256:${"e".repeat(64)}`,
    approval_decision_digest: `sha256:${"f".repeat(64)}`, scope: record.scope, scope_id: record.scope_id,
    allowed_project_ids: [], write_payload_digest: digest("cmg/working-memory-write-payload/v1/snapshot", record),
    idempotency_key: "", admitted: true, reasons: [], evaluated_at: "2026-09-25T08:10:00.000Z",
  };
  base.idempotency_key = digest("cmg/human-approved-memory-admission/v1/idempotency", {
    candidate_id: base.candidate_id, candidate_version: base.candidate_version,
    candidate_digest: base.candidate_digest, governance_digest: base.governance_digest,
    approval_request_id: base.approval_request_id, approval_request_digest: base.approval_request_digest,
    approval_decision_digest: base.approval_decision_digest, scope: base.scope, scope_id: base.scope_id,
    allowed_project_ids: base.allowed_project_ids, write_payload_digest: base.write_payload_digest,
  });
  return { admission: { ...base, admission_digest: digest("cmg/human-approved-memory-admission/v1/admission", base) }, record };
}

function row(record: any) {
  return {
    record_id: record.id, content: record.content, type: record.type, priority: record.priority,
    scene_name: record.scene_name, session_key: record.sessionKey, session_id: record.sessionId,
    team_id: record.teamId, task_id: "", user_id: record.userId, agent_id: record.agentId,
    version: record.version, timestamp_str: record.timestamps[0], timestamp_start: "", timestamp_end: "",
    created_time: record.createdAt, updated_time: record.updatedAt, metadata_json: JSON.stringify(record.metadata),
  };
}

function fixtureStore(delay = false) {
  const rows: any[] = [];
  const store = {
    queryL1Records: async () => rows,
    upsertL1: async (record: any) => {
      if (delay) await new Promise((resolve) => setTimeout(resolve, 5));
      rows.push(row(record));
      return true;
    },
  } as unknown as IMemoryStore;
  return { rows, store };
}

const auth = { apiKey: "test", serviceId: "test" };
function options(store: IMemoryStore) {
  return { getStore: () => store,
    requestIsolation: { teamId: "team", userId: "user", agentId: "agent", sessionId: "session" },
    now: () => "2026-09-25T08:11:00.000Z" };
}

function directOptions(store: IMemoryStore, teamId = "team") {
  return { getStore: () => store,
    requestIsolation: { teamId, userId: "user", agentId: "agent", sessionId: "session" },
    now: () => "2026-10-07T01:01:00.000Z" };
}

function isolationAwareStore(delay = false) {
  const rows: any[] = [];
  let writes = 0;
  let failReads = false;
  const store = {
    readL1RecordExact: async (recordId: string) => {
      if (failReads) return { status: "read_failed" };
      const matches = rows.filter((item) => item.record_id === recordId);
      return matches.length === 1 ? { status: "found", row: matches[0] } :
        matches.length === 0 ? { status: "not_found" } : { status: "read_failed" };
    },
    queryL1Records: async (filter: any = {}) => {
      if (failReads) return [];
      let found = rows;
      if (filter.recordIds?.length) found = found.filter((item) => filter.recordIds.includes(item.record_id));
      if (filter.teamId !== undefined) found = found.filter((item) => item.team_id === filter.teamId);
      if (filter.userId !== undefined) found = found.filter((item) => item.user_id === filter.userId);
      if (filter.agentId !== undefined) found = found.filter((item) => item.agent_id === filter.agentId);
      return found;
    },
    upsertL1: async (record: any) => {
      if (delay) await new Promise((resolve) => setTimeout(resolve, 5));
      writes += 1;
      const existing = rows.findIndex((item) => item.record_id === record.id);
      if (existing >= 0) rows.splice(existing, 1);
      rows.push(row(record));
      return true;
    },
  } as unknown as IMemoryStore;
  return { rows, store, writes: () => writes, failReads: () => { failReads = true; } };
}

function tcvdbStore() {
  return new TcvdbMemoryStore({
    url: "http://127.0.0.1:1", username: "test", apiKey: "test", database: "task7",
    embeddingModel: "none", timeout: 10,
  });
}

function tcvdbDocument(recordId: string) {
  return {
    id: recordId, text: "foreign secret body", type: "instruction", priority: 100,
    scene_name: "approved-working-memory", team_id: "foreign", user_id: "user", agent_id: "agent",
    session_key: "session", session_id: "session", task_id: "", version: 1,
    timestamp_str: "2026-10-07T01:01:00.000Z", timestamp_start: "2026-10-07T01:01:00.000Z",
    timestamp_end: "2026-10-07T01:01:00.000Z", metadata_json: "{}",
    created_time_ms: 1791334860000, updated_time_ms: 1791334860000,
  };
}

describe("approved Working Memory lifecycle", () => {
  it("persists an immutable successor and derives predecessor superseded / successor current", async () => {
    const { rows, store } = fixtureStore();
    const first = approvedFixture();
    expect((await handleApprovedMemoryWrite(first, auth, "first", options(store))).data).toMatchObject({ status: "created" });
    const second = approvedFixture({ content: "Use immutable successor publication.", marker: "b",
      supersedes: [first.record.memory_id] });
    expect((await handleApprovedMemoryWrite(second, auth, "second", options(store))).data).toMatchObject({ status: "updated" });
    expect(rows).toHaveLength(2);
    expect(rows[0].content).toBe(first.record.content);

    const search = await handleApprovedMemorySearch({ scope: "project", scope_id: "project:test" }, auth, "search", options(store));
    expect(search.data).toMatchObject({ total: 2, items: [
      { record: first.record, currentness: "superseded", successor_ids: [second.record.memory_id] },
      { record: second.record, currentness: "current", predecessor_ids: [first.record.memory_id] },
    ] });
    expect((search.data as any).items[1].relation_digest).toMatch(/^sha256:[a-f0-9]{64}$/);

    const replay = await handleApprovedMemoryWrite(second, auth, "replay", options(store));
    expect(replay.data).toMatchObject({ status: "exact_replay" });
    expect(rows).toHaveLength(2);
  });

  it("rejects missing predecessor, scope drift, self reference, stale version, and existing branch with zero writes", async () => {
    const { rows, store } = fixtureStore();
    const first = approvedFixture();
    await handleApprovedMemoryWrite(first, auth, "first", options(store));
    const invalid = [
      approvedFixture({ marker: "b", supersedes: [`wm_sha256_${"0".repeat(64)}`] }),
      approvedFixture({ marker: "d", scopeId: "project:other", supersedes: [first.record.memory_id] }),
      approvedFixture({ marker: "e", supersedes: [first.record.memory_id], expectedVersion: 2 }),
    ];
    for (const [index, input] of invalid.entries()) {
      expect(await handleApprovedMemoryWrite(input, auth, `bad-${index}`, options(store)))
        .toMatchObject({ code: 409, data: { status: "conflict" } });
    }
    const second = approvedFixture({ marker: "b", supersedes: [first.record.memory_id] });
    expect((await handleApprovedMemoryWrite(second, auth, "second", options(store))).data).toMatchObject({ status: "updated" });
    const branch = approvedFixture({ marker: "d", supersedes: [first.record.memory_id] });
    expect(await handleApprovedMemoryWrite(branch, auth, "branch", options(store)))
      .toMatchObject({ code: 409, data: { status: "conflict" } });
    expect(rows).toHaveLength(2);
  });

  it("serializes two concurrent successors so only one is written and the other reports branch conflict", async () => {
    const { rows, store } = fixtureStore(true);
    const first = approvedFixture();
    await handleApprovedMemoryWrite(first, auth, "first", options(store));
    const left = approvedFixture({ content: "Left successor.", marker: "b", supersedes: [first.record.memory_id] });
    const right = approvedFixture({ content: "Right successor.", marker: "d", supersedes: [first.record.memory_id] });
    const results = await Promise.all([
      handleApprovedMemoryWrite(left, auth, "left", options(store)),
      handleApprovedMemoryWrite(right, auth, "right", options(store)),
    ]);
    expect(results.map((result) => (result.data as any)?.status).sort()).toEqual(["conflict", "updated"]);
    expect(rows).toHaveLength(2);
  });

  it("parallel identical direct writes commit once on one process and Store instance", async () => {
    const state = isolationAwareStore(true);
    const input = directFixture();
    const results = await Promise.all(Array.from({ length: 8 }, (_, index) =>
      handleApprovedMemoryWrite(input, auth, `direct-parallel-${index}`, directOptions(state.store))));
    expect(results.map((result) => (result.data as any)?.status).sort()).toEqual([
      "created", "exact_replay", "exact_replay", "exact_replay",
      "exact_replay", "exact_replay", "exact_replay", "exact_replay",
    ]);
    expect(state.writes()).toBe(1);
    expect(new Set(state.rows.map((item) => item.record_id))).toEqual(new Set([input.record.memory_id]));
  });

  it("parallel conflicting direct admissions choose one winner and never overwrite it", async () => {
    const state = isolationAwareStore(true);
    const left = directFixture();
    const right = directFixture();
    right.admission.safety.risk_reasons = ["hard_term:必须"];
    right.admission = rehashDirectAdmission(right.admission);
    const results = await Promise.all([
      handleApprovedMemoryWrite(left, auth, "direct-left", directOptions(state.store)),
      handleApprovedMemoryWrite(right, auth, "direct-right", directOptions(state.store)),
    ]);
    expect(results.map((result) => (result.data as any)?.status).sort()).toEqual(["conflict", "created"]);
    expect(state.writes()).toBe(1);
    expect(JSON.parse(state.rows[0].metadata_json).admission_digest).toBe(left.admission.admission_digest);
  });

  it("reconciles a caller-side lost response by exact get and replay without a second record", async () => {
    const state = isolationAwareStore();
    const input = directFixture();
    await handleApprovedMemoryWrite(input, auth, "direct-lost-response", directOptions(state.store));

    const reconciled = await handleApprovedMemoryGet({ memory_id: input.record.memory_id,
      idempotency_key: input.admission.idempotency_key, scope: input.record.scope, scope_id: input.record.scope_id },
    auth, "direct-reconcile", directOptions(state.store));
    expect(reconciled).toMatchObject({ code: 0, data: { record: input.record, readback_status: "verified" } });
    expect((await handleApprovedMemoryWrite(input, auth, "direct-retry", directOptions(state.store))).data)
      .toMatchObject({ status: "exact_replay" });
    expect(state.writes()).toBe(1);
    expect(state.rows).toHaveLength(1);
  });

  it("rejects a foreign-isolation deterministic id before an upsert can overwrite it", async () => {
    const state = isolationAwareStore();
    const input = directFixture();
    expect((await handleApprovedMemoryWrite(input, auth, "direct-foreign-seed", directOptions(state.store, "foreign"))).data)
      .toMatchObject({ status: "created" });

    state.rows[0].content = "foreign secret body";
    state.rows[0].metadata_json = JSON.stringify({ secret: "foreign provenance secret" });
    const result = await handleApprovedMemoryWrite(input, auth, "direct-foreign-collision", directOptions(state.store, "team"));
    expect(result).toMatchObject({ code: 409, data: { status: "conflict" } });
    expect(JSON.stringify(result)).not.toContain("foreign secret");
    expect(state.writes()).toBe(1);
    expect(state.rows[0].team_id).toBe("foreign");
  });

  it("does not treat a Store read failure hidden as an empty result as definitive not found", async () => {
    const state = isolationAwareStore();
    const input = directFixture();
    await handleApprovedMemoryWrite(input, auth, "direct-read-failure-seed", directOptions(state.store, "foreign"));
    state.failReads();

    expect(await handleApprovedMemoryWrite(input, auth, "direct-read-failure", directOptions(state.store, "team")))
      .toMatchObject({ code: 503, data: { status: "unresolved" } });
    expect(state.writes()).toBe(1);
    expect(state.rows[0].team_id).toBe("foreign");
  });

  it("rejects direct writes when the Store has no exact-id read capability", async () => {
    const input = directFixture();
    let writes = 0;
    const store = {
      queryL1Records: async () => [],
      upsertL1: async () => { writes += 1; return true; },
    } as unknown as IMemoryStore;

    expect(await handleApprovedMemoryWrite(input, auth, "direct-no-exact-read", directOptions(store)))
      .toMatchObject({ code: 503, data: { status: "unresolved", readback_status: "unknown" } });
    expect(writes).toBe(0);
  });

  it("fails closed when an exact-id capability returns a malformed found result", async () => {
    const input = directFixture();
    let writes = 0;
    const store = {
      readL1RecordExact: async () => ({ status: "found" }),
      queryL1Records: async () => [],
      upsertL1: async () => { writes += 1; return true; },
    } as unknown as IMemoryStore;

    expect(await handleApprovedMemoryWrite(input, auth, "direct-malformed-exact-read", directOptions(store)))
      .toMatchObject({ code: 503, data: { status: "unresolved", readback_status: "unknown" } });
    expect(writes).toBe(0);
  });

  it("preserves post-commit readback uncertainty and later reconciles the same id", async () => {
    const input = directFixture();
    const rows: any[] = [];
    let writes = 0;
    let failReadback = false;
    const store = {
      readL1RecordExact: async (recordId: string) => {
        if (failReadback) return { status: "read_failed" };
        const found = rows.find((item) => item.record_id === recordId);
        return found ? { status: "found", row: found } : { status: "not_found" };
      },
      queryL1Records: async () => rows,
      upsertL1: async (record: any) => {
        writes += 1;
        rows.push(row(record));
        failReadback = true;
        return true;
      },
    } as unknown as IMemoryStore;

    expect(await handleApprovedMemoryWrite(input, auth, "direct-postcommit-failure", directOptions(store)))
      .toMatchObject({ code: 503, data: { status: "unresolved", readback_status: "unknown" } });
    expect(writes).toBe(1);
    failReadback = false;
    expect(await handleApprovedMemoryWrite(input, auth, "direct-postcommit-reconcile", directOptions(store)))
      .toMatchObject({ code: 0, data: { status: "exact_replay", readback_status: "verified" } });
    expect(writes).toBe(1);
    expect(rows).toHaveLength(1);
  });

  it("SQLite exact-id read distinguishes found, not found, and a real closed-database failure", async () => {
    const root = await mkdtemp(join(tmpdir(), "approved-memory-exact-read-"));
    const database = join(root, "memory.sqlite");
    let store = new VectorStore(database, 0);
    const input = directFixture();
    try {
      await store.init();
      expect((await handleApprovedMemoryWrite(input, auth, "sqlite-foreign-seed", directOptions(store, "foreign"))).data)
        .toMatchObject({ status: "created" });
      expect(await (store as any).readL1RecordExact(input.record.memory_id))
        .toMatchObject({ status: "found", row: { record_id: input.record.memory_id, team_id: "foreign" } });
      expect(await (store as any).readL1RecordExact(`wm_sha256_${"0".repeat(64)}`))
        .toEqual({ status: "not_found" });

      store.close();
      expect(await (store as any).readL1RecordExact(input.record.memory_id)).toEqual({ status: "read_failed" });
      expect(store.queryL1Records({ recordIds: [input.record.memory_id] })).toEqual([]);
      let writes = 0;
      const failedStore = {
        readL1RecordExact: (recordId: string) => (store as any).readL1RecordExact(recordId),
        queryL1Records: async () => { throw new Error("must not query after exact read failure"); },
        upsertL1: async () => { writes += 1; return true; },
      } as unknown as IMemoryStore;
      expect(await handleApprovedMemoryWrite(input, auth, "sqlite-read-failure", directOptions(failedStore)))
        .toMatchObject({ code: 503, data: { status: "unresolved" } });
      expect(writes).toBe(0);

      store = new VectorStore(database, 0);
      await store.init();
      expect(await (store as any).readL1RecordExact(input.record.memory_id))
        .toMatchObject({ status: "found", row: { content: input.record.content, team_id: "foreign" } });
    } finally {
      store.close();
      await rm(root, { recursive: true, force: true });
    }
  });

  it("TCVDB exact-id adapter fails closed on rejection, malformed, wrong-id, and ambiguous responses", async () => {
    const input = directFixture();
    const store = tcvdbStore();
    const client = (store as any).client;
    const calls: any[] = [];
    client.query = async (_collection: string, query: any) => {
      calls.push(query);
      return { documents: [tcvdbDocument(input.record.memory_id)] };
    };
    expect(await (store as any).readL1RecordExact(input.record.memory_id))
      .toMatchObject({ status: "found", row: { record_id: input.record.memory_id, team_id: "foreign" } });
    expect(calls[0]).toMatchObject({ documentIds: [input.record.memory_id], retrieveVector: false });

    client.query = async () => ({ documents: [] });
    expect(await (store as any).readL1RecordExact(input.record.memory_id)).toEqual({ status: "not_found" });
    client.query = async () => { throw new Error("transport rejected"); };
    expect(await (store as any).readL1RecordExact(input.record.memory_id)).toEqual({ status: "read_failed" });
    expect(await store.queryL1Records({ recordIds: [input.record.memory_id] })).toEqual([]);
    for (const response of [
      { documents: null },
      { documents: [tcvdbDocument(`wm_sha256_${"0".repeat(64)}`)] },
      { documents: [tcvdbDocument(input.record.memory_id), tcvdbDocument(input.record.memory_id)] },
      { documents: [{ id: input.record.memory_id }] },
    ]) {
      client.query = async () => response;
      expect(await (store as any).readL1RecordExact(input.record.memory_id)).toEqual({ status: "read_failed" });
    }

    let writes = 0;
    client.query = async () => { throw new Error("transport rejected"); };
    (store as any).upsertL1 = async () => { writes += 1; return true; };
    expect(await handleApprovedMemoryWrite(input, auth, "tcvdb-read-failure", directOptions(store)))
      .toMatchObject({ code: 503, data: { status: "unresolved" } });
    expect(writes).toBe(0);
  });

  it("reports a pre-existing structural branch as conflicted without selecting a timestamp winner", async () => {
    const rootStore = fixtureStore();
    const first = approvedFixture();
    await handleApprovedMemoryWrite(first, auth, "first", options(rootStore.store));
    const leftStore = fixtureStore();
    leftStore.rows.push(structuredClone(rootStore.rows[0]));
    const rightStore = fixtureStore();
    rightStore.rows.push(structuredClone(rootStore.rows[0]));
    const left = approvedFixture({ content: "Left successor.", marker: "b", supersedes: [first.record.memory_id] });
    const right = approvedFixture({ content: "Right successor.", marker: "d", supersedes: [first.record.memory_id] });
    await handleApprovedMemoryWrite(left, auth, "left", options(leftStore.store));
    await handleApprovedMemoryWrite(right, auth, "right", options(rightStore.store));

    const branchStore = fixtureStore();
    branchStore.rows.push(rootStore.rows[0], leftStore.rows[1], rightStore.rows[1]);
    const search = await handleApprovedMemorySearch({ scope: "project", scope_id: "project:test" }, auth, "search",
      options(branchStore.store));
    expect((search.data as any).items.map((item: any) => item.currentness)).toEqual([
      "conflicted", "conflicted", "conflicted"
    ]);
    expect((search.data as any).items.every((item: any) => item.lineage_status === "conflict")).toBe(true);
  });

  it("does not merge identical content across scopes", async () => {
    const { rows, store } = fixtureStore();
    const first = approvedFixture({ scopeId: "project:first" });
    const second = approvedFixture({ marker: "b", scopeId: "project:second" });
    expect((await handleApprovedMemoryWrite(first, auth, "first", options(store))).data).toMatchObject({ status: "created" });
    expect((await handleApprovedMemoryWrite(second, auth, "second", options(store))).data).toMatchObject({ status: "created" });
    expect(rows).toHaveLength(2);
  });

  it("fails closed when stored supersession metadata is changed without the approved payload identity", async () => {
    const { rows, store } = fixtureStore();
    const first = approvedFixture();
    await handleApprovedMemoryWrite(first, auth, "first", options(store));
    const metadata = JSON.parse(rows[0].metadata_json);
    metadata.approved_payload.supersedes = [`wm_sha256_${"0".repeat(64)}`];
    metadata.approved_payload.expected_version = 1;
    metadata.write_payload_digest = digest("cmg/working-memory-write-payload/v1/snapshot", metadata.approved_payload);
    rows[0].metadata_json = JSON.stringify(metadata);

    const search = await handleApprovedMemorySearch({ scope: "project", scope_id: "project:test" }, auth, "search", options(store));
    expect(search.data).toMatchObject({ total: 0, items: [] });
  });

  it("persists and reopens the immutable lineage through the real isolated SQLite store", async () => {
    const root = await mkdtemp(join(tmpdir(), "approved-memory-v1-8-"));
    const database = join(root, "memory.sqlite");
    let store = new VectorStore(database, 0);
    try {
      await store.init();
      const first = approvedFixture();
      const second = approvedFixture({ marker: "b", supersedes: [first.record.memory_id] });
      expect((await handleApprovedMemoryWrite(first, auth, "first", options(store))).data).toMatchObject({ status: "created" });
      expect((await handleApprovedMemoryWrite(second, auth, "second", options(store))).data).toMatchObject({ status: "updated" });
      store.close();
      store = new VectorStore(database, 0);
      await store.init();
      const search = await handleApprovedMemorySearch({ scope: "project", scope_id: "project:test" }, auth, "search",
        options(store));
      expect(search.data).toMatchObject({ total: 2, items: [
        { record: first.record, currentness: "superseded" },
        { record: second.record, currentness: "current" },
      ] });
    } finally {
      store.close();
      await rm(root, { recursive: true, force: true });
    }
  });
});
