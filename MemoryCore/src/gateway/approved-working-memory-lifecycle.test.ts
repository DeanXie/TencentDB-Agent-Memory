import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { IMemoryStore } from "../core/store/types.js";
import { VectorStore } from "../core/store/sqlite.js";
import {
  handleApprovedMemoryGet,
  handleApprovedMemorySearch,
  handleApprovedMemoryWrite
} from "./approved-working-memory.js";

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
