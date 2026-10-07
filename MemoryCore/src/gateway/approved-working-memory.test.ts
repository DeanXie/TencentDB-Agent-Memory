import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { IMemoryStore } from "../core/store/types.js";
import { handleApprovedMemoryGet, handleApprovedMemorySearch, handleApprovedMemoryWrite } from "./approved-working-memory.js";
import { handleV2Route } from "./v2-router.js";

const CMG_DIRECT_VECTOR_PATH = "F:\\AI\\CodexMemoryGovernance\\tests\\fixtures\\explicit-memory-contract-vectors.json";

function directFixture() {
  const fixture = JSON.parse(readFileSync(CMG_DIRECT_VECTOR_PATH, "utf8")).vectors[0];
  return structuredClone({ admission: fixture.admission, record: fixture.writePayload });
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

function approvedFixture() {
  const body = {
    content: "Use create-only evidence publication.", memory_kind: "architecture_decision",
    scope: "project", scope_id: "project:test", allowed_project_ids: [], status: "current",
    candidate_digest: `sha256:${"a".repeat(64)}`, candidate_version: 1,
    expected_version: null, supersedes: [],
  };
  const record = { memory_id: `wm_sha256_${digest("cmg/working-memory-write-payload/v1/identity", body).slice(7)}`, ...body };
  const base = {
    contract: "cmg/human-approved-memory-admission/v1",
    candidate_id: `wmc_sha256_${"b".repeat(64)}`, candidate_version: 1,
    candidate_digest: record.candidate_digest, governance_digest: `sha256:${"c".repeat(64)}`,
    approval_request_id: `wmar_sha256_${"d".repeat(64)}`, approval_request_digest: `sha256:${"e".repeat(64)}`,
    approval_decision_digest: `sha256:${"f".repeat(64)}`, scope: record.scope, scope_id: record.scope_id,
    allowed_project_ids: [], write_payload_digest: digest("cmg/working-memory-write-payload/v1/snapshot", record),
    idempotency_key: "", admitted: true, reasons: [], evaluated_at: "2026-09-25T04:10:00.000Z",
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

function exactReadFrom(rows: any[]) {
  return async (recordId: string) => {
    const matches = rows.filter((item) => item.record_id === recordId);
    return matches.length === 1 ? { status: "found", row: matches[0] } :
      matches.length === 0 ? { status: "not_found" } : { status: "read_failed" };
  };
}

describe("approved Working Memory boundary", () => {
  it("persists the frozen CMG direct v2 vector with the exact deterministic memory id", async () => {
    const input = directFixture();
    const rows: any[] = [];
    const store = {
      readL1RecordExact: exactReadFrom(rows),
      queryL1Records: async () => rows,
      upsertL1: async (record: any) => { rows.push({
        record_id: record.id, content: record.content, type: record.type, priority: record.priority,
        scene_name: record.scene_name, session_key: record.sessionKey, session_id: record.sessionId,
        team_id: record.teamId, task_id: "", user_id: record.userId, agent_id: record.agentId,
        version: record.version, timestamp_str: record.timestamps[0], timestamp_start: "", timestamp_end: "",
        created_time: record.createdAt, updated_time: record.updatedAt, metadata_json: JSON.stringify(record.metadata),
      }); return true; },
    } as unknown as IMemoryStore;
    const result = await handleApprovedMemoryWrite(input, { apiKey: "test", serviceId: "test" }, "direct-red", {
      getStore: () => store,
      requestIsolation: { teamId: "team", userId: "user", agentId: "agent", sessionId: "session" },
      now: () => "2026-10-07T01:01:00.000Z",
    });

    expect(result).toMatchObject({ code: 0, data: {
      status: "created",
      readback_status: "verified",
      memory_id: "wm_sha256_c0af6ffea4c96506d2d4b0a21ba3ddc25cc8b03f5d57b5a140d207374d540c64",
      write_payload_digest: "sha256:a56f3173fd4b0eec0d8504013ffa48724775c2f39ab2a6abc3742160c9b5ca04",
      admission_digest: "sha256:f06a9d2128b3740847656b58f997ce6fb6457651bc69dfc5fcceb476520db14f",
    } });
    expect(JSON.parse(rows[0].metadata_json)).toMatchObject({
      contract: "cmg/approved-working-memory-record/v2",
      authorization_type: "explicit_user_memory_command",
      command_id: input.record.command_id,
      source_digest: input.record.source_digest,
      authorization_digest: input.record.authorization_digest,
    });
    const options = { getStore: () => store,
      requestIsolation: { teamId: "team", userId: "user", agentId: "agent", sessionId: "session" } };
    expect((await handleApprovedMemoryGet({ memory_id: input.record.memory_id,
      idempotency_key: input.admission.idempotency_key, scope: "project", scope_id: input.record.scope_id },
    { apiKey: "test", serviceId: "test" }, "direct-get", options)).data)
      .toMatchObject({ record: input.record, readback_status: "verified" });
    expect((await handleApprovedMemorySearch({ scope: "project", scope_id: input.record.scope_id },
      { apiKey: "test", serviceId: "test" }, "direct-search", options)).data)
      .toMatchObject({ total: 1, items: [{ record: input.record }] });
    const legacy = approvedFixture();
    expect((await handleApprovedMemoryWrite(legacy, { apiKey: "test", serviceId: "test" }, "mixed-legacy", options)).data)
      .toMatchObject({ status: "created" });
    expect((await handleApprovedMemorySearch({ scope: "project", scope_id: legacy.record.scope_id },
      { apiKey: "test", serviceId: "test" }, "mixed-legacy-search", options)).data)
      .toMatchObject({ total: 1, items: [{ record: legacy.record }] });
    expect((await handleApprovedMemorySearch({ scope: "project", scope_id: input.record.scope_id },
      { apiKey: "test", serviceId: "test" }, "mixed-direct-search", options)).data)
      .toMatchObject({ total: 1, items: [{ record: input.record }] });
  });

  it("strictly rejects mixed, unknown, missing, or mutated direct contracts before store access", async () => {
    const direct = directFixture();
    const legacy = approvedFixture();
    const mutations: Array<(value: any) => void> = [
      (value) => { value.admission = legacy.admission; },
      (value) => { value.record = legacy.record; },
      (value) => { value.admission.contract = "cmg/human-approved-memory-admission/v3"; },
      (value) => { value.record.contract = "cmg/working-memory-write-payload/v3"; },
      (value) => { delete value.admission.schema_version; },
      (value) => { delete value.record.schema_version; },
      (value) => { delete value.record.source_digest; },
      (value) => { delete value.record.authorization_digest; },
      (value) => { delete value.admission.safety.provenance.source_contract; },
      (value) => { delete value.admission.safety.provenance.user_item_id; },
      (value) => { value.record.memory_id = `wm_sha256_${"0".repeat(64)}`; },
      (value) => { value.admission.write_payload_digest = `sha256:${"0".repeat(64)}`; },
      (value) => { value.admission.safety.provenance.authorization_id = `wmauth_sha256_${"0".repeat(64)}`; },
      (value) => { value.record.source_digest = `sha256:${"0".repeat(64)}`; },
      (value) => { value.record.scope_id = "project:other"; },
      (value) => { value.admission.safety.provenance.content_digest = `sha256:${"0".repeat(64)}`; },
      (value) => { value.admission.admission_digest = `sha256:${"0".repeat(64)}`; },
      (value) => { value.admission.authorization_type = "human_review_approval"; },
    ];

    for (const mutate of mutations) {
      const body = structuredClone(direct);
      mutate(body);
      let reads = 0;
      let writes = 0;
      const store = { queryL1Records: async () => { reads += 1; return []; },
        upsertL1: async () => { writes += 1; return true; } } as unknown as IMemoryStore;
      const result = await handleApprovedMemoryWrite(body, { apiKey: "test", serviceId: "test" }, "direct-invalid", {
        getStore: () => store,
        requestIsolation: { teamId: "team", userId: "user", agentId: "agent", sessionId: "session" },
      });
      expect(result.code).toBe(400);
      expect(reads).toBe(0);
      expect(writes).toBe(0);
    }
  });

  it("replays one exact direct binding and conflicts on a different valid admission without overwrite", async () => {
    const input = directFixture();
    const rows: any[] = [];
    let writes = 0;
    const store = {
      readL1RecordExact: exactReadFrom(rows),
      queryL1Records: async () => rows,
      upsertL1: async (record: any) => { writes += 1; rows.push({
        record_id: record.id, content: record.content, type: record.type, priority: record.priority,
        scene_name: record.scene_name, session_key: record.sessionKey, session_id: record.sessionId,
        team_id: record.teamId, task_id: "", user_id: record.userId, agent_id: record.agentId,
        version: record.version, timestamp_str: record.timestamps[0], timestamp_start: "", timestamp_end: "",
        created_time: record.createdAt, updated_time: record.updatedAt, metadata_json: JSON.stringify(record.metadata),
      }); return true; },
    } as unknown as IMemoryStore;
    const options = { getStore: () => store,
      requestIsolation: { teamId: "team", userId: "user", agentId: "agent", sessionId: "session" },
      now: () => "2026-10-07T01:01:00.000Z" };

    expect((await handleApprovedMemoryWrite(input, { apiKey: "test", serviceId: "test" }, "direct-first", options)).data)
      .toMatchObject({ status: "created" });
    expect((await handleApprovedMemoryWrite(input, { apiKey: "test", serviceId: "test" }, "direct-replay", options)).data)
      .toMatchObject({ status: "exact_replay" });
    const divergent = structuredClone(input);
    divergent.admission.safety.risk_reasons = ["hard_term:必须"];
    divergent.admission = rehashDirectAdmission(divergent.admission);
    expect(await handleApprovedMemoryWrite(divergent, { apiKey: "test", serviceId: "test" }, "direct-conflict", options))
      .toMatchObject({ code: 409, data: { status: "conflict" } });
    expect(writes).toBe(1);
    expect(rows).toHaveLength(1);
  });

  it("rejects an unauthenticated direct request at the existing route boundary before store access", async () => {
    const input = directFixture();
    let storeCalls = 0;
    const req = { headers: {
      "x-tdai-service-id": "test-service", "x-tdai-team-id": "team", "x-tdai-user-id": "user",
      "x-tdai-agent-id": "agent", "x-tdai-session-id": "session",
    } } as any;
    let response: any;
    const handled = await handleV2Route(req, {} as any, "/v3/approved-memory/write", "POST", async () => input,
      (_res, status, body) => { response = { status, body }; }, {
        getStore: () => { storeCalls += 1; return undefined; }, getEmbedding: () => undefined, getStorage: () => undefined,
        deployMode: "standalone", v3StrictIsolation: true,
        logger: { info() {}, warn() {}, error() {}, debug() {} } as any,
      });
    expect(handled).toBe(true);
    expect(response).toMatchObject({ status: 401, body: { code: 401 } });
    expect(storeCalls).toBe(0);
  });

  it("persists exact approved payload and verifies readback before success", async () => {
    const input = approvedFixture();
    const rows: any[] = [];
    const store = {
      queryL1Records: async () => rows,
      upsertL1: async (record: any) => { rows.push({
        record_id: record.id, content: record.content, type: record.type, priority: record.priority,
        scene_name: record.scene_name, session_key: record.sessionKey, session_id: record.sessionId,
        team_id: record.teamId, task_id: "", user_id: record.userId, agent_id: record.agentId,
        version: record.version, timestamp_str: record.timestamps[0], timestamp_start: "", timestamp_end: "",
        created_time: record.createdAt, updated_time: record.updatedAt, metadata_json: JSON.stringify(record.metadata),
      }); return true; },
    } as unknown as IMemoryStore;
    const result = await handleApprovedMemoryWrite(input, { apiKey: "test", serviceId: "test" }, "req-1", {
      getStore: () => store,
      requestIsolation: { teamId: "team", userId: "user", agentId: "agent", sessionId: "session" },
      now: () => "2026-09-25T04:11:00.000Z",
    });
    expect(result).toMatchObject({ code: 0, data: { status: "created", readback_status: "verified", memory_id: input.record.memory_id } });
  });

  it("treats exact replay as idempotent and divergent replay as conflict", async () => {
    const input = approvedFixture();
    const rows: any[] = [];
    let writes = 0;
    const store = {
      queryL1Records: async () => rows,
      upsertL1: async (record: any) => { writes += 1; rows.push({
        record_id: record.id, content: record.content, type: record.type, priority: record.priority,
        scene_name: record.scene_name, session_key: record.sessionKey, session_id: record.sessionId,
        team_id: record.teamId, task_id: "", user_id: record.userId, agent_id: record.agentId,
        version: record.version, timestamp_str: record.timestamps[0], timestamp_start: "", timestamp_end: "",
        created_time: record.createdAt, updated_time: record.updatedAt, metadata_json: JSON.stringify(record.metadata),
      }); return true; },
    } as unknown as IMemoryStore;
    const options = { getStore: () => store, requestIsolation: { teamId: "team", userId: "user", agentId: "agent", sessionId: "session" }, now: () => "2026-09-25T04:11:00.000Z" };
    await handleApprovedMemoryWrite(input, { apiKey: "test", serviceId: "test" }, "req-1", options);
    expect((await handleApprovedMemoryWrite(input, { apiKey: "test", serviceId: "test" }, "req-2", options)).data)
      .toMatchObject({ status: "exact_replay" });
    const divergent = structuredClone(input);
    divergent.record.content = "divergent";
    expect(await handleApprovedMemoryWrite(divergent, { apiKey: "test", serviceId: "test" }, "req-3", options))
      .toMatchObject({ code: 400 });
    expect(writes).toBe(1);
    expect(rows[0].content).toBe(input.record.content);
  });

  it("rejects shortcuts, unknown fields, invalid lineage, and scope mismatch before store mutation", async () => {
    const valid = approvedFixture();
    const cases = [
      { approved: true, record: valid.record },
      { ...valid, extra: true },
      { ...valid, admission: { ...valid.admission, admitted: false } },
      { ...valid, admission: { ...valid.admission, candidate_digest: `sha256:${"0".repeat(64)}` } },
      { ...valid, record: { ...valid.record, scope_id: "project:other" } },
    ];
    for (const body of cases) {
      let calls = 0;
      const store = { queryL1Records: async () => [], upsertL1: async () => { calls += 1; return true; } } as unknown as IMemoryStore;
      const result = await handleApprovedMemoryWrite(body, { apiKey: "test", serviceId: "test" }, "req-bad", {
        getStore: () => store, requestIsolation: { teamId: "team", userId: "user", agentId: "agent", sessionId: "session" },
      });
      expect(result.code).toBe(400);
      expect(calls).toBe(0);
    }
  });

  it("fails closed when write fails or exact readback cannot be verified", async () => {
    const input = approvedFixture();
    const isolation = { teamId: "team", userId: "user", agentId: "agent", sessionId: "session" };
    const failedStore = { queryL1Records: async () => [], upsertL1: async () => false } as unknown as IMemoryStore;
    expect(await handleApprovedMemoryWrite(input, { apiKey: "test", serviceId: "test" }, "req-fail", { getStore: () => failedStore, requestIsolation: isolation }))
      .toMatchObject({ code: 503, data: { status: "failed", readback_status: "not_verified" } });
    const missingStore = { queryL1Records: async () => [], upsertL1: async () => true } as unknown as IMemoryStore;
    expect(await handleApprovedMemoryWrite(input, { apiKey: "test", serviceId: "test" }, "req-missing", { getStore: () => missingStore, requestIsolation: isolation }))
      .toMatchObject({ code: 503, data: { status: "unresolved", readback_status: "missing" } });
  });

  it("treats an occupied memory id without valid approved metadata as conflict and never overwrites", async () => {
    const input = approvedFixture();
    let writes = 0;
    const occupied = {
      record_id: input.record.memory_id, content: "unrelated existing record", type: "instruction", priority: 1,
      scene_name: "other", session_key: "session", session_id: "session", team_id: "team", task_id: "",
      user_id: "user", agent_id: "agent", version: 1, timestamp_str: "", timestamp_start: "", timestamp_end: "",
      created_time: "2026-09-25T04:00:00.000Z", updated_time: "2026-09-25T04:00:00.000Z", metadata_json: "{}",
    };
    const store = { queryL1Records: async () => [occupied], upsertL1: async () => { writes += 1; return true; } } as unknown as IMemoryStore;
    const result = await handleApprovedMemoryWrite(input, { apiKey: "test", serviceId: "test" }, "req-collision", {
      getStore: () => store, requestIsolation: { teamId: "team", userId: "user", agentId: "agent", sessionId: "session" },
    });
    expect(result).toMatchObject({ code: 409, data: { status: "conflict" } });
    expect(writes).toBe(0);
  });

  it("rejects stored approved metadata with unknown fields instead of treating it as exact replay", async () => {
    const input = approvedFixture();
    let persisted: any;
    let writes = 0;
    const store = {
      queryL1Records: async () => persisted ? [persisted] : [],
      upsertL1: async (record: any) => { writes += 1; persisted = {
        record_id: record.id, content: record.content, type: record.type, priority: record.priority,
        scene_name: record.scene_name, session_key: record.sessionKey, session_id: record.sessionId,
        team_id: record.teamId, task_id: "", user_id: record.userId, agent_id: record.agentId,
        version: record.version, timestamp_str: record.timestamps[0], timestamp_start: "", timestamp_end: "",
        created_time: record.createdAt, updated_time: record.updatedAt,
        metadata_json: JSON.stringify({ ...record.metadata, unexpected: true }),
      }; return true; },
    } as unknown as IMemoryStore;
    const options = { getStore: () => store, requestIsolation: { teamId: "team", userId: "user", agentId: "agent", sessionId: "session" } };
    const first = await handleApprovedMemoryWrite(input, { apiKey: "test", serviceId: "test" }, "req-1", options);
    expect(first).toMatchObject({ code: 409, data: { status: "conflict" } });
    expect(writes).toBe(1);
  });

  it("gets and searches only approved records in the exact scope and isolation", async () => {
    const input = approvedFixture();
    let persisted: any = null;
    const store = {
      queryL1Records: async () => persisted ? [persisted] : [],
      upsertL1: async (record: any) => { persisted = {
        record_id: record.id, content: record.content, type: record.type, priority: record.priority,
        scene_name: record.scene_name, session_key: record.sessionKey, session_id: record.sessionId,
        team_id: record.teamId, task_id: "", user_id: record.userId, agent_id: record.agentId,
        version: record.version, timestamp_str: record.timestamps[0], timestamp_start: "", timestamp_end: "",
        created_time: record.createdAt, updated_time: record.updatedAt, metadata_json: JSON.stringify(record.metadata),
      }; return true; },
    } as unknown as IMemoryStore;
    const options = { getStore: () => store, requestIsolation: { teamId: "team", userId: "user", agentId: "agent", sessionId: "session" } };
    await handleApprovedMemoryWrite(input, { apiKey: "test", serviceId: "test" }, "req-write", options);
    expect((await handleApprovedMemoryGet({ memory_id: input.record.memory_id, idempotency_key: input.admission.idempotency_key,
      scope: input.record.scope, scope_id: input.record.scope_id }, { apiKey: "test", serviceId: "test" }, "req-get", options)).data)
      .toMatchObject({ record: input.record, readback_status: "verified" });
    expect((await handleApprovedMemorySearch({ scope: input.record.scope, scope_id: input.record.scope_id },
      { apiKey: "test", serviceId: "test" }, "req-search", options)).data).toMatchObject({ total: 1, items: [{ record: input.record }] });
    expect((await handleApprovedMemorySearch({ scope: input.record.scope, scope_id: "project:other" },
      { apiKey: "test", serviceId: "test" }, "req-other", options)).data).toMatchObject({ total: 0 });
  });

  it("exposes the narrow write endpoint through the existing authenticated v3 router", async () => {
    const input = approvedFixture();
    const rows: any[] = [];
    const store = {
      queryL1Records: async () => rows,
      upsertL1: async (record: any) => { rows.push({
        record_id: record.id, content: record.content, type: record.type, priority: record.priority,
        scene_name: record.scene_name, session_key: record.sessionKey, session_id: record.sessionId,
        team_id: record.teamId, task_id: "", user_id: record.userId, agent_id: record.agentId,
        version: record.version, timestamp_str: record.timestamps[0], timestamp_start: "", timestamp_end: "",
        created_time: record.createdAt, updated_time: record.updatedAt, metadata_json: JSON.stringify(record.metadata),
      }); return true; },
    } as unknown as IMemoryStore;
    const req = { headers: {
      authorization: "Bearer test", "x-tdai-service-id": "test-service", "x-tdai-team-id": "team",
      "x-tdai-user-id": "user", "x-tdai-agent-id": "agent", "x-tdai-session-id": "session",
    } } as any;
    let response: any;
    const handled = await handleV2Route(req, {} as any, "/v3/approved-memory/write", "POST", async () => input,
      (_res, status, body) => { response = { status, body }; }, {
        getStore: () => store, getEmbedding: () => undefined, getStorage: () => undefined,
        deployMode: "standalone", v3StrictIsolation: true,
        logger: { info() {}, warn() {}, error() {}, debug() {} } as any,
      });
    expect(handled).toBe(true);
    expect(response).toMatchObject({ status: 200, body: { code: 0, data: { status: "created" } } });
  });
});
