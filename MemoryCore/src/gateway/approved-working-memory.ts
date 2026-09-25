import { createHash } from "node:crypto";
import { z } from "zod";
import type { MemoryRecord } from "../core/record/l1-writer.js";
import type { IMemoryStore, L1RecordRow } from "../core/store/types.js";
import type { ApiResponseEnvelope, V2AuthContext } from "./v2-schemas.js";

export const APPROVED_WORKING_MEMORY_RECORD_CONTRACT = "cmg/approved-working-memory-record/v1";
export const APPROVED_WORKING_MEMORY_RESULT_CONTRACT = "cmg/approved-working-memory-persistence-result/v1";

const SHA = /^sha256:[a-f0-9]{64}$/;
const SAFE_ID = /^[A-Za-z0-9._:-]{1,256}$/;
const MEMORY_ID = /^wm_sha256_[a-f0-9]{64}$/;
const CANDIDATE_ID = /^wmc_sha256_[a-f0-9]{64}$/;
const REQUEST_ID = /^wmar_sha256_[a-f0-9]{64}$/;
const sha = z.string().regex(SHA);
const scope = z.enum(["project", "cross_project", "global"]);
const safeId = z.string().regex(SAFE_ID);
const ids = z.array(safeId).max(64).refine((value) => new Set(value).size === value.length);
const isoTimestamp = z.string().refine((value) => {
  try { return new Date(value).toISOString() === value; } catch { return false; }
});

const approvedPayloadSchema = z.object({
  memory_id: z.string().regex(MEMORY_ID),
  content: z.string().min(1).max(1024),
  memory_kind: safeId,
  scope,
  scope_id: safeId,
  allowed_project_ids: ids,
  status: z.literal("current"),
  candidate_digest: sha,
  candidate_version: z.literal(1),
  expected_version: z.number().int().min(1).nullable(),
  supersedes: z.array(safeId).max(8).refine((value) => new Set(value).size === value.length),
}).strict().superRefine((value, ctx) => {
  if ((value.scope === "cross_project") !== (value.allowed_project_ids.length > 0)) {
    ctx.addIssue({ code: "custom", message: "scope/allowed_project_ids mismatch" });
  }
  if ((value.supersedes.length === 0) !== (value.expected_version === null) || value.supersedes.length > 1) {
    ctx.addIssue({ code: "custom", message: "supersedes/expected_version mismatch" });
  }
});

const admissionSchema = z.object({
  contract: z.literal("cmg/human-approved-memory-admission/v1"),
  candidate_id: z.string().regex(CANDIDATE_ID),
  candidate_version: z.literal(1),
  candidate_digest: sha,
  governance_digest: sha,
  approval_request_id: z.string().regex(REQUEST_ID),
  approval_request_digest: sha,
  approval_decision_digest: sha,
  scope,
  scope_id: safeId,
  allowed_project_ids: ids,
  write_payload_digest: sha,
  idempotency_key: sha,
  admitted: z.literal(true),
  reasons: z.array(z.never()).length(0),
  evaluated_at: isoTimestamp,
  admission_digest: sha,
}).strict();

export const approvedMemoryWriteRequestSchema = z.object({
  admission: admissionSchema,
  record: approvedPayloadSchema,
}).strict();

export const approvedMemoryGetRequestSchema = z.object({
  memory_id: z.string().regex(MEMORY_ID),
  idempotency_key: sha,
  scope,
  scope_id: safeId,
}).strict();

export const approvedMemorySearchRequestSchema = z.object({
  scope,
  scope_id: safeId,
  allowed_project_ids: ids.optional(),
}).strict();

const approvedStoredMetadataSchema = z.object({
  contract: z.literal(APPROVED_WORKING_MEMORY_RECORD_CONTRACT),
  storage_status: z.literal("approved"),
  approved_payload: approvedPayloadSchema,
  write_payload_digest: sha,
  candidate_id: z.string().regex(CANDIDATE_ID),
  governance_digest: sha,
  approval_request_id: z.string().regex(REQUEST_ID),
  approval_request_digest: sha,
  approval_decision_digest: sha,
  admission_digest: sha,
  idempotency_key: sha,
  stored_at: isoTimestamp,
}).strict();

type ApprovedPayload = z.infer<typeof approvedPayloadSchema>;
type Admission = z.infer<typeof admissionSchema>;
type ApprovedRow = NonNullable<ReturnType<typeof parseApprovedRow>>;
type Isolation = { teamId?: string; userId: string; agentId: string; sessionId: string; taskId?: string };
export interface ApprovedWorkingMemoryDeps {
  getStore: () => IMemoryStore | undefined;
  requestIsolation?: Isolation;
  now?: () => string;
}

function successEnvelope<T>(data: T, requestId: string): ApiResponseEnvelope<T> {
  return { code: 0, message: "ok", request_id: requestId, data };
}

function errorEnvelope(code: number, message: string, requestId: string): ApiResponseEnvelope {
  return { code, message, request_id: requestId };
}

function errorWithData(code: number, message: string, requestId: string, data: unknown): ApiResponseEnvelope {
  return { code, message, request_id: requestId, data };
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

function omit<T extends Record<string, unknown>>(value: T, key: keyof T): Record<string, unknown> {
  const copy = { ...value };
  delete copy[key];
  return copy;
}

function validateBinding(admission: Admission, record: ApprovedPayload): boolean {
  const recordBody = omit(record, "memory_id");
  const memoryId = `wm_sha256_${digest("cmg/working-memory-write-payload/v1/identity", recordBody).slice(7)}`;
  const payloadDigest = digest("cmg/working-memory-write-payload/v1/snapshot", record);
  const admissionIdentity = digest("cmg/human-approved-memory-admission/v1/idempotency", {
    candidate_id: admission.candidate_id,
    candidate_version: admission.candidate_version,
    candidate_digest: admission.candidate_digest,
    governance_digest: admission.governance_digest,
    approval_request_id: admission.approval_request_id,
    approval_request_digest: admission.approval_request_digest,
    approval_decision_digest: admission.approval_decision_digest,
    scope: admission.scope,
    scope_id: admission.scope_id,
    allowed_project_ids: admission.allowed_project_ids,
    write_payload_digest: admission.write_payload_digest,
  });
  const admissionDigest = digest("cmg/human-approved-memory-admission/v1/admission", omit(admission, "admission_digest"));
  return record.memory_id === memoryId && admission.write_payload_digest === payloadDigest &&
    admission.idempotency_key === admissionIdentity && admission.admission_digest === admissionDigest &&
    admission.candidate_digest === record.candidate_digest && admission.candidate_version === record.candidate_version &&
    admission.scope === record.scope && admission.scope_id === record.scope_id &&
    stable(admission.allowed_project_ids) === stable(record.allowed_project_ids);
}

function parseApprovedRow(row: L1RecordRow, isolation?: Isolation) {
  if (isolation && (row.team_id !== isolation.teamId || row.user_id !== isolation.userId || row.agent_id !== isolation.agentId)) return null;
  try {
    const parsed = approvedStoredMetadataSchema.safeParse(JSON.parse(row.metadata_json));
    if (!parsed.success || parsed.data.approved_payload.memory_id !== row.record_id ||
        parsed.data.approved_payload.content !== row.content) return null;
    const expectedMemoryId = `wm_sha256_${digest("cmg/working-memory-write-payload/v1/identity",
      omit(parsed.data.approved_payload, "memory_id")).slice(7)}`;
    if (parsed.data.approved_payload.memory_id !== expectedMemoryId) return null;
    const expectedDigest = digest("cmg/working-memory-write-payload/v1/snapshot", parsed.data.approved_payload);
    if (parsed.data.write_payload_digest !== expectedDigest) return null;
    return { row, metadata: parsed.data, record: parsed.data.approved_payload, payload_digest: expectedDigest };
  } catch { return null; }
}

async function approvedRows(store: IMemoryStore, isolation?: Isolation) {
  const rows = await store.queryL1Records({
    teamId: isolation?.teamId, userId: isolation?.userId, agentId: isolation?.agentId,
  });
  return rows.map((row) => parseApprovedRow(row, isolation)).filter((value) => value !== null);
}

const writeLocks = new WeakMap<object, Promise<void>>();

async function withStoreWriteLock<T>(store: IMemoryStore, operation: () => Promise<T>): Promise<T> {
  const previous = writeLocks.get(store as object) ?? Promise.resolve();
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const tail = previous.then(() => gate);
  writeLocks.set(store as object, tail);
  await previous;
  try { return await operation(); }
  finally {
    release();
    if (writeLocks.get(store as object) === tail) writeLocks.delete(store as object);
  }
}

function sameScope(left: ApprovedPayload, right: ApprovedPayload): boolean {
  return left.scope === right.scope && left.scope_id === right.scope_id &&
    stable(left.allowed_project_ids) === stable(right.allowed_project_ids);
}

type LifecycleView = {
  currentness: "current" | "superseded" | "conflicted" | "invalid";
  lineage_status: "valid" | "conflict" | "invalid";
  predecessor_ids: string[];
  successor_ids: string[];
  relation_digest: string | null;
};

function lifecycleViews(items: ApprovedRow[]): Map<string, LifecycleView> {
  const byId = new Map(items.map((item) => [item.record.memory_id, item]));
  const successors = new Map<string, string[]>();
  const invalid = new Set<string>();
  const relations = new Map<string, string>();
  for (const item of items) {
    const { record } = item;
    if (record.supersedes.length === 0) continue;
    const predecessorId = record.supersedes[0];
    const predecessor = byId.get(predecessorId);
    if (predecessorId === record.memory_id || !predecessor || !sameScope(record, predecessor.record) ||
        record.expected_version !== predecessor.row.version) {
      invalid.add(record.memory_id);
      continue;
    }
    successors.set(predecessorId, [...(successors.get(predecessorId) ?? []), record.memory_id]);
    relations.set(record.memory_id, digest(`${APPROVED_WORKING_MEMORY_RECORD_CONTRACT}/supersession-relation`, {
      predecessor_id: predecessorId,
      predecessor_digest: predecessor.payload_digest,
      successor_id: record.memory_id,
      successor_digest: item.payload_digest,
      scope: record.scope,
      scope_id: record.scope_id,
      allowed_project_ids: record.allowed_project_ids,
    }));
  }
  for (const item of items) {
    const origin = item.record.memory_id;
    const seen = new Set<string>();
    let cursor: string | undefined = origin;
    while (cursor) {
      if (seen.has(cursor)) {
        for (const id of seen) invalid.add(id);
        break;
      }
      seen.add(cursor);
      const current = byId.get(cursor);
      cursor = current?.record.supersedes[0];
    }
  }
  const branched = new Set<string>();
  for (const [predecessorId, ids] of successors) {
    if (ids.length > 1) {
      branched.add(predecessorId);
      ids.forEach((id) => branched.add(id));
    }
  }
  return new Map(items.map((item) => {
    const id = item.record.memory_id;
    const successorIds = [...(successors.get(id) ?? [])].sort();
    const predecessorIds = [...item.record.supersedes];
    const currentness = invalid.has(id) ? "invalid" : branched.has(id) ? "conflicted" :
      successorIds.length === 1 ? "superseded" : "current";
    return [id, {
      currentness,
      lineage_status: invalid.has(id) ? "invalid" : branched.has(id) ? "conflict" : "valid",
      predecessor_ids: predecessorIds,
      successor_ids: successorIds,
      relation_digest: relations.get(id) ?? null,
    }];
  }));
}

function lifecycleItem(item: ApprovedRow, views: Map<string, LifecycleView>) {
  return {
    record: item.record,
    write_payload_digest: item.payload_digest,
    admission_digest: item.metadata.admission_digest,
    idempotency_key: item.metadata.idempotency_key,
    stored_at: item.metadata.stored_at,
    record_version: item.row.version,
    ...views.get(item.record.memory_id)!,
  };
}

function persistenceResult(status: string, admission: Admission, record: ApprovedPayload, storedAt: string,
  readbackStatus: string) {
  const body = {
    contract: APPROVED_WORKING_MEMORY_RESULT_CONTRACT,
    status,
    target: "tencentdb-working-memory",
    memory_id: record.memory_id,
    idempotency_key: admission.idempotency_key,
    admission_digest: admission.admission_digest,
    write_payload_digest: admission.write_payload_digest,
    readback_digest: readbackStatus === "verified" ? admission.write_payload_digest : null,
    readback_status: readbackStatus,
    stored_at: storedAt,
  };
  return { ...body, receipt_digest: digest(`${APPROVED_WORKING_MEMORY_RESULT_CONTRACT}/receipt`, body) };
}

export async function handleApprovedMemoryWrite(body: unknown, _auth: V2AuthContext, requestId: string,
  deps: ApprovedWorkingMemoryDeps): Promise<ApiResponseEnvelope> {
  const parsed = approvedMemoryWriteRequestSchema.safeParse(body);
  if (!parsed.success || !validateBinding(parsed.success ? parsed.data.admission : {} as Admission,
      parsed.success ? parsed.data.record : {} as ApprovedPayload)) {
    return errorEnvelope(400, "approved memory request invalid", requestId);
  }
  const { admission, record } = parsed.data;
  const store = deps.getStore();
  const isolation = deps.requestIsolation;
  if (!store || !isolation?.teamId || !isolation.userId || !isolation.agentId || !isolation.sessionId) {
    return errorEnvelope(503, "approved memory store or isolation unavailable", requestId);
  }
  return withStoreWriteLock(store, async () => {
  const now = deps.now?.() ?? new Date().toISOString();
  const rawRows = await store.queryL1Records({
    teamId: isolation.teamId, userId: isolation.userId, agentId: isolation.agentId,
  });
  const occupiedById = rawRows.find((row) => row.record_id === record.memory_id);
  if (occupiedById && !parseApprovedRow(occupiedById, isolation)) {
    return errorWithData(409, "approved memory record id collision", requestId,
      persistenceResult("conflict", admission, record, now, "not_verified"));
  }
  const existing = rawRows.map((row) => parseApprovedRow(row, isolation)).filter((item) => item !== null)
    .find((item) => item.record.memory_id === record.memory_id || item.metadata.idempotency_key === admission.idempotency_key);
  if (existing) {
    const exact = existing.metadata.idempotency_key === admission.idempotency_key &&
      existing.metadata.admission_digest === admission.admission_digest &&
      existing.metadata.write_payload_digest === admission.write_payload_digest && stable(existing.record) === stable(record);
    return exact
      ? successEnvelope(persistenceResult("exact_replay", admission, record, String(existing.metadata.stored_at), "verified"), requestId)
      : errorWithData(409, "approved memory conflict", requestId, persistenceResult("conflict", admission, record, now, "not_verified"));
  }
  const existingApproved = rawRows.map((row) => parseApprovedRow(row, isolation)).filter((item) => item !== null);
  let writeStatus = "created";
  if (record.supersedes.length === 1) {
    const predecessorId = record.supersedes[0];
    const predecessor = existingApproved.find((item) => item.record.memory_id === predecessorId);
    const views = lifecycleViews(existingApproved);
    if (!predecessor || predecessorId === record.memory_id || !sameScope(record, predecessor.record) ||
        record.expected_version !== predecessor.row.version || views.get(predecessorId)?.currentness !== "current") {
      return errorWithData(409, "approved memory supersession conflict", requestId,
        persistenceResult("conflict", admission, record, now, "not_verified"));
    }
    writeStatus = "updated";
  }
  const metadata = {
    contract: APPROVED_WORKING_MEMORY_RECORD_CONTRACT,
    storage_status: "approved",
    approved_payload: record,
    write_payload_digest: admission.write_payload_digest,
    candidate_id: admission.candidate_id,
    governance_digest: admission.governance_digest,
    approval_request_id: admission.approval_request_id,
    approval_request_digest: admission.approval_request_digest,
    approval_decision_digest: admission.approval_decision_digest,
    admission_digest: admission.admission_digest,
    idempotency_key: admission.idempotency_key,
    stored_at: now,
  };
  const l1: MemoryRecord = {
    id: record.memory_id, content: record.content, type: "instruction", priority: 100,
    scene_name: "approved-working-memory", source_message_ids: [], metadata: metadata as any,
    timestamps: [admission.evaluated_at], createdAt: now, updatedAt: now, version: 1,
    sessionKey: isolation.sessionId, sessionId: isolation.sessionId, taskId: isolation.taskId,
    teamId: isolation.teamId, userId: isolation.userId, agentId: isolation.agentId,
  };
  if (await store.upsertL1(l1, undefined) !== true) {
    return errorWithData(503, "approved memory write failed", requestId, persistenceResult("failed", admission, record, now, "not_verified"));
  }
  const readbackRows = await store.queryL1Records({
    teamId: isolation.teamId, userId: isolation.userId, agentId: isolation.agentId,
  });
  const rawReadback = readbackRows.find((row) => row.record_id === record.memory_id);
  const readback = rawReadback ? parseApprovedRow(rawReadback, isolation) : null;
  if (!rawReadback) {
    return errorWithData(503, "approved memory readback missing", requestId, persistenceResult("unresolved", admission, record, now, "missing"));
  }
  if (!readback) {
    return errorWithData(409, "approved memory readback schema mismatch", requestId,
      persistenceResult("conflict", admission, record, now, "mismatch"));
  }
  const exact = stable(readback.record) === stable(record) && readback.metadata.idempotency_key === admission.idempotency_key &&
    readback.metadata.admission_digest === admission.admission_digest && readback.metadata.write_payload_digest === admission.write_payload_digest;
  if (!exact) {
    return errorWithData(409, "approved memory readback mismatch", requestId, persistenceResult("conflict", admission, record, now, "mismatch"));
  }
  return successEnvelope(persistenceResult(writeStatus, admission, record, now, "verified"), requestId);
  });
}

export async function handleApprovedMemoryGet(body: unknown, _auth: V2AuthContext, requestId: string,
  deps: ApprovedWorkingMemoryDeps): Promise<ApiResponseEnvelope> {
  const parsed = approvedMemoryGetRequestSchema.safeParse(body);
  const store = deps.getStore();
  if (!parsed.success) return errorEnvelope(400, "approved memory get invalid", requestId);
  if (!store) return errorEnvelope(503, "approved memory store unavailable", requestId);
  const items = await approvedRows(store, deps.requestIsolation);
  const match = items.find((item) => item.record.memory_id === parsed.data.memory_id &&
    item.metadata.idempotency_key === parsed.data.idempotency_key && item.record.scope === parsed.data.scope &&
    item.record.scope_id === parsed.data.scope_id);
  return match ? successEnvelope({ ...lifecycleItem(match, lifecycleViews(items)), readback_status: "verified" }, requestId)
    : errorEnvelope(404, "approved memory not found", requestId);
}

export async function handleApprovedMemorySearch(body: unknown, _auth: V2AuthContext, requestId: string,
  deps: ApprovedWorkingMemoryDeps): Promise<ApiResponseEnvelope> {
  const parsed = approvedMemorySearchRequestSchema.safeParse(body);
  const store = deps.getStore();
  if (!parsed.success) return errorEnvelope(400, "approved memory search invalid", requestId);
  if (!store) return errorEnvelope(503, "approved memory store unavailable", requestId);
  const approved = await approvedRows(store, deps.requestIsolation);
  const views = lifecycleViews(approved);
  const items = approved.filter((item) => item.record.scope === parsed.data.scope &&
    item.record.scope_id === parsed.data.scope_id && (parsed.data.allowed_project_ids === undefined ||
      stable(item.record.allowed_project_ids) === stable(parsed.data.allowed_project_ids)))
    .map((item) => lifecycleItem(item, views));
  return successEnvelope({ items, total: items.length }, requestId);
}
