import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createRequireInternalServiceToken } from "../src/middlewares/internal-auth.middleware";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import {
  INCIDENT_SEVERITY,
  VIOLATION_TYPE,
  EVIDENCE_TYPE,
} from "../src/common/constants/incident.constant";
import { isUuid } from "../src/common/helpers/uuid.helper";
import {
  aiVisionEventInputSchema,
  aiVisionBatchInputSchema,
} from "../src/modules/integration/ai-vision.validation";
import {
  AiVisionIntegrationService,
  deriveDeterministicUuid,
  normalizeBoundingBox,
  resolveEvidenceStorageKey,
} from "../src/modules/integration/ai-vision.service";
import { AiVisionKafkaConsumer } from "../src/modules/integration/ai-vision.consumer";
import { HttpNotificationServiceClient } from "../src/modules/incident/notification-client.interface";
import { IncidentService } from "../src/modules/incident/incident.service";
import { markDeduplicatedIncident } from "../src/modules/incident/incident.repository";
import { incidentRouter } from "../src/modules/incident/incident.route";

describe("AI Vision Incident Ingestion (HTTP + Kafka)", () => {
  it("should enforce fail-closed M2M internal service token middleware", () => {
    const disabledMw = createRequireInternalServiceToken("");
    let errDisabled: any;
    disabledMw(
      { headers: { [GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN]: "any" } } as any,
      {} as any,
      (err?: any) => {
        errDisabled = err;
      },
    );
    assert.ok(errDisabled instanceof AppError);
    assert.equal(errDisabled.statusCode, 503);

    const mw = createRequireInternalServiceToken("internal_secret_token_32chars_min!!");
    let errMissing: any;
    mw({ headers: {} } as any, {} as any, (err?: any) => {
      errMissing = err;
    });
    assert.equal(errMissing?.statusCode, 401);

    let errWrong: any;
    mw(
      { headers: { [GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN]: "bad" } } as any,
      {} as any,
      (err?: any) => {
        errWrong = err;
      },
    );
    assert.equal(errWrong?.statusCode, 403);
    assert.equal(errWrong?.code, ERROR_CODE.FORBIDDEN);

    let errValid: any = "uncalled";
    mw(
      {
        headers: {
          [GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN]:
            "internal_secret_token_32chars_min!!",
        },
      } as any,
      {} as any,
      (err?: any) => {
        errValid = err;
      },
    );
    assert.equal(errValid, undefined);
  });

  it("should derive valid deterministic UUIDv5 for non-UUID eventIds and preserve UUIDs", () => {
    const validUuid = "0199a001-0000-7000-8000-000000000001";
    assert.equal(deriveDeterministicUuid(validUuid), validUuid);

    const a = deriveDeterministicUuid("a1b2c3d4e5f6");
    const b = deriveDeterministicUuid("a1b2c3d4e5f6");
    const c = deriveDeterministicUuid("ffffff000000");
    assert.equal(isUuid(a), true);
    assert.equal(a, b);
    assert.notEqual(a, c);
  });

  it("should extract safe MinIO storageKey from explicit objectKey or URLs", () => {
    const siteId = "0199a001-0000-7000-8000-0000000000aa";

    assert.equal(
      resolveEvidenceStorageKey(
        `evidences/${siteId}/CAM-01/snap.jpg`,
        "http://localhost:9000/ignored.jpg",
        siteId,
        "CAM-01",
        "fallback.jpg",
      ),
      `evidences/${siteId}/CAM-01/snap.jpg`,
    );

    assert.equal(
      resolveEvidenceStorageKey(
        undefined,
        `http://localhost:9000/ppe-evidences/evidences/${siteId}/CAM-01/20261116_track1.jpg?X-Amz-Signature=abc`,
        siteId,
        "CAM-01",
        "fallback.jpg",
      ),
      `evidences/${siteId}/CAM-01/20261116_track1.jpg`,
    );

    // Path traversal attempt is ignored in favor of safe normalized key
    const safe = resolveEvidenceStorageKey(
      "evidences/../etc/passwd",
      "http://localhost/no-evidences-prefix.jpg",
      siteId,
      "CAM-01",
      "safe.jpg",
    );
    assert.equal(safe, `evidences/${siteId}/CAM-01/safe.jpg`);
  });

  it("should normalize pixel bounding boxes into [0..1] ratios for frontend HUD", () => {
    const normalized = normalizeBoundingBox(
      { x: 640, y: 180, width: 320, height: 360 },
      1280,
      720,
    );
    assert.deepEqual(normalized, { x: 0.5, y: 0.25, width: 0.25, height: 0.5 });

    const alreadyNormalized = normalizeBoundingBox(
      { x: 0.2, y: 0.3, width: 0.4, height: 0.5 },
      1920,
      1080,
    );
    assert.deepEqual(alreadyNormalized, { x: 0.2, y: 0.3, width: 0.4, height: 0.5 });
  });

  it("should validate both direct AI ViolationEvent and Kafka envelope payloads", () => {
    const rawEvent = {
      cameraCode: "CAM-01",
      timestamp: "2026-11-16T09:00:00.000Z",
      evidence: {
        snapshotUrl: "http://localhost:9000/ppe-evidences/evidences/site-1/CAM-01/snap.jpg",
        frameResolution: { width: 1280, height: 720 },
      },
      detections: [
        {
          class: "PERSON",
          confidence: 0.92,
          box: { x: 100, y: 100, width: 200, height: 400 },
          trackId: 1,
        },
      ],
      violations: [
        {
          violationType: "NO_HELMET",
          severity: "HIGH",
          description: "Không đội mũ bảo hộ",
          confidence: 0.92,
          box: { x: 100, y: 100, width: 200, height: 400 },
        },
      ],
    };

    const parsedDirect = aiVisionEventInputSchema.parse(rawEvent);
    assert.ok("cameraCode" in parsedDirect);

    const parsedEnvelope = aiVisionEventInputSchema.parse({
      topic: "ppe.violation.detected",
      producer: "smart-ppe-ai-service",
      payload: rawEvent,
    });
    assert.ok("payload" in parsedEnvelope);

    const parsedBatch = aiVisionBatchInputSchema.parse({ events: [rawEvent] });
    assert.equal(parsedBatch.events.length, 1);
  });

  it("should ingest ViolationEvent with camera lookup, MinIO storageKey, and normalized detections", async () => {
    const capturedDtos: any[] = [];
    const lookupCalls: any[] = [];
    const siteUuid = "0199a001-0000-7000-8000-0000000000aa";
    const camUuid = "0199a001-0000-7000-8000-000000000001";

    const mockIncidentSvc = {
      createIncident: async (dto: any) => {
        capturedDtos.push(dto);
        return { id: "0199a001-0000-7000-8000-999999999999", ...dto };
      },
    } as any;

    const mockCameraClient = {
      lookupCamera: async (q: any) => {
        lookupCalls.push(q);
        return { id: camUuid, siteId: siteUuid, code: "CAM-01" };
      },
    };

    const service = new AiVisionIntegrationService(mockIncidentSvc, mockCameraClient);

    const res = await service.ingestEvent({
      eventId: "evt_track1_1234",
      cameraCode: "CAM-01",
      timestamp: "2026-11-16T09:15:00.000Z",
      evidence: {
        snapshotUrl: `http://localhost:9000/ppe-evidences/evidences/${siteUuid}/CAM-01/violation.jpg`,
        referenceSnapshotUrl: `http://localhost:9000/ppe-evidences/evidences/${siteUuid}/CAM-01/violation_ref.jpg`,
        checksum: "a".repeat(64),
        mimeType: "image/jpeg",
        frameResolution: { width: 1000, height: 1000 },
      },
      detections: [
        {
          class: "PERSON",
          confidence: 0.91,
          box: { x: 250, y: 100, width: 200, height: 500 },
          trackId: 7,
        },
      ],
      violations: [
        {
          violationType: "NO_HELMET",
          severity: "HIGH",
          description: "Thiếu mũ bảo hộ",
          confidence: 0.91,
          box: { x: 250, y: 100, width: 200, height: 500 },
        },
        {
          violationType: "NO_VEST",
          severity: "MEDIUM",
          description: "Thiếu áo phản quang",
          confidence: 0.85,
        },
      ],
      metadata: {
        model: "yolo11s.pt",
        contractVersion: "2.1.0-PPE-STABLE",
        annotatedInImage: false,
      },
    });

    assert.equal(lookupCalls.length, 1);
    assert.deepEqual(lookupCalls[0], { code: "CAM-01" });
    assert.equal(capturedDtos.length, 1);

    const dto = capturedDtos[0];
    assert.equal(dto.siteId, siteUuid);
    assert.equal(dto.cameraId, camUuid);
    assert.equal(isUuid(dto.violationId), true);
    assert.equal(dto.violationType, VIOLATION_TYPE.MULTI_VIOLATION);
    assert.equal(dto.severity, INCIDENT_SEVERITY.HIGH);
    assert.equal(dto.initialEvidence.evidenceType, EVIDENCE_TYPE.SNAPSHOT);
    assert.equal(
      dto.initialEvidence.storageKey,
      `evidences/${siteUuid}/CAM-01/violation.jpg`,
    );
    assert.equal(
      dto.initialReferenceEvidence.evidenceType,
      EVIDENCE_TYPE.REFERENCE_SNAPSHOT,
    );
    assert.equal(
      dto.initialReferenceEvidence.storageKey,
      `evidences/${siteUuid}/CAM-01/violation_ref.jpg`,
    );
    assert.deepEqual(dto.initialEvidence.metadata.aiDetections.violation.box, {
      x: 0.25,
      y: 0.1,
      width: 0.2,
      height: 0.5,
    });
    assert.equal(dto.initialEvidence.metadata.aiDetections.annotatedInImage, false);
    assert.equal(res.storageKey, `evidences/${siteUuid}/CAM-01/violation.jpg`);
  });

  it("should process Kafka violation envelopes and reject malformed messages safely", async () => {
    const siteUuid = "0199a001-0000-7000-8000-0000000000bb";
    const camUuid = "0199a001-0000-7000-8000-000000000002";

    const mockIncidentSvc = {
      createIncident: async (dto: any) => ({
        id: "0199a001-0000-7000-8000-888888888888",
        ...dto,
      }),
    } as any;

    const integrationSvc = new AiVisionIntegrationService(mockIncidentSvc, {
      lookupCamera: async () => ({
        id: camUuid,
        siteId: siteUuid,
        code: "CAM-02",
      }),
    } as any);
    const consumer = new AiVisionKafkaConsumer(integrationSvc);

    const okResult = await consumer.processRawMessage(
      JSON.stringify({
        topic: "ppe.violation.detected",
        producer: "smart-ppe-ai-service",
        payload: {
          siteId: siteUuid,
          cameraId: camUuid,
          cameraCode: "CAM-02",
          timestamp: "2026-11-16T09:20:00.000Z",
          evidence: {
            snapshotUrl: `http://localhost:9000/ppe-evidences/evidences/${siteUuid}/CAM-02/ev.jpg`,
            frameResolution: { width: 1280, height: 720 },
          },
          violations: [
            {
              violationType: "NO_HELMET",
              severity: "HIGH",
              description: "No helmet",
              confidence: 0.9,
            },
          ],
        },
      }),
    );

    assert.equal(okResult.success, true);
    assert.equal(okResult.incidentId, "0199a001-0000-7000-8000-888888888888");

    const badJson = await consumer.processRawMessage("{broken-json");
    assert.equal(badJson.success, false);
    assert.equal(badJson.retryable, false);

    const invalidPayload = await consumer.processRawMessage(JSON.stringify({ foo: "bar" }));
    assert.equal(invalidPayload.success, false);
    assert.equal(invalidPayload.retryable, false);
  });

  it("should reject mismatched siteId via CameraLookupClient even when both UUIDs are supplied", async () => {
    const camUuid = "0199a001-0000-7000-8000-000000000011";
    const realSiteUuid = "0199a001-0000-7000-8000-0000000000aa";
    const victimSiteUuid = "0199a001-0000-7000-8000-0000000000bb";

    const service = new AiVisionIntegrationService(
      { createIncident: async () => ({ id: "unused" }) } as any,
      {
        lookupCamera: async () => ({
          id: camUuid,
          siteId: realSiteUuid,
          code: "CAM-11",
        }),
      } as any,
    );

    await assert.rejects(
      () =>
        service.ingestEvent({
          siteId: victimSiteUuid,
          cameraId: camUuid,
          cameraCode: "CAM-11",
          timestamp: "2026-11-16T09:30:00.000Z",
          evidence: {
            snapshotUrl: `http://localhost:9000/ppe-evidences/evidences/${victimSiteUuid}/CAM-11/x.jpg`,
          },
          violations: [
            {
              violationType: "NO_HELMET",
              severity: "HIGH",
              description: "No helmet",
              confidence: 0.9,
            },
          ],
        }),
      (err: any) => err instanceof AppError && err.statusCode === 422,
    );
  });

  it("should scope non-UUID eventId per siteId and cameraId to avoid cross-tenant idempotency collisions", async () => {
    const violationIds: string[] = [];
    const siteA = "0199a001-0000-7000-8000-0000000000aa";
    const siteB = "0199a001-0000-7000-8000-0000000000bb";
    const camA = "0199a001-0000-7000-8000-000000000101";
    const camB = "0199a001-0000-7000-8000-000000000202";

    const mockIncidentSvc = {
      createIncident: async (dto: any) => {
        violationIds.push(dto.violationId);
        return { id: dto.violationId };
      },
    } as any;

    const svcA = new AiVisionIntegrationService(mockIncidentSvc, {
      lookupCamera: async () => ({ id: camA, siteId: siteA, code: "CAM-SHARED" }),
    } as any);
    const svcB = new AiVisionIntegrationService(mockIncidentSvc, {
      lookupCamera: async () => ({ id: camB, siteId: siteB, code: "CAM-SHARED" }),
    } as any);

    await svcA.ingestEvent({
      eventId: "shared-evt-1",
      cameraCode: "CAM-SHARED",
      timestamp: "2026-11-16T09:31:00.000Z",
      evidence: { snapshotUrl: "http://localhost:9000/a.jpg" },
      violations: [
        { violationType: "NO_HELMET", severity: "HIGH", description: "No helmet", confidence: 0.9 },
      ],
    });

    await svcB.ingestEvent({
      eventId: "shared-evt-1",
      cameraCode: "CAM-SHARED",
      timestamp: "2026-11-16T09:31:00.000Z",
      evidence: { snapshotUrl: "http://localhost:9000/b.jpg" },
      violations: [
        { violationType: "NO_HELMET", severity: "HIGH", description: "No helmet", confidence: 0.9 },
      ],
    });

    assert.equal(violationIds.length, 2);
    assert.notEqual(violationIds[0], violationIds[1]);
  });

  it("should enforce strict UUID format and valid ISO timestamp and rethrow transient Kafka errors", async () => {
    assert.equal(isUuid("0199a001-0000-7000-8000-000000000001"), true);
    assert.equal(isUuid("------------------------------------"), false);
    assert.equal(isUuid("0199a001000070008000000000000001----"), false);

    assert.equal(
      aiVisionBatchInputSchema.safeParse({
        events: [
          {
            cameraCode: "CAM-01",
            timestamp: "not-a-valid-date",
            evidence: { snapshotUrl: "http://localhost/snap.jpg" },
            violations: [
              { violationType: "NO_HELMET", severity: "HIGH", description: "x", confidence: 0.9 },
            ],
          },
        ],
      }).success,
      false,
    );

    const transientConsumer = new AiVisionKafkaConsumer({
      ingestEvent: async () => {
        throw new Error("PostgreSQL connection lost");
      },
    } as any);

    const payload = JSON.stringify({
      cameraCode: "CAM-01",
      timestamp: "2026-11-16T09:40:00.000Z",
      evidence: { snapshotUrl: "http://localhost/snap.jpg" },
      violations: [
        { violationType: "NO_HELMET", severity: "HIGH", description: "x", confidence: 0.9 },
      ],
    });

    await assert.rejects(() => transientConsumer.handleMessageValue(payload));
  });

  it("should dispatch realtime HTTP notification via HttpNotificationServiceClient with M2M headers and skip deduplicated hits", async () => {
    const requests: Array<{ url: string; init: RequestInit }> = [];
    const client = new HttpNotificationServiceClient({
      baseUrl: "http://notification-service:8889",
      internalToken: "m2m-secret-token",
      gatewaySecret: "gw-secret-key",
      fetcher: (async (url: string | URL | Request, init?: RequestInit) => {
        requests.push({ url: String(url), init: init || {} });
        return new Response(
          JSON.stringify({ success: true, data: { dispatchedCount: 2 } }),
          { status: 201, headers: { "Content-Type": "application/json" } },
        );
      }) as typeof fetch,
    });

    const incId = "0199a001-0000-7000-8000-000000000777";
    const evId = "0199a001-0000-7000-8000-000000000888";
    const siteId = "0199a001-0000-7000-8000-0000000000aa";
    const cameraId = "0199a001-0000-7000-8000-000000000001";

    let callIndex = 0;
    const mockRepo = {
      createIncident: async (dto: any) => {
        callIndex++;
        const record = {
          id: incId,
          siteId: dto.siteId,
          cameraId: dto.cameraId,
          violationType: dto.violationType,
          severity: dto.severity || "HIGH",
          description: dto.description || "Thiếu mũ bảo hộ",
          detectedAt: new Date("2026-11-16T10:00:00.000Z"),
          evidences: [
            {
              id: evId,
              evidenceType: EVIDENCE_TYPE.SNAPSHOT,
              storageKey: `evidences/${siteId}/CAM-01/snap.jpg`,
            },
          ],
        };
        return callIndex === 2 ? markDeduplicatedIncident(record) : record;
      },
    } as any;

    const svc = new IncidentService(mockRepo, undefined, client);

    // Lần 1: Sự cố mới -> phải gọi Notification Service kèm M2M token + cameraCode + evidenceUrl
    await svc.createIncident(
      {
        siteId,
        cameraId,
        violationId: "0199a001-0000-7000-8000-000000000999",
        violationType: "NO_HELMET",
        detectedAt: new Date("2026-11-16T10:00:00.000Z"),
      },
      "00000000-0000-0000-0000-000000000000",
      { cameraCode: "CAM-01" },
    );

    // Chờ microtask async fire-and-forget dispatch
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(requests.length, 1);
    assert.equal(
      requests[0].url,
      "http://notification-service:8889/api/v1/notifications/internal/trigger-incident",
    );
    const reqHeaders = requests[0].init.headers as Record<string, string>;
    assert.equal(reqHeaders[GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN], "m2m-secret-token");
    assert.equal(reqHeaders[GATEWAY_HEADERS.INTERNAL_SECRET], "gw-secret-key");
    const parsedBody = JSON.parse(String(requests[0].init.body));
    assert.equal(parsedBody.incidentId, incId);
    assert.equal(parsedBody.cameraCode, "CAM-01");
    assert.equal(parsedBody.evidenceUrl, `/api/v1/evidences/${evId}/download-url`);

    // Lần 2: Duplicate violationId (markDeduplicatedIncident) -> không bắn trùng thông báo
    await svc.createIncident(
      {
        siteId,
        cameraId,
        violationId: "0199a001-0000-7000-8000-000000000999",
        violationType: "NO_HELMET",
        detectedAt: new Date("2026-11-16T10:00:00.000Z"),
      },
      "00000000-0000-0000-0000-000000000000",
      { cameraCode: "CAM-01" },
    );
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(requests.length, 1);
  });

  it("must mount GET /internal/:id before GET /:id on incidentRouter", () => {
    const getPaths = (incidentRouter.stack || [])
      .filter((layer: any) => layer.route?.methods?.get)
      .map((layer: any) => layer.route.path);

    const internalIdx = getPaths.indexOf("/internal/:id");
    const idIdx = getPaths.indexOf("/:id");
    assert.ok(internalIdx !== -1, "GET /internal/:id route must exist");
    assert.ok(idIdx !== -1, "GET /:id route must exist");
    assert.ok(internalIdx < idIdx, "GET /internal/:id must precede /:id");
  });
});
