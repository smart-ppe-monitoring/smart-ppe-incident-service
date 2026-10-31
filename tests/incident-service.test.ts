import fs from "node:fs";
import path from "node:path";
import { describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import jwt from "jsonwebtoken";
import {
  INCIDENT_STATUS,
  VIOLATION_TYPE,
  INCIDENT_SEVERITY,
  EVIDENCE_TYPE,
  ASSIGNMENT_STATUS,
  VALID_INCIDENT_TRANSITIONS,
  EVIDENCE_ACCESS_ACTION,
} from "../src/common/constants/incident.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import {
  requirePermission,
  requireAnyPermission,
} from "../src/middlewares/permission.middleware";
import {
  authMiddleware,
  extractTokenFromRequest,
} from "../src/middlewares/auth.middleware";
import {
  requireGatewayOrigin,
  createRequireGatewayOrigin,
} from "../src/middlewares/request-id.middleware";
import { maintenanceGuard } from "../src/middlewares/maintenance.middleware";
import { MEDIA_LIMITS } from "../src/common/constants/media.constant";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import {
  createIncidentSchema,
  updateIncidentSchema,
  incidentQuerySchema,
  reviewIncidentSchema,
  resolveIncidentSchema,
  closeIncidentSchema,
  createEvidenceSchema,
} from "../src/modules/incident/incident.validation";
import { IncidentService } from "../src/modules/incident/incident.service";
import {
  IncidentRepository,
  serializeEvidence,
  serializeIncident,
  normalizeActorUuid,
  SYSTEM_ACTOR_UUID,
} from "../src/modules/incident/incident.repository";
import { parseTrustProxy } from "../src/config/env.config";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import incidentApp from "../src/incident.app";

describe("Task BE-06: PPE Incident Management Service Suite", () => {
  // ── 1. Constants & Status Domain ───────────────────────────────────────────
  describe("1. Incident Domain Constants & State Machine Rules", () => {
    it("should define standard incident lifecycle status constants according to D08.pdf", () => {
      assert.equal(INCIDENT_STATUS.PENDING_REVIEW, "PENDING_REVIEW");
      assert.equal(INCIDENT_STATUS.CONFIRMED, "CONFIRMED");
      assert.equal(INCIDENT_STATUS.DISMISSED, "DISMISSED");
      assert.equal(INCIDENT_STATUS.RESOLVED, "RESOLVED");
      assert.equal(INCIDENT_STATUS.CLOSED, "CLOSED");
    });

    it("should define PPE violation types and severity levels", () => {
      assert.equal(VIOLATION_TYPE.NO_HELMET, "NO_HELMET");
      assert.equal(VIOLATION_TYPE.NO_VEST, "NO_VEST");
      assert.equal(VIOLATION_TYPE.RESTRICTED_AREA, "RESTRICTED_AREA");
      assert.equal(VIOLATION_TYPE.MULTI_VIOLATION, "MULTI_VIOLATION");

      assert.equal(INCIDENT_SEVERITY.LOW, "LOW");
      assert.equal(INCIDENT_SEVERITY.MEDIUM, "MEDIUM");
      assert.equal(INCIDENT_SEVERITY.HIGH, "HIGH");
      assert.equal(INCIDENT_SEVERITY.CRITICAL, "CRITICAL");
    });

    it("should define digital evidence types and assignment statuses", () => {
      assert.equal(EVIDENCE_TYPE.SNAPSHOT, "SNAPSHOT");
      assert.equal(EVIDENCE_TYPE.VIDEO_CLIP, "VIDEO_CLIP");

      assert.equal(ASSIGNMENT_STATUS.ACTIVE, "ACTIVE");
      assert.equal(ASSIGNMENT_STATUS.COMPLETED, "COMPLETED");
    });

    it("should validate transition rules defined in VALID_INCIDENT_TRANSITIONS", () => {
      assert.deepEqual(VALID_INCIDENT_TRANSITIONS[INCIDENT_STATUS.PENDING_REVIEW], [
        INCIDENT_STATUS.CONFIRMED,
        INCIDENT_STATUS.DISMISSED,
      ]);
      assert.deepEqual(VALID_INCIDENT_TRANSITIONS[INCIDENT_STATUS.CONFIRMED], [
        INCIDENT_STATUS.RESOLVED,
      ]);
      assert.deepEqual(VALID_INCIDENT_TRANSITIONS[INCIDENT_STATUS.DISMISSED], [
        INCIDENT_STATUS.CLOSED,
      ]);
      assert.deepEqual(VALID_INCIDENT_TRANSITIONS[INCIDENT_STATUS.RESOLVED], [
        INCIDENT_STATUS.CLOSED,
      ]);
      assert.deepEqual(VALID_INCIDENT_TRANSITIONS[INCIDENT_STATUS.CLOSED], []);
    });

    it("should define PPE incident permissions in PERMISSIONS constant", () => {
      assert.equal(PERMISSIONS.PPE_INCIDENT_READ, "PPE_INCIDENT_READ");
      assert.equal(PERMISSIONS.PPE_INCIDENT_REVIEW, "PPE_INCIDENT_REVIEW");
      assert.equal(PERMISSIONS.PPE_INCIDENT_UPDATE, "PPE_INCIDENT_UPDATE");
      assert.equal(PERMISSIONS.PPE_INCIDENT_DELETE, "PPE_INCIDENT_DELETE");
      assert.equal(PERMISSIONS.PPE_INCIDENT_MANAGE, "PPE_INCIDENT_MANAGE");
    });
  });

  // ── 2. Zod Validation Schemas ──────────────────────────────────────────────
  describe("2. Request Validation Schemas", () => {
    it("should validate valid incident creation payload with initial evidence", () => {
      const validPayload = {
        siteId: "11111111-1111-4111-8111-111111111111",
        cameraId: "22222222-2222-4222-8222-222222222222",
        violationType: VIOLATION_TYPE.NO_HELMET,
        severity: INCIDENT_SEVERITY.HIGH,
        detectedAt: new Date().toISOString(),
        description: "Phát hiện công nhân không đội mũ bảo hộ tại cổng A",
        initialEvidence: {
          evidenceType: EVIDENCE_TYPE.SNAPSHOT,
          storageKey: "evidences/2026/10/snapshot-1.jpg",
          fileName: "snapshot-1.jpg",
          mimeType: "image/jpeg",
          fileSize: 1048576,
          capturedAt: new Date().toISOString(),
          metadata: {
            width: 1920,
            height: 1080,
            checksum: "a1b2c3d4e5f6",
            aiDetections: { confidence: 0.96, label: "no_helmet" },
          },
        },
      };

      const result = createIncidentSchema.safeParse(validPayload);
      assert.equal(result.success, true);
    });

    it("should reject invalid siteId or cameraId format in createIncidentSchema", () => {
      const invalidPayload = {
        siteId: "not-a-valid-uuid",
        cameraId: "22222222-2222-4222-8222-222222222222",
        violationType: VIOLATION_TYPE.NO_VEST,
        detectedAt: new Date().toISOString(),
      };

      const result = createIncidentSchema.safeParse(invalidPayload);
      assert.equal(result.success, false);
      if (!result.success) {
        assert.ok(result.error.errors.some((e) => e.path.includes("siteId")));
      }
    });

    it("should reject empty update payload in updateIncidentSchema", () => {
      const emptyPayload = {};
      const result = updateIncidentSchema.safeParse(emptyPayload);
      assert.equal(result.success, false);
      if (!result.success) {
        assert.ok(
          result.error.errors.some((e) =>
            e.message.includes("Cần cung cấp ít nhất một trường"),
          ),
        );
      }
    });

    it("should validate reviewIncidentSchema decision CONFIRMED without reason", () => {
      const payload = {
        decision: "CONFIRMED",
      };
      const result = reviewIncidentSchema.safeParse(payload);
      assert.equal(result.success, true);
    });

    it("should reject reviewIncidentSchema decision DISMISSED when reason is missing or < 3 chars", () => {
      const payloadMissing = {
        decision: "DISMISSED",
      };
      const resultMissing = reviewIncidentSchema.safeParse(payloadMissing);
      assert.equal(resultMissing.success, false);

      const payloadTooShort = {
        decision: "DISMISSED",
        reason: "ab",
      };
      const resultTooShort = reviewIncidentSchema.safeParse(payloadTooShort);
      assert.equal(resultTooShort.success, false);

      const payloadValid = {
        decision: "DISMISSED",
        reason: "Góc quay bị khuất bóng râm, công nhân có đeo mũ vải bảo hộ",
      };
      const resultValid = reviewIncidentSchema.safeParse(payloadValid);
      assert.equal(resultValid.success, true);
    });

    it("should require resolutionNote with at least 3 characters in resolveIncidentSchema", () => {
      const invalid = { resolutionNote: "ok" };
      const resultInvalid = resolveIncidentSchema.safeParse(invalid);
      assert.equal(resultInvalid.success, false);

      const valid = {
        resolutionNote: "Đã lập biên bản nhắc nhở công nhân và bổ sung trang thiết bị tại hiện trường",
      };
      const resultValid = resolveIncidentSchema.safeParse(valid);
      assert.equal(resultValid.success, true);
    });

    it("should reject invalid initial status such as CLOSED or DISMISSED in createIncidentSchema", () => {
      const payloadClosed = {
        siteId: "11111111-1111-4111-8111-111111111111",
        cameraId: "22222222-2222-4222-8222-222222222222",
        violationType: VIOLATION_TYPE.NO_HELMET,
        status: INCIDENT_STATUS.CLOSED,
        detectedAt: new Date().toISOString(),
      };
      const resultClosed = createIncidentSchema.safeParse(payloadClosed);
      assert.equal(resultClosed.success, false);

      const payloadValid = {
        siteId: "11111111-1111-4111-8111-111111111111",
        cameraId: "22222222-2222-4222-8222-222222222222",
        violationType: VIOLATION_TYPE.NO_HELMET,
        status: INCIDENT_STATUS.PENDING_REVIEW,
        detectedAt: new Date().toISOString(),
      };
      const resultValid = createIncidentSchema.safeParse(payloadValid);
      assert.equal(resultValid.success, true);
    });

    it("should reject path traversal in storageKey and invalid mimeType in createEvidenceSchema", () => {
      const payloadTraversal = {
        cameraId: "22222222-2222-4222-8222-222222222222",
        evidenceType: EVIDENCE_TYPE.SNAPSHOT,
        storageKey: "../../../etc/passwd",
        fileName: "test.jpg",
        mimeType: "image/jpeg",
        capturedAt: new Date().toISOString(),
      };
      const resultTraversal = createEvidenceSchema.safeParse(payloadTraversal);
      assert.equal(resultTraversal.success, false);

      const payloadBadMime = {
        cameraId: "22222222-2222-4222-8222-222222222222",
        evidenceType: EVIDENCE_TYPE.SNAPSHOT,
        storageKey: "evidences/test.jpg",
        fileName: "test.jpg",
        mimeType: "invalid-mime-type",
        capturedAt: new Date().toISOString(),
      };
      const resultBadMime = createEvidenceSchema.safeParse(payloadBadMime);
      assert.equal(resultBadMime.success, false);
    });
  });

  // ── 3. BigInt Serialization Helper ─────────────────────────────────────────
  describe("3. Data Serialization & BigInt Safety", () => {
    it("should serialize BigInt fileSize to number without crashing JSON.stringify", () => {
      const evidenceData = {
        id: "ev-1",
        fileSize: BigInt(5242880),
        fileName: "clip.mp4",
      };

      const serialized = serializeEvidence(evidenceData);
      assert.equal(typeof serialized.fileSize, "number");
      assert.equal(serialized.fileSize, 5242880);

      // JSON stringify phải chạy trơn tru không ném lỗi
      const json = JSON.stringify(serialized);
      assert.ok(json.includes('"fileSize":5242880'));
    });

    it("should serialize evidence deleted by repository to safe number fileSize", async () => {
      const mockPrismaClient = {
        evidence: {
          delete: async () => ({
            id: "ev-del-1",
            fileSize: BigInt(10485760),
            fileName: "deleted-video.mp4",
          }),
        },
      };
      const repo = new IncidentRepository(mockPrismaClient);
      const deleted = await repo.deleteEvidence("ev-del-1");
      assert.equal(typeof deleted.fileSize, "number");
      assert.equal(deleted.fileSize, 10485760);
      assert.doesNotThrow(() => JSON.stringify(deleted));
    });

    it("should serialize incident with nested evidences containing BigInt", () => {
      const incidentData = {
        id: "inc-1",
        status: INCIDENT_STATUS.CONFIRMED,
        evidences: [
          { id: "ev-1", fileSize: BigInt(1024) },
          { id: "ev-2", fileSize: BigInt(2048) },
        ],
      };

      const serialized = serializeIncident(incidentData);
      assert.equal(typeof serialized.evidences[0].fileSize, "number");
      assert.equal(typeof serialized.evidences[1].fileSize, "number");
      assert.doesNotThrow(() => JSON.stringify(serialized));
    });
  });

  // ── 4. Service State Machine Transitions & Business Logic ──────────────────
  describe("4. Incident Service Lifecycle & State Transitions", () => {
    const fakeIncidentId = "11111111-1111-4111-8111-111111111111";
    const fakeActorId = "99999999-9999-4999-8999-999999999999";

    it("should review and CONFIRM a pending incident", async () => {
      const mockRepo = {
        findIncidentById: async (id: string) => ({
          id,
          status: INCIDENT_STATUS.PENDING_REVIEW,
        }),
        transitionStatus: async (params: any) => ({
          id: params.incidentId,
          status: params.newStatus,
          history: [params],
        }),
      } as unknown as IncidentRepository;

      const service = new IncidentService(mockRepo);
      const result = await service.reviewIncident(
        fakeIncidentId,
        { decision: "CONFIRMED", reason: "Xác nhận vi phạm chuẩn" },
        fakeActorId,
      );

      assert.equal(result.status, INCIDENT_STATUS.CONFIRMED);
    });

    it("should reject review transition if incident is not PENDING_REVIEW", async () => {
      const mockRepo = {
        findIncidentById: async (id: string) => ({
          id,
          status: INCIDENT_STATUS.CONFIRMED,
        }),
      } as unknown as IncidentRepository;

      const service = new IncidentService(mockRepo);

      await assert.rejects(
        async () => {
          await service.reviewIncident(
            fakeIncidentId,
            { decision: "CONFIRMED" },
            fakeActorId,
          );
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.equal(err.code, ERROR_CODE.INVALID_STATUS_TRANSITION);
          assert.equal(err.statusCode, 400);
          return true;
        },
      );
    });

    it("should resolve a CONFIRMED incident and record resolvedAt", async () => {
      let passedResolvedAt: any = null;
      const mockRepo = {
        findIncidentById: async (id: string) => ({
          id,
          status: INCIDENT_STATUS.CONFIRMED,
        }),
        transitionStatus: async (params: any) => {
          passedResolvedAt = params.resolvedAt;
          return {
            id: params.incidentId,
            status: params.newStatus,
            resolvedAt: params.resolvedAt,
          };
        },
      } as unknown as IncidentRepository;

      const service = new IncidentService(mockRepo);
      const result = await service.resolveIncident(
        fakeIncidentId,
        { resolutionNote: "Đã xử phạt và lập biên bản đầy đủ" },
        fakeActorId,
      );

      assert.equal(result.status, INCIDENT_STATUS.RESOLVED);
      assert.ok(passedResolvedAt instanceof Date);
    });

    it("should reject resolving an incident that is not CONFIRMED", async () => {
      const mockRepo = {
        findIncidentById: async (id: string) => ({
          id,
          status: INCIDENT_STATUS.PENDING_REVIEW,
        }),
      } as unknown as IncidentRepository;

      const service = new IncidentService(mockRepo);

      await assert.rejects(
        async () => {
          await service.resolveIncident(
            fakeIncidentId,
            { resolutionNote: "Giải quyết sớm" },
            fakeActorId,
          );
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.equal(err.code, ERROR_CODE.INVALID_STATUS_TRANSITION);
          return true;
        },
      );
    });

    it("should allow closing an incident from RESOLVED or DISMISSED", async () => {
      const mockRepoResolved = {
        findIncidentById: async (id: string) => ({
          id,
          status: INCIDENT_STATUS.RESOLVED,
        }),
        transitionStatus: async (params: any) => ({
          id: params.incidentId,
          status: params.newStatus,
        }),
      } as unknown as IncidentRepository;

      const service = new IncidentService(mockRepoResolved);
      const result = await service.closeIncident(
        fakeIncidentId,
        { closeNote: "Hồ sơ hoàn tất" },
        fakeActorId,
      );
      assert.equal(result.status, INCIDENT_STATUS.CLOSED);

      const mockRepoDismissed = {
        findIncidentById: async (id: string) => ({
          id,
          status: INCIDENT_STATUS.DISMISSED,
        }),
        transitionStatus: async (params: any) => ({
          id: params.incidentId,
          status: params.newStatus,
        }),
      } as unknown as IncidentRepository;

      const service2 = new IncidentService(mockRepoDismissed);
      const result2 = await service2.closeIncident(
        fakeIncidentId,
        { closeNote: "Bác bỏ cảnh báo sai thành công" },
        fakeActorId,
      );
      assert.equal(result2.status, INCIDENT_STATUS.CLOSED);
    });

    it("should prevent updating an incident that is already CLOSED", async () => {
      const mockRepo = {
        findIncidentById: async (id: string) => ({
          id,
          status: INCIDENT_STATUS.CLOSED,
        }),
      } as unknown as IncidentRepository;

      const service = new IncidentService(mockRepo);

      await assert.rejects(
        async () => {
          await service.updateIncident(fakeIncidentId, {
            description: "Thử cập nhật incident đã đóng",
          });
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.equal(err.code, ERROR_CODE.BAD_REQUEST);
          return true;
        },
      );
    });

    it("should prevent assigning an incident that is already CLOSED or DISMISSED", async () => {
      const mockRepo = {
        findIncidentById: async (id: string) => ({
          id,
          status: INCIDENT_STATUS.CLOSED,
        }),
      } as unknown as IncidentRepository;

      const service = new IncidentService(mockRepo);

      await assert.rejects(
        async () => {
          await service.assignIncident(fakeIncidentId, {
            assignedTo: "88888888-8888-4888-8888-888888888888",
          });
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.equal(err.code, ERROR_CODE.BAD_REQUEST);
          return true;
        },
      );
    });

    it("should prevent adding evidence to an incident that is already CLOSED", async () => {
      const mockRepo = {
        findIncidentById: async (id: string) => ({
          id,
          status: INCIDENT_STATUS.CLOSED,
        }),
      } as unknown as IncidentRepository;

      const service = new IncidentService(mockRepo);

      await assert.rejects(
        async () => {
          await service.addEvidence(fakeIncidentId, {
            cameraId: "22222222-2222-4222-8222-222222222222",
            evidenceType: EVIDENCE_TYPE.SNAPSHOT,
            storageKey: "evidences/snap.jpg",
            fileName: "snap.jpg",
            mimeType: "image/jpeg",
            capturedAt: new Date(),
          });
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.equal(err.code, ERROR_CODE.BAD_REQUEST);
          return true;
        },
      );
    });
  });

  // ── 5. Express App & Endpoint Registrations ────────────────────────────────
  describe("5. Incident Express Application & Route Endpoints", () => {
    it("should export an initialized Express app instance", () => {
      assert.ok(incidentApp);
      assert.equal(typeof incidentApp.listen, "function");
    });

    it("should have registered health check routes in incidentApp router stack", () => {
      const stack = (incidentApp as any)._router?.stack || [];
      const routePaths = stack
        .filter((layer: any) => layer.route)
        .map((layer: any) => layer.route.path);

      assert.ok(routePaths.includes("/health"));
      assert.ok(routePaths.includes("/api/v1/incidents/health"));
      assert.ok(routePaths.includes("/incidents/health"));
    });
  });

  // ── 6. Full-Text Search (FTS) & Service Routing ─────────────────────────────
  describe("6. Incident Full-Text Search (FTS) & Query Routing", () => {
    it("should route to repository.searchFts when query.search is present", async () => {
      let calledSearchFts = false;
      let calledFindAll = false;

      const mockRepo = {
        searchFts: async (_query: any) => {
          calledSearchFts = true;
          return {
            data: [],
            meta: { total: 0, page: 1, limit: 20, totalPages: 0 },
          };
        },
        findAllIncidents: async (_query: any) => {
          calledFindAll = true;
          return {
            data: [],
            meta: { total: 0, page: 1, limit: 20, totalPages: 0 },
          };
        },
      } as unknown as IncidentRepository;

      const service = new IncidentService(mockRepo);

      await service.getAllIncidents({ search: "không đội mũ" });
      assert.strictEqual(calledSearchFts, true);
      assert.strictEqual(calledFindAll, false);
    });

    it("should fallback to repository.findAllIncidents when query.search is absent or blank", async () => {
      let calledSearchFts = false;
      let calledFindAll = false;

      const mockRepo = {
        searchFts: async (_query: any) => {
          calledSearchFts = true;
          return {
            data: [],
            meta: { total: 0, page: 1, limit: 20, totalPages: 0 },
          };
        },
        findAllIncidents: async (_query: any) => {
          calledFindAll = true;
          return {
            data: [],
            meta: { total: 0, page: 1, limit: 20, totalPages: 0 },
          };
        },
      } as unknown as IncidentRepository;

      const service = new IncidentService(mockRepo);

      await service.getAllIncidents({ status: "PENDING_REVIEW" });
      assert.strictEqual(calledSearchFts, false);
      assert.strictEqual(calledFindAll, true);

      calledFindAll = false;
      await service.getAllIncidents({ search: "   " });
      assert.strictEqual(calledSearchFts, false);
      assert.strictEqual(calledFindAll, true);
    });

    it("should validate and parse search string in incidentQuerySchema", () => {
      const parsed = incidentQuerySchema.parse({
        search: "  khu vuc nguy hiem  ",
        page: 1,
        limit: 10,
      });
      assert.strictEqual(parsed.search, "khu vuc nguy hiem");
      assert.strictEqual(parsed.page, 1);
      assert.strictEqual(parsed.limit, 10);
    });

    it("should support custom sortBy and sortOrder when calling searchFts", async () => {
      let passedQuery: any = null;

      const mockRepo = {
        searchFts: async (query: any) => {
          passedQuery = query;
          return {
            data: [],
            meta: { total: 0, page: 1, limit: 20, totalPages: 0 },
          };
        },
      } as unknown as IncidentRepository;

      const service = new IncidentService(mockRepo);
      await service.getAllIncidents({
        search: "NO_VEST",
        sortBy: "detectedAt",
        sortOrder: "asc",
      });

      assert.strictEqual(passedQuery.search, "NO_VEST");
      assert.strictEqual(passedQuery.sortBy, "detectedAt");
      assert.strictEqual(passedQuery.sortOrder, "asc");
    });
  });

  // ── 7. Security Patches: SEC-01 to SEC-16 ─────────────────────────────────
  describe("7. Security Patches: SEC-01 to SEC-16", () => {
    describe("SEC-01: 2FA Purpose Isolation in Auth Middleware", () => {
      it("should reject token with purpose 2FA_VERIFICATION", () => {
        mock.method(jwt, "decode", () => ({
          header: { alg: "RS256" },
          payload: {},
        }));
        mock.method(jwt, "verify", () => ({
          sub: "usr-2fa-1",
          email: "pending2fa@test.com",
          role: ROLES.SAFETY_OFFICER,
          purpose: JWT_PURPOSE.TWO_FACTOR,
        }));

        try {
          const req: any = {
            headers: { authorization: "Bearer dummy-2fa-token" },
          };
          let error: any = null;
          authMiddleware(req, {} as any, (err?: any) => {
            error = err;
          });

          assert.ok(error instanceof AppError);
          assert.strictEqual(error.statusCode, 401);
          assert.strictEqual(error.code, ERROR_CODE.UNAUTHORIZED);
          assert.strictEqual(error.message, "Token không hợp lệ để truy cập tài nguyên được bảo vệ");
          assert.strictEqual(req.user, undefined);
        } finally {
          mock.restoreAll();
        }
      });

      it("should reject token with type TEMP or non-access purpose", () => {
        mock.method(jwt, "decode", () => ({
          header: { alg: "RS256" },
          payload: {},
        }));
        mock.method(jwt, "verify", () => ({
          sub: "usr-temp-1",
          email: "temp@test.com",
          role: ROLES.SAFETY_OFFICER,
          type: "TEMP",
        }));

        try {
          const req: any = {
            headers: { authorization: "Bearer dummy-temp-token" },
          };
          let error: any = null;
          authMiddleware(req, {} as any, (err?: any) => {
            error = err;
          });

          assert.ok(error instanceof AppError);
          assert.strictEqual(error.statusCode, 401);
          assert.strictEqual(error.code, ERROR_CODE.UNAUTHORIZED);
          assert.strictEqual(error.message, "Token không hợp lệ để truy cập tài nguyên được bảo vệ");
        } finally {
          mock.restoreAll();
        }
      });

      it("should accept valid token with purpose ACCESS", () => {
        mock.method(jwt, "decode", () => ({
          header: { alg: "RS256" },
          payload: {},
        }));
        mock.method(jwt, "verify", () => ({
          sub: "usr-valid-1",
          email: "valid@test.com",
          role: ROLES.SAFETY_OFFICER,
          purpose: JWT_PURPOSE.ACCESS,
          permissions: [PERMISSIONS.PPE_INCIDENT_READ],
        }));

        try {
          const req: any = {
            headers: { authorization: "Bearer dummy-access-token" },
          };
          let error: any = null;
          authMiddleware(req, {} as any, (err?: any) => {
            error = err;
          });

          assert.strictEqual(error, undefined);
          assert.ok(req.user);
          assert.strictEqual(req.user.id, "usr-valid-1");
        } finally {
          mock.restoreAll();
        }
      });
    });

    describe("SEC-02: API Key Admin Owner Permission Scoping", () => {
      it("should restrict Admin API Key when required permission is absent from apiKey.permissions", () => {
        const req: any = {
          user: {
            id: "usr-admin-1",
            email: "admin@test.com",
            role: ROLES.ADMIN,
            permissions: [],
          },
          apiKey: {
            id: "key-readonly-1",
            name: "Read-Only Key",
            prefix: "ppe_key",
            permissions: [PERMISSIONS.PPE_INCIDENT_READ],
          },
        };

        let error: any = null;
        const middleware = requirePermission(PERMISSIONS.PPE_INCIDENT_DELETE);
        middleware(req, {} as any, (err?: any) => {
          error = err;
        });

        assert.ok(error instanceof AppError);
        assert.strictEqual(error.statusCode, 403);
        assert.strictEqual(error.code, ERROR_CODE.FORBIDDEN);
      });

      it("should permit Admin API Key when required permission is present in apiKey.permissions", () => {
        const req: any = {
          user: {
            id: "usr-admin-1",
            email: "admin@test.com",
            role: ROLES.ADMIN,
            permissions: [],
          },
          apiKey: {
            id: "key-delete-1",
            name: "Delete-Capable Key",
            prefix: "ppe_key",
            permissions: [PERMISSIONS.PPE_INCIDENT_DELETE],
          },
        };

        let error: any = null;
        const middleware = requirePermission(PERMISSIONS.PPE_INCIDENT_DELETE);
        middleware(req, {} as any, (err?: any) => {
          error = err;
        });

        assert.strictEqual(error, undefined);
      });

      it("should allow human Admin without API Key to bypass permission checks", () => {
        const req: any = {
          user: {
            id: "usr-admin-1",
            email: "admin@test.com",
            role: ROLES.ADMIN,
            permissions: [],
          },
        };

        let error: any = null;
        const middleware = requirePermission(PERMISSIONS.PPE_INCIDENT_DELETE);
        middleware(req, {} as any, (err?: any) => {
          error = err;
        });

        assert.strictEqual(error, undefined);
      });

      it("should enforce scoping in requireAnyPermission for Admin API Key", () => {
        const req: any = {
          user: {
            id: "usr-admin-1",
            email: "admin@test.com",
            role: ROLES.ADMIN,
            permissions: [],
          },
          apiKey: {
            id: "key-readonly-1",
            name: "Read-Only Key",
            prefix: "ppe_key",
            permissions: [PERMISSIONS.PPE_INCIDENT_READ],
          },
        };

        let error: any = null;
        const middleware = requireAnyPermission(
          PERMISSIONS.PPE_INCIDENT_DELETE,
          PERMISSIONS.PPE_INCIDENT_MANAGE,
        );
        middleware(req, {} as any, (err?: any) => {
          error = err;
        });

        assert.ok(error instanceof AppError);
        assert.strictEqual(error.statusCode, 403);
        assert.strictEqual(error.code, ERROR_CODE.FORBIDDEN);
      });
    });

    // ── SEC-03: Storage Cleanup on Incident Deletion ─────────────────────────
    describe("SEC-03: Storage Cleanup on Incident Deletion", () => {
      const siteId = "11111111-1111-4111-8111-111111111111";
      const incidentId = "22222222-2222-4222-8222-222222222222";

      it("should delete all associated evidence objects from MinIO storage before deleting incident record", async () => {
        const deletedKeys: string[] = [];
        const mockStorage = {
          deleteObject: mock.fn(async (key: string) => {
            deletedKeys.push(key);
          }),
        } as any;

        const mockRepo = {
          findIncidentById: mock.fn(async (id: string) => ({
            id,
            siteId,
            status: INCIDENT_STATUS.CONFIRMED,
            evidences: [
              { id: "ev-1", storageKey: `evidences/${siteId}/cam-1/2026/10/30/${incidentId}/snap1.jpg` },
              { id: "ev-2", storageKey: `evidences/${siteId}/cam-1/2026/10/30/${incidentId}/video.mp4` },
            ],
          })),
          deleteIncident: mock.fn(async (id: string) => ({ id })),
        } as any;

        const service = new IncidentService(mockRepo, mockStorage);
        const result = await service.deleteIncident(incidentId);

        assert.strictEqual(result.id, incidentId);
        assert.strictEqual(mockStorage.deleteObject.mock.callCount(), 2);
        assert.strictEqual(deletedKeys.length, 2);
        assert.strictEqual(deletedKeys[0], `evidences/${siteId}/cam-1/2026/10/30/${incidentId}/snap1.jpg`);
        assert.strictEqual(deletedKeys[1], `evidences/${siteId}/cam-1/2026/10/30/${incidentId}/video.mp4`);
        assert.strictEqual(mockRepo.deleteIncident.mock.callCount(), 1);
      });

      it("should continue and delete incident from repository even if storage deletion fails gracefully", async () => {
        const mockStorage = {
          deleteObject: mock.fn(async () => {
            throw new Error("MinIO connection reset");
          }),
        } as any;

        const mockRepo = {
          findIncidentById: mock.fn(async (id: string) => ({
            id,
            siteId,
            status: INCIDENT_STATUS.PENDING_REVIEW,
            evidences: [
              { id: "ev-1", storageKey: `evidences/${siteId}/cam-1/2026/10/30/${incidentId}/snap1.jpg` },
            ],
          })),
          deleteIncident: mock.fn(async (id: string) => ({ id })),
        } as any;

        const service = new IncidentService(mockRepo, mockStorage);
        const result = await service.deleteIncident(incidentId);

        assert.strictEqual(result.id, incidentId);
        assert.strictEqual(mockRepo.deleteIncident.mock.callCount(), 1);
      });
    });

    // ── SEC-04: Cross-Tenant Storage Key Isolation in AddEvidence ────────────
    describe("SEC-04: Cross-Tenant Storage Key Isolation in AddEvidence", () => {
      const siteId = "11111111-1111-4111-8111-111111111111";
      const otherSiteId = "33333333-3333-4333-8333-333333333333";
      const incidentId = "22222222-2222-4222-8222-222222222222";
      const otherIncidentId = "44444444-4444-4444-8444-444444444444";
      const cameraId = "55555555-5555-4555-8555-555555555555";

      it("should reject storageKey not starting with evidences/ prefix in schema", () => {
        const payload = {
          cameraId,
          evidenceType: EVIDENCE_TYPE.SNAPSHOT,
          storageKey: "invoices/company-secret.pdf",
          fileName: "snap.jpg",
          mimeType: "image/jpeg",
          capturedAt: new Date().toISOString(),
        };
        const result = createEvidenceSchema.safeParse(payload);
        assert.strictEqual(result.success, false);
      });

      it("should reject storageKey with absolute path or double slashes in schema", () => {
        const payloadRoot = {
          cameraId,
          evidenceType: EVIDENCE_TYPE.SNAPSHOT,
          storageKey: "/evidences/test.jpg",
          fileName: "snap.jpg",
          mimeType: "image/jpeg",
          capturedAt: new Date().toISOString(),
        };
        assert.strictEqual(createEvidenceSchema.safeParse(payloadRoot).success, false);

        const payloadDoubleSlash = {
          cameraId,
          evidenceType: EVIDENCE_TYPE.SNAPSHOT,
          storageKey: "evidences//test.jpg",
          fileName: "snap.jpg",
          mimeType: "image/jpeg",
          capturedAt: new Date().toISOString(),
        };
        assert.strictEqual(createEvidenceSchema.safeParse(payloadDoubleSlash).success, false);
      });

      it("should reject adding evidence when storageKey belongs to a different siteId", async () => {
        const mockRepo = {
          findIncidentById: mock.fn(async (id: string) => ({
            id,
            siteId,
            status: INCIDENT_STATUS.CONFIRMED,
          })),
        } as any;

        const service = new IncidentService(mockRepo);

        await assert.rejects(
          async () => {
            await service.addEvidence(incidentId, {
              cameraId,
              evidenceType: EVIDENCE_TYPE.SNAPSHOT,
              storageKey: `evidences/${otherSiteId}/${cameraId}/2026/10/30/${incidentId}/snap.jpg`,
              fileName: "snap.jpg",
              mimeType: "image/jpeg",
              capturedAt: new Date(),
            });
          },
          (err: any) => {
            assert.ok(err instanceof AppError);
            assert.strictEqual(err.statusCode, 400);
            assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
            assert.ok(err.message.includes("công trường"));
            return true;
          },
        );
      });

      it("should reject adding evidence when storageKey belongs to a different incidentId", async () => {
        const mockRepo = {
          findIncidentById: mock.fn(async (id: string) => ({
            id,
            siteId,
            status: INCIDENT_STATUS.CONFIRMED,
          })),
        } as any;

        const service = new IncidentService(mockRepo);

        await assert.rejects(
          async () => {
            await service.addEvidence(incidentId, {
              cameraId,
              evidenceType: EVIDENCE_TYPE.SNAPSHOT,
              storageKey: `evidences/${siteId}/${cameraId}/2026/10/30/${otherIncidentId}/snap.jpg`,
              fileName: "snap.jpg",
              mimeType: "image/jpeg",
              capturedAt: new Date(),
            });
          },
          (err: any) => {
            assert.ok(err instanceof AppError);
            assert.strictEqual(err.statusCode, 400);
            assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
            assert.ok(err.message.includes("sự cố"));
            return true;
          },
        );
      });

      it("should permit adding evidence when storageKey matches current incident site and ID", async () => {
        const validKey = `evidences/${siteId}/${cameraId}/2026/10/30/${incidentId}/snap.jpg`;
        const mockRepo = {
          findIncidentById: mock.fn(async (id: string) => ({
            id,
            siteId,
            status: INCIDENT_STATUS.CONFIRMED,
          })),
          createEvidence: mock.fn(async (data: any) => ({
            id: "ev-created-1",
            ...data,
          })),
        } as any;

        const service = new IncidentService(mockRepo);
        const result = await service.addEvidence(incidentId, {
          cameraId,
          evidenceType: EVIDENCE_TYPE.SNAPSHOT,
          storageKey: validKey,
          fileName: "snap.jpg",
          mimeType: "image/jpeg",
          capturedAt: new Date(),
        });

        assert.strictEqual(result.id, "ev-created-1");
        assert.strictEqual(result.storageKey, validKey);
        assert.strictEqual(mockRepo.createEvidence.mock.callCount(), 1);
      });

      it("should reject creating incident with initialEvidence having mismatched siteId in storageKey", async () => {
        const mockRepo = {
          createIncident: mock.fn(),
        } as any;

        const service = new IncidentService(mockRepo);

        await assert.rejects(
          async () => {
            await service.createIncident(
              {
                siteId,
                cameraId,
                violationType: VIOLATION_TYPE.NO_HELMET,
                detectedAt: new Date(),
                initialEvidence: {
                  cameraId,
                  evidenceType: EVIDENCE_TYPE.SNAPSHOT,
                  storageKey: `evidences/${otherSiteId}/${cameraId}/2026/10/30/fake/snap.jpg`,
                  fileName: "snap.jpg",
                  mimeType: "image/jpeg",
                  capturedAt: new Date(),
                },
              },
              "usr-1",
            );
          },
          (err: any) => {
            assert.ok(err instanceof AppError);
            assert.strictEqual(err.statusCode, 400);
            assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
            return true;
          },
        );
      });
    });

    // ── SEC-05: Dockerfile Runner Stage Public Key and Lockfile Pinning ───────
    describe("SEC-05: Dockerfile Runner Stage Public Key and Lockfile Pinning", () => {
      it("should ensure public.key.pem and pnpm-lock.yaml exist for container build", () => {
        const keyPath = path.resolve(__dirname, "../keys/public.key.pem");
        const lockPath = path.resolve(__dirname, "../pnpm-lock.yaml");
        const dockerfilePath = path.resolve(__dirname, "../Dockerfile");

        assert.ok(fs.existsSync(keyPath), "keys/public.key.pem must exist");
        assert.ok(fs.existsSync(lockPath), "pnpm-lock.yaml must exist");

        const dockerfileContent = fs.readFileSync(dockerfilePath, "utf-8");
        assert.ok(
          dockerfileContent.includes("COPY package.json pnpm-lock.yaml* ./"),
          "Dockerfile Stage 1 must copy pnpm-lock.yaml",
        );
        assert.ok(
          dockerfileContent.includes("COPY --from=builder /app/keys ./keys"),
          "Dockerfile Stage 3 must copy keys/ into runner stage",
        );
      });
    });

    // ── SEC-06: Enforcement of mustChangePassword Flag in Satellite Auth ─────
    describe("SEC-06: Enforcement of mustChangePassword Flag in Satellite Auth", () => {
      it("should reject access with 403 FORBIDDEN when token contains mustChangePassword: true", () => {
        mock.method(jwt, "decode", () => ({
          header: { alg: "RS256" },
          payload: {},
        }));
        mock.method(jwt, "verify", () => ({
          sub: "usr-temp-pwd-1",
          email: "user@test.com",
          role: ROLES.SAFETY_OFFICER,
          purpose: JWT_PURPOSE.ACCESS,
          mustChangePassword: true,
        }));

        let capturedError: any = null;
        const req: any = {
          headers: { authorization: "Bearer token-must-change-password" },
        };

        authMiddleware(req, {} as any, (err?: any) => {
          capturedError = err;
        });

        assert.ok(capturedError instanceof AppError);
        assert.strictEqual(capturedError.statusCode, 403);
        assert.strictEqual(capturedError.code, ERROR_CODE.FORBIDDEN);
        assert.ok(capturedError.message.includes("đổi mật khẩu"));
      });

      it("should permit access when token contains mustChangePassword: false", () => {
        mock.method(jwt, "decode", () => ({
          header: { alg: "RS256" },
          payload: {},
        }));
        mock.method(jwt, "verify", () => ({
          sub: "usr-normal-pwd-1",
          email: "normal@test.com",
          role: ROLES.SAFETY_OFFICER,
          purpose: JWT_PURPOSE.ACCESS,
          mustChangePassword: false,
        }));

        let capturedError: any = null;
        const req: any = {
          headers: { authorization: "Bearer valid-normal-token" },
        };

        authMiddleware(req, {} as any, (err?: any) => {
          capturedError = err;
        });

        assert.strictEqual(capturedError, undefined);
        assert.strictEqual(req.user?.id, "usr-normal-pwd-1");
      });
    });

    // ── SEC-07: Strict Actor ID Validation & Anti-System Coercion ────────────
    describe("SEC-07: Strict Actor ID Validation & Anti-System Coercion", () => {
      it("should throw VALIDATION_ERROR when an invalid actorId is provided without fallback", () => {
        assert.throws(
          () => normalizeActorUuid("invalid-uuid-string", false),
          (err: any) => {
            assert.ok(err instanceof AppError);
            assert.strictEqual(err.statusCode, 400);
            assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
            return true;
          },
        );
      });

      it("should throw VALIDATION_ERROR when an invalid actorId is provided even if fallback is allowed", () => {
        assert.throws(
          () => normalizeActorUuid("malformed-actor-id", true),
          (err: any) => {
            assert.ok(err instanceof AppError);
            assert.strictEqual(err.statusCode, 400);
            assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
            return true;
          },
        );
      });

      it("should throw VALIDATION_ERROR when actorId is missing and fallback is disallowed", () => {
        assert.throws(
          () => normalizeActorUuid(undefined, false),
          (err: any) => {
            assert.ok(err instanceof AppError);
            assert.strictEqual(err.statusCode, 400);
            assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
            return true;
          },
        );
      });

      it("should return SYSTEM_ACTOR_UUID when actorId is empty and fallback is explicitly allowed", () => {
        assert.strictEqual(normalizeActorUuid(undefined, true), SYSTEM_ACTOR_UUID);
        assert.strictEqual(normalizeActorUuid(null, true), SYSTEM_ACTOR_UUID);
        assert.strictEqual(normalizeActorUuid("", true), SYSTEM_ACTOR_UUID);
      });

      it("should return valid UUID unchanged", () => {
        const validId = "11111111-1111-4111-8111-111111111111";
        assert.strictEqual(normalizeActorUuid(validId, false), validId);
      });

      it("should safely return false in isUserAssignedToIncident when given an invalid non-UUID userId", async () => {
        const repo = new IncidentRepository({} as any);
        const result = await repo.isUserAssignedToIncident("inc-1", "invalid-actor-id");
        assert.strictEqual(result, false);
      });

      it("should reject repository.addComment when given an invalid actorId", async () => {
        const repo = new IncidentRepository({} as any);
        await assert.rejects(
          async () => {
            await repo.addComment("inc-1", "not-a-uuid", "test comment");
          },
          (err: any) => {
            assert.ok(err instanceof AppError);
            assert.strictEqual(err.statusCode, 400);
            assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
            return true;
          },
        );
      });
    });

    // ── SEC-08: Trust Proxy Single Hop Configuration ─────────────────────────
    describe("SEC-08: Trust Proxy Single Hop Configuration", () => {
      it("should resolve 'true' to 1 hop (Traefik Ingress) instead of boolean true to prevent IP spoofing", () => {
        const result = parseTrustProxy("true");
        assert.strictEqual(result, 1);
      });

      it("should preserve 'false', numeric hops, and custom subnet lists", () => {
        assert.strictEqual(parseTrustProxy("false"), false);
        assert.strictEqual(parseTrustProxy("2"), 2);
        assert.deepStrictEqual(parseTrustProxy("10.0.0.1, 10.0.0.2"), ["10.0.0.1", "10.0.0.2"]);
      });
    });

    // ── SEC-09: Evidence Download & Integrity Site-Level Scoping (BOLA) ──────
    describe("SEC-09: Evidence Download & Integrity Site-Level Scoping (BOLA)", () => {
      const siteA = "11111111-1111-4111-8111-111111111111";
      const siteB = "22222222-2222-4222-8222-222222222222";
      const evidenceId = "33333333-3333-4333-8333-333333333333";

      it("should reject getEvidenceDownloadUrl with 403 FORBIDDEN when user site does not match evidence site", async () => {
        const mockRepo = {
          findEvidenceById: mock.fn(async (id: string) => ({
            id,
            storageKey: `evidences/${siteB}/cam-1/2026/10/31/inc-1/snap.jpg`,
            fileName: "snap.jpg",
            mimeType: "image/jpeg",
            incident: { id: "inc-1", siteId: siteB },
          })),
        } as any;
        const mockStorage = {
          getPresignedDownloadUrl: mock.fn(async () => "https://s3/download-url"),
        } as any;

        const service = new IncidentService(mockRepo, mockStorage);

        await assert.rejects(
          async () => {
            await service.getEvidenceDownloadUrl(
              evidenceId,
              "usr-officer-1",
              900,
              EVIDENCE_ACCESS_ACTION.VIEW,
              { role: ROLES.SAFETY_OFFICER, siteId: siteA },
            );
          },
          (err: any) => {
            assert.ok(err instanceof AppError);
            assert.strictEqual(err.statusCode, 403);
            assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
            assert.ok(err.message.includes("công trường"));
            return true;
          },
        );
      });

      it("should permit getEvidenceDownloadUrl when user site matches evidence site", async () => {
        const mockRepo = {
          findEvidenceById: mock.fn(async (id: string) => ({
            id,
            storageKey: `evidences/${siteA}/cam-1/2026/10/31/inc-1/snap.jpg`,
            fileName: "snap.jpg",
            mimeType: "image/jpeg",
            incident: { id: "inc-1", siteId: siteA },
          })),
          logEvidenceAccess: mock.fn(async () => {}),
        } as any;
        const mockStorage = {
          getPresignedDownloadUrl: mock.fn(async () => "https://s3/download-url"),
        } as any;

        const service = new IncidentService(mockRepo, mockStorage);
        const result = await service.getEvidenceDownloadUrl(
          evidenceId,
          "usr-officer-1",
          900,
          EVIDENCE_ACCESS_ACTION.DOWNLOAD,
          { role: ROLES.SAFETY_OFFICER, siteId: siteA },
        );

        assert.strictEqual(result.downloadUrl, "https://s3/download-url");
        assert.strictEqual(mockStorage.getPresignedDownloadUrl.mock.callCount(), 1);
      });

      it("should permit getEvidenceDownloadUrl for ADMIN regardless of site", async () => {
        const mockRepo = {
          findEvidenceById: mock.fn(async (id: string) => ({
            id,
            storageKey: `evidences/${siteB}/cam-1/2026/10/31/inc-1/snap.jpg`,
            fileName: "snap.jpg",
            mimeType: "image/jpeg",
            incident: { id: "inc-1", siteId: siteB },
          })),
          logEvidenceAccess: mock.fn(async () => {}),
        } as any;
        const mockStorage = {
          getPresignedDownloadUrl: mock.fn(async () => "https://s3/admin-url"),
        } as any;

        const service = new IncidentService(mockRepo, mockStorage);
        const result = await service.getEvidenceDownloadUrl(
          evidenceId,
          "usr-admin-1",
          900,
          EVIDENCE_ACCESS_ACTION.VIEW,
          { role: ROLES.ADMIN, siteId: siteA },
        );

        assert.strictEqual(result.downloadUrl, "https://s3/admin-url");
      });

      it("should reject verifyEvidenceIntegrity with 403 FORBIDDEN when user site does not match evidence site", async () => {
        const mockRepo = {
          findEvidenceById: mock.fn(async (id: string) => ({
            id,
            storageKey: `evidences/${siteB}/cam-1/2026/10/31/inc-1/snap.jpg`,
            metadata: { checksum: "abc123sha" },
            incident: { id: "inc-1", siteId: siteB },
          })),
        } as any;
        const mockStorage = {
          verifyChecksum: mock.fn(),
        } as any;

        const service = new IncidentService(mockRepo, mockStorage);

        await assert.rejects(
          async () => {
            await service.verifyEvidenceIntegrity(evidenceId, {
              role: ROLES.SAFETY_OFFICER,
              siteId: siteA,
            });
          },
          (err: any) => {
            assert.ok(err instanceof AppError);
            assert.strictEqual(err.statusCode, 403);
            assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
            return true;
          },
        );
      });
    });

    // ── SEC-10: Violation ID Unique Constraint & Concurrent Deduplication ────
    describe("SEC-10: Violation ID Unique Constraint & Concurrent Deduplication", () => {
      it("should define @unique on violationId in schema.prisma", () => {
        const schemaPath = path.resolve(__dirname, "../prisma/schema.prisma");
        const schemaContent = fs.readFileSync(schemaPath, "utf-8");
        assert.ok(
          schemaContent.includes('violationId   String?   @unique @map("violation_id")'),
          "violationId must have @unique constraint in prisma/schema.prisma",
        );
      });

      it("should gracefully recover from P2002 race condition by returning existing incident", async () => {
        const violationId = "44444444-4444-4444-8444-444444444444";
        const existingIncident = {
          id: "inc-race-winner-1",
          siteId: "11111111-1111-4111-8111-111111111111",
          cameraId: "22222222-2222-4222-8222-222222222222",
          violationId,
          violationType: VIOLATION_TYPE.NO_HELMET,
          status: INCIDENT_STATUS.PENDING_REVIEW,
          evidences: [],
          statusHistory: [],
        };

        const mockPrismaClient = {
          $transaction: mock.fn(async () => {
            const p2002Err: any = new Error("Unique constraint failed on the fields: (`violation_id`)");
            p2002Err.code = "P2002";
            throw p2002Err;
          }),
          incident: {
            findFirst: mock.fn(async () => existingIncident),
          },
        };

        const repo = new IncidentRepository(mockPrismaClient);
        const result = await repo.createIncident(
          {
            siteId: "11111111-1111-4111-8111-111111111111",
            cameraId: "22222222-2222-4222-8222-222222222222",
            violationId,
            violationType: VIOLATION_TYPE.NO_HELMET,
            detectedAt: new Date(),
          },
          "usr-11111111-1111-4111-8111-111111111111",
        );

        assert.strictEqual(result.id, "inc-race-winner-1");
        assert.strictEqual(result.violationId, violationId);
      });
    });

    // ── SEC-11: Transactional Outbox Pattern in Incident Lifecycle Transitions
    describe("SEC-11: Transactional Outbox Pattern in Incident Lifecycle Transitions", () => {
      it("should define OutboxEvent model in schema.prisma", () => {
        const schemaPath = path.resolve(__dirname, "../prisma/schema.prisma");
        const schemaContent = fs.readFileSync(schemaPath, "utf-8");
        assert.ok(
          schemaContent.includes("model OutboxEvent {"),
          "schema.prisma must declare model OutboxEvent",
        );
        assert.ok(
          schemaContent.includes('@@map("outbox_events")'),
          "OutboxEvent must map to outbox_events table",
        );
      });

      it("should persist outbox record during status transition transaction", async () => {
        let createdOutboxEvent: any = null;
        const incidentId = "55555555-5555-4555-8555-555555555555";
        const actorId = "66666666-6666-4666-8666-666666666666";

        const mockTx = {
          incident: {
            update: mock.fn(async () => ({ id: incidentId, siteId: "site-1" })),
            findUnique: mock.fn(async () => ({
              id: incidentId,
              status: INCIDENT_STATUS.CONFIRMED,
              statusHistory: [],
            })),
          },
          incidentStatusHistory: {
            create: mock.fn(async () => ({ id: "hist-1" })),
          },
          outboxEvent: {
            create: mock.fn(async (params: any) => {
              createdOutboxEvent = params.data;
              return { id: "outbox-1", ...params.data };
            }),
          },
        };

        const mockPrisma = {
          $transaction: mock.fn(async (callback: any) => callback(mockTx)),
        };

        const repo = new IncidentRepository(mockPrisma);
        await repo.transitionStatus({
          incidentId,
          oldStatus: INCIDENT_STATUS.PENDING_REVIEW,
          newStatus: INCIDENT_STATUS.CONFIRMED,
          changedBy: actorId,
          reason: "Confirmed PPE violation",
        });

        assert.ok(createdOutboxEvent !== null);
        assert.strictEqual(createdOutboxEvent.eventType, "ppe.incident.status_changed");
        assert.strictEqual(createdOutboxEvent.aggregateId, incidentId);
        assert.strictEqual(createdOutboxEvent.status, "PENDING");
        assert.strictEqual(createdOutboxEvent.payload.newStatus, INCIDENT_STATUS.CONFIRMED);
        assert.strictEqual(createdOutboxEvent.payload.oldStatus, INCIDENT_STATUS.PENDING_REVIEW);
      });

      it("should persist ppe.incident.resolved outbox record when transitioning to RESOLVED", async () => {
        let createdOutboxEvent: any = null;
        const incidentId = "55555555-5555-4555-8555-555555555555";
        const actorId = "66666666-6666-4666-8666-666666666666";

        const mockTx = {
          incident: {
            update: mock.fn(async () => ({ id: incidentId, siteId: "site-1" })),
            findUnique: mock.fn(async () => ({
              id: incidentId,
              status: INCIDENT_STATUS.RESOLVED,
              statusHistory: [],
            })),
          },
          incidentStatusHistory: {
            create: mock.fn(async () => ({ id: "hist-1" })),
          },
          outboxEvent: {
            create: mock.fn(async (params: any) => {
              createdOutboxEvent = params.data;
              return { id: "outbox-2", ...params.data };
            }),
          },
        };

        const mockPrisma = {
          $transaction: mock.fn(async (callback: any) => callback(mockTx)),
        };

        const repo = new IncidentRepository(mockPrisma);
        await repo.transitionStatus({
          incidentId,
          oldStatus: INCIDENT_STATUS.CONFIRMED,
          newStatus: INCIDENT_STATUS.RESOLVED,
          changedBy: actorId,
          reason: "Resolution note",
          resolvedAt: new Date(),
        });

        assert.ok(createdOutboxEvent !== null);
        assert.strictEqual(createdOutboxEvent.eventType, "ppe.incident.resolved");
        assert.strictEqual(createdOutboxEvent.payload.newStatus, INCIDENT_STATUS.RESOLVED);
      });
    });

    // ── SEC-12: requireGatewayOrigin Enforcement on Route Pipeline ───────────
    describe("SEC-12: requireGatewayOrigin Enforcement on Route Pipeline", () => {
      const configuredSecret = "internal-gateway-secret-test-1234567890";

      it("should reject request when GATEWAY_INTERNAL_SECRET is configured and header is missing", () => {
        const middleware = createRequireGatewayOrigin(configuredSecret);
        const req: any = { headers: {} };
        let caughtError: any = null;

        middleware(req, {} as any, (err?: any) => {
          caughtError = err;
        });

        assert.ok(caughtError instanceof AppError);
        assert.strictEqual(caughtError.statusCode, 403);
        assert.strictEqual(caughtError.code, ERROR_CODE.GATEWAY_REQUIRED);
      });

      it("should reject request when header x-gateway-secret does not match configured secret", () => {
        const middleware = createRequireGatewayOrigin(configuredSecret);
        const req: any = {
          headers: {
            [GATEWAY_HEADERS.INTERNAL_SECRET]: "wrong-secret-value",
          },
        };
        let caughtError: any = null;

        middleware(req, {} as any, (err?: any) => {
          caughtError = err;
        });

        assert.ok(caughtError instanceof AppError);
        assert.strictEqual(caughtError.statusCode, 403);
        assert.strictEqual(caughtError.code, ERROR_CODE.GATEWAY_REQUIRED);
      });

      it("should permit request when header x-gateway-secret matches configured secret", () => {
        const middleware = createRequireGatewayOrigin(configuredSecret);
        const req: any = {
          headers: {
            [GATEWAY_HEADERS.INTERNAL_SECRET]: configuredSecret,
          },
        };
        let called = false;
        let caughtError: any = null;

        middleware(req, {} as any, (err?: any) => {
          called = true;
          caughtError = err;
        });

        assert.strictEqual(called, true);
        assert.strictEqual(caughtError, undefined);
      });

      it("should bypass check when secret is not configured (monolith / local dev mode)", () => {
        const middleware = createRequireGatewayOrigin("");
        const req: any = { headers: {} };
        let called = false;

        middleware(req, {} as any, () => {
          called = true;
        });

        assert.strictEqual(called, true);
      });
    });

    // ── SEC-13: PostgreSQL FTS tsquery Syntax Error Handling & Fallback ──────
    describe("SEC-13: PostgreSQL FTS tsquery Syntax Error Handling & Fallback", () => {
      it("should fallback to findAllIncidents when to_tsquery throws syntax error", async () => {
        const fallbackResults = {
          data: [
            {
              id: "99999999-9999-4999-8999-999999999999",
              siteId: "site-1",
              status: INCIDENT_STATUS.CONFIRMED,
              violationType: VIOLATION_TYPE.NO_HELMET,
            },
          ],
          meta: { page: 1, limit: 20, total: 1, totalPages: 1 },
        };

        const mockDb = {
          $queryRaw: mock.fn(async () => {
            throw new Error('syntax error in tsquery: "& | !" (code: 42601)');
          }),
        };

        const repo = new IncidentRepository(mockDb as any);
        repo.findAllIncidents = mock.fn(async (_query: any) => fallbackResults as any);

        const result = await repo.searchFts({
          search: "& | ! syntax_bomb",
          page: 1,
          limit: 20,
        });

        assert.strictEqual(result.data.length, 1);
        assert.strictEqual(result.data[0].id, "99999999-9999-4999-8999-999999999999");
        assert.strictEqual((repo.findAllIncidents as any).mock.callCount(), 1);
      });
    });

    // ── SEC-14: Direct Multipart Upload Size Bound & Event Loop Protection ────
    describe("SEC-14: Direct Multipart Upload Size Bound & Event Loop Protection", () => {
      it("should define MAX_DIRECT_UPLOAD_BYTES as 5MB to prevent heap starvation", () => {
        assert.strictEqual(MEDIA_LIMITS.MAX_DIRECT_UPLOAD_BYTES, 5 * 1024 * 1024);
        assert.ok(MEDIA_LIMITS.MAX_DIRECT_UPLOAD_BYTES < MEDIA_LIMITS.MAX_FILE_SIZE_BYTES);
      });
    });

    // ── SEC-15: Maintenance Guard Verification with Dynamic Activation & Admin Bypass ──
    describe("SEC-15: Maintenance Guard Verification with Dynamic Activation & Admin Bypass", () => {
      it("should allow request when maintenance mode is inactive", async () => {
        const guard = maintenanceGuard({ isMaintenanceMode: false });
        const req: any = { url: "/api/v1/incidents" };
        let called = false;
        let caughtError: any = null;

        await guard(req, {} as any, (err?: any) => {
          called = true;
          caughtError = err;
        });

        assert.strictEqual(called, true);
        assert.strictEqual(caughtError, undefined);
      });

      it("should reject regular user with 503 SYSTEM_MAINTENANCE when maintenance mode is active", async () => {
        const guard = maintenanceGuard({ isMaintenanceMode: true });
        const req: any = {
          originalUrl: "/api/v1/incidents",
          user: {
            id: "user-1",
            role: ROLES.SAFETY_OFFICER,
            permissions: [PERMISSIONS.PPE_INCIDENT_READ],
          },
        };
        let caughtError: any = null;

        await guard(req, {} as any, (err?: any) => {
          caughtError = err;
        });

        assert.ok(caughtError instanceof AppError);
        assert.strictEqual(caughtError.statusCode, 503);
        assert.strictEqual(caughtError.code, ERROR_CODE.SYSTEM_MAINTENANCE);
      });

      it("should permit health check and openapi routes during maintenance mode", async () => {
        const guard = maintenanceGuard({ isMaintenanceMode: true });
        const reqHealth: any = { originalUrl: "/api/v1/incidents/health" };
        let healthCalled = false;
        await guard(reqHealth, {} as any, () => {
          healthCalled = true;
        });
        assert.strictEqual(healthCalled, true);

        const reqOpenApi: any = { originalUrl: "/api/v1/incidents/openapi.json" };
        let openApiCalled = false;
        await guard(reqOpenApi, {} as any, () => {
          openApiCalled = true;
        });
        assert.strictEqual(openApiCalled, true);
      });

      it("should permit Admin or MAINTENANCE_BYPASS users during maintenance mode", async () => {
        const guard = maintenanceGuard({ isMaintenanceMode: true });
        const reqAdmin: any = {
          originalUrl: "/api/v1/incidents",
          user: {
            id: "admin-1",
            role: ROLES.ADMIN,
            permissions: [],
          },
        };
        let adminCalled = false;
        await guard(reqAdmin, {} as any, () => {
          adminCalled = true;
        });
        assert.strictEqual(adminCalled, true);

        const reqBypass: any = {
          originalUrl: "/api/v1/incidents",
          user: {
            id: "operator-1",
            role: ROLES.SAFETY_OFFICER,
            permissions: ["MAINTENANCE_BYPASS"],
          },
        };
        let bypassCalled = false;
        await guard(reqBypass, {} as any, () => {
          bypassCalled = true;
        });
        assert.strictEqual(bypassCalled, true);
      });
    });

    // ── SEC-16: Query String JWT Authentication Ban on Incident Service ──────
    describe("SEC-16: Query String JWT Authentication Ban on Incident Service", () => {
      it("should extract token from Authorization Bearer header", () => {
        const req: any = {
          headers: { authorization: "Bearer header-token-xyz" },
        };
        assert.strictEqual(extractTokenFromRequest(req), "header-token-xyz");
      });

      it("should extract token from HttpOnly cookie", () => {
        const req: any = {
          cookies: { accessToken: "cookie-token-abc" },
        };
        assert.strictEqual(extractTokenFromRequest(req), "cookie-token-abc");
      });

      it("should ignore query string token in extractTokenFromRequest even on /stream or /download", () => {
        const reqStream: any = {
          path: "/api/v1/evidences/123/stream",
          query: { token: "query-token-stream" },
        };
        assert.strictEqual(extractTokenFromRequest(reqStream), undefined);

        const reqDownload: any = {
          path: "/api/v1/evidences/123/download",
          query: { ticket: "query-ticket-download" },
        };
        assert.strictEqual(extractTokenFromRequest(reqDownload), undefined);
      });

      it("should reject request with 400 VALIDATION_ERROR when query contains token or ticket or access_token", async () => {
        const reqWithToken: any = {
          path: "/api/v1/evidences/123/download",
          query: { token: "leaked-token" },
        };
        let tokenError: any = null;
        await authMiddleware(reqWithToken, {} as any, (err?: any) => {
          tokenError = err;
        });

        assert.ok(tokenError instanceof AppError);
        assert.strictEqual(tokenError.statusCode, 400);
        assert.strictEqual(tokenError.code, ERROR_CODE.VALIDATION_ERROR);
        assert.ok(tokenError.message.includes("query string"));

        const reqWithTicket: any = {
          path: "/api/v1/incidents",
          query: { ticket: "leaked-ticket" },
        };
        let ticketError: any = null;
        await authMiddleware(reqWithTicket, {} as any, (err?: any) => {
          ticketError = err;
        });

        assert.ok(ticketError instanceof AppError);
        assert.strictEqual(ticketError.statusCode, 400);
        assert.strictEqual(ticketError.code, ERROR_CODE.VALIDATION_ERROR);
      });
    });
  });
});


