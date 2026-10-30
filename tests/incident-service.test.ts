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
} from "../src/common/constants/incident.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import {
  requirePermission,
  requireAnyPermission,
} from "../src/middlewares/permission.middleware";
import { authMiddleware } from "../src/middlewares/auth.middleware";
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
import { IncidentRepository, serializeEvidence, serializeIncident } from "../src/modules/incident/incident.repository";
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

  // ── 7. Security Patches: SEC-01 & SEC-02 ───────────────────────────────────
  describe("7. Security Patches: SEC-01 & SEC-02", () => {
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
  });
});


