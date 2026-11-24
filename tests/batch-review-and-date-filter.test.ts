import { describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import {
  IncidentRepository,
  extractAiTelemetry,
  serializeIncident,
} from "../src/modules/incident/incident.repository";
import { IncidentService } from "../src/modules/incident/incident.service";
import { incidentRouter } from "../src/modules/incident/incident.route";
import {
  batchReviewIncidentsSchema,
  incidentQuerySchema,
  incidentStatusCountsQuerySchema,
  feedbackDatasetQuerySchema,
} from "../src/modules/incident/incident.validation";
import {
  ASSIGNMENT_STATUS,
  EVIDENCE_TYPE,
  INCIDENT_STATUS,
  VIOLATION_TYPE,
} from "../src/common/constants/incident.constant";
import { ROLES } from "../src/common/constants/role.constant";

describe("Batch Review & Date Filter Suite", () => {
  const validUuid1 = "11111111-1111-4111-8111-111111111111";
  const validUuid2 = "22222222-2222-4222-8222-222222222222";
  const validUuid3 = "33333333-3333-4333-8333-333333333333";
  const siteA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const siteB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const actorId = "99999999-9999-4999-8999-999999999999";

  describe("1. Validation Schemas", () => {
    it("batchReviewIncidentsSchema should accept valid CONFIRM payload", () => {
      const parsed = batchReviewIncidentsSchema.safeParse({
        ids: [validUuid1, validUuid2],
        action: "CONFIRM",
      });
      assert.strictEqual(parsed.success, true);
    });

    it("batchReviewIncidentsSchema should accept valid REJECT payload with resolutionNote", () => {
      const parsed = batchReviewIncidentsSchema.safeParse({
        ids: [validUuid1],
        action: "REJECT",
        resolutionNote: "Khách tham quan được miễn trừ PPE",
      });
      assert.strictEqual(parsed.success, true);
    });

    it("batchReviewIncidentsSchema should reject REJECT action when resolutionNote is missing", () => {
      const parsed = batchReviewIncidentsSchema.safeParse({
        ids: [validUuid1],
        action: "REJECT",
      });
      assert.strictEqual(parsed.success, false);
      if (!parsed.success) {
        assert.ok(
          parsed.error.errors.some((e) =>
            e.message.includes("Bắt buộc phải nhập lý do"),
          ),
        );
      }
    });

    it("batchReviewIncidentsSchema should reject REJECT action when resolutionNote is less than 3 chars", () => {
      const parsed = batchReviewIncidentsSchema.safeParse({
        ids: [validUuid1],
        action: "REJECT",
        resolutionNote: "ab",
      });
      assert.strictEqual(parsed.success, false);
    });

    it("batchReviewIncidentsSchema should reject empty ids array", () => {
      const parsed = batchReviewIncidentsSchema.safeParse({
        ids: [],
        action: "CONFIRM",
      });
      assert.strictEqual(parsed.success, false);
    });

    it("batchReviewIncidentsSchema should reject invalid action", () => {
      const parsed = batchReviewIncidentsSchema.safeParse({
        ids: [validUuid1],
        action: "INVALID_ACTION",
      });
      assert.strictEqual(parsed.success, false);
    });

    it("incidentQuerySchema should accept startDate and endDate", () => {
      const parsed = incidentQuerySchema.safeParse({
        startDate: "2026-11-01",
        endDate: "2026-11-09",
      });
      assert.strictEqual(parsed.success, true);
      assert.ok(parsed.data?.startDate instanceof Date);
      assert.ok(parsed.data?.endDate instanceof Date);
    });
  });

  describe("2. Batch Review Service & Repository Execution", () => {
    it("should batch CONFIRM pending incidents and record history & outbox events", async () => {
      const updatedRecords: any[] = [];
      const historyCreated: any[] = [];
      const outboxCreated: any[] = [];

      const mockPrisma = {
        $transaction: async (fn: any) => {
          const tx = {
            incident: {
              findMany: mock.fn(async () => [
                { id: validUuid1, siteId: siteA, status: INCIDENT_STATUS.PENDING_REVIEW },
                { id: validUuid2, siteId: siteA, status: INCIDENT_STATUS.PENDING_REVIEW },
              ]),
              updateMany: mock.fn(async (args: any) => {
                updatedRecords.push(args);
                return { count: 2 };
              }),
            },
            incidentStatusHistory: {
              createMany: mock.fn(async (args: any) => {
                historyCreated.push(...args.data);
                return { count: args.data.length };
              }),
            },
            outboxEvent: {
              createMany: mock.fn(async (args: any) => {
                outboxCreated.push(...args.data);
                return { count: args.data.length };
              }),
            },
          };
          return fn(tx);
        },
      };

      const repo = new IncidentRepository(mockPrisma);
      const service = new IncidentService(repo);

      const result = await service.batchReviewIncidents(
        {
          ids: [validUuid1, validUuid2],
          action: "CONFIRM",
          resolutionNote: "Xác nhận vi phạm an toàn PPE",
        },
        actorId,
        { role: ROLES.ADMIN },
      );

      assert.strictEqual(result.total, 2);
      assert.strictEqual(result.updatedCount, 2);
      assert.strictEqual(result.action, "CONFIRM");
      assert.strictEqual(result.newStatus, INCIDENT_STATUS.CONFIRMED);
      assert.deepStrictEqual(result.updatedIds, [validUuid1, validUuid2]);

      // Verify updateMany call
      assert.strictEqual(updatedRecords.length, 1);
      assert.strictEqual(updatedRecords[0].data.status, INCIDENT_STATUS.CONFIRMED);

      // Verify status history entries
      assert.strictEqual(historyCreated.length, 2);
      assert.strictEqual(historyCreated[0].newStatus, INCIDENT_STATUS.CONFIRMED);
      assert.strictEqual(historyCreated[0].changedBy, actorId);

      // Verify outbox events
      assert.strictEqual(outboxCreated.length, 2);
      assert.strictEqual(outboxCreated[0].eventType, "ppe.incident.status_changed");
    });

    it("should batch REJECT pending incidents and update status to DISMISSED", async () => {
      const updatedRecords: any[] = [];
      const historyCreated: any[] = [];

      const mockPrisma = {
        $transaction: async (fn: any) => {
          const tx = {
            incident: {
              findMany: mock.fn(async () => [
                { id: validUuid3, siteId: siteB, status: INCIDENT_STATUS.PENDING_REVIEW },
              ]),
              updateMany: mock.fn(async (args: any) => {
                updatedRecords.push(args);
                return { count: 1 };
              }),
            },
            incidentStatusHistory: {
              createMany: mock.fn(async (args: any) => {
                historyCreated.push(...args.data);
                return { count: args.data.length };
              }),
            },
            outboxEvent: {
              createMany: mock.fn(async () => ({ count: 1 })),
            },
          };
          return fn(tx);
        },
      };

      const repo = new IncidentRepository(mockPrisma);
      const service = new IncidentService(repo);

      const result = await service.batchReviewIncidents(
        {
          ids: [validUuid3],
          action: "REJECT",
          resolutionNote: "Góc quay bị khuất, bác bỏ cảnh báo",
        },
        actorId,
        { role: ROLES.ADMIN },
      );

      assert.strictEqual(result.total, 1);
      assert.strictEqual(result.updatedCount, 1);
      assert.strictEqual(result.action, "REJECT");
      assert.strictEqual(result.newStatus, INCIDENT_STATUS.DISMISSED);
      assert.deepStrictEqual(result.updatedIds, [validUuid3]);
      assert.strictEqual(updatedRecords[0].data.status, INCIDENT_STATUS.DISMISSED);
    });

    it("should enforce site scoping for non-admin users during batch review", async () => {
      let queriedWhere: any = null;

      const mockPrisma = {
        $transaction: async (fn: any) => {
          const tx = {
            incident: {
              findMany: mock.fn(async (args: any) => {
                queriedWhere = args.where;
                // Only return incidents matching user's site
                return [];
              }),
              updateMany: mock.fn(async () => ({ count: 0 })),
            },
            incidentStatusHistory: {
              createMany: mock.fn(async () => ({ count: 0 })),
            },
          };
          return fn(tx);
        },
      };

      const repo = new IncidentRepository(mockPrisma);
      const service = new IncidentService(repo);

      const result = await service.batchReviewIncidents(
        {
          ids: [validUuid1, validUuid2],
          action: "CONFIRM",
        },
        actorId,
        {
          role: ROLES.SAFETY_OFFICER,
          siteId: siteA,
        },
      );

      assert.strictEqual(result.total, 2);
      assert.strictEqual(result.updatedCount, 0);
      assert.deepStrictEqual(queriedWhere.siteId, { in: [siteA] });
    });

    it("should fail closed and return 0 updated records for non-admin user with 0 assigned sites", async () => {
      let transactionCalled = false;

      const mockPrisma = {
        $transaction: async () => {
          transactionCalled = true;
          return { total: 2, updatedCount: 2 };
        },
      };

      const repo = new IncidentRepository(mockPrisma as any);
      const service = new IncidentService(repo);

      const result = await service.batchReviewIncidents(
        {
          ids: [validUuid1, validUuid2],
          action: "CONFIRM",
        },
        actorId,
        {
          role: ROLES.SAFETY_OFFICER,
          siteId: undefined,
          siteIds: [],
        },
      );

      assert.strictEqual(result.total, 2);
      assert.strictEqual(result.updatedCount, 0);
      assert.deepStrictEqual(result.updatedIds, []);
      // Verification: Fail-closed immediately without touching DB transaction
      assert.strictEqual(transactionCalled, false);
    });

    it("should deduplicate incident IDs in batchReviewIncidents", async () => {
      let passedIds: string[] = [];

      const mockRepo = {
        batchTransitionStatus: mock.fn(async (params: any) => {
          passedIds = params.incidentIds;
          return {
            total: params.incidentIds.length,
            updatedCount: params.incidentIds.length,
            action: params.action,
            newStatus: INCIDENT_STATUS.CONFIRMED,
            updatedIds: params.incidentIds,
          };
        }),
      } as unknown as IncidentRepository;

      const service = new IncidentService(mockRepo);

      const result = await service.batchReviewIncidents(
        {
          ids: [validUuid1, validUuid1, validUuid2, validUuid2, validUuid1],
          action: "CONFIRM",
        },
        actorId,
        { role: ROLES.ADMIN },
      );

      assert.strictEqual(result.total, 2);
      assert.deepStrictEqual(passedIds, [validUuid1, validUuid2]);
    });
  });

  describe("3. Date Filtering via startDate and endDate", () => {
    it("should filter by startDate and endDate in findAllIncidents", async () => {
      let capturedWhere: any = null;

      const mockPrisma = {
        incident: {
          count: mock.fn(async (args: any) => {
            capturedWhere = args.where;
            return 0;
          }),
          findMany: mock.fn(async () => []),
        },
      };

      const repo = new IncidentRepository(mockPrisma);
      const startDate = new Date("2026-11-01T00:00:00Z");
      const endDate = new Date("2026-11-09T23:59:59Z");

      await repo.findAllIncidents({
        startDate,
        endDate,
      });

      assert.ok(capturedWhere);
      assert.ok(capturedWhere.detectedAt);
      assert.deepStrictEqual(capturedWhere.detectedAt.gte, startDate);
      assert.deepStrictEqual(capturedWhere.detectedAt.lte, endDate);
    });

    it("should support fallback to fromDate and toDate when startDate is absent", async () => {
      let capturedWhere: any = null;

      const mockPrisma = {
        incident: {
          count: mock.fn(async (args: any) => {
            capturedWhere = args.where;
            return 0;
          }),
          findMany: mock.fn(async () => []),
        },
      };

      const repo = new IncidentRepository(mockPrisma);
      const fromDate = new Date("2026-10-15T00:00:00Z");
      const toDate = new Date("2026-10-20T23:59:59Z");

      await repo.findAllIncidents({
        fromDate,
        toDate,
      });

      assert.ok(capturedWhere);
      assert.ok(capturedWhere.detectedAt);
      assert.deepStrictEqual(capturedWhere.detectedAt.gte, fromDate);
      assert.deepStrictEqual(capturedWhere.detectedAt.lte, toDate);
    });
  });

  describe("4. Status Counts KPI Suite", () => {
    describe("Validation Schema", () => {
      it("should accept valid empty query", () => {
        const parsed = incidentStatusCountsQuerySchema.safeParse({});
        assert.strictEqual(parsed.success, true);
      });

      it("should accept valid siteId, cameraId, and ISO date strings", () => {
        const parsed = incidentStatusCountsQuerySchema.safeParse({
          siteId: siteA,
          cameraId: validUuid1,
          fromDate: "2026-11-01T00:00:00.000Z",
          toDate: "2026-11-10T23:59:59.999Z",
        });
        assert.strictEqual(parsed.success, true);
        if (parsed.success) {
          assert.strictEqual(parsed.data.siteId, siteA);
          assert.strictEqual(parsed.data.cameraId, validUuid1);
          assert.ok(parsed.data.fromDate instanceof Date);
          assert.ok(parsed.data.toDate instanceof Date);
        }
      });

      it("should support startDate and endDate as aliases", () => {
        const parsed = incidentStatusCountsQuerySchema.safeParse({
          startDate: "2026-11-01",
          endDate: "2026-11-10",
        });
        assert.strictEqual(parsed.success, true);
        if (parsed.success) {
          assert.ok(parsed.data.startDate instanceof Date);
          assert.ok(parsed.data.endDate instanceof Date);
        }
      });

      it("should reject invalid siteId or cameraId format", () => {
        const parsed1 = incidentStatusCountsQuerySchema.safeParse({
          siteId: "not-a-uuid",
        });
        assert.strictEqual(parsed1.success, false);

        const parsed2 = incidentStatusCountsQuerySchema.safeParse({
          cameraId: "12345",
        });
        assert.strictEqual(parsed2.success, false);
      });
    });

    describe("Repository Execution", () => {
      it("should execute 7 parallel count queries with correct filters", async () => {
        const capturedCalls: any[] = [];
        const mockPrisma = {
          incident: {
            count: mock.fn(async (args: any) => {
              capturedCalls.push(args);
              if (args.where?.status === INCIDENT_STATUS.PENDING_REVIEW) return 6;
              if (args.where?.status === INCIDENT_STATUS.CONFIRMED) return 4;
              if (args.where?.status === INCIDENT_STATUS.CLOSED) return 12;
              if (args.where?.status === INCIDENT_STATUS.DISMISSED) return 3;
              if (args.where?.severity === "CRITICAL") return 5;
              if (args.where?.status?.in) return 37;
              return 48; // total
            }),
          },
        };

        const repo = new IncidentRepository(mockPrisma);
        const fromDate = new Date("2026-11-01T00:00:00Z");
        const toDate = new Date("2026-11-10T23:59:59Z");

        const result = await repo.getStatusCounts(
          {
            siteId: siteA,
            cameraId: validUuid1,
            fromDate,
            toDate,
          },
          [siteA],
        );

        assert.deepStrictEqual(result, {
          total: 48,
          pendingReview: 6,
          confirmed: 4,
          critical: 5,
          resolved: 37,
          closed: 12,
          dismissed: 3,
        });

        assert.strictEqual(capturedCalls.length, 7);
        for (const call of capturedCalls) {
          assert.strictEqual(call.where.siteId, siteA);
          assert.strictEqual(call.where.cameraId, validUuid1);
          assert.deepStrictEqual(call.where.detectedAt.gte, fromDate);
          assert.deepStrictEqual(call.where.detectedAt.lte, toDate);
        }
      });

      it("should defense-in-depth restrict where.siteId to empty set when query.siteId is outside siteFilter", async () => {
        const capturedCalls: any[] = [];
        const mockPrisma = {
          incident: {
            count: mock.fn(async (args: any) => {
              capturedCalls.push(args);
              return 0;
            }),
          },
        };

        const repo = new IncidentRepository(mockPrisma);
        const disallowedSite = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

        await repo.getStatusCounts({ siteId: disallowedSite }, [siteA]);

        assert.strictEqual(capturedCalls.length, 7);
        for (const call of capturedCalls) {
          assert.deepStrictEqual(call.where.siteId, { in: [] });
        }
      });
    });

    describe("Service Tenant Scoping & Business Logic", () => {
      it("should allow admin to query across any site", async () => {
        let repoPassedFilter: string[] | undefined = undefined;
        const mockRepo = {
          getStatusCounts: mock.fn(async (_query: any, siteFilter?: string[]) => {
            repoPassedFilter = siteFilter;
            return { total: 10, pendingReview: 2, critical: 1, resolved: 7 };
          }),
        };

        const service = new IncidentService(mockRepo as any);
        const adminContext = {
          userId: actorId,
          role: ROLES.ADMIN,
          siteId: undefined,
          siteIds: [],
        };

        const res = await service.getStatusCounts({ siteId: siteA }, adminContext);
        assert.strictEqual(res.total, 10);
        assert.strictEqual(repoPassedFilter, undefined);
      });

      it("should scope non-admin user to allowed sites", async () => {
        let repoPassedFilter: string[] | undefined = undefined;
        const mockRepo = {
          getStatusCounts: mock.fn(async (_query: any, siteFilter?: string[]) => {
            repoPassedFilter = siteFilter;
            return { total: 5, pendingReview: 1, critical: 0, resolved: 4 };
          }),
        };

        const service = new IncidentService(mockRepo as any);
        const nonAdminContext = {
          userId: actorId,
          role: ROLES.SAFETY_OFFICER,
          siteId: siteA,
          siteIds: [siteB],
        };

        const res = await service.getStatusCounts({}, nonAdminContext);
        assert.strictEqual(res.total, 5);
        assert.deepStrictEqual(repoPassedFilter, [siteA, siteB]);
      });

      it("should fail closed and return 0 counts for non-admin with 0 assigned sites", async () => {
        const mockRepo = {
          getStatusCounts: mock.fn(async () => {
            throw new Error("Should not be called!");
          }),
        };

        const service = new IncidentService(mockRepo as any);
        const nonAdminContext = {
          userId: actorId,
          role: ROLES.SAFETY_OFFICER,
          siteId: undefined,
          siteIds: [],
        };

        const res = await service.getStatusCounts({}, nonAdminContext);
        assert.deepStrictEqual(res, {
          total: 0,
          pendingReview: 0,
          confirmed: 0,
          critical: 0,
          resolved: 0,
          closed: 0,
          dismissed: 0,
        });
        assert.strictEqual(mockRepo.getStatusCounts.mock.callCount(), 0);
      });

      it("should fail closed if non-admin requests a siteId outside their allowed sites", async () => {
        const mockRepo = {
          getStatusCounts: mock.fn(async () => {
            throw new Error("Should not be called!");
          }),
        };

        const service = new IncidentService(mockRepo as any);
        const nonAdminContext = {
          userId: actorId,
          role: ROLES.SAFETY_OFFICER,
          siteId: siteA,
          siteIds: [],
        };

        const disallowedSite = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        const res = await service.getStatusCounts({ siteId: disallowedSite }, nonAdminContext);
        assert.deepStrictEqual(res, {
          total: 0,
          pendingReview: 0,
          confirmed: 0,
          critical: 0,
          resolved: 0,
          closed: 0,
          dismissed: 0,
        });
        assert.strictEqual(mockRepo.getStatusCounts.mock.callCount(), 0);
      });

      it("should deduplicate site IDs when user has overlapping siteId and siteIds", async () => {
        let repoPassedFilter: string[] | undefined = undefined;
        const mockRepo = {
          getStatusCounts: mock.fn(async (_query: any, siteFilter?: string[]) => {
            repoPassedFilter = siteFilter;
            return {
              total: 3,
              pendingReview: 1,
              confirmed: 0,
              critical: 0,
              resolved: 2,
              closed: 0,
              dismissed: 0,
            };
          }),
        };

        const service = new IncidentService(mockRepo as any);
        const nonAdminContext = {
          userId: actorId,
          role: ROLES.SAFETY_OFFICER,
          siteId: siteA,
          siteIds: [siteA, siteB],
        };

        const res = await service.getStatusCounts({}, nonAdminContext);
        assert.strictEqual(res.total, 3);
        assert.deepStrictEqual(repoPassedFilter, [siteA, siteB]);
      });
    });
  });

  describe("5. Issue #2: AI Telemetry Normalization, includeAllAssignments, cameraIds & Feedback Dataset", () => {
    it("extractAiTelemetry & serializeIncident extract real confidence and trackId (with storageKey fallback and null when absent)", () => {
      const withMeta = serializeIncident({
        id: validUuid1,
        violationType: VIOLATION_TYPE.NO_HELMET,
        evidences: [
          {
            evidenceType: EVIDENCE_TYPE.SNAPSHOT,
            storageKey: `evidences/${siteA}/cam-1/2026/11/24/${validUuid1}/snap.jpg`,
            fileSize: BigInt(2048),
            metadata: {
              aiDetections: {
                violation: { type: "NO_HELMET", confidence: 0.91234 },
                allDetections: [
                  { class: "NO_HELMET", confidence: 0.91234, track_id: 14 },
                  { class: "PERSON", confidence: 0.98, track_id: 7 },
                ],
              },
            },
          },
        ],
      });
      assert.strictEqual(withMeta.confidence, 0.9123);
      assert.strictEqual(withMeta.trackId, 14);

      const withStorageFallback = extractAiTelemetry({
        violationType: VIOLATION_TYPE.NO_VEST,
        evidences: [
          {
            evidenceType: EVIDENCE_TYPE.SNAPSHOT,
            storageKey: `evidences/${siteA}/cam-1/2026/11/24/ev_track23_snap.jpg`,
            metadata: null,
          },
        ],
      });
      assert.strictEqual(withStorageFallback.confidence, null);
      assert.strictEqual(withStorageFallback.trackId, 23);

      const emptyTelemetry = serializeIncident({
        id: validUuid2,
        violationType: VIOLATION_TYPE.NO_HELMET,
        evidences: [],
      });
      assert.strictEqual(emptyTelemetry.confidence, null);
      assert.strictEqual(emptyTelemetry.trackId, null);
    });

    it("incidentQuerySchema parses includeAllAssignments, includeAssignments, and cameraIds (CSV or array)", () => {
      const parsedCsv = incidentQuerySchema.parse({
        includeAssignments: "true",
        includeAllAssignments: "true",
        cameraIds: `${validUuid1}, ${validUuid2}`,
      });
      assert.strictEqual(parsedCsv.includeAssignments, true);
      assert.strictEqual(parsedCsv.includeAllAssignments, true);
      assert.deepStrictEqual(parsedCsv.cameraIds, [validUuid1, validUuid2]);

      const parsedArr = incidentQuerySchema.parse({
        includeAssignments: "false",
        cameraIds: [validUuid3],
      });
      assert.strictEqual(parsedArr.includeAssignments, false);
      assert.deepStrictEqual(parsedArr.cameraIds, [validUuid3]);
    });

    it("findAllIncidents supports includeAllAssignments=true (returning COMPLETED assignments) and cameraIds filter", async () => {
      let capturedFindManyArgs: any = null;
      const mockDb = {
        incident: {
          count: mock.fn(async () => 1),
          findMany: mock.fn(async (args: any) => {
            capturedFindManyArgs = args;
            return [
              {
                id: validUuid1,
                siteId: siteA,
                cameraId: validUuid2,
                violationType: VIOLATION_TYPE.NO_HELMET,
                evidences: [],
                assignments: [
                  { id: validUuid3, assignedTo: actorId, status: ASSIGNMENT_STATUS.COMPLETED },
                ],
              },
            ];
          }),
        },
      };

      const repo = new IncidentRepository(mockDb);
      const res = await repo.findAllIncidents({
        includeAllAssignments: true,
        assignedTo: actorId,
        cameraIds: [validUuid2, validUuid3],
      });

      assert.deepStrictEqual(capturedFindManyArgs.where.cameraId, {
        in: [validUuid2, validUuid3],
      });
      assert.deepStrictEqual(capturedFindManyArgs.where.assignments, {
        some: { assignedTo: actorId },
      });
      assert.deepStrictEqual(capturedFindManyArgs.include.assignments, {
        orderBy: { assignedAt: "desc" },
      });
      assert.strictEqual(res.data[0].assignments?.length, 1);
      assert.strictEqual(res.data[0].assignments?.[0].status, ASSIGNMENT_STATUS.COMPLETED);
    });

    it("mounts GET /feedback-dataset before GET /:id and validates feedbackDatasetQuerySchema", () => {
      const stack = incidentRouter.stack || [];
      const feedbackIdx = stack.findIndex(
        (layer: any) => layer.route?.path === "/feedback-dataset" && layer.route?.methods?.get,
      );
      const paramIdx = stack.findIndex(
        (layer: any) => layer.route?.path === "/:id" && layer.route?.methods?.get,
      );
      assert.ok(feedbackIdx !== -1, "GET /feedback-dataset must exist");
      assert.ok(paramIdx !== -1, "GET /:id must exist");
      assert.ok(feedbackIdx < paramIdx, "GET /feedback-dataset must precede GET /:id");

      const valid = feedbackDatasetQuerySchema.safeParse({
        label: "FALSE_ALARM",
        cameraIds: `${validUuid1},${validUuid2}`,
        limit: "25",
      });
      assert.strictEqual(valid.success, true);
      if (valid.success) {
        assert.strictEqual(valid.data.label, "FALSE_ALARM");
        assert.strictEqual(valid.data.limit, 25);
        assert.deepStrictEqual(valid.data.cameraIds, [validUuid1, validUuid2]);
      }

      const invalid = feedbackDatasetQuerySchema.safeParse({ label: "UNKNOWN" });
      assert.strictEqual(invalid.success, false);
    });

    it("findFeedbackDataset maps TRUE_VIOLATION / FALSE_ALARM with snapshotStorageKey, aiDetections, reviewReason, and enforces site scoping", async () => {
      const reviewedAt = new Date("2026-11-24T09:00:00.000Z");
      const mockDb = {
        incident: {
          count: mock.fn(async () => 2),
          findMany: mock.fn(async () => [
            {
              id: validUuid1,
              siteId: siteA,
              cameraId: validUuid2,
              violationType: VIOLATION_TYPE.NO_HELMET,
              status: INCIDENT_STATUS.DISMISSED,
              detectedAt: new Date("2026-11-24T08:00:00.000Z"),
              statusHistory: [
                {
                  newStatus: INCIDENT_STATUS.DISMISSED,
                  reason: "Ánh nắng chói phản chiếu nhầm nón trắng",
                  changedBy: actorId,
                  changedAt: reviewedAt,
                },
              ],
              evidences: [
                {
                  evidenceType: EVIDENCE_TYPE.SNAPSHOT,
                  storageKey: `evidences/${siteA}/${validUuid2}/2026/11/24/${validUuid1}/snap.jpg`,
                  metadata: {
                    aiDetections: {
                      violation: { type: "NO_HELMET", confidence: 0.78 },
                      allDetections: [{ class: "NO_HELMET", confidence: 0.78, track_id: 5 }],
                    },
                  },
                },
              ],
            },
            {
              id: validUuid3,
              siteId: siteA,
              cameraId: validUuid2,
              violationType: VIOLATION_TYPE.NO_VEST,
              status: INCIDENT_STATUS.CLOSED,
              detectedAt: new Date("2026-11-24T08:15:00.000Z"),
              statusHistory: [
                {
                  newStatus: INCIDENT_STATUS.CONFIRMED,
                  reason: "Xác nhận công nhân thiếu áo phản quang",
                  changedBy: actorId,
                  changedAt: reviewedAt,
                },
              ],
              evidences: [],
            },
          ]),
        },
      };

      const repo = new IncidentRepository(mockDb);
      const service = new IncidentService(repo);

      const res = await service.getFeedbackDataset(
        { page: 1, limit: 50 },
        { id: actorId, role: ROLES.SAFETY_MANAGER, siteId: siteA },
      );

      assert.strictEqual(res.meta.total, 2);
      assert.strictEqual(res.data[0].label, "FALSE_ALARM");
      assert.strictEqual(res.data[0].reviewReason, "Ánh nắng chói phản chiếu nhầm nón trắng");
      assert.strictEqual(res.data[0].confidence, 0.78);
      assert.strictEqual(res.data[0].trackId, 5);
      assert.ok(res.data[0].snapshotStorageKey?.endsWith("/snap.jpg"));
      assert.ok(res.data[0].aiDetections);

      assert.strictEqual(res.data[1].label, "TRUE_VIOLATION");
      assert.strictEqual(res.data[1].confidence, null);
      assert.strictEqual(res.data[1].trackId, null);
      assert.strictEqual(res.data[1].snapshotStorageKey, null);

      // Fail-closed khi non-admin không có site
      const emptyRes = await service.getFeedbackDataset(
        { page: 1, limit: 50 },
        { id: actorId, role: ROLES.SAFETY_OFFICER, siteIds: [] },
      );
      assert.strictEqual(emptyRes.data.length, 0);
      assert.strictEqual(emptyRes.meta.total, 0);
    });
  });
});

