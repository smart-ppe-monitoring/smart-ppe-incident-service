import { describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import { IncidentRepository } from "../src/modules/incident/incident.repository";
import { IncidentService } from "../src/modules/incident/incident.service";
import {
  batchReviewIncidentsSchema,
  incidentQuerySchema,
} from "../src/modules/incident/incident.validation";
import {
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
});

