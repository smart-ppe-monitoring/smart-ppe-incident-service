import { describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import { IncidentController } from "../src/modules/incident/incident.controller";
import { IncidentService } from "../src/modules/incident/incident.service";
import { IncidentRepository } from "../src/modules/incident/incident.repository";
import { incidentRouter } from "../src/modules/incident/incident.route";
import {
  batchAssignIncidentsSchema,
  batchResolveIncidentsSchema,
  batchCloseIncidentsSchema,
} from "../src/modules/incident/incident.validation";
import {
  ASSIGNMENT_STATUS,
  EVIDENCE_TYPE,
  INCIDENT_OUTBOX_EVENT,
  INCIDENT_STATUS,
  VIOLATION_TYPE,
} from "../src/common/constants/incident.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { AppError } from "../src/common/errors/app-error";
import { buildOpenApiSpec } from "../src/config/openapi/openapi.registry";
import { registerIncidentOpenApi } from "../src/modules/incident/incident.openapi";

describe("Issue #4: Incident BOLA Site-Scoping, Assignment Validation/Outbox & Batch Workflows", () => {
  const siteA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const siteB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const cameraA = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  const cameraB = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const incId1 = "11111111-1111-4111-8111-111111111111";
  const incId2 = "22222222-2222-4222-8222-222222222222";
  const incId3 = "33333333-3333-4333-8333-333333333333";
  const evId1 = "44444444-4444-4444-8444-444444444444";
  const actorManagerA = "55555555-5555-4555-8555-555555555555";
  const officerA = "66666666-6666-4666-8666-666666666666";
  const officerB = "77777777-7777-4777-8777-777777777777";

  const userSiteA = {
    id: actorManagerA,
    role: ROLES.SAFETY_MANAGER,
    siteId: siteA,
    siteIds: [siteA],
    email: "manager.a@smartppe.local",
    fullName: "Manager Site A",
  };

  const userNoSite = {
    id: officerA,
    role: ROLES.SAFETY_OFFICER,
    siteId: undefined,
    siteIds: [],
  };

  const userAdmin = {
    id: "88888888-8888-4888-8888-888888888888",
    role: ROLES.ADMIN,
    siteId: undefined,
    siteIds: [],
  };

  describe("AC #1: BOLA Site-Scoping across all :id and incident-scoped evidence endpoints", () => {
    it("IncidentController forwards req.user across all incident :id, upload, and batch endpoints", async () => {
      const capturedUserContexts: Array<{ op: string; user: any }> = [];
      const fakeService = {
        createIncident: async (_b: any, _a: string, _c: any, user: any) => {
          capturedUserContexts.push({ op: "createIncident", user });
          return { id: incId1 };
        },
        getIncidentById: async (_id: string, user: any) => {
          capturedUserContexts.push({ op: "getIncidentById", user });
          return { id: incId1 };
        },
        updateIncident: async (_id: string, _b: any, user: any) => {
          capturedUserContexts.push({ op: "updateIncident", user });
          return { id: incId1 };
        },
        deleteIncident: async (_id: string, user: any) => {
          capturedUserContexts.push({ op: "deleteIncident", user });
          return { id: incId1 };
        },
        reviewIncident: async (_id: string, _b: any, _a: string, user: any) => {
          capturedUserContexts.push({ op: "reviewIncident", user });
          return { id: incId1 };
        },
        resolveIncident: async (
          _id: string,
          _b: any,
          _a: string,
          _r: string,
          user: any,
        ) => {
          capturedUserContexts.push({ op: "resolveIncident", user });
          return { id: incId1 };
        },
        closeIncident: async (
          _id: string,
          _b: any,
          _a: string,
          _r: string,
          user: any,
        ) => {
          capturedUserContexts.push({ op: "closeIncident", user });
          return { id: incId1 };
        },
        assignIncident: async (_id: string, _b: any, _a: string, user: any) => {
          capturedUserContexts.push({ op: "assignIncident", user });
          return { id: "asg-1" };
        },
        getIncidentAssignments: async (_id: string, user: any) => {
          capturedUserContexts.push({ op: "getIncidentAssignments", user });
          return [];
        },
        addIncidentComment: async (
          _id: string,
          _b: any,
          _a: string,
          _ctx: any,
          user: any,
        ) => {
          capturedUserContexts.push({ op: "addIncidentComment", user });
          return { id: "cmt-1" };
        },
        getIncidentComments: async (_id: string, user: any) => {
          capturedUserContexts.push({ op: "getIncidentComments", user });
          return [];
        },
        addEvidence: async (_id: string, _b: any, user: any) => {
          capturedUserContexts.push({ op: "addEvidence", user });
          return { id: evId1 };
        },
        requestEvidenceUploadUrl: async (_b: any, _a: string, user: any) => {
          capturedUserContexts.push({ op: "requestEvidenceUploadUrl", user });
          return { uploadUrl: "https://minio/put" };
        },
        uploadEvidenceDirect: async (
          _b: any,
          _f: any,
          _a: string,
          user: any,
        ) => {
          capturedUserContexts.push({ op: "uploadEvidenceDirect", user });
          return { id: evId1 };
        },
        batchAssignIncidents: async (_b: any, _a: string, user: any) => {
          capturedUserContexts.push({ op: "batchAssignIncidents", user });
          return { total: 1, assignedCount: 1 };
        },
        batchResolveIncidents: async (
          _b: any,
          _a: string,
          _r: string,
          user: any,
        ) => {
          capturedUserContexts.push({ op: "batchResolveIncidents", user });
          return { total: 1, resolvedCount: 1 };
        },
        batchCloseIncidents: async (
          _b: any,
          _a: string,
          _r: string,
          user: any,
        ) => {
          capturedUserContexts.push({ op: "batchCloseIncidents", user });
          return { total: 1, closedCount: 1 };
        },
      } as unknown as IncidentService;

      const controller = new IncidentController(fakeService);
      const res: any = {
        statusCode: 200,
        status(code: number) {
          this.statusCode = code;
          return this;
        },
        json() {
          return this;
        },
      };
      const next = (err?: any) => {
        if (err) throw err;
      };
      const baseReq = (extra: Record<string, any> = {}): any => ({
        params: { id: incId1 },
        body: {},
        user: userSiteA,
        ...extra,
      });

      await controller.createIncident(baseReq(), res, next);
      await controller.findIncidentById(baseReq(), res, next);
      await controller.updateIncident(baseReq(), res, next);
      await controller.deleteIncident(baseReq(), res, next);
      await controller.reviewIncident(baseReq(), res, next);
      await controller.resolveIncident(baseReq(), res, next);
      await controller.closeIncident(baseReq(), res, next);
      await controller.assignIncident(baseReq(), res, next);
      await controller.getIncidentAssignments(baseReq(), res, next);
      await controller.addIncidentComment(baseReq(), res, next);
      await controller.getIncidentComments(baseReq(), res, next);
      await controller.addEvidence(baseReq(), res, next);
      await controller.requestEvidenceUploadUrl(baseReq(), res, next);
      await controller.uploadEvidenceDirect(
        baseReq({ file: { buffer: Buffer.from("x") } }),
        res,
        next,
      );
      await controller.batchAssignIncidents(baseReq(), res, next);
      await controller.batchResolveIncidents(baseReq(), res, next);
      await controller.batchCloseIncidents(baseReq(), res, next);

      assert.strictEqual(capturedUserContexts.length, 17);
      for (const item of capturedUserContexts) {
        assert.strictEqual(
          item.user,
          userSiteA,
          `${item.op} must forward req.user to IncidentService`,
        );
      }
    });

    it("rejects cross-site access (403 FORBIDDEN) and empty-site users on every :id endpoint, while permitting ADMIN and M2M", async () => {
      const incidentInSiteB: any = {
        id: incId2,
        siteId: siteB,
        cameraId: cameraB,
        violationType: VIOLATION_TYPE.NO_HELMET,
        severity: "HIGH",
        status: INCIDENT_STATUS.CONFIRMED,
        detectedAt: new Date(),
        evidences: [],
        assignments: [],
        comments: [],
      };

      const mockRepo = {
        findIncidentById: async (id: string) =>
          id === incId2 ? { ...incidentInSiteB } : null,
        findAssignmentsByIncidentId: async () => [],
        findCommentsByIncidentId: async () => [],
        transitionStatus: async (p: any) => ({ id: p.incidentId, status: p.newStatus }),
      } as unknown as IncidentRepository;

      const service = new IncidentService(mockRepo);

      const assertForbidden = async (fn: () => Promise<unknown>, label: string) => {
        await assert.rejects(
          fn,
          (err: any) => {
            assert.ok(err instanceof AppError, `${label}: expected AppError`);
            assert.strictEqual(err.statusCode, 403, `${label}: expected 403`);
            assert.strictEqual(
              err.code,
              ERROR_CODE.FORBIDDEN,
              `${label}: expected FORBIDDEN`,
            );
            return true;
          },
          label,
        );
      };

      for (const blockedUser of [userSiteA, userNoSite]) {
        await assertForbidden(
          () =>
            service.createIncident(
              {
                siteId: siteB,
                cameraId: cameraB,
                violationType: VIOLATION_TYPE.NO_HELMET,
                detectedAt: new Date(),
              },
              blockedUser.id,
              undefined,
              blockedUser,
            ),
          "createIncident",
        );
        await assertForbidden(
          () => service.getIncidentById(incId2, blockedUser),
          "getIncidentById",
        );
        await assertForbidden(
          () => service.updateIncident(incId2, { description: "edit" }, blockedUser),
          "updateIncident",
        );
        await assertForbidden(
          () => service.deleteIncident(incId2, blockedUser),
          "deleteIncident",
        );
        await assertForbidden(
          () =>
            service.reviewIncident(
              incId2,
              { decision: "CONFIRMED" },
              blockedUser.id,
              blockedUser,
            ),
          "reviewIncident",
        );
        await assertForbidden(
          () =>
            service.resolveIncident(
              incId2,
              { resolutionNote: "Fixed" },
              blockedUser.id,
              blockedUser.role,
              blockedUser,
            ),
          "resolveIncident",
        );
        await assertForbidden(
          () =>
            service.closeIncident(
              incId2,
              { closeNote: "Done" },
              blockedUser.id,
              blockedUser.role,
              blockedUser,
            ),
          "closeIncident",
        );
        await assertForbidden(
          () =>
            service.assignIncident(
              incId2,
              { assignedTo: officerB },
              blockedUser.id,
              blockedUser,
            ),
          "assignIncident",
        );
        await assertForbidden(
          () => service.getIncidentAssignments(incId2, blockedUser),
          "getIncidentAssignments",
        );
        await assertForbidden(
          () =>
            service.addIncidentComment(
              incId2,
              { comment: "Cross-site comment" },
              blockedUser.id,
              undefined,
              blockedUser,
            ),
          "addIncidentComment",
        );
        await assertForbidden(
          () => service.getIncidentComments(incId2, blockedUser),
          "getIncidentComments",
        );
        await assertForbidden(
          () =>
            service.addEvidence(
              incId2,
              {
                cameraId: cameraB,
                evidenceType: EVIDENCE_TYPE.SNAPSHOT,
                storageKey: `evidences/${siteB}/snap.jpg`,
                fileName: "snap.jpg",
                mimeType: "image/jpeg",
                capturedAt: new Date(),
              },
              blockedUser,
            ),
          "addEvidence",
        );
        await assertForbidden(
          () =>
            service.requestEvidenceUploadUrl(
              {
                incidentId: incId2,
                cameraId: cameraB,
                siteId: siteB,
                evidenceType: EVIDENCE_TYPE.SNAPSHOT,
                fileName: "snap.jpg",
                mimeType: "image/jpeg",
              },
              blockedUser.id,
              blockedUser,
            ),
          "requestEvidenceUploadUrl",
        );
        await assertForbidden(
          () =>
            service.uploadEvidenceDirect(
              {
                incidentId: incId2,
                cameraId: cameraB,
                evidenceType: EVIDENCE_TYPE.SNAPSHOT,
              },
              {
                buffer: Buffer.from("img"),
                originalname: "snap.jpg",
                mimetype: "image/jpeg",
                size: 3,
              },
              blockedUser.id,
              blockedUser,
            ),
          "uploadEvidenceDirect",
        );
      }

      // ADMIN and M2M (userContext = undefined) can access Site B
      const adminLoaded = await service.getIncidentById(incId2, userAdmin);
      assert.strictEqual(adminLoaded.id, incId2);
      const internalLoaded = await service.getIncidentById(incId2, undefined);
      assert.strictEqual(internalLoaded.id, incId2);
    });
  });

  describe("AC #2: Assignee Site Validation, CONFIRMED-only Status & Transactional Outbox Event", () => {
    it("rejects assignment when incident status is PENDING_REVIEW, RESOLVED, or DISMISSED", async () => {
      for (const invalidStatus of [
        INCIDENT_STATUS.PENDING_REVIEW,
        INCIDENT_STATUS.RESOLVED,
        INCIDENT_STATUS.DISMISSED,
      ]) {
        const mockRepo = {
          findIncidentById: async () => ({
            id: incId1,
            siteId: siteA,
            status: invalidStatus,
          }),
        } as unknown as IncidentRepository;

        const service = new IncidentService(mockRepo);
        await assert.rejects(
          () =>
            service.assignIncident(
              incId1,
              { assignedTo: officerA },
              actorManagerA,
              userSiteA,
            ),
          (err: AppError) =>
            err.statusCode === 400 && err.code === ERROR_CODE.BAD_REQUEST,
        );
      }
    });

    it("rejects assignment when assignedTo does not belong to incident site or is inactive", async () => {
      const mockRepo = {
        findIncidentById: async () => ({
          id: incId1,
          siteId: siteA,
          cameraId: cameraA,
          status: INCIDENT_STATUS.CONFIRMED,
        }),
      } as unknown as IncidentRepository;

      const directory = {
        getSiteUserMap: async () =>
          new Map([
            [
              officerA,
              {
                id: officerA,
                email: "a@smartppe.local",
                fullName: "Officer A",
                role: ROLES.SAFETY_OFFICER,
                isActive: false, // Inactive!
              },
            ],
          ]),
      };

      const service = new IncidentService(mockRepo, undefined, undefined, directory);

      // User not in site A at all (e.g. officerB)
      await assert.rejects(
        () =>
          service.assignIncident(
            incId1,
            { assignedTo: officerB },
            actorManagerA,
            userSiteA,
          ),
        (err: AppError) =>
          err.statusCode === 400 && err.code === ERROR_CODE.VALIDATION_ERROR,
      );

      // Inactive user in site A
      await assert.rejects(
        () =>
          service.assignIncident(
            incId1,
            { assignedTo: officerA },
            actorManagerA,
            userSiteA,
          ),
        (err: AppError) =>
          err.statusCode === 400 && err.code === ERROR_CODE.VALIDATION_ERROR,
      );
    });

    it("creates ACTIVE assignment, writes ppe.incident.assigned OutboxEvent in transaction, enriches assignedToName, and dispatches notification", async () => {
      const createdOutbox: any[] = [];
      const dispatchedNotifications: any[] = [];
      const mockPrisma = {
        incident: {
          findUnique: async () => ({
            id: incId1,
            siteId: siteA,
            cameraId: cameraA,
            violationType: VIOLATION_TYPE.NO_HELMET,
            severity: "HIGH",
            status: INCIDENT_STATUS.CONFIRMED,
            detectedAt: new Date(),
            description: "Missing helmet",
            evidences: [],
            statusHistory: [],
            assignments: [],
            comments: [],
          }),
        },
        $transaction: async (fn: any) => {
          const tx = {
            incidentAssignment: {
              updateMany: mock.fn(async () => ({ count: 0 })),
              create: mock.fn(async (args: any) => ({
                id: "asg-new-1",
                ...args.data,
                assignedAt: new Date("2026-11-27T10:00:00Z"),
              })),
            },
            outboxEvent: {
              createMany: mock.fn(async (args: any) => {
                createdOutbox.push(...args.data);
                return { count: args.data.length };
              }),
            },
          };
          return fn(tx);
        },
      };

      const repo = new IncidentRepository(mockPrisma);
      const directory = {
        getSiteUserMap: async () =>
          new Map([
            [
              officerA,
              {
                id: officerA,
                email: "officera@smartppe.local",
                fullName: "Nguyen Van A",
                role: ROLES.SAFETY_OFFICER,
                isActive: true,
              },
            ],
          ]),
      };
      const notifier = {
        dispatchIncidentNotification: async (payload: any) => {
          dispatchedNotifications.push(payload);
          return { dispatched: true };
        },
      };

      const service = new IncidentService(repo, undefined, notifier, directory);
      const assignment = await service.assignIncident(
        incId1,
        { assignedTo: officerA, note: "Ưu tiên xử lý ngay trong ca sáng" },
        actorManagerA,
        userSiteA,
      );

      assert.strictEqual(assignment.id, "asg-new-1");
      assert.strictEqual(assignment.assignedTo, officerA);
      assert.strictEqual(assignment.status, ASSIGNMENT_STATUS.ACTIVE);
      assert.strictEqual((assignment as any).assignedToName, "Nguyen Van A");

      assert.strictEqual(createdOutbox.length, 1);
      assert.strictEqual(
        createdOutbox[0].eventType,
        INCIDENT_OUTBOX_EVENT.ASSIGNED,
      );
      assert.strictEqual(createdOutbox[0].aggregateId, incId1);
      assert.strictEqual(createdOutbox[0].payload.assignedTo, officerA);
      assert.strictEqual(createdOutbox[0].payload.assignedBy, actorManagerA);
      assert.strictEqual(createdOutbox[0].payload.siteId, siteA);

      assert.strictEqual(dispatchedNotifications.length, 1);
      assert.deepStrictEqual(dispatchedNotifications[0].recipientUserIds, [
        officerA,
      ]);
    });
  });

  describe("AC #3 & AC #4: Batch Assign, Batch Resolve (Shared Evidence), Batch Close & CLOSED Guards", () => {
    it("validates schemas, route ordering before /:id, and OpenAPI definitions for batch-assign, batch-resolve, batch-close", () => {
      assert.strictEqual(
        batchAssignIncidentsSchema.safeParse({
          ids: [incId1, incId2],
          assignedTo: officerA,
          note: "Nhóm ca sáng",
        }).success,
        true,
      );
      assert.strictEqual(
        batchResolveIncidentsSchema.safeParse({
          ids: [incId1, incId2],
          resolutionNote: "Đã nhắc nhở và bổ sung mũ bảo hộ",
          sharedEvidence: {
            storageKey: `evidences/${siteA}/after-fix.jpg`,
            fileName: "after-fix.jpg",
            mimeType: "image/jpeg",
            fileSize: 2048,
          },
        }).success,
        true,
      );
      assert.strictEqual(
        batchCloseIncidentsSchema.safeParse({
          ids: [incId1],
          closeNote: "Hoàn tất",
        }).success,
        true,
      );

      const routes = incidentRouter.stack
        .filter((l: any) => l.route)
        .map((l: any) => l.route.path);
      const idParamIdx = routes.indexOf("/:id");
      assert.ok(idParamIdx > -1);
      for (const batchPath of [
        "/batch-assign",
        "/batch-resolve",
        "/batch-close",
      ]) {
        const idx = routes.indexOf(batchPath);
        assert.ok(idx > -1, `${batchPath} must be registered on incidentRouter`);
        assert.ok(idx < idParamIdx, `${batchPath} must be mounted BEFORE /:id`);
      }

      registerIncidentOpenApi();
      const spec = buildOpenApiSpec();
      const paths = spec.paths as Record<string, any>;
      assert.ok(paths["/incidents/batch-assign"]?.post);
      assert.ok(paths["/incidents/batch-resolve"]?.post);
      assert.ok(paths["/incidents/batch-close"]?.post);
    });

    it("batchAssignIncidents enforces site scoping, assignee site check, fail-closed 0 sites, and writes OutboxEvents", async () => {
      const createdAssignments: any[] = [];
      const createdOutbox: any[] = [];
      let capturedCandidateWhere: any = null;

      const mockPrisma = {
        incident: {
          findMany: mock.fn(async (args: any) => {
            capturedCandidateWhere = args.where;
            return [
              {
                id: incId1,
                siteId: siteA,
                cameraId: cameraA,
                violationType: VIOLATION_TYPE.NO_HELMET,
                severity: "HIGH",
                status: INCIDENT_STATUS.CONFIRMED,
                detectedAt: new Date(),
              },
              {
                id: incId2,
                siteId: siteA,
                cameraId: cameraA,
                violationType: VIOLATION_TYPE.NO_VEST,
                severity: "MEDIUM",
                status: INCIDENT_STATUS.CONFIRMED,
                detectedAt: new Date(),
              },
            ];
          }),
        },
        $transaction: async (fn: any) => {
          const tx = {
            incidentAssignment: {
              updateMany: mock.fn(async () => ({ count: 0 })),
              createMany: mock.fn(async (args: any) => {
                createdAssignments.push(...args.data);
                return { count: args.data.length };
              }),
            },
            outboxEvent: {
              createMany: mock.fn(async (args: any) => {
                createdOutbox.push(...args.data);
                return { count: args.data.length };
              }),
            },
          };
          return fn(tx);
        },
      };

      const repo = new IncidentRepository(mockPrisma);
      const directory = {
        getSiteUserMap: async () =>
          new Map([
            [
              officerA,
              {
                id: officerA,
                email: "officera@smartppe.local",
                fullName: "Officer A",
                role: ROLES.SAFETY_OFFICER,
                isActive: true,
              },
            ],
          ]),
      };
      const service = new IncidentService(repo, undefined, undefined, directory);

      // Fail closed on 0 sites
      const emptyRes = await service.batchAssignIncidents(
        { ids: [incId1], assignedTo: officerA },
        actorManagerA,
        userNoSite,
      );
      assert.strictEqual(emptyRes.assignedCount, 0);

      // Site-scoped batch assign (incId3 skipped since not returned in Site A)
      const res = await service.batchAssignIncidents(
        { ids: [incId1, incId2, incId3], assignedTo: officerA, note: "Batch test" },
        actorManagerA,
        userSiteA,
      );

      assert.deepStrictEqual(capturedCandidateWhere.siteId, { in: [siteA] });
      assert.strictEqual(res.total, 3);
      assert.strictEqual(res.assignedCount, 2);
      assert.strictEqual(res.assignedToName, "Officer A");
      assert.deepStrictEqual(res.assignedIds, [incId1, incId2]);
      assert.deepStrictEqual(res.skippedIds, [incId3]);
      assert.strictEqual(createdAssignments.length, 2);
      assert.strictEqual(createdOutbox.length, 2);
      assert.strictEqual(
        createdOutbox[0].eventType,
        INCIDENT_OUTBOX_EVENT.ASSIGNED,
      );
    });

    it("batchResolveIncidents attaches 1 sharedEvidence key to multiple incidents in 1 transaction and protects shared object on deletion", async () => {
      const createdEvidences: any[] = [];
      const createdHistory: any[] = [];
      const createdOutbox: any[] = [];
      const deletedStorageKeys: string[] = [];

      const sharedKey = `evidences/${siteA}/shared-after-fix.jpg`;
      let remainingRefCount = 1;

      const mockPrisma = {
        $transaction: async (fn: any) => {
          const tx = {
            incident: {
              findMany: mock.fn(async () => [
                {
                  id: incId1,
                  siteId: siteA,
                  cameraId: cameraA,
                  status: INCIDENT_STATUS.CONFIRMED,
                },
                {
                  id: incId2,
                  siteId: siteA,
                  cameraId: cameraA,
                  status: INCIDENT_STATUS.CONFIRMED,
                },
              ]),
              updateMany: mock.fn(async () => ({ count: 2 })),
            },
            evidence: {
              create: mock.fn(async (args: any) => {
                createdEvidences.push(args.data);
                return { id: `ev-${createdEvidences.length}`, ...args.data };
              }),
            },
            incidentStatusHistory: {
              createMany: mock.fn(async (args: any) => {
                createdHistory.push(...args.data);
                return { count: args.data.length };
              }),
            },
            outboxEvent: {
              createMany: mock.fn(async (args: any) => {
                createdOutbox.push(...args.data);
                return { count: args.data.length };
              }),
            },
          };
          return fn(tx);
        },
        evidence: {
          findUnique: async () => ({
            id: evId1,
            storageKey: sharedKey,
            incident: { id: incId1, siteId: siteA, status: INCIDENT_STATUS.RESOLVED },
          }),
          count: async () => remainingRefCount,
          delete: async (args: any) => ({ id: args.where.id, fileSize: BigInt(100) }),
        },
        evidenceAccessLog: {
          create: async () => ({}),
        },
      };

      const storageMock = {
        deleteObject: async (key: string) => {
          deletedStorageKeys.push(key);
        },
      } as any;

      const repo = new IncidentRepository(mockPrisma);
      const service = new IncidentService(repo, storageMock);

      // Reject cross-site sharedEvidence key
      await assert.rejects(
        () =>
          service.batchResolveIncidents(
            {
              ids: [incId1, incId2],
              resolutionNote: "Fix completed",
              sharedEvidence: {
                storageKey: `evidences/${siteB}/wrong-site.jpg`,
                fileName: "wrong.jpg",
                mimeType: "image/jpeg",
              },
            },
            actorManagerA,
            ROLES.SAFETY_MANAGER,
            userSiteA,
          ),
        (err: AppError) =>
          err.statusCode === 403 && err.code === ERROR_CODE.FORBIDDEN,
      );

      const res = await service.batchResolveIncidents(
        {
          ids: [incId1, incId2, incId3],
          resolutionNote: "Công nhân đã trang bị đầy đủ mũ bảo hộ",
          sharedEvidence: {
            storageKey: sharedKey,
            fileName: "shared-after-fix.jpg",
            mimeType: "image/jpeg",
            fileSize: 4096,
            metadata: { checksum: "sha256-shared" },
          },
        },
        actorManagerA,
        ROLES.SAFETY_MANAGER,
        userSiteA,
      );

      assert.strictEqual(res.total, 3);
      assert.strictEqual(res.resolvedCount, 2);
      assert.strictEqual(res.newStatus, INCIDENT_STATUS.RESOLVED);
      assert.deepStrictEqual(res.resolvedIds, [incId1, incId2]);
      assert.deepStrictEqual(res.skippedIds, [incId3]);
      assert.strictEqual(res.sharedEvidenceStorageKey, sharedKey);

      assert.strictEqual(createdEvidences.length, 2);
      assert.strictEqual(createdEvidences[0].storageKey, sharedKey);
      assert.strictEqual(createdEvidences[1].storageKey, sharedKey);
      assert.strictEqual(createdHistory.length, 2);
      assert.strictEqual(createdOutbox.length, 2);
      assert.strictEqual(
        createdOutbox[0].eventType,
        INCIDENT_OUTBOX_EVENT.RESOLVED,
      );

      // Deleting 1 of the shared evidence rows must NOT delete the MinIO object while remainingRefCount > 0
      await service.deleteEvidence(evId1, userSiteA);
      assert.strictEqual(deletedStorageKeys.length, 0);

      // Once no remaining evidence references that key, deleting removes the object
      remainingRefCount = 0;
      await service.deleteEvidence(evId1, userSiteA);
      assert.deepStrictEqual(deletedStorageKeys, [sharedKey]);
    });

    it("batchCloseIncidents restricts non-manager to assigned incidents, writes history & outbox, and blocks deleteIncident on CLOSED incidents", async () => {
      let capturedWhere: any = null;
      const createdOutbox: any[] = [];

      const mockPrisma = {
        $transaction: async (fn: any) => {
          const tx = {
            incident: {
              findMany: mock.fn(async (args: any) => {
                capturedWhere = args.where;
                return [{ id: incId1, siteId: siteA, status: INCIDENT_STATUS.RESOLVED }];
              }),
              updateMany: mock.fn(async () => ({ count: 1 })),
            },
            incidentStatusHistory: {
              createMany: mock.fn(async () => ({ count: 1 })),
            },
            outboxEvent: {
              createMany: mock.fn(async (args: any) => {
                createdOutbox.push(...args.data);
                return { count: args.data.length };
              }),
            },
          };
          return fn(tx);
        },
        incident: {
          findUnique: async () => ({
            id: incId1,
            siteId: siteA,
            status: INCIDENT_STATUS.CLOSED,
            evidences: [],
          }),
        },
      };

      const repo = new IncidentRepository(mockPrisma);
      const service = new IncidentService(repo);

      const officerRes = await service.batchCloseIncidents(
        { ids: [incId1, incId2], closeNote: "Đóng nhóm ca sáng" },
        officerA,
        ROLES.SAFETY_OFFICER,
        { id: officerA, role: ROLES.SAFETY_OFFICER, siteId: siteA },
      );

      assert.strictEqual(officerRes.closedCount, 1);
      assert.deepStrictEqual(officerRes.closedIds, [incId1]);
      assert.deepStrictEqual(officerRes.skippedIds, [incId2]);
      assert.deepStrictEqual(capturedWhere.assignments, {
        some: { assignedTo: officerA, status: ASSIGNMENT_STATUS.ACTIVE },
      });
      assert.strictEqual(createdOutbox.length, 1);
      assert.strictEqual(
        createdOutbox[0].eventType,
        INCIDENT_OUTBOX_EVENT.STATUS_CHANGED,
      );

      // AC #4: CLOSED incident cannot be deleted
      await assert.rejects(
        () => service.deleteIncident(incId1, userSiteA),
        (err: AppError) =>
          err.statusCode === 400 && err.code === ERROR_CODE.BAD_REQUEST,
      );
    });
  });
});
