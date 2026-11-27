import { describe, it, before, after, mock } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import type http from "node:http";
import type { AddressInfo } from "node:net";
import jwt from "jsonwebtoken";
import incidentApp from "../src/incident.app";
import { incidentPrisma } from "../src/database/incident.client";
import { envConfig } from "../src/config/env.config";
import { jwtConfig } from "../src/config/jwt.config";
import { GATEWAY_HEADERS } from "../src/common/constants/gateway.constant";
import { JWT_ALGORITHM, JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { ROLES } from "../src/common/constants/role.constant";
import {
  EVIDENCE_ACCESS_ACTION,
  EVIDENCE_LIFECYCLE_FILTER,
  EVIDENCE_TYPE,
  INCIDENT_SEVERITY,
  INCIDENT_STATUS,
  VIOLATION_TYPE,
} from "../src/common/constants/incident.constant";
import { EvidenceStorageService } from "../src/common/services/evidence-storage.service";
import { IncidentController } from "../src/modules/incident/incident.controller";
import { IncidentRepository } from "../src/modules/incident/incident.repository";
import { evidenceRouter } from "../src/modules/incident/incident.route";
import { IncidentService } from "../src/modules/incident/incident.service";
import {
  batchDeleteEvidencesSchema,
  evidenceAccessLogsQuerySchema,
  evidenceQuerySchema,
  evidenceSummaryQuerySchema,
} from "../src/modules/incident/incident.validation";
import { buildOpenApiSpec } from "../src/config/openapi/openapi.registry";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";

describe("Issue #3: Evidence Fail-Closed BOLA, Server-Side Filters, Summary, Access Logs & Storage URL", () => {
  const siteA = "11111111-1111-4111-8111-111111111111";
  const siteB = "22222222-2222-4222-8222-222222222222";
  const camA = "33333333-3333-4333-8333-333333333333";
  const incA = "44444444-4444-4444-8444-444444444444";
  const evA = "55555555-5555-4555-8555-555555555555";
  const evClosed = "66666666-6666-4666-8666-666666666666";
  const actorId = "77777777-7777-4777-8777-777777777777";

  describe("1. Zod Schemas, Constants & Route Ordering", () => {
    it("defines VERIFY and DELETE actions and EVIDENCE_LIFECYCLE_FILTER constants", () => {
      assert.equal(EVIDENCE_ACCESS_ACTION.VERIFY, "VERIFY");
      assert.equal(EVIDENCE_ACCESS_ACTION.DELETE, "DELETE");
      assert.equal(EVIDENCE_LIFECYCLE_FILTER.ACTIVE, "ACTIVE");
      assert.equal(EVIDENCE_LIFECYCLE_FILTER.OPEN, "OPEN");
      assert.equal(EVIDENCE_LIFECYCLE_FILTER.ARCHIVED, "ARCHIVED");
    });

    it("validates expanded evidenceQuerySchema, evidenceSummaryQuerySchema, evidenceAccessLogsQuerySchema & batchDeleteEvidencesSchema", () => {
      const q = evidenceQuerySchema.safeParse({
        siteId: siteA,
        cameraIds: `${camA}`,
        search: "helmet",
        violationType: VIOLATION_TYPE.NO_HELMET,
        incidentStatus: INCIDENT_STATUS.CONFIRMED,
        lifecycle: EVIDENCE_LIFECYCLE_FILTER.ACTIVE,
        hasChecksum: "true",
        fromDate: "2026-11-01T00:00:00.000Z",
        toDate: "2026-11-27T23:59:59.000Z",
        sortBy: "fileSize",
        sortOrder: "asc",
      });
      assert.equal(q.success, true);
      if (q.success) {
        assert.equal(q.data.siteId, siteA);
        assert.deepEqual(q.data.cameraIds, [camA]);
        assert.equal(q.data.hasChecksum, true);
        assert.equal(q.data.sortBy, "fileSize");
      }

      const sq = evidenceSummaryQuerySchema.safeParse({
        siteId: siteA,
        lifecycle: EVIDENCE_LIFECYCLE_FILTER.ARCHIVED,
        hasChecksum: "false",
      });
      assert.equal(sq.success, true);

      const logQ = evidenceAccessLogsQuerySchema.safeParse({
        page: 1,
        limit: 10,
        action: EVIDENCE_ACCESS_ACTION.VERIFY,
      });
      assert.equal(logQ.success, true);

      const emptyBatch = batchDeleteEvidencesSchema.safeParse({ ids: [] });
      assert.equal(emptyBatch.success, false);
      const validBatch = batchDeleteEvidencesSchema.safeParse({
        ids: [evA, evClosed],
      });
      assert.equal(validBatch.success, true);
    });

    it("mounts /summary and /batch-delete BEFORE /:id on evidenceRouter and registers OpenAPI paths", () => {
      const routePaths = (evidenceRouter as any).stack
        .filter((layer: any) => layer.route)
        .map((layer: any) => layer.route.path);

      const summaryIdx = routePaths.indexOf("/summary");
      const batchDelIdx = routePaths.indexOf("/batch-delete");
      const idIdx = routePaths.indexOf("/:id");
      const logsIdx = routePaths.indexOf("/:id/access-logs");

      assert.ok(summaryIdx !== -1 && idIdx !== -1 && summaryIdx < idIdx);
      assert.ok(batchDelIdx !== -1 && batchDelIdx < idIdx);
      assert.ok(logsIdx !== -1);

      const spec = buildOpenApiSpec() as any;
      assert.ok(spec.paths["/evidences/summary"]?.get);
      assert.ok(spec.paths["/evidences/batch-delete"]?.post);
      assert.ok(spec.paths["/evidences/{id}/access-logs"]?.get);
    });
  });

  describe("2. Presigned URL Public Endpoint Signing", () => {
    it("signs upload & download presigned URLs with publicEndpoint host instead of internal MinIO host", async () => {
      const storage = new EvidenceStorageService(undefined, "ppe-evidences", {
        endpoint: "http://ppe-minio:9000",
        publicEndpoint: "https://storage.smartppe.local",
        accessKeyId: "minio_admin",
        secretAccessKey: "minio_admin_secret",
        forcePathStyle: true,
      });

      const key = `evidences/${siteA}/${camA}/2026/11/27/${incA}/SNAPSHOT_1.jpg`;
      const uploadUrl = await storage.getPresignedUploadUrl(
        key,
        "image/jpeg",
        300,
      );
      const downloadUrl = await storage.getPresignedDownloadUrl(
        key,
        300,
        "snap.jpg",
        EVIDENCE_ACCESS_ACTION.VIEW,
      );

      const upParsed = new URL(uploadUrl);
      const downParsed = new URL(downloadUrl);
      assert.equal(upParsed.origin, "https://storage.smartppe.local");
      assert.equal(downParsed.origin, "https://storage.smartppe.local");
      assert.ok(upParsed.searchParams.get("X-Amz-Signature"));
      assert.ok(downParsed.searchParams.get("X-Amz-Signature"));
    });
  });

  describe("3. Fail-Closed BOLA, Closed Guard, Audit Trail & Controller Hardening", () => {
    it("getEvidenceById fails CLOSED when non-admin user has NO assigned sites", async () => {
      const mockRepo = {
        findEvidenceById: mock.fn(async () => ({
          id: evA,
          storageKey: `evidences/${siteA}/${camA}/snap.jpg`,
          incident: { id: incA, siteId: siteA, status: INCIDENT_STATUS.CONFIRMED },
        })),
      } as any;
      const service = new IncidentService(mockRepo);

      await assert.rejects(
        () =>
          service.getEvidenceById(evA, actorId, {
            id: actorId,
            role: ROLES.SAFETY_OFFICER,
            siteIds: [],
          }),
        (err: AppError) =>
          err.statusCode === 403 && err.code === ERROR_CODE.FORBIDDEN,
      );
    });

    it("getAllEvidences & getEvidencesSummary fail CLOSED for non-admin with empty sites or unauthorized siteId", async () => {
      let repoCalled = false;
      const mockRepo = {
        findAllEvidences: async () => {
          repoCalled = true;
          return { data: [], meta: { total: 0, page: 1, limit: 20, totalPages: 0 } };
        },
        getEvidencesSummary: async () => {
          repoCalled = true;
          return {
            total: 99,
            byType: { SNAPSHOT: 99, REFERENCE_SNAPSHOT: 0, VIDEO_CLIP: 0 },
            totalBytes: 1000,
            withChecksumCount: 99,
          };
        },
      } as any;
      const service = new IncidentService(mockRepo);

      const emptyList = await service.getAllEvidences(
        {},
        { id: actorId, role: ROLES.SAFETY_OFFICER, siteIds: [] },
      );
      assert.equal(emptyList.meta.total, 0);
      assert.equal(repoCalled, false);

      const crossSiteSummary = await service.getEvidencesSummary(
        { siteId: siteB },
        { id: actorId, role: ROLES.SAFETY_MANAGER, siteIds: [siteA] },
      );
      assert.equal(crossSiteSummary.total, 0);
      assert.equal(crossSiteSummary.totalBytes, 0);
      assert.equal(repoCalled, false);
    });

    it("verifyEvidenceIntegrity logs VERIFY, deleteEvidence blocks CLOSED incident & logs DELETE", async () => {
      const accessLogs: Array<{ evidenceId: string; userId: string; action: string }> = [];
      let deletedId = "";
      let deletedKey = "";

      const mockRepo = {
        findEvidenceById: async (id: string) => {
          if (id === evClosed) {
            return {
              id: evClosed,
              storageKey: `evidences/${siteA}/${camA}/closed.jpg`,
              incident: { id: incA, siteId: siteA, status: INCIDENT_STATUS.CLOSED },
            };
          }
          return {
            id: evA,
            storageKey: `evidences/${siteA}/${camA}/open.jpg`,
            metadata: { checksum: "abc123" },
            incident: { id: incA, siteId: siteA, status: INCIDENT_STATUS.CONFIRMED },
          };
        },
        logEvidenceAccess: async (entry: any) => {
          accessLogs.push(entry);
        },
        deleteEvidence: async (id: string) => {
          deletedId = id;
          return { id };
        },
      } as any;
      const mockStorage = {
        verifyChecksum: async () => ({
          isValid: true,
          actualChecksum: "abc123",
          expectedChecksum: "abc123",
        }),
        deleteObject: async (k: string) => {
          deletedKey = k;
        },
      } as any;

      const service = new IncidentService(mockRepo, mockStorage);

      const verifyRes = await service.verifyEvidenceIntegrity(evA, {
        id: actorId,
        role: ROLES.SAFETY_MANAGER,
        siteIds: [siteA],
      });
      assert.equal(verifyRes.isValid, true);
      await new Promise((r) => setTimeout(r, 10));
      assert.equal(accessLogs.length, 1);
      assert.equal(accessLogs[0].action, EVIDENCE_ACCESS_ACTION.VERIFY);
      assert.equal(accessLogs[0].userId, actorId);

      // Block delete when incident is CLOSED
      await assert.rejects(
        () =>
          service.deleteEvidence(evClosed, {
            id: actorId,
            role: ROLES.ADMIN,
          }),
        (err: AppError) =>
          err.statusCode === 400 && err.code === ERROR_CODE.BAD_REQUEST,
      );
      assert.equal(deletedId, "");

      // Allow delete when open and site matches, logging DELETE
      await service.deleteEvidence(evA, {
        id: actorId,
        role: ROLES.SAFETY_MANAGER,
        siteIds: [siteA],
      });
      assert.equal(deletedId, evA);
      assert.equal(deletedKey, `evidences/${siteA}/${camA}/open.jpg`);
      assert.equal(accessLogs[1].action, EVIDENCE_ACCESS_ACTION.DELETE);
    });

    it("batchDeleteEvidences respects site-scoping and skips CLOSED incidents", async () => {
      const deletedDbIds: string[] = [];
      const deletedStorageKeys: string[] = [];
      const accessLogs: any[] = [];

      const mockRepo = {
        findEvidencesByIds: async () => [
          {
            id: evA,
            storageKey: `evidences/${siteA}/${camA}/a.jpg`,
            incident: { id: incA, siteId: siteA, status: INCIDENT_STATUS.CONFIRMED },
          },
          {
            id: evClosed,
            storageKey: `evidences/${siteA}/${camA}/closed.jpg`,
            incident: { id: incA, siteId: siteA, status: INCIDENT_STATUS.CLOSED },
          },
          {
            id: "88888888-8888-4888-8888-888888888888",
            storageKey: `evidences/${siteB}/${camA}/b.jpg`,
            incident: { id: "inc-b", siteId: siteB, status: INCIDENT_STATUS.CONFIRMED },
          },
        ],
        logEvidenceAccess: async (entry: any) => {
          accessLogs.push(entry);
        },
        deleteEvidencesByIds: async (ids: string[]) => {
          deletedDbIds.push(...ids);
          return ids.length;
        },
      } as any;
      const mockStorage = {
        deleteObject: async (k: string) => {
          deletedStorageKeys.push(k);
        },
      } as any;

      const service = new IncidentService(mockRepo, mockStorage);
      const res = await service.batchDeleteEvidences(
        {
          ids: [
            evA,
            evClosed,
            "88888888-8888-4888-8888-888888888888",
            "99999999-9999-4999-8999-999999999999",
          ],
        },
        { id: actorId, role: ROLES.SAFETY_MANAGER, siteIds: [siteA] },
      );

      assert.equal(res.total, 4);
      assert.equal(res.deletedCount, 1);
      assert.deepEqual(res.deletedIds, [evA]);
      assert.equal(res.skippedIds.length, 3);
      assert.deepEqual(deletedDbIds, [evA]);
      assert.deepEqual(deletedStorageKeys, [`evidences/${siteA}/${camA}/a.jpg`]);
      assert.equal(accessLogs.length, 1);
      assert.equal(accessLogs[0].action, EVIDENCE_ACCESS_ACTION.DELETE);
    });

    it("IncidentController passes req.user to getAllEvidences/deleteEvidence and ignores spoofed x-site-id header", async () => {
      let capturedListUser: any;
      let capturedGetUser: any;
      let capturedDownloadUser: any;
      let capturedVerifyUser: any;
      let capturedDeleteUser: any;

      const mockService = {
        getAllEvidences: async (_q: any, user: any) => {
          capturedListUser = user;
          return { data: [], meta: { total: 0, page: 1, limit: 20, totalPages: 0 } };
        },
        getEvidenceById: async (id: string, _actorId: any, user: any) => {
          capturedGetUser = user;
          return { id };
        },
        getEvidenceDownloadUrl: async (_id: any, _actorId: any, _exp: any, _act: any, user: any) => {
          capturedDownloadUser = user;
          return { downloadUrl: "https://example.com" };
        },
        verifyEvidenceIntegrity: async (_id: any, user: any) => {
          capturedVerifyUser = user;
          return { isValid: true };
        },
        deleteEvidence: async (id: string, user: any) => {
          capturedDeleteUser = user;
          return { id };
        },
      };

      const controller = new IncidentController(mockService as any);
      const tokenUser = {
        id: actorId,
        role: ROLES.SAFETY_OFFICER,
        siteId: siteA,
        siteIds: [siteA],
      };
      const req: any = {
        params: { id: evA },
        query: {},
        user: tokenUser,
        headers: {
          "x-site-id": siteB,
        },
      };
      const res: any = { json: () => {} };
      const noop = () => {};

      await controller.findAllEvidences(req, res, noop);
      await controller.findEvidenceById(req, res, noop);
      await controller.getEvidenceDownloadUrl(req, res, noop);
      await controller.verifyEvidenceIntegrity(req, res, noop);
      await controller.deleteEvidence(req, res, noop);

      assert.strictEqual(capturedListUser, tokenUser);
      assert.strictEqual(capturedGetUser, tokenUser);
      assert.strictEqual(capturedDownloadUser, tokenUser);
      assert.strictEqual(capturedVerifyUser, tokenUser);
      assert.strictEqual(capturedDeleteUser, tokenUser);
      assert.equal(capturedGetUser.siteId, siteA);
    });
  });

  describe("4. IncidentRepository Filtering & Summary Aggregation", () => {
    it("findAllEvidences builds incident relation filters, checksum filter, search filter and includes compact incident", async () => {
      let capturedFindManyArgs: any;
      let capturedCountArgs: any;
      const mockDb = {
        evidence: {
          count: async (args: any) => {
            capturedCountArgs = args;
            return 1;
          },
          findMany: async (args: any) => {
            capturedFindManyArgs = args;
            return [
              {
                id: evA,
                incidentId: incA,
                cameraId: camA,
                evidenceType: EVIDENCE_TYPE.SNAPSHOT,
                storageKey: `evidences/${siteA}/${camA}/snap.jpg`,
                fileName: "snap.jpg",
                mimeType: "image/jpeg",
                fileSize: BigInt(2048),
                capturedAt: new Date(),
                createdAt: new Date(),
                metadata: { checksum: "sha256hex" },
                incident: {
                  id: incA,
                  siteId: siteA,
                  cameraId: camA,
                  violationType: VIOLATION_TYPE.NO_HELMET,
                  severity: INCIDENT_SEVERITY.HIGH,
                  status: INCIDENT_STATUS.CONFIRMED,
                  detectedAt: new Date(),
                },
              },
            ];
          },
        },
      };

      const repo = new IncidentRepository(mockDb as any);
      const res = await repo.findAllEvidences(
        {
          siteId: siteA,
          violationType: VIOLATION_TYPE.NO_HELMET,
          lifecycle: EVIDENCE_LIFECYCLE_FILTER.ACTIVE,
          hasChecksum: true,
          search: "snap",
          fromDate: "2026-11-01T00:00:00.000Z",
        },
        [siteA],
      );

      assert.equal(res.meta.total, 1);
      assert.equal(res.data[0].fileSize, 2048);
      assert.equal(res.data[0].incident.siteId, siteA);
      assert.ok(capturedFindManyArgs.include.incident.select.status);
      assert.deepEqual(capturedCountArgs.where.incident, {
        is: { siteId: siteA, violationType: VIOLATION_TYPE.NO_HELMET },
      });
      assert.ok(Array.isArray(capturedCountArgs.where.AND));
      assert.equal(capturedCountArgs.where.AND.length, 3);
    });

    it("getEvidencesSummary aggregates totals, byType breakdown, BigInt totalBytes & withChecksumCount", async () => {
      const mockDb = {
        evidence: {
          aggregate: async () => ({
            _count: { _all: 5 },
            _sum: { fileSize: BigInt(1048576) },
          }),
          groupBy: async () => [
            { evidenceType: EVIDENCE_TYPE.SNAPSHOT, _count: { _all: 3 } },
            { evidenceType: EVIDENCE_TYPE.VIDEO_CLIP, _count: { _all: 2 } },
          ],
          count: async () => 4,
        },
      };

      const repo = new IncidentRepository(mockDb as any);
      const summary = await repo.getEvidencesSummary({ siteId: siteA }, [siteA]);
      assert.deepEqual(summary, {
        total: 5,
        byType: {
          SNAPSHOT: 3,
          REFERENCE_SNAPSHOT: 0,
          VIDEO_CLIP: 2,
        },
        totalBytes: 1048576,
        withChecksumCount: 4,
      });
    });
  });

  describe("5. Live HTTP + PostgreSQL (ppe_incident_db) Integration Tests", () => {
    let dbAvailable = false;
    let server: http.Server | null = null;
    let baseUrl = "";
    const originalPublicKey = jwtConfig.publicKey;
    let privateKey = "";
    const createdIncidentIds: string[] = [];

    const liveSiteA = "aaaaaaaa-0000-4000-8000-000000000011";
    const liveSiteB = "bbbbbbbb-0000-4000-8000-000000000022";
    const liveCamA = "cccccccc-0000-4000-8000-000000000033";
    const liveUserId = "dddddddd-0000-4000-8000-000000000044";
    const suffix = crypto.randomBytes(4).toString("hex");

    function signToken(claims: Record<string, unknown>): string {
      return jwt.sign(
        {
          id: liveUserId,
          email: `issue3-${suffix}@smartppe.local`,
          purpose: JWT_PURPOSE.ACCESS,
          mustChangePassword: false,
          ...claims,
        },
        privateKey,
        { algorithm: JWT_ALGORITHM.RS256, expiresIn: "10m" },
      );
    }

    async function requestApi(
      method: "GET" | "POST" | "DELETE",
      path: string,
      token: string,
      body?: unknown,
      extraHeaders: Record<string, string> = {},
    ) {
      const headers: Record<string, string> = {
        authorization: `Bearer ${token}`,
        ...extraHeaders,
      };
      if (envConfig.gateway.internalSecret) {
        headers[GATEWAY_HEADERS.INTERNAL_SECRET] =
          envConfig.gateway.internalSecret;
      }
      if (body !== undefined) {
        headers["content-type"] = "application/json";
      }
      const res = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      const text = await res.text();
      return {
        status: res.status,
        body: text ? JSON.parse(text) : null,
      };
    }

    before(async () => {
      try {
        await incidentPrisma.$queryRaw`SELECT 1`;
        dbAvailable = true;
      } catch {
        dbAvailable = false;
        return;
      }

      const pair = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      privateKey = pair.privateKey;
      (jwtConfig as any).publicKey = pair.publicKey;

      server = await new Promise<http.Server>((resolve) => {
        const s = incidentApp.listen(0, "127.0.0.1", () => resolve(s));
      });
      const addr = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${addr.port}`;
    });

    after(async () => {
      try {
        if (dbAvailable && createdIncidentIds.length > 0) {
          await incidentPrisma.incident
            .deleteMany({ where: { id: { in: createdIncidentIds } } })
            .catch(() => {});
        }
      } finally {
        (jwtConfig as any).publicKey = originalPublicKey;
        if (server) {
          await new Promise<void>((resolve) => {
            server!.close(() => resolve());
          });
        }
        await incidentPrisma.$disconnect().catch(() => {});
      }
    });

    it("enforces fail-closed site scoping, filters, summary, access-logs and CLOSED delete guard end-to-end on ppe_incident_db", async (t) => {
      if (!dbAvailable) {
        t.skip("PostgreSQL ppe_incident_db is unavailable");
        return;
      }

      const incOpenA = await incidentPrisma.incident.create({
        data: {
          siteId: liveSiteA,
          cameraId: liveCamA,
          violationType: VIOLATION_TYPE.NO_HELMET,
          severity: INCIDENT_SEVERITY.HIGH,
          status: INCIDENT_STATUS.CONFIRMED,
          detectedAt: new Date("2026-11-20T10:00:00.000Z"),
          description: `Issue3 open site A ${suffix}`,
        },
      });
      const incClosedA = await incidentPrisma.incident.create({
        data: {
          siteId: liveSiteA,
          cameraId: liveCamA,
          violationType: VIOLATION_TYPE.NO_VEST,
          severity: INCIDENT_SEVERITY.MEDIUM,
          status: INCIDENT_STATUS.CLOSED,
          detectedAt: new Date("2026-11-21T10:00:00.000Z"),
          description: `Issue3 closed site A ${suffix}`,
        },
      });
      const incSiteB = await incidentPrisma.incident.create({
        data: {
          siteId: liveSiteB,
          cameraId: liveCamA,
          violationType: VIOLATION_TYPE.NO_HELMET,
          severity: INCIDENT_SEVERITY.CRITICAL,
          status: INCIDENT_STATUS.CONFIRMED,
          detectedAt: new Date("2026-11-22T10:00:00.000Z"),
          description: `Issue3 site B ${suffix}`,
        },
      });
      createdIncidentIds.push(incOpenA.id, incClosedA.id, incSiteB.id);

      const evOpenA = await incidentPrisma.evidence.create({
        data: {
          incidentId: incOpenA.id,
          cameraId: liveCamA,
          evidenceType: EVIDENCE_TYPE.SNAPSHOT,
          storageKey: `evidences/${liveSiteA}/${liveCamA}/open_${suffix}.jpg`,
          fileName: `open_${suffix}.jpg`,
          mimeType: "image/jpeg",
          fileSize: BigInt(12000),
          capturedAt: new Date("2026-11-20T10:00:00.000Z"),
          metadata: {
            create: {
              checksum: `chk_${suffix}`,
            },
          },
        },
      });
      const evClosedA = await incidentPrisma.evidence.create({
        data: {
          incidentId: incClosedA.id,
          cameraId: liveCamA,
          evidenceType: EVIDENCE_TYPE.VIDEO_CLIP,
          storageKey: `evidences/${liveSiteA}/${liveCamA}/closed_${suffix}.mp4`,
          fileName: `closed_${suffix}.mp4`,
          mimeType: "video/mp4",
          fileSize: BigInt(45000),
          capturedAt: new Date("2026-11-21T10:00:00.000Z"),
        },
      });
      const evSiteB = await incidentPrisma.evidence.create({
        data: {
          incidentId: incSiteB.id,
          cameraId: liveCamA,
          evidenceType: EVIDENCE_TYPE.SNAPSHOT,
          storageKey: `evidences/${liveSiteB}/${liveCamA}/secret_${suffix}.jpg`,
          fileName: `secret_${suffix}.jpg`,
          mimeType: "image/jpeg",
          fileSize: BigInt(99000),
          capturedAt: new Date("2026-11-22T10:00:00.000Z"),
        },
      });

      const noSiteToken = signToken({
        role: ROLES.SAFETY_OFFICER,
        siteIds: [],
        permissions: [
          PERMISSIONS.PPE_INCIDENT_READ,
          PERMISSIONS.PPE_INCIDENT_DELETE,
        ],
      });
      const siteAToken = signToken({
        role: ROLES.SAFETY_MANAGER,
        siteIds: [liveSiteA],
        permissions: [
          PERMISSIONS.PPE_INCIDENT_READ,
          PERMISSIONS.PPE_INCIDENT_DELETE,
        ],
      });

      // 1. User with NO sites fails closed on list, summary, detail, delete (even with spoofed x-site-id)
      const noSiteList = await requestApi(
        "GET",
        `/api/v1/evidences?search=${suffix}`,
        noSiteToken,
        undefined,
        { "x-site-id": liveSiteA },
      );
      assert.strictEqual(noSiteList.status, 200);
      assert.strictEqual(noSiteList.body.meta.total, 0);

      const noSiteSummary = await requestApi(
        "GET",
        `/api/v1/evidences/summary?search=${suffix}`,
        noSiteToken,
      );
      assert.strictEqual(noSiteSummary.status, 200);
      assert.strictEqual(noSiteSummary.body.data.total, 0);

      const noSiteGet = await requestApi(
        "GET",
        `/api/v1/evidences/${evOpenA.id}`,
        noSiteToken,
        undefined,
        { "x-site-id": liveSiteA },
      );
      assert.strictEqual(noSiteGet.status, 403);

      // 2. Site A manager sees only Site A evidences with compact incident & filter support
      const siteAList = await requestApi(
        "GET",
        `/api/v1/evidences?search=${suffix}&hasChecksum=true`,
        siteAToken,
      );
      assert.strictEqual(siteAList.status, 200);
      assert.strictEqual(siteAList.body.meta.total, 1);
      assert.strictEqual(siteAList.body.data[0].id, evOpenA.id);
      assert.strictEqual(siteAList.body.data[0].incident.siteId, liveSiteA);
      assert.strictEqual(
        siteAList.body.data[0].incident.violationType,
        VIOLATION_TYPE.NO_HELMET,
      );

      // Summary for Site A includes both evOpenA + evClosedA, excludes evSiteB
      const siteASummary = await requestApi(
        "GET",
        `/api/v1/evidences/summary?search=${suffix}`,
        siteAToken,
      );
      assert.strictEqual(siteASummary.status, 200);
      assert.strictEqual(siteASummary.body.data.total, 2);
      assert.strictEqual(siteASummary.body.data.byType.SNAPSHOT, 1);
      assert.strictEqual(siteASummary.body.data.byType.VIDEO_CLIP, 1);
      assert.strictEqual(siteASummary.body.data.totalBytes, 57000);
      assert.strictEqual(siteASummary.body.data.withChecksumCount, 1);

      // Cross-site detail & delete on Site B fail with 403
      const crossDetail = await requestApi(
        "GET",
        `/api/v1/evidences/${evSiteB.id}`,
        siteAToken,
      );
      assert.strictEqual(crossDetail.status, 403);

      const crossDelete = await requestApi(
        "DELETE",
        `/api/v1/evidences/${evSiteB.id}`,
        siteAToken,
      );
      assert.strictEqual(crossDelete.status, 403);

      // View open evidence logs VIEW action retrievable via GET /:id/access-logs
      const viewOpen = await requestApi(
        "GET",
        `/api/v1/evidences/${evOpenA.id}`,
        siteAToken,
      );
      assert.strictEqual(viewOpen.status, 200);
      await new Promise((r) => setTimeout(r, 50));

      const logsRes = await requestApi(
        "GET",
        `/api/v1/evidences/${evOpenA.id}/access-logs`,
        siteAToken,
      );
      assert.strictEqual(logsRes.status, 200);
      assert.ok(
        logsRes.body.data.some(
          (l: any) =>
            l.action === EVIDENCE_ACCESS_ACTION.VIEW && l.userId === liveUserId,
        ),
      );

      // Delete CLOSED evidence blocked with 400
      const deleteClosed = await requestApi(
        "DELETE",
        `/api/v1/evidences/${evClosedA.id}`,
        siteAToken,
      );
      assert.strictEqual(deleteClosed.status, 400);

      // Batch delete skips evClosedA and evSiteB, deletes only evOpenA
      const batchRes = await requestApi(
        "POST",
        "/api/v1/evidences/batch-delete",
        siteAToken,
        { ids: [evOpenA.id, evClosedA.id, evSiteB.id] },
      );
      assert.strictEqual(batchRes.status, 200);
      assert.strictEqual(batchRes.body.data.deletedCount, 1);
      assert.deepEqual(batchRes.body.data.deletedIds, [evOpenA.id]);
      assert.deepEqual(batchRes.body.data.skippedIds.sort(), [
        evClosedA.id,
        evSiteB.id,
      ].sort());
    });
  });
});
