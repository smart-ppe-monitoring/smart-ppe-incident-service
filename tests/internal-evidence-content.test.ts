import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { incidentRouter } from "../src/modules/incident/incident.route";
import { requireInternalServiceToken } from "../src/middlewares/internal-auth.middleware";
import { IncidentService } from "../src/modules/incident/incident.service";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";

describe("Internal M2M Evidence Binary Endpoint (/internal/evidences/:id/content)", () => {
  it("mounts GET /internal/evidences/:id/content BEFORE /:id and enforces requireInternalServiceToken", () => {
    const stack = (incidentRouter as any).stack || [];
    const internalContentIdx = stack.findIndex(
      (layer: any) =>
        layer.route?.path === "/internal/evidences/:id/content" &&
        layer.route?.methods?.get,
    );
    const paramIdIdx = stack.findIndex(
      (layer: any) => layer.route?.path === "/:id" && layer.route?.methods?.get,
    );

    assert.ok(internalContentIdx >= 0, "Route /internal/evidences/:id/content must be mounted");
    assert.ok(paramIdIdx >= 0, "Route /:id must exist");
    assert.ok(
      internalContentIdx < paramIdIdx,
      "Internal evidence content route must be registered BEFORE /:id",
    );

    const routeLayer = stack[internalContentIdx];
    const hasInternalGuard = routeLayer.route.stack.some(
      (s: any) => s.handle === requireInternalServiceToken,
    );
    assert.equal(hasInternalGuard, true);
  });

  it("returns buffer for raster image evidence, enforces incidentId match (anti-BOLA), rejects SVG, and checks fileSize before downloading", async () => {
    const sampleBuffer = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);
    const validIncidentId = "22222222-2222-4222-8222-222222222222";
    const otherIncidentId = "33333333-3333-4333-8333-333333333333";
    let getObjectBufferCalls = 0;

    let currentRecord: any = {
      id: "11111111-1111-4111-8111-111111111111",
      incidentId: validIncidentId,
      storageKey: "evidences/site/cam/inc/snapshot.jpg",
      fileName: "snapshot.jpg",
      mimeType: "image/jpeg",
      fileSize: sampleBuffer.length,
    };
    let currentBuffer: Buffer = sampleBuffer;

    const svc = new IncidentService(
      {
        findEvidenceById: async () => currentRecord,
      } as any,
      {
        getObjectBuffer: async () => {
          getObjectBufferCalls++;
          return currentBuffer;
        },
      } as any,
    );

    const ok = await svc.getEvidenceBinaryForInternal(
      "11111111-1111-4111-8111-111111111111",
      validIncidentId,
    );
    assert.equal(ok.mimeType, "image/jpeg");
    assert.equal(ok.fileName, "snapshot.jpg");
    assert.deepEqual(ok.buffer, sampleBuffer);
    assert.equal(getObjectBufferCalls, 1);

    // Cross-incident BOLA rejected with 403 BEFORE downloading from MinIO
    await assert.rejects(
      () =>
        svc.getEvidenceBinaryForInternal(
          "11111111-1111-4111-8111-111111111111",
          otherIncidentId,
        ),
      (err: any) =>
        err instanceof AppError &&
        err.statusCode === 403 &&
        err.code === ERROR_CODE.FORBIDDEN,
    );
    assert.equal(getObjectBufferCalls, 1);

    // Non-image & SVG rejected
    for (const badMime of ["video/mp4", "image/svg+xml"]) {
      currentRecord = { ...currentRecord, mimeType: badMime };
      await assert.rejects(
        () =>
          svc.getEvidenceBinaryForInternal(
            "11111111-1111-4111-8111-111111111111",
            validIncidentId,
          ),
        (err: any) =>
          err instanceof AppError &&
          err.statusCode === 400 &&
          err.code === ERROR_CODE.VALIDATION_ERROR,
      );
    }
    assert.equal(getObjectBufferCalls, 1);

    // Oversized fileSize (>10MB) rejected BEFORE calling getObjectBuffer
    currentRecord = {
      ...currentRecord,
      mimeType: "image/png",
      fileSize: 10 * 1024 * 1024 + 1,
    };
    await assert.rejects(
      () =>
        svc.getEvidenceBinaryForInternal(
          "11111111-1111-4111-8111-111111111111",
          validIncidentId,
        ),
      (err: any) =>
        err instanceof AppError &&
        err.statusCode === 400 &&
        err.code === ERROR_CODE.VALIDATION_ERROR,
    );
    assert.equal(getObjectBufferCalls, 1, "Must not download object when DB fileSize > 10MB");

    // Actual buffer >10MB when DB fileSize=0 is still rejected post-download
    currentRecord = { ...currentRecord, fileSize: 0 };
    currentBuffer = Buffer.alloc(10 * 1024 * 1024 + 1, 1);
    await assert.rejects(
      () =>
        svc.getEvidenceBinaryForInternal(
          "11111111-1111-4111-8111-111111111111",
          validIncidentId,
        ),
      (err: any) =>
        err instanceof AppError &&
        err.statusCode === 400 &&
        err.code === ERROR_CODE.VALIDATION_ERROR,
    );

    // Missing evidence -> 404
    currentRecord = null;
    await assert.rejects(
      () =>
        svc.getEvidenceBinaryForInternal(
          "11111111-1111-4111-8111-111111111111",
          validIncidentId,
        ),
      (err: any) =>
        err instanceof AppError &&
        err.statusCode === 404 &&
        err.code === ERROR_CODE.EVIDENCE_NOT_FOUND,
    );
  });
});
