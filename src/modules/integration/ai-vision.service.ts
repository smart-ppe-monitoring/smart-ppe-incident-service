import crypto from "node:crypto";
import path from "node:path";
import {
  IncidentService,
  incidentService,
} from "../incident/incident.service";
import { SYSTEM_ACTOR_UUID } from "../incident/incident.repository";
import { CreateIncidentDto } from "../incident/incident.dto";
import {
  VIOLATION_TYPE,
  ViolationType,
  INCIDENT_SEVERITY,
  IncidentSeverity,
  INCIDENT_STATUS,
  EVIDENCE_TYPE,
} from "../../common/constants/incident.constant";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";
import { isUuid } from "../../common/helpers/uuid.helper";
import {
  AiVisionEventInput,
  AiVisionViolationPayload,
} from "./ai-vision.validation";
import {
  CameraIdentity,
  CameraLookupClient,
  cameraLookupClient,
} from "./camera-lookup.client";

export interface BatchIngestResult {
  total: number;
  succeeded: number;
  failed: number;
  results: Array<{ index: number; incidentId: string; status: string }>;
  errors: Array<{ index: number; error: string }>;
}

const SEVERITY_RANK: Record<IncidentSeverity, number> = {
  [INCIDENT_SEVERITY.LOW]: 1,
  [INCIDENT_SEVERITY.MEDIUM]: 2,
  [INCIDENT_SEVERITY.HIGH]: 3,
  [INCIDENT_SEVERITY.CRITICAL]: 4,
};

/**
 * Chuyển đổi chuỗi bất kỳ sang UUID v5 tất định để đảm bảo idempotency ở mức CSDL PostgreSQL.
 */
export function deriveDeterministicUuid(raw: string): string {
  if (isUuid(raw)) {
    return raw.toLowerCase();
  }
  const bytes = crypto.createHash("sha256").update(raw).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/**
 * Trích xuất objectKey hợp lệ (`evidences/...`) từ objectKey tường minh hoặc MinIO URL.
 */
export function resolveEvidenceStorageKey(
  explicitKey: string | null | undefined,
  url: string | null | undefined,
  fallbackSiteId: string,
  fallbackCameraCode: string,
  suffixName: string,
): string {
  const cleanExplicit = (explicitKey || "").trim();
  if (
    cleanExplicit.startsWith("evidences/") &&
    !cleanExplicit.includes("..") &&
    !cleanExplicit.includes("//")
  ) {
    return cleanExplicit;
  }

  const rawUrl = (url || "").trim();
  if (rawUrl) {
    let pathname = rawUrl;
    try {
      pathname = decodeURIComponent(new URL(rawUrl).pathname);
    } catch {
      pathname = rawUrl.split("?")[0] || rawUrl;
    }
    const match = pathname.match(/(?:^|\/)(evidences\/.+)$/);
    if (match && match[1]) {
      const candidate = match[1].replace(/^\/+/, "");
      if (!candidate.includes("..") && !candidate.includes("//")) {
        return candidate;
      }
    }
  }

  const safeCam = fallbackCameraCode.replace(/[^A-Za-z0-9_-]/g, "") || "CAM";
  return `evidences/${fallbackSiteId}/${safeCam}/${suffixName}`;
}

export function normalizeBoundingBox(
  box: { x: number; y: number; width: number; height: number } | null | undefined,
  frameWidth: number,
  frameHeight: number,
) {
  if (!box) return undefined;
  const isNormalized =
    box.x <= 1.0 && box.y <= 1.0 && box.width <= 1.0 && box.height <= 1.0;

  if (isNormalized || frameWidth <= 0 || frameHeight <= 0) {
    return {
      x: Math.max(0, Math.min(1, Number(box.x))),
      y: Math.max(0, Math.min(1, Number(box.y))),
      width: Math.max(0, Math.min(1, Number(box.width))),
      height: Math.max(0, Math.min(1, Number(box.height))),
    };
  }

  return {
    x: Math.max(0, Math.min(1, Number((box.x / frameWidth).toFixed(4)))),
    y: Math.max(0, Math.min(1, Number((box.y / frameHeight).toFixed(4)))),
    width: Math.max(0, Math.min(1, Number((box.width / frameWidth).toFixed(4)))),
    height: Math.max(0, Math.min(1, Number((box.height / frameHeight).toFixed(4)))),
  };
}

function mapViolationType(rawType: string): ViolationType {
  const upper = rawType.trim().toUpperCase();
  if (upper === VIOLATION_TYPE.NO_HELMET || upper.includes("HELMET")) {
    return VIOLATION_TYPE.NO_HELMET;
  }
  if (upper === VIOLATION_TYPE.NO_VEST || upper.includes("VEST")) {
    return VIOLATION_TYPE.NO_VEST;
  }
  if (
    upper === VIOLATION_TYPE.RESTRICTED_AREA ||
    upper === "UNAUTHORIZED_ZONE" ||
    upper.includes("RESTRICT")
  ) {
    return VIOLATION_TYPE.RESTRICTED_AREA;
  }
  if (upper === VIOLATION_TYPE.MULTI_VIOLATION) {
    return VIOLATION_TYPE.MULTI_VIOLATION;
  }
  return VIOLATION_TYPE.NO_HELMET;
}

function resolveAggregateViolationType(
  violations: AiVisionViolationPayload["violations"],
): ViolationType {
  const distinct = new Set(violations.map((v) => mapViolationType(v.violationType)));
  if (distinct.size > 1) {
    return VIOLATION_TYPE.MULTI_VIOLATION;
  }
  return Array.from(distinct)[0] || VIOLATION_TYPE.NO_HELMET;
}

function resolveHighestSeverity(
  payload: AiVisionViolationPayload,
): IncidentSeverity {
  if (payload.summary?.highestSeverity) {
    return payload.summary.highestSeverity;
  }
  let highest: IncidentSeverity = INCIDENT_SEVERITY.MEDIUM;
  for (const v of payload.violations) {
    if (SEVERITY_RANK[v.severity] > SEVERITY_RANK[highest]) {
      highest = v.severity;
    }
  }
  return highest;
}

export class AiVisionIntegrationService {
  constructor(
    private readonly incidents: IncidentService = incidentService,
    private readonly cameraClient: Pick<CameraLookupClient, "lookupCamera"> = cameraLookupClient,
  ) {}

  private unwrapPayload(input: AiVisionEventInput): {
    payload: AiVisionViolationPayload;
    envelopeEventId?: string;
  } {
    if ("payload" in input && input.payload) {
      return {
        payload: input.payload,
        envelopeEventId: input.eventId,
      };
    }
    return {
      payload: input as AiVisionViolationPayload,
    };
  }

  private async resolveCameraIdentity(
    payload: AiVisionViolationPayload,
  ): Promise<CameraIdentity> {
    const meta = (payload.metadata || {}) as Record<string, unknown>;
    const candidateSiteId =
      payload.siteId ||
      payload.site?.id ||
      (typeof meta.siteId === "string" ? meta.siteId : undefined);
    const candidateCameraId =
      payload.cameraId ||
      payload.camera?.id ||
      (typeof meta.cameraId === "string" ? meta.cameraId : undefined);
    const candidateCode =
      payload.cameraCode ||
      payload.camera?.code ||
      (typeof meta.cameraCode === "string" ? meta.cameraCode : undefined);

    let resolved: CameraIdentity | null = null;
    if (candidateCameraId && isUuid(candidateCameraId)) {
      resolved = await this.cameraClient.lookupCamera({ id: candidateCameraId });
    } else if (candidateCode) {
      resolved = await this.cameraClient.lookupCamera({ code: candidateCode });
    }

    if (resolved) {
      if (candidateSiteId && resolved.siteId !== candidateSiteId) {
        throw new AppError(
          "siteId trong sự kiện không khớp với công trường của camera đã đăng ký",
          422,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }
      if (
        candidateCode &&
        resolved.code &&
        resolved.code.toUpperCase() !== candidateCode.toUpperCase()
      ) {
        throw new AppError(
          "cameraCode trong sự kiện không khớp với camera được tra cứu",
          422,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }
      return resolved;
    }

    throw new AppError(
      "Không thể xác định siteId và cameraId hợp lệ cho sự kiện AI Vision",
      422,
      ERROR_CODE.VALIDATION_ERROR,
    );
  }

  async ingestEvent(input: AiVisionEventInput) {
    const { payload, envelopeEventId } = this.unwrapPayload(input);
    const camera = await this.resolveCameraIdentity(payload);

    const meta = (payload.metadata || {}) as Record<string, unknown>;
    const primaryViolation = payload.violations[0];
    const violationType = resolveAggregateViolationType(payload.violations);
    const severity = resolveHighestSeverity(payload);

    const rawIdempotencyKey =
      payload.violationId ||
      payload.eventId ||
      envelopeEventId ||
      (typeof meta.violationId === "string" ? meta.violationId : undefined) ||
      (typeof meta.eventId === "string" ? meta.eventId : undefined) ||
      `${payload.timestamp}:${violationType}`;

    const scopedKey = isUuid(rawIdempotencyKey)
      ? rawIdempotencyKey.toLowerCase()
      : `${camera.siteId}:${camera.id}:${rawIdempotencyKey}`;

    const violationId = deriveDeterministicUuid(scopedKey);

    const frameW = payload.evidence.frameResolution?.width || 1280;
    const frameH = payload.evidence.frameResolution?.height || 720;

    const snapFileName =
      path.posix.basename(payload.evidence.snapshotUrl.split("?")[0] || "") ||
      `${violationId}.jpg`;
    const storageKey = resolveEvidenceStorageKey(
      payload.evidence.objectKey,
      payload.evidence.snapshotUrl,
      camera.siteId,
      camera.code,
      snapFileName,
    );

    const detections = Array.isArray(payload.detections) ? payload.detections : [];

    const primaryBox = normalizeBoundingBox(
      primaryViolation.box ||
        detections.find((d) => d.class.toUpperCase() === "PERSON")?.box,
      frameW,
      frameH,
    );

    const aiDetectionsMeta = {
      model: typeof meta.model === "string" ? meta.model : undefined,
      contractVersion:
        typeof meta.contractVersion === "string" ? meta.contractVersion : undefined,
      annotatedInImage:
        typeof meta.annotatedInImage === "boolean" ? meta.annotatedInImage : true,
      violation: {
        type: violationType,
        confidence: primaryViolation.confidence,
        box: primaryBox,
      },
      allDetections: detections.map((d) => ({
        class: d.class,
        confidence: d.confidence,
        track_id: d.trackId ?? null,
        box: normalizeBoundingBox(d.box, frameW, frameH),
        bbox: [
          Math.round(d.box.x),
          Math.round(d.box.y),
          Math.round(d.box.x + d.box.width),
          Math.round(d.box.y + d.box.height),
        ],
      })),
    };

    const refUrl = payload.evidence.referenceSnapshotUrl || undefined;
    const refObjectKey = payload.evidence.referenceObjectKey || undefined;
    const hasReference = Boolean(refUrl || refObjectKey);

    const createDto: CreateIncidentDto = {
      siteId: camera.siteId,
      cameraId: camera.id,
      violationId,
      violationType,
      severity,
      status: INCIDENT_STATUS.PENDING_REVIEW,
      detectedAt: payload.timestamp,
      description:
        primaryViolation.description ||
        payload.violations.map((v) => v.description || v.violationType).filter(Boolean).join("; ") ||
        `AI phát hiện vi phạm ${violationType} tại camera ${camera.code}`,
      initialEvidence: {
        cameraId: camera.id,
        evidenceType: EVIDENCE_TYPE.SNAPSHOT,
        storageKey,
        fileName: path.posix.basename(storageKey),
        mimeType: payload.evidence.mimeType || "image/jpeg",
        fileSize: payload.evidence.fileSize || 0,
        capturedAt: payload.timestamp,
        metadata: {
          width: frameW,
          height: frameH,
          checksum: payload.evidence.checksum || null,
          aiDetections: aiDetectionsMeta,
        },
      },
      ...(hasReference
        ? {
            initialReferenceEvidence: {
              cameraId: camera.id,
              evidenceType: EVIDENCE_TYPE.REFERENCE_SNAPSHOT,
              storageKey: resolveEvidenceStorageKey(
                refObjectKey,
                refUrl,
                camera.siteId,
                camera.code,
                `${violationId}_ref.jpg`,
              ),
              fileName: path.posix.basename(
                refObjectKey || refUrl?.split("?")[0] || `${violationId}_ref.jpg`,
              ),
              mimeType: payload.evidence.mimeType || "image/jpeg",
              fileSize: payload.evidence.referenceFileSize || 0,
              capturedAt: payload.timestamp,
              metadata: {
                width: frameW,
                height: frameH,
                checksum: payload.evidence.referenceChecksum || null,
              },
            },
          }
        : {}),
    };

    const created = await this.incidents.createIncident(
      createDto,
      SYSTEM_ACTOR_UUID,
      { cameraCode: camera.code },
    );
    return {
      incident: created,
      violationId,
      cameraId: camera.id,
      siteId: camera.siteId,
      storageKey,
    };
  }

  async ingestBatch(events: AiVisionEventInput[]): Promise<BatchIngestResult> {
    const results: BatchIngestResult["results"] = [];
    const errors: BatchIngestResult["errors"] = [];

    for (let i = 0; i < events.length; i++) {
      try {
        const res = await this.ingestEvent(events[i]);
        results.push({
          index: i,
          incidentId: res.incident.id,
          status: res.incident.status,
        });
      } catch (err: any) {
        errors.push({
          index: i,
          error: err?.message || "Failed to ingest AI vision event",
        });
      }
    }

    return {
      total: events.length,
      succeeded: results.length,
      failed: errors.length,
      results,
      errors,
    };
  }
}

export const aiVisionIntegrationService = new AiVisionIntegrationService();
