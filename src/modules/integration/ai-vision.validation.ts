import { z } from "zod";
import {
  INCIDENT_SEVERITY,
} from "../../common/constants/incident.constant";

const boundingBoxSchema = z.object({
  x: z.coerce.number().min(0),
  y: z.coerce.number().min(0),
  width: z.coerce.number().min(0),
  height: z.coerce.number().min(0),
});

const frameResolutionSchema = z.object({
  width: z.coerce.number().int().positive().default(1280),
  height: z.coerce.number().int().positive().default(720),
});

const aiDetectionSchema = z.object({
  class: z.string().min(1),
  confidence: z.coerce.number().min(0).max(1),
  box: boundingBoxSchema,
  trackId: z.coerce.number().int().optional().nullable(),
});

const aiViolationItemSchema = z.object({
  violationType: z.string().min(1),
  severity: z
    .enum([
      INCIDENT_SEVERITY.LOW,
      INCIDENT_SEVERITY.MEDIUM,
      INCIDENT_SEVERITY.HIGH,
      INCIDENT_SEVERITY.CRITICAL,
    ])
    .default(INCIDENT_SEVERITY.HIGH),
  description: z.string().optional().default(""),
  confidence: z.coerce.number().min(0).max(1).default(0.8),
  box: boundingBoxSchema.optional().nullable(),
  workerName: z.string().optional().nullable(),
  workerId: z.string().optional().nullable(),
});

/**
 * Schema linh hoạt cho sự kiện AI Vision (Contract 2.1.0-PPE-STABLE + canonical format).
 * Cho phép gửi trực tiếp hoặc bọc trong Kafka envelope { topic, producer, payload }.
 */
export const aiVisionViolationPayloadSchema = z
  .object({
    eventId: z.string().trim().min(1).optional(),
    violationId: z.string().trim().min(1).optional(),
    siteId: z.string().uuid().optional(),
    cameraId: z.string().uuid().optional(),
    siteCode: z.string().trim().min(1).optional(),
    cameraCode: z.string().trim().min(1).optional(),
    site: z
      .object({
        id: z.string().uuid().optional(),
        code: z.string().min(1).optional(),
        name: z.string().optional(),
      })
      .optional(),
    camera: z
      .object({
        id: z.string().uuid().optional(),
        code: z.string().min(1).optional(),
        name: z.string().optional(),
        zone: z.string().optional(),
      })
      .optional(),
    timestamp: z
      .string()
      .trim()
      .refine(
        (v) =>
          /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?$/.test(
            v,
          ) && !Number.isNaN(Date.parse(v)),
        { message: "timestamp phải là chuỗi ngày giờ ISO-8601 hợp lệ" },
      ),
    evidence: z.object({
      snapshotUrl: z.string().min(1),
      objectKey: z.string().trim().min(1).optional(),
      referenceSnapshotUrl: z.string().optional().nullable(),
      referenceObjectKey: z.string().trim().min(1).optional().nullable(),
      clipUrl: z.string().optional().nullable(),
      checksum: z.string().trim().max(128).optional().nullable(),
      referenceChecksum: z.string().trim().max(128).optional().nullable(),
      fileSize: z.coerce.number().int().nonnegative().optional(),
      referenceFileSize: z.coerce.number().int().nonnegative().optional(),
      mimeType: z.string().optional().default("image/jpeg"),
      frameResolution: frameResolutionSchema.optional(),
    }),
    detections: z
      .array(aiDetectionSchema)
      .max(500, "Tối đa 500 detection trong mỗi sự kiện")
      .optional()
      .default([]),
    violations: z
      .array(aiViolationItemSchema)
      .min(1, "Sự kiện vi phạm phải chứa ít nhất 1 hành vi vi phạm")
      .max(100, "Tối đa 100 vi phạm trong mỗi sự kiện"),
    summary: z
      .object({
        totalPersons: z.coerce.number().int().min(0).default(0),
        totalViolations: z.coerce.number().int().min(1).default(1),
        highestSeverity: z
          .enum([
            INCIDENT_SEVERITY.LOW,
            INCIDENT_SEVERITY.MEDIUM,
            INCIDENT_SEVERITY.HIGH,
            INCIDENT_SEVERITY.CRITICAL,
          ])
          .optional(),
      })
      .optional(),
    metadata: z.record(z.unknown()).optional(),
  })
  .refine((data) => Boolean(data.cameraCode || data.camera?.code || data.cameraId || data.camera?.id), {
    message: "Thiếu định danh camera (cameraCode hoặc cameraId)",
  });

export const aiVisionKafkaEnvelopeSchema = z.object({
  eventId: z.string().optional(),
  topic: z.string().optional(),
  traceId: z.string().optional(),
  timestamp: z.union([z.number(), z.string()]).optional(),
  producer: z.string().optional(),
  payload: aiVisionViolationPayloadSchema,
});

export const aiVisionEventInputSchema = z.union([
  aiVisionKafkaEnvelopeSchema,
  aiVisionViolationPayloadSchema,
]);

export const aiVisionBatchInputSchema = z.object({
  events: z
    .array(aiVisionEventInputSchema)
    .min(1, "Batch sự kiện phải có ít nhất 1 phần tử")
    .max(50, "Batch sự kiện tối đa 50 phần tử"),
});

export type AiVisionViolationPayload = z.infer<typeof aiVisionViolationPayloadSchema>;
export type AiVisionEventInput = z.infer<typeof aiVisionEventInputSchema>;
export type AiVisionBatchInput = z.infer<typeof aiVisionBatchInputSchema>;
