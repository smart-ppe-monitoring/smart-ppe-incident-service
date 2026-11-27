import { z } from "zod";
import {
  INCIDENT_STATUS,
  VIOLATION_TYPE,
  INCIDENT_SEVERITY,
  EVIDENCE_TYPE,
  EVIDENCE_ACCESS_ACTION,
  EVIDENCE_LIFECYCLE_FILTER,
} from "../../common/constants/incident.constant";

const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const uuidSchema = z
  .string()
  .trim()
  .regex(UUID_REGEX, "ID phải là định dạng UUID hợp lệ");

const booleanQuerySchema = z
  .union([
    z.boolean(),
    z.enum(["true", "false"]).transform((val) => val === "true"),
  ])
  .optional();

const uuidListQuerySchema = z.preprocess((val) => {
  if (val === undefined || val === null || val === "") return undefined;
  if (Array.isArray(val)) return val;
  if (typeof val === "string") {
    return val
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return val;
}, z.array(uuidSchema).max(100, "Tối đa 100 cameraIds trong một truy vấn").optional());

export const incidentIdParamSchema = z.object({
  id: uuidSchema,
});

export const evidenceIdParamSchema = z.object({
  id: uuidSchema,
});

// ── Evidence Schemas ─────────────────────────────────────────────────────────
export const createEvidenceMetadataSchema = z.object({
  width: z.coerce.number().int().positive().nullable().optional(),
  height: z.coerce.number().int().positive().nullable().optional(),
  durationSeconds: z.coerce.number().int().nonnegative().nullable().optional(),
  frameRate: z.coerce.number().positive().nullable().optional(),
  checksum: z.string().trim().max(128).nullable().optional(),
  aiDetections: z.record(z.unknown()).nullable().optional(),
});

export const storageKeySchema = z
  .string({ required_error: "storageKey là bắt buộc" })
  .trim()
  .min(3, "storageKey tối thiểu 3 ký tự")
  .max(1000, "storageKey tối đa 1000 ký tự")
  .refine((val) => !val.includes(".."), {
    message: "storageKey không được chứa ký tự path traversal (..)",
  })
  .refine((val) => !val.startsWith("/") && !val.includes("//"), {
    message: "storageKey không được chứa đường dẫn tuyệt đối hoặc dấu gạch chéo lặp lại",
  })
  .refine((val) => val.startsWith("evidences/"), {
    message: "storageKey phải bắt đầu bằng tiền tố 'evidences/'",
  });

export const createEvidenceSchema = z.object({
  cameraId: uuidSchema,
  evidenceType: z.enum(
    [EVIDENCE_TYPE.SNAPSHOT, EVIDENCE_TYPE.REFERENCE_SNAPSHOT, EVIDENCE_TYPE.VIDEO_CLIP],
    { errorMap: () => ({ message: "Loại bằng chứng không hợp lệ (SNAPSHOT | REFERENCE_SNAPSHOT | VIDEO_CLIP)" }) },
  ),
  storageKey: storageKeySchema,
  fileName: z
    .string({ required_error: "Tên tệp là bắt buộc" })
    .trim()
    .min(1, "Tên tệp không được để trống")
    .max(255, "Tên tệp tối đa 255 ký tự"),
  mimeType: z
    .string({ required_error: "mimeType là bắt buộc" })
    .trim()
    .min(1, "mimeType không được để trống")
    .max(100, "mimeType tối đa 100 ký tự")
    .regex(
      /^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+$/,
      "Định dạng MIME type không hợp lệ",
    ),
  fileSize: z.coerce.number().nonnegative("Kích thước tệp không âm").default(0),
  capturedAt: z.coerce.date({
    required_error: "Thời gian ghi nhận (capturedAt) là bắt buộc",
  }),
  metadata: createEvidenceMetadataSchema.optional(),
});

const evidenceFilterShape = {
  incidentId: uuidSchema.optional(),
  siteId: uuidSchema.optional(),
  cameraId: uuidSchema.optional(),
  cameraIds: uuidListQuerySchema,
  evidenceType: z
    .enum([
      EVIDENCE_TYPE.SNAPSHOT,
      EVIDENCE_TYPE.REFERENCE_SNAPSHOT,
      EVIDENCE_TYPE.VIDEO_CLIP,
    ])
    .optional(),
  violationType: z
    .enum([
      VIOLATION_TYPE.NO_HELMET,
      VIOLATION_TYPE.NO_VEST,
      VIOLATION_TYPE.RESTRICTED_AREA,
      VIOLATION_TYPE.MULTI_VIOLATION,
    ])
    .optional(),
  incidentStatus: z
    .enum([
      INCIDENT_STATUS.PENDING_REVIEW,
      INCIDENT_STATUS.CONFIRMED,
      INCIDENT_STATUS.DISMISSED,
      INCIDENT_STATUS.RESOLVED,
      INCIDENT_STATUS.CLOSED,
    ])
    .optional(),
  lifecycle: z
    .enum([
      EVIDENCE_LIFECYCLE_FILTER.ACTIVE,
      EVIDENCE_LIFECYCLE_FILTER.OPEN,
      EVIDENCE_LIFECYCLE_FILTER.ARCHIVED,
      INCIDENT_STATUS.PENDING_REVIEW,
      INCIDENT_STATUS.CONFIRMED,
      INCIDENT_STATUS.DISMISSED,
      INCIDENT_STATUS.RESOLVED,
      INCIDENT_STATUS.CLOSED,
    ])
    .optional(),
  hasChecksum: booleanQuerySchema,
  search: z.string().trim().max(200).optional(),
  fromDate: z.coerce.date().optional(),
  toDate: z.coerce.date().optional(),
  startDate: z.coerce.date().optional(),
  endDate: z.coerce.date().optional(),
};

export const evidenceSummaryQuerySchema = z.object(evidenceFilterShape);

export const evidenceQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  ...evidenceFilterShape,
  sortBy: z.enum(["capturedAt", "createdAt", "fileSize"]).optional(),
  sortOrder: z.enum(["asc", "desc"]).optional(),
});

export const evidenceAccessLogsQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  action: z
    .enum([
      EVIDENCE_ACCESS_ACTION.VIEW,
      EVIDENCE_ACCESS_ACTION.DOWNLOAD,
      EVIDENCE_ACCESS_ACTION.VERIFY,
      EVIDENCE_ACCESS_ACTION.DELETE,
    ])
    .optional(),
});

export const batchDeleteEvidencesSchema = z.object({
  ids: z
    .array(uuidSchema, {
      required_error: "Danh sách ID bằng chứng (ids) là bắt buộc",
    })
    .min(1, "Danh sách ID bằng chứng không được để trống")
    .max(100, "Tối đa 100 bằng chứng mỗi lần xóa hàng loạt"),
});

// ── Incident Schemas ─────────────────────────────────────────────────────────
export const createIncidentSchema = z.object({
  siteId: uuidSchema,
  cameraId: uuidSchema,
  violationId: uuidSchema.nullable().optional(),
  violationType: z.enum(
    [
      VIOLATION_TYPE.NO_HELMET,
      VIOLATION_TYPE.NO_VEST,
      VIOLATION_TYPE.RESTRICTED_AREA,
      VIOLATION_TYPE.MULTI_VIOLATION,
    ],
    { errorMap: () => ({ message: "Loại vi phạm không hợp lệ" }) },
  ),
  severity: z
    .enum(
      [
        INCIDENT_SEVERITY.LOW,
        INCIDENT_SEVERITY.MEDIUM,
        INCIDENT_SEVERITY.HIGH,
        INCIDENT_SEVERITY.CRITICAL,
      ],
      { errorMap: () => ({ message: "Mức độ nghiêm trọng không hợp lệ" }) },
    )
    .optional(),
  status: z
    .enum([INCIDENT_STATUS.PENDING_REVIEW], {
      errorMap: () => ({
        message: "Trạng thái sự cố khi tạo mới chỉ có thể là PENDING_REVIEW",
      }),
    })
    .optional(),
  detectedAt: z.coerce.date({
    required_error: "Thời điểm phát hiện (detectedAt) là bắt buộc",
  }),
  description: z.string().trim().max(2000).nullable().optional(),
  initialEvidence: z
    .object({
      cameraId: uuidSchema.optional(),
      evidenceType: z.enum([
        EVIDENCE_TYPE.SNAPSHOT,
        EVIDENCE_TYPE.REFERENCE_SNAPSHOT,
        EVIDENCE_TYPE.VIDEO_CLIP,
      ]),
      storageKey: storageKeySchema,
      fileName: z.string().trim().min(1).max(255),
      mimeType: z
        .string()
        .trim()
        .min(1)
        .max(100)
        .regex(
          /^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+$/,
          "Định dạng MIME type không hợp lệ",
        ),
      fileSize: z.coerce.number().nonnegative().optional(),
      capturedAt: z.coerce.date(),
      metadata: createEvidenceMetadataSchema.optional(),
    })
    .optional(),
  initialReferenceEvidence: z
    .object({
      cameraId: uuidSchema.optional(),
      evidenceType: z.enum([
        EVIDENCE_TYPE.SNAPSHOT,
        EVIDENCE_TYPE.REFERENCE_SNAPSHOT,
        EVIDENCE_TYPE.VIDEO_CLIP,
      ]).default(EVIDENCE_TYPE.REFERENCE_SNAPSHOT),
      storageKey: storageKeySchema,
      fileName: z.string().trim().min(1).max(255),
      mimeType: z
        .string()
        .trim()
        .min(1)
        .max(100)
        .regex(
          /^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+$/,
          "Định dạng MIME type không hợp lệ",
        ),
      fileSize: z.coerce.number().nonnegative().optional(),
      capturedAt: z.coerce.date(),
      metadata: createEvidenceMetadataSchema.optional(),
    })
    .optional(),
});

export const updateIncidentSchema = z
  .object({
    violationType: z
      .enum([
        VIOLATION_TYPE.NO_HELMET,
        VIOLATION_TYPE.NO_VEST,
        VIOLATION_TYPE.RESTRICTED_AREA,
        VIOLATION_TYPE.MULTI_VIOLATION,
      ])
      .optional(),
    severity: z
      .enum([
        INCIDENT_SEVERITY.LOW,
        INCIDENT_SEVERITY.MEDIUM,
        INCIDENT_SEVERITY.HIGH,
        INCIDENT_SEVERITY.CRITICAL,
      ])
      .optional(),
    description: z.string().trim().max(2000).nullable().optional(),
  })
  .refine(
    (data) => Object.keys(data).length > 0,
    "Cần cung cấp ít nhất một trường để cập nhật",
  );

export const incidentQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  search: z.string().trim().max(200).optional(),
  siteId: uuidSchema.optional(),
  cameraId: uuidSchema.optional(),
  cameraIds: uuidListQuerySchema,
  assignedTo: uuidSchema.optional(),
  assignedToMe: booleanQuerySchema,
  includeAssignments: booleanQuerySchema,
  includeAllAssignments: booleanQuerySchema,
  violationType: z
    .enum([
      VIOLATION_TYPE.NO_HELMET,
      VIOLATION_TYPE.NO_VEST,
      VIOLATION_TYPE.RESTRICTED_AREA,
      VIOLATION_TYPE.MULTI_VIOLATION,
    ])
    .optional(),
  severity: z
    .enum([
      INCIDENT_SEVERITY.LOW,
      INCIDENT_SEVERITY.MEDIUM,
      INCIDENT_SEVERITY.HIGH,
      INCIDENT_SEVERITY.CRITICAL,
    ])
    .optional(),
  status: z
    .enum([
      INCIDENT_STATUS.PENDING_REVIEW,
      INCIDENT_STATUS.CONFIRMED,
      INCIDENT_STATUS.DISMISSED,
      INCIDENT_STATUS.RESOLVED,
      INCIDENT_STATUS.CLOSED,
    ])
    .optional(),
  fromDate: z.coerce.date().optional(),
  toDate: z.coerce.date().optional(),
  startDate: z.coerce.date().optional(),
  endDate: z.coerce.date().optional(),
  sortBy: z.enum(["detectedAt", "createdAt", "severity", "status"]).optional(),
  sortOrder: z.enum(["asc", "desc"]).optional(),
});

export const incidentStatusCountsQuerySchema = z.object({
  siteId: uuidSchema.optional(),
  cameraId: uuidSchema.optional(),
  cameraIds: uuidListQuerySchema,
  fromDate: z.coerce.date().optional(),
  toDate: z.coerce.date().optional(),
  startDate: z.coerce.date().optional(),
  endDate: z.coerce.date().optional(),
});

export const feedbackDatasetQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  siteId: uuidSchema.optional(),
  cameraId: uuidSchema.optional(),
  cameraIds: uuidListQuerySchema,
  violationType: z
    .enum([
      VIOLATION_TYPE.NO_HELMET,
      VIOLATION_TYPE.NO_VEST,
      VIOLATION_TYPE.RESTRICTED_AREA,
      VIOLATION_TYPE.MULTI_VIOLATION,
    ])
    .optional(),
  label: z.enum(["TRUE_VIOLATION", "FALSE_ALARM"]).optional(),
  fromDate: z.coerce.date().optional(),
  toDate: z.coerce.date().optional(),
  startDate: z.coerce.date().optional(),
  endDate: z.coerce.date().optional(),
});

// ── Lifecycle Schemas ────────────────────────────────────────────────────────
export const batchReviewIncidentsSchema = z
  .object({
    ids: z
      .array(uuidSchema, {
        required_error: "Danh sách ID sự cố (ids) là bắt buộc",
      })
      .min(1, "Danh sách ID sự cố không được để trống")
      .max(100, "Tối đa 100 sự cố mỗi lần duyệt hàng loạt"),
    action: z.enum(["CONFIRM", "REJECT"], {
      errorMap: () => ({ message: "Hành động chỉ có thể là CONFIRM hoặc REJECT" }),
    }),
    resolutionNote: z.string().trim().max(1000).optional(),
  })
  .refine(
    (data) => {
      if (data.action === "REJECT") {
        return (
          typeof data.resolutionNote === "string" &&
          data.resolutionNote.trim().length >= 3
        );
      }
      return true;
    },
    {
      message:
        "Bắt buộc phải nhập lý do (tối thiểu 3 ký tự) khi bác bỏ cảnh báo vi phạm (REJECT)",
      path: ["resolutionNote"],
    },
  );

export const reviewIncidentSchema = z
  .object({
    decision: z.enum(["CONFIRMED", "DISMISSED"], {
      errorMap: () => ({ message: "Quyết định duyệt phải là CONFIRMED hoặc DISMISSED" }),
    }),
    reason: z.string().trim().max(1000).optional(),
  })
  .refine(
    (data) => {
      if (data.decision === "DISMISSED") {
        return typeof data.reason === "string" && data.reason.trim().length >= 3;
      }
      return true;
    },
    {
      message: "Bắt buộc cung cấp lý do (tối thiểu 3 ký tự) khi bác bỏ cảnh báo vi phạm (DISMISSED)",
      path: ["reason"],
    },
  );

export const resolveIncidentSchema = z.object({
  resolutionNote: z
    .string({ required_error: "Ghi chú giải quyết vi phạm là bắt buộc" })
    .trim()
    .min(3, "Ghi chú giải quyết phải có ít nhất 3 ký tự")
    .max(2000, "Ghi chú giải quyết tối đa 2000 ký tự"),
});

export const closeIncidentSchema = z.object({
  closeNote: z.string().trim().max(2000).optional(),
});

// ── Assignment & Comment Schemas ─────────────────────────────────────────────
export const createIncidentAssignmentSchema = z.object({
  assignedTo: uuidSchema,
  note: z.string().trim().max(1000, "Ghi chú phân công tối đa 1000 ký tự").optional(),
});

export const sharedResolutionEvidenceSchema = z.object({
  cameraId: uuidSchema.optional(),
  evidenceType: z
    .enum([
      EVIDENCE_TYPE.SNAPSHOT,
      EVIDENCE_TYPE.REFERENCE_SNAPSHOT,
      EVIDENCE_TYPE.VIDEO_CLIP,
    ])
    .default(EVIDENCE_TYPE.REFERENCE_SNAPSHOT),
  storageKey: storageKeySchema,
  fileName: z
    .string({ required_error: "Tên tệp là bắt buộc" })
    .trim()
    .min(1, "Tên tệp không được để trống")
    .max(255, "Tên tệp tối đa 255 ký tự"),
  mimeType: z
    .string({ required_error: "mimeType là bắt buộc" })
    .trim()
    .min(1, "mimeType không được để trống")
    .max(100, "mimeType tối đa 100 ký tự")
    .regex(
      /^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+$/,
      "Định dạng MIME type không hợp lệ",
    ),
  fileSize: z.coerce.number().nonnegative("Kích thước tệp không âm").default(0),
  capturedAt: z.coerce.date().optional(),
  metadata: createEvidenceMetadataSchema.optional(),
});

export const batchAssignIncidentsSchema = z.object({
  ids: z
    .array(uuidSchema, {
      required_error: "Danh sách ID sự cố (ids) là bắt buộc",
    })
    .min(1, "Danh sách ID sự cố không được để trống")
    .max(100, "Tối đa 100 sự cố mỗi lần phân công hàng loạt"),
  assignedTo: uuidSchema,
  note: z.string().trim().max(1000, "Ghi chú phân công tối đa 1000 ký tự").optional(),
});

export const batchResolveIncidentsSchema = z.object({
  ids: z
    .array(uuidSchema, {
      required_error: "Danh sách ID sự cố (ids) là bắt buộc",
    })
    .min(1, "Danh sách ID sự cố không được để trống")
    .max(100, "Tối đa 100 sự cố mỗi lần khắc phục hàng loạt"),
  resolutionNote: z
    .string({ required_error: "Ghi chú giải quyết vi phạm là bắt buộc" })
    .trim()
    .min(3, "Ghi chú giải quyết phải có ít nhất 3 ký tự")
    .max(2000, "Ghi chú giải quyết tối đa 2000 ký tự"),
  sharedEvidence: sharedResolutionEvidenceSchema.optional(),
});

export const batchCloseIncidentsSchema = z.object({
  ids: z
    .array(uuidSchema, {
      required_error: "Danh sách ID sự cố (ids) là bắt buộc",
    })
    .min(1, "Danh sách ID sự cố không được để trống")
    .max(100, "Tối đa 100 sự cố mỗi lần đóng hồ sơ hàng loạt"),
  closeNote: z.string().trim().max(2000, "Ghi chú đóng hồ sơ tối đa 2000 ký tự").optional(),
});

export const createIncidentCommentSchema = z.object({
  comment: z
    .string({ required_error: "Nội dung bình luận là bắt buộc" })
    .trim()
    .min(1, "Nội dung bình luận không được để trống")
    .max(2000, "Nội dung bình luận không được vượt quá 2000 ký tự"),
});
