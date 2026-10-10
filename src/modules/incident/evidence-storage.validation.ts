import { z } from "zod";
import {
  EVIDENCE_TYPE,
  EVIDENCE_ACCESS_ACTION,
} from "../../common/constants/incident.constant";
import { uuidSchema } from "./incident.validation";

export const ALLOWED_EVIDENCE_MIME_TYPES = [
  "image/jpeg",
  "image/png",
  "image/webp",
  "video/mp4",
  "video/webm",
  "video/quicktime",
] as const;

export const requestEvidenceUploadUrlSchema = z.object({
  incidentId: uuidSchema,
  cameraId: uuidSchema,
  siteId: uuidSchema,
  evidenceType: z.enum(
    [EVIDENCE_TYPE.SNAPSHOT, EVIDENCE_TYPE.VIDEO_CLIP],
    { errorMap: () => ({ message: "Loại bằng chứng không hợp lệ (SNAPSHOT | VIDEO_CLIP)" }) },
  ),
  fileName: z
    .string({ required_error: "Tên tệp tin là bắt buộc" })
    .trim()
    .min(1, "Tên tệp không được để trống")
    .max(255, "Tên tệp tối đa 255 ký tự")
    .refine((val) => !val.includes(".."), {
      message: "Tên tệp không được chứa ký tự path traversal (..)",
    }),
  mimeType: z
    .string({ required_error: "mimeType là bắt buộc" })
    .trim()
    .toLowerCase()
    .refine(
      (val) => (ALLOWED_EVIDENCE_MIME_TYPES as readonly string[]).includes(val),
      {
        message:
          "Định dạng MIME không được hỗ trợ (chỉ chấp nhận image/jpeg, image/png, image/webp, video/mp4, video/webm, video/quicktime)",
      },
    ),
  fileSize: z.coerce
    .number()
    .positive("Kích thước tệp phải lớn hơn 0")
    .max(500 * 1024 * 1024, "Kích thước tệp vượt quá 500MB")
    .optional(),
  expiresInSeconds: z.coerce
    .number()
    .int()
    .min(60, "Thời gian hết hạn tối thiểu 60 giây")
    .max(86400, "Thời gian hết hạn tối đa 24 giờ")
    .optional(),
});

export const directUploadEvidenceSchema = z.object({
  incidentId: uuidSchema,
  cameraId: uuidSchema,
  evidenceType: z.enum(
    [EVIDENCE_TYPE.SNAPSHOT, EVIDENCE_TYPE.VIDEO_CLIP],
    { errorMap: () => ({ message: "Loại bằng chứng không hợp lệ (SNAPSHOT | VIDEO_CLIP)" }) },
  ),
  capturedAt: z.coerce.date().optional(),
  aiDetections: z
    .preprocess((val) => {
      if (typeof val === "string" && val.trim().length > 0) {
        try {
          return JSON.parse(val);
        } catch {
          return val;
        }
      }
      return val;
    }, z.record(z.unknown()).nullable())
    .optional(),
});

export const downloadUrlQuerySchema = z.object({
  expiresInSeconds: z.coerce
    .number()
    .int()
    .min(60, "Thời gian hết hạn tối thiểu 60 giây")
    .max(86400, "Thời gian hết hạn tối đa 24 giờ (86400 giây)")
    .default(900),
  action: z
    .enum([EVIDENCE_ACCESS_ACTION.VIEW, EVIDENCE_ACCESS_ACTION.DOWNLOAD])
    .default(EVIDENCE_ACCESS_ACTION.VIEW),
});

