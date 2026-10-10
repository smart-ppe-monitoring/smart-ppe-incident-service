import { Router } from "express";
import { incidentController } from "./incident.controller";
import { authMiddleware } from "../../middlewares/auth.middleware";
import { requirePermission } from "../../middlewares/permission.middleware";
import { validate } from "../../middlewares/validate.middleware";
import { uploadImageMiddleware } from "../../middlewares/upload.middleware";
import { PERMISSIONS } from "../../common/constants/permission.constant";
import {
  incidentIdParamSchema,
  evidenceIdParamSchema,
  createIncidentSchema,
  updateIncidentSchema,
  incidentQuerySchema,
  reviewIncidentSchema,
  resolveIncidentSchema,
  closeIncidentSchema,
  createIncidentAssignmentSchema,
  createIncidentCommentSchema,
  createEvidenceSchema,
  evidenceQuerySchema,
} from "./incident.validation";
import {
  requestEvidenceUploadUrlSchema,
  directUploadEvidenceSchema,
  downloadUrlQuerySchema,
} from "./evidence-storage.validation";

// ── Incident Routes (/api/v1/incidents) ──────────────────────────────────────
export const incidentRouter = Router();

incidentRouter.get(
  "/",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_READ),
  validate(incidentQuerySchema, "query"),
  incidentController.findAllIncidents,
);

incidentRouter.post(
  "/",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_MANAGE),
  validate(createIncidentSchema),
  incidentController.createIncident,
);

incidentRouter.get(
  "/:id",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_READ),
  validate(incidentIdParamSchema, "params"),
  incidentController.findIncidentById,
);

incidentRouter.put(
  "/:id",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_UPDATE),
  validate(incidentIdParamSchema, "params"),
  validate(updateIncidentSchema),
  incidentController.updateIncident,
);

incidentRouter.delete(
  "/:id",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_DELETE),
  validate(incidentIdParamSchema, "params"),
  incidentController.deleteIncident,
);

// ── Incident Lifecycle Transitions ─────────────────────────────────────────
incidentRouter.post(
  "/:id/review",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_REVIEW),
  validate(incidentIdParamSchema, "params"),
  validate(reviewIncidentSchema),
  incidentController.reviewIncident,
);

incidentRouter.post(
  "/:id/resolve",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_UPDATE),
  validate(incidentIdParamSchema, "params"),
  validate(resolveIncidentSchema),
  incidentController.resolveIncident,
);

incidentRouter.post(
  "/:id/close",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_MANAGE),
  validate(incidentIdParamSchema, "params"),
  validate(closeIncidentSchema),
  incidentController.closeIncident,
);

// ── Incident Assignments & Comments ────────────────────────────────────────
incidentRouter.get(
  "/:id/assignments",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_READ),
  validate(incidentIdParamSchema, "params"),
  incidentController.getIncidentAssignments,
);

incidentRouter.post(
  "/:id/assignments",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_MANAGE),
  validate(incidentIdParamSchema, "params"),
  validate(createIncidentAssignmentSchema),
  incidentController.assignIncident,
);

incidentRouter.get(
  "/:id/comments",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_READ),
  validate(incidentIdParamSchema, "params"),
  incidentController.getIncidentComments,
);

incidentRouter.post(
  "/:id/comments",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_UPDATE),
  validate(incidentIdParamSchema, "params"),
  validate(createIncidentCommentSchema),
  incidentController.addIncidentComment,
);

// ── Incident Evidences (Nested) ─────────────────────────────────────────────
incidentRouter.post(
  "/:id/evidences",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_UPDATE),
  validate(incidentIdParamSchema, "params"),
  validate(createEvidenceSchema),
  incidentController.addEvidence,
);

// ── Evidence Direct Routes (/api/v1/evidences) ───────────────────────────────
export const evidenceRouter = Router();

// Presigned Upload URL cho AI pipeline hoặc client
evidenceRouter.post(
  "/upload-url",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_UPDATE),
  validate(requestEvidenceUploadUrlSchema),
  incidentController.requestEvidenceUploadUrl,
);

// Direct Multipart Upload (nhận file buffer, trích xuất metadata và lưu MinIO)
evidenceRouter.post(
  "/direct-upload",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_UPDATE),
  uploadImageMiddleware.single("file"),
  validate(directUploadEvidenceSchema),
  incidentController.uploadEvidenceDirect,
);

evidenceRouter.get(
  "/",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_READ),
  validate(evidenceQuerySchema, "query"),
  incidentController.findAllEvidences,
);

evidenceRouter.get(
  "/:id",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_READ),
  validate(evidenceIdParamSchema, "params"),
  incidentController.findEvidenceById,
);

// Presigned Download / View URL
evidenceRouter.get(
  "/:id/download-url",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_READ),
  validate(evidenceIdParamSchema, "params"),
  validate(downloadUrlQuerySchema, "query"),
  incidentController.getEvidenceDownloadUrl,
);

// Xác thực tính toàn vẹn pháp lý (Tamper Evidence Checksum Verification - Mục 1 & 2.1 D08.pdf)
evidenceRouter.get(
  "/:id/verify-checksum",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_READ),
  validate(evidenceIdParamSchema, "params"),
  incidentController.verifyEvidenceIntegrity,
);

evidenceRouter.delete(
  "/:id",
  authMiddleware,
  requirePermission(PERMISSIONS.PPE_INCIDENT_DELETE),
  validate(evidenceIdParamSchema, "params"),
  incidentController.deleteEvidence,
);
