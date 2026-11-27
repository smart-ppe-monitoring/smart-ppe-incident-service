import {
  IncidentStatus,
  ViolationType,
  IncidentSeverity,
  EvidenceType,
  AssignmentStatus,
  EvidenceAccessAction,
  EvidenceLifecycleFilter,
} from "../../common/constants/incident.constant";
import {
  PaginationMeta,
  PaginatedResult,
} from "../../common/types/pagination.type";

export type { PaginationMeta };
export type PaginatedResultDto<T> = PaginatedResult<T>;

// ── Evidence DTOs ────────────────────────────────────────────────────────────
export interface CreateEvidenceMetadataDto {
  width?: number | null;
  height?: number | null;
  durationSeconds?: number | null;
  frameRate?: number | null;
  checksum?: string | null;
  aiDetections?: Record<string, unknown> | null;
}

export interface CreateEvidenceDto {
  incidentId?: string;
  cameraId: string;
  evidenceType: EvidenceType;
  storageKey: string;
  fileName: string;
  mimeType: string;
  fileSize?: number | bigint;
  capturedAt: string | Date;
  metadata?: CreateEvidenceMetadataDto;
}

export interface IncidentSummaryRefDto {
  id: string;
  siteId: string;
  cameraId: string;
  violationType: ViolationType | string;
  severity: IncidentSeverity | string;
  status: IncidentStatus | string;
  detectedAt: Date;
}

export interface EvidenceSummaryQueryDto {
  incidentId?: string;
  siteId?: string;
  cameraId?: string;
  cameraIds?: string[];
  evidenceType?: EvidenceType;
  violationType?: ViolationType;
  incidentStatus?: IncidentStatus;
  lifecycle?: EvidenceLifecycleFilter | IncidentStatus;
  hasChecksum?: boolean;
  search?: string;
  fromDate?: string | Date;
  toDate?: string | Date;
  startDate?: string | Date;
  endDate?: string | Date;
}

export interface EvidenceQueryDto extends EvidenceSummaryQueryDto {
  page?: number;
  limit?: number;
  sortBy?: "capturedAt" | "createdAt" | "fileSize";
  sortOrder?: "asc" | "desc";
}

export interface EvidenceSummaryDto {
  total: number;
  byType: Record<EvidenceType, number>;
  totalBytes: number;
  withChecksumCount: number;
}

export interface CreateEvidenceAccessLogDto {
  evidenceId: string;
  userId: string;
  action: EvidenceAccessAction;
}

export interface EvidenceAccessLogsQueryDto {
  page?: number;
  limit?: number;
  action?: EvidenceAccessAction;
}

export interface EvidenceAccessLogItemDto {
  id: string;
  evidenceId: string;
  userId: string;
  userName?: string;
  userRole?: string;
  action: EvidenceAccessAction | string;
  accessedAt: Date;
}

export interface BatchDeleteEvidencesDto {
  ids: string[];
}

export interface BatchDeleteEvidencesResultDto {
  total: number;
  deletedCount: number;
  deletedIds: string[];
  skippedIds: string[];
}

// ── Incident DTOs ────────────────────────────────────────────────────────────
export interface CreateIncidentDto {
  siteId: string;
  cameraId: string;
  violationId?: string | null;
  violationType: ViolationType;
  severity?: IncidentSeverity;
  status?: IncidentStatus;
  detectedAt: string | Date;
  description?: string | null;
  initialEvidence?: Omit<CreateEvidenceDto, "incidentId">;
  initialReferenceEvidence?: Omit<CreateEvidenceDto, "incidentId">;
}

export interface UpdateIncidentDto {
  violationType?: ViolationType;
  severity?: IncidentSeverity;
  description?: string | null;
}

export interface IncidentUserContext {
  id?: string;
  role?: string;
  siteId?: string;
  siteIds?: string[];
}

export interface IncidentQueryDto {
  page?: number;
  limit?: number;
  search?: string;
  siteId?: string;
  cameraId?: string;
  cameraIds?: string[];
  assignedTo?: string;
  assignedToMe?: boolean;
  includeAssignments?: boolean;
  includeAllAssignments?: boolean;
  violationType?: ViolationType;
  severity?: IncidentSeverity;
  status?: IncidentStatus;
  fromDate?: string | Date;
  toDate?: string | Date;
  startDate?: string | Date;
  endDate?: string | Date;
  sortBy?: "detectedAt" | "createdAt" | "severity" | "status";
  sortOrder?: "asc" | "desc";
}

// ── Lifecycle Transitions DTOs ───────────────────────────────────────────────
export interface ReviewIncidentDto {
  decision: "CONFIRMED" | "DISMISSED";
  reason?: string;
}

export interface BatchReviewIncidentDto {
  ids: string[];
  action: "CONFIRM" | "REJECT";
  resolutionNote?: string;
}

export interface BatchReviewResultDto {
  total: number;
  updatedCount: number;
  action: "CONFIRM" | "REJECT";
  newStatus: string;
  updatedIds: string[];
}

export interface ResolveIncidentDto {
  resolutionNote: string;
}

export interface CloseIncidentDto {
  closeNote?: string;
}

// ── Assignment & Comment DTOs ────────────────────────────────────────────────
export interface CreateIncidentAssignmentDto {
  assignedTo: string;
  note?: string;
}

export interface BatchAssignIncidentsDto {
  ids: string[];
  assignedTo: string;
  note?: string;
}

export interface BatchAssignResultDto {
  total: number;
  assignedCount: number;
  assignedTo: string;
  assignedToName?: string;
  assignedIds: string[];
  skippedIds: string[];
}

export interface SharedResolutionEvidenceDto {
  cameraId?: string;
  evidenceType?: EvidenceType;
  storageKey: string;
  fileName: string;
  mimeType: string;
  fileSize?: number | bigint;
  capturedAt?: string | Date;
  metadata?: CreateEvidenceMetadataDto;
}

export interface BatchResolveIncidentsDto {
  ids: string[];
  resolutionNote: string;
  sharedEvidence?: SharedResolutionEvidenceDto;
}

export interface BatchResolveResultDto {
  total: number;
  resolvedCount: number;
  newStatus: string;
  resolvedIds: string[];
  skippedIds: string[];
  sharedEvidenceStorageKey?: string;
}

export interface BatchCloseIncidentsDto {
  ids: string[];
  closeNote?: string;
}

export interface BatchCloseResultDto {
  total: number;
  closedCount: number;
  newStatus: string;
  closedIds: string[];
  skippedIds: string[];
}

export interface CreateIncidentCommentDto {
  comment: string;
}

// ── Incident Response Item DTOs ─────────────────────────────────────────────
export interface IncidentEvidenceItemDto {
  id: string;
  incidentId: string;
  cameraId: string;
  evidenceType: EvidenceType;
  storageKey: string;
  fileName: string;
  mimeType: string;
  fileSize: number;
  capturedAt: Date;
  createdAt: Date;
  metadata?: CreateEvidenceMetadataDto | null;
  incident?: IncidentSummaryRefDto;
}

export interface IncidentAssignmentItemDto {
  id: string;
  incidentId: string;
  assignedTo: string;
  assignedToName?: string;
  assignedAt: Date;
  unassignedAt?: Date | null;
  status: AssignmentStatus | string;
}

export interface IncidentCommentItemDto {
  id: string;
  incidentId: string;
  userId: string;
  userName?: string;
  userRole?: string;
  comment: string;
  createdAt: Date;
}

export interface IncidentItemDto {
  id: string;
  siteId: string;
  cameraId: string;
  violationId?: string | null;
  violationType: ViolationType;
  severity: IncidentSeverity;
  status: IncidentStatus;
  confidence?: number | null;
  trackId?: number | null;
  detectedAt: Date;
  resolvedAt?: Date | null;
  description?: string | null;
  createdAt: Date;
  updatedAt: Date;
  evidences?: IncidentEvidenceItemDto[];
  assignments?: IncidentAssignmentItemDto[];
  comments?: IncidentCommentItemDto[];
  _count?: {
    evidences: number;
    comments: number;
    assignments: number;
  };
}

export interface IncidentStatusCountsQueryDto {
  siteId?: string;
  cameraId?: string;
  cameraIds?: string[];
  fromDate?: Date | string;
  toDate?: Date | string;
  startDate?: Date | string;
  endDate?: Date | string;
}

export interface IncidentStatusCountsDto {
  total: number;
  pendingReview: number;
  confirmed: number;
  critical: number;
  resolved: number;
  closed: number;
  dismissed: number;
}

export type FeedbackDatasetLabel = "TRUE_VIOLATION" | "FALSE_ALARM";

export interface FeedbackDatasetQueryDto {
  page?: number;
  limit?: number;
  siteId?: string;
  cameraId?: string;
  cameraIds?: string[];
  violationType?: ViolationType;
  label?: FeedbackDatasetLabel;
  fromDate?: Date | string;
  toDate?: Date | string;
  startDate?: Date | string;
  endDate?: Date | string;
}

export interface FeedbackDatasetItemDto {
  incidentId: string;
  label: FeedbackDatasetLabel;
  status: IncidentStatus | string;
  reviewReason: string | null;
  reviewedBy: string | null;
  reviewedAt: Date | null;
  violationType: ViolationType | string;
  confidence: number | null;
  trackId: number | null;
  cameraId: string;
  siteId: string;
  detectedAt: Date;
  snapshotStorageKey: string | null;
  aiDetections: Record<string, unknown> | null;
}

