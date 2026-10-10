import {
  IncidentStatus,
  ViolationType,
  IncidentSeverity,
  EvidenceType,
  AssignmentStatus,
  EvidenceAccessAction,
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

export interface EvidenceQueryDto {
  page?: number;
  limit?: number;
  incidentId?: string;
  cameraId?: string;
  evidenceType?: EvidenceType;
  sortBy?: "capturedAt" | "createdAt";
  sortOrder?: "asc" | "desc";
}

export interface CreateEvidenceAccessLogDto {
  evidenceId: string;
  userId: string;
  action: EvidenceAccessAction;
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
}

export interface UpdateIncidentDto {
  violationType?: ViolationType;
  severity?: IncidentSeverity;
  description?: string | null;
}

export interface IncidentQueryDto {
  page?: number;
  limit?: number;
  search?: string;
  siteId?: string;
  cameraId?: string;
  violationType?: ViolationType;
  severity?: IncidentSeverity;
  status?: IncidentStatus;
  fromDate?: string | Date;
  toDate?: string | Date;
  sortBy?: "detectedAt" | "createdAt" | "severity" | "status";
  sortOrder?: "asc" | "desc";
}

// ── Lifecycle Transitions DTOs ───────────────────────────────────────────────
export interface ReviewIncidentDto {
  decision: "CONFIRMED" | "DISMISSED";
  reason?: string;
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
}

export interface IncidentItemDto {
  id: string;
  siteId: string;
  cameraId: string;
  violationId?: string | null;
  violationType: ViolationType;
  severity: IncidentSeverity;
  status: IncidentStatus;
  detectedAt: Date;
  resolvedAt?: Date | null;
  description?: string | null;
  createdAt: Date;
  updatedAt: Date;
  evidences?: IncidentEvidenceItemDto[];
  _count?: {
    evidences: number;
    comments: number;
    assignments: number;
  };
}

