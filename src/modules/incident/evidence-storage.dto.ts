import {
  EvidenceType,
  EvidenceAccessAction,
} from "../../common/constants/incident.constant";
import { CreateEvidenceMetadataDto } from "./incident.dto";

export interface RequestEvidenceUploadUrlDto {
  incidentId: string;
  cameraId: string;
  siteId?: string;
  evidenceType: EvidenceType;
  fileName: string;
  mimeType: string;
  fileSize?: number;
  expiresInSeconds?: number;
}

export interface EvidenceUploadUrlResponseDto {
  uploadUrl: string;
  storageKey: string;
  expiresInSeconds: number;
}

export interface DirectUploadEvidenceDto {
  incidentId: string;
  cameraId: string;
  evidenceType: EvidenceType;
  capturedAt?: string | Date;
  aiDetections?: Record<string, unknown> | null;
}

export interface DownloadUrlQueryDto {
  expiresInSeconds?: number;
  action?: EvidenceAccessAction;
}

export interface EvidenceDownloadUrlResponseDto {
  downloadUrl: string;
  expiresInSeconds: number;
  fileName: string;
  mimeType: string;
}

export interface VerifyEvidenceChecksumResponseDto {
  evidenceId: string;
  expectedChecksum: string;
  actualChecksum: string;
  isValid: boolean;
  verifiedAt: string;
}

