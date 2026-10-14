import {
  IncidentRepository,
  incidentRepository,
} from "./incident.repository";
import {
  EvidenceStorageService,
  evidenceStorageService,
} from "../../common/services/evidence-storage.service";
import {
  NotificationService,
  notificationService,
} from "./notification-client.interface";
import { imageProcessingService } from "../../common/services/image-processing.service";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";
import {
  CreateIncidentDto,
  UpdateIncidentDto,
  IncidentQueryDto,
  ReviewIncidentDto,
  ResolveIncidentDto,
  CloseIncidentDto,
  CreateIncidentAssignmentDto,
  CreateIncidentCommentDto,
  CreateEvidenceDto,
  EvidenceQueryDto,
} from "./incident.dto";
import {
  RequestEvidenceUploadUrlDto,
  DirectUploadEvidenceDto,
  EvidenceUploadUrlResponseDto,
  EvidenceDownloadUrlResponseDto,
  VerifyEvidenceChecksumResponseDto,
} from "./evidence-storage.dto";
import {
  INCIDENT_STATUS,
  EVIDENCE_ACCESS_ACTION,
  EvidenceAccessAction,
} from "../../common/constants/incident.constant";
import { ROLES } from "../../common/constants/role.constant";

export class IncidentService {
  private readonly repository: IncidentRepository;
  private readonly storage: EvidenceStorageService;
  private readonly notification: NotificationService;

  constructor(
    repository?: IncidentRepository,
    storage?: EvidenceStorageService,
    notification?: NotificationService,
  ) {
    this.repository = repository || incidentRepository;
    this.storage = storage || evidenceStorageService;
    this.notification = notification || notificationService;
  }

  // ── Incident CRUD Operations ───────────────────────────────────────────────
  async createIncident(data: CreateIncidentDto, actorId: string) {
    const created = await this.repository.createIncident(data, actorId);

    // Tự động phát thông báo sự cố vi phạm PPE cho cán bộ an toàn (Task BE-08)
    this.notification
      .dispatchIncidentNotification({
        incidentId: created.id,
        siteId: created.siteId,
        cameraId: created.cameraId,
        violationType: created.violationType,
        severity: created.severity,
        description: created.description || undefined,
        detectedAt: created.detectedAt,
      })
      .catch((err) => {
        console.warn(
          "[IncidentService] Không thể tự động phát thông báo sự cố:",
          err?.message || err,
        );
      });

    return created;
  }

  async getIncidentById(id: string) {
    const incident = await this.repository.findIncidentById(id);
    if (!incident) {
      throw new AppError(
        "Không tìm thấy sự cố vi phạm",
        404,
        ERROR_CODE.INCIDENT_NOT_FOUND,
      );
    }
    return incident;
  }

  async getAllIncidents(query: IncidentQueryDto) {
    if (
      query.search?.trim() &&
      typeof this.repository.searchFts === "function"
    ) {
      return this.repository.searchFts(query);
    }
    return this.repository.findAllIncidents(query);
  }

  async updateIncident(id: string, data: UpdateIncidentDto) {
    const incident = await this.getIncidentById(id);

    if (incident.status === INCIDENT_STATUS.CLOSED) {
      throw new AppError(
        "Không thể cập nhật thông tin sự cố đã đóng",
        400,
        ERROR_CODE.BAD_REQUEST,
      );
    }

    return this.repository.updateIncident(id, data);
  }

  async deleteIncident(id: string) {
    await this.getIncidentById(id);
    return this.repository.deleteIncident(id);
  }

  // ── Incident Lifecycle Transitions ─────────────────────────────────────────
  async reviewIncident(id: string, dto: ReviewIncidentDto, actorId: string) {
    const incident = await this.getIncidentById(id);

    if (incident.status !== INCIDENT_STATUS.PENDING_REVIEW) {
      throw new AppError(
        `Chỉ có thể duyệt sự cố đang ở trạng thái PENDING_REVIEW (hiện tại: ${incident.status})`,
        400,
        ERROR_CODE.INVALID_STATUS_TRANSITION,
      );
    }

    const newStatus =
      dto.decision === "CONFIRMED"
        ? INCIDENT_STATUS.CONFIRMED
        : INCIDENT_STATUS.DISMISSED;

    const reason =
      dto.decision === "CONFIRMED"
        ? dto.reason || "Xác nhận vi phạm quy chuẩn an toàn PPE"
        : dto.reason;

    return this.repository.transitionStatus({
      incidentId: id,
      oldStatus: incident.status,
      newStatus,
      changedBy: actorId,
      reason,
    });
  }

  async resolveIncident(
    id: string,
    dto: ResolveIncidentDto,
    actorId: string,
    userRole?: string,
  ) {
    const incident = await this.getIncidentById(id);

    if (
      userRole &&
      userRole !== ROLES.ADMIN &&
      userRole !== ROLES.SAFETY_MANAGER &&
      userRole !== ROLES.MANAGER
    ) {
      const isAssigned = await this.repository.isUserAssignedToIncident(id, actorId);
      if (!isAssigned) {
        throw new AppError(
          "Bạn không có quyền xử lý sự cố này (chỉ người được phân công hoặc quản lý mới có quyền)",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    if (incident.status !== INCIDENT_STATUS.CONFIRMED) {
      throw new AppError(
        `Chỉ có thể giải quyết sự cố đã được xác nhận vi phạm (CONFIRMED). Trạng thái hiện tại: ${incident.status}`,
        400,
        ERROR_CODE.INVALID_STATUS_TRANSITION,
      );
    }

    return this.repository.transitionStatus({
      incidentId: id,
      oldStatus: incident.status,
      newStatus: INCIDENT_STATUS.RESOLVED,
      changedBy: actorId,
      reason: dto.resolutionNote,
      resolvedAt: new Date(),
    });
  }

  async closeIncident(
    id: string,
    dto: CloseIncidentDto,
    actorId: string,
    userRole?: string,
  ) {
    const incident = await this.getIncidentById(id);

    if (
      userRole &&
      userRole !== ROLES.ADMIN &&
      userRole !== ROLES.SAFETY_MANAGER &&
      userRole !== ROLES.MANAGER
    ) {
      const isAssigned = await this.repository.isUserAssignedToIncident(id, actorId);
      if (!isAssigned) {
        throw new AppError(
          "Bạn không có quyền đóng sự cố này (chỉ người được phân công hoặc quản lý mới có quyền)",
          403,
          ERROR_CODE.FORBIDDEN,
        );
      }
    }

    if (
      incident.status !== INCIDENT_STATUS.RESOLVED &&
      incident.status !== INCIDENT_STATUS.DISMISSED
    ) {
      throw new AppError(
        `Chỉ có thể đóng sự cố đã được giải quyết (RESOLVED) hoặc đã bị bác bỏ (DISMISSED). Trạng thái hiện tại: ${incident.status}`,
        400,
        ERROR_CODE.INVALID_STATUS_TRANSITION,
      );
    }

    return this.repository.transitionStatus({
      incidentId: id,
      oldStatus: incident.status,
      newStatus: INCIDENT_STATUS.CLOSED,
      changedBy: actorId,
      reason: dto.closeNote || "Đóng hồ sơ sự cố an toàn",
    });
  }

  // ── Assignment & Comment Operations ────────────────────────────────────────
  async assignIncident(id: string, dto: CreateIncidentAssignmentDto) {
    const incident = await this.getIncidentById(id);

    if (
      incident.status === INCIDENT_STATUS.CLOSED ||
      incident.status === INCIDENT_STATUS.DISMISSED
    ) {
      throw new AppError(
        `Không thể phân công xử lý sự cố đã ở trạng thái ${incident.status}`,
        400,
        ERROR_CODE.BAD_REQUEST,
      );
    }

    return this.repository.assignIncident(id, dto.assignedTo);
  }

  async getIncidentAssignments(id: string) {
    await this.getIncidentById(id);
    return this.repository.findAssignmentsByIncidentId(id);
  }

  async addIncidentComment(
    id: string,
    dto: CreateIncidentCommentDto,
    actorId: string,
  ) {
    await this.getIncidentById(id);
    return this.repository.addComment(id, actorId, dto.comment);
  }

  async getIncidentComments(id: string) {
    await this.getIncidentById(id);
    return this.repository.findCommentsByIncidentId(id);
  }

  // ── Evidence Operations ────────────────────────────────────────────────────
  async addEvidence(incidentId: string, dto: CreateEvidenceDto) {
    const incident = await this.getIncidentById(incidentId);

    if (incident.status === INCIDENT_STATUS.CLOSED) {
      throw new AppError(
        "Không thể đính kèm bằng chứng vào sự cố đã đóng",
        400,
        ERROR_CODE.BAD_REQUEST,
      );
    }

    return this.repository.createEvidence({
      ...dto,
      incidentId,
    });
  }

  async getEvidenceById(id: string, actorId?: string) {
    const evidence = await this.repository.findEvidenceById(id);
    if (!evidence) {
      throw new AppError(
        "Không tìm thấy bằng chứng vi phạm",
        404,
        ERROR_CODE.EVIDENCE_NOT_FOUND,
      );
    }

    if (actorId) {
      // Ghi nhận log truy cập bằng chứng không đồng bộ, không chặn luồng trả dữ liệu
      this.repository
        .logEvidenceAccess({
          evidenceId: id,
          userId: actorId,
          action: EVIDENCE_ACCESS_ACTION.VIEW,
        })
        .catch((err) => {
          console.error("Không thể ghi log truy cập bằng chứng:", err);
        });
    }

    return evidence;
  }

  async getAllEvidences(query: EvidenceQueryDto) {
    return this.repository.findAllEvidences(query);
  }

  async deleteEvidence(id: string) {
    const evidence = await this.getEvidenceById(id);
    const deleted = await this.repository.deleteEvidence(id);
    if (evidence.storageKey) {
      await this.storage.deleteObject(evidence.storageKey);
    }
    return deleted;
  }

  // ── Evidence Storage Abstraction Operations (BE-07) ────────────────────────
  /**
   * Sinh Presigned Upload PUT URL để AI Vision / Client tải trực tiếp tệp lên Object Storage (MinIO/S3)
   */
  async requestEvidenceUploadUrl(
    dto: RequestEvidenceUploadUrlDto,
    _actorId: string,
  ): Promise<EvidenceUploadUrlResponseDto> {
    const incident = await this.getIncidentById(dto.incidentId);

    if (incident.status === INCIDENT_STATUS.CLOSED) {
      throw new AppError(
        "Không thể tải lên bằng chứng cho sự cố đã đóng",
        400,
        ERROR_CODE.BAD_REQUEST,
      );
    }

    // Luôn ưu tiên siteId chính xác từ sự cố trong CSDL
    const storageKey = this.storage.generateStorageKey({
      siteId: incident.siteId || dto.siteId || "",
      cameraId: dto.cameraId,
      incidentId: dto.incidentId,
      evidenceType: dto.evidenceType,
      originalFileName: dto.fileName,
    });

    const expiresInSeconds = dto.expiresInSeconds || 900; // Mặc định 15 phút
    const uploadUrl = await this.storage.getPresignedUploadUrl(
      storageKey,
      dto.mimeType,
      expiresInSeconds,
    );

    return {
      uploadUrl,
      storageKey,
      expiresInSeconds,
    };
  }

  /**
   * Tải tệp trực tiếp (Direct Multipart Upload), tự động trích xuất metadata và tính toán SHA-256 Checksum
   */
  async uploadEvidenceDirect(
    dto: DirectUploadEvidenceDto,
    file: {
      buffer: Buffer;
      originalname: string;
      mimetype: string;
      size: number;
    },
    _actorId: string,
  ) {
    if (!file || !file.buffer || file.buffer.length === 0) {
      throw new AppError(
        "Tệp tải lên không hợp lệ hoặc dữ liệu rỗng",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    const incident = await this.getIncidentById(dto.incidentId);
    if (incident.status === INCIDENT_STATUS.CLOSED) {
      throw new AppError(
        "Không thể đính kèm bằng chứng vào sự cố đã đóng",
        400,
        ERROR_CODE.BAD_REQUEST,
      );
    }

    const storageKey = this.storage.generateStorageKey({
      siteId: incident.siteId,
      cameraId: dto.cameraId,
      incidentId: dto.incidentId,
      evidenceType: dto.evidenceType,
      originalFileName: file.originalname,
    });

    // 1. Đẩy buffer lên Object Storage (MinIO / S3) và tính SHA-256
    const uploadResult = await this.storage.uploadBuffer(
      storageKey,
      file.buffer,
      file.mimetype,
    );

    // 2. Trích xuất metadata hình ảnh bằng Sharp nếu là tệp ảnh
    let width: number | null = null;
    let height: number | null = null;
    if (file.mimetype.toLowerCase().startsWith("image/")) {
      try {
        const { metadata } = await imageProcessingService.validateImageBuffer(
          file.buffer,
        );
        width = metadata.width ?? null;
        height = metadata.height ?? null;
      } catch {
        // Bỏ qua nếu là định dạng ảnh đặc biệt không hỗ trợ đo đạc kích thước
      }
    }

    // 3. Lưu bản ghi bằng chứng vào CSDL ppe_incident_db
    return this.repository.createEvidence({
      incidentId: dto.incidentId,
      cameraId: dto.cameraId,
      evidenceType: dto.evidenceType,
      storageKey,
      fileName: file.originalname,
      mimeType: file.mimetype,
      fileSize: uploadResult.fileSize,
      capturedAt: dto.capturedAt || new Date(),
      metadata: {
        width,
        height,
        checksum: uploadResult.checksum,
        aiDetections: dto.aiDetections ?? undefined,
      },
    });
  }

  /**
   * Sinh Presigned GET URL để tải hoặc xem tệp bằng chứng an toàn có hạn định,
   * đồng thời tự động ghi nhận nhật ký truy vết vào EvidenceAccessLog (Mục 1 & 2.1 D08.pdf)
   */
  async getEvidenceDownloadUrl(
    evidenceId: string,
    actorId?: string,
    expiresInSeconds: number = 3600,
    action: EvidenceAccessAction = EVIDENCE_ACCESS_ACTION.DOWNLOAD,
  ): Promise<EvidenceDownloadUrlResponseDto> {
    // 1. Chỉ tìm bằng chứng, không truyền actorId vào getEvidenceById để tránh ghi log VIEW kép
    const evidence = await this.getEvidenceById(evidenceId);

    // 2. Sinh presigned URL với content-disposition tương ứng (inline vs attachment)
    const downloadUrl = await this.storage.getPresignedDownloadUrl(
      evidence.storageKey,
      expiresInSeconds,
      evidence.fileName,
      action,
    );

    // 3. Ghi nhận log truy vết theo đúng action thực tế được yêu cầu
    if (actorId) {
      this.repository
        .logEvidenceAccess({
          evidenceId,
          userId: actorId,
          action,
        })
        .catch((err) => {
          console.warn(
            "[EvidenceStorage] Không thể ghi log truy vết bằng chứng:",
            err?.message || err,
          );
        });
    }

    return {
      downloadUrl,
      expiresInSeconds,
      fileName: evidence.fileName,
      mimeType: evidence.mimeType,
    };
  }

  /**
   * Kiểm tra tính toàn vẹn pháp lý (Tamper Evidence Checksum Verification)
   * Tải tệp từ MinIO/S3 và đối chiếu mã băm SHA-256 với giá trị lưu trong CSDL
   */
  async verifyEvidenceIntegrity(
    evidenceId: string,
  ): Promise<VerifyEvidenceChecksumResponseDto> {
    const evidence = await this.getEvidenceById(evidenceId);
    const expectedChecksum = evidence.metadata?.checksum;

    if (!expectedChecksum) {
      throw new AppError(
        "Bằng chứng này chưa có mã băm toàn vẹn (checksum) được ghi nhận trong CSDL",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    const verifyResult = await this.storage.verifyChecksum(
      evidence.storageKey,
      expectedChecksum,
    );

    return {
      evidenceId,
      expectedChecksum,
      actualChecksum: verifyResult.actualChecksum,
      isValid: verifyResult.isValid,
      verifiedAt: new Date().toISOString(),
    };
  }
}

export const incidentService = new IncidentService();
