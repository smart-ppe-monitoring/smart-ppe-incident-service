import {
  IncidentRepository,
  incidentRepository,
  isDeduplicatedIncident,
} from "./incident.repository";
import {
  EvidenceStorageService,
  evidenceStorageService,
} from "../../common/services/evidence-storage.service";
import {
  NotificationService,
  notificationService,
} from "./notification-client.interface";
import {
  IdentityUserDirectory,
  IncidentSiteUserInfo,
  identityUserDirectory,
} from "./identity-client.interface";
import { imageProcessingService } from "../../common/services/image-processing.service";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";
import {
  CreateIncidentDto,
  UpdateIncidentDto,
  IncidentQueryDto,
  IncidentUserContext,
  IncidentStatusCountsQueryDto,
  IncidentStatusCountsDto,
  FeedbackDatasetQueryDto,
  FeedbackDatasetItemDto,
  IncidentItemDto,
  PaginatedResultDto,
  ReviewIncidentDto,
  BatchReviewIncidentDto,
  BatchReviewResultDto,
  ResolveIncidentDto,
  CloseIncidentDto,
  CreateIncidentAssignmentDto,
  CreateIncidentCommentDto,
  CreateEvidenceDto,
  EvidenceQueryDto,
  EvidenceSummaryQueryDto,
  EvidenceSummaryDto,
  EvidenceAccessLogsQueryDto,
  EvidenceAccessLogItemDto,
  BatchDeleteEvidencesDto,
  BatchDeleteEvidencesResultDto,
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
  EVIDENCE_TYPE,
} from "../../common/constants/incident.constant";
import { ROLES } from "../../common/constants/role.constant";
import { isUuid } from "../../common/helpers/uuid.helper";

export class IncidentService {
  private readonly repository: IncidentRepository;
  private readonly storage: EvidenceStorageService;
  private readonly notification: NotificationService;
  private readonly identityDirectory: IdentityUserDirectory;

  constructor(
    repository?: IncidentRepository,
    storage?: EvidenceStorageService,
    notification?: NotificationService,
    identityDirectory?: IdentityUserDirectory,
  ) {
    this.repository = repository || incidentRepository;
    this.storage = storage || evidenceStorageService;
    this.notification = notification || notificationService;
    this.identityDirectory = identityDirectory || identityUserDirectory;
  }

  // ── Incident CRUD Operations ───────────────────────────────────────────────
  async createIncident(
    data: CreateIncidentDto,
    actorId: string,
    context?: { cameraCode?: string; siteName?: string },
  ) {
    if (data.initialEvidence?.storageKey && data.siteId) {
      const parts = data.initialEvidence.storageKey.split("/");
      if (parts.length >= 3 && isUuid(parts[1]) && parts[1] !== data.siteId) {
        throw new AppError(
          "storageKey của bằng chứng ban đầu không thuộc phạm vi công trường của sự cố",
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }
    }

    if (data.initialReferenceEvidence?.storageKey && data.siteId) {
      const parts = data.initialReferenceEvidence.storageKey.split("/");
      if (parts.length >= 3 && isUuid(parts[1]) && parts[1] !== data.siteId) {
        throw new AppError(
          "storageKey của ảnh đối chứng ban đầu không thuộc phạm vi công trường của sự cố",
          400,
          ERROR_CODE.VALIDATION_ERROR,
        );
      }
    }

    const created = await this.repository.createIncident(data, actorId);

    // Chống bắn trùng thông báo realtime/email nếu violationId đã tồn tại (idempotency hit)
    if (isDeduplicatedIncident(created)) {
      return created;
    }

    // Tự động phát thông báo sự cố vi phạm PPE cho cán bộ an toàn (Task BE-08)
    // SEC-29: Sử dụng hằng số tập trung EVIDENCE_TYPE thay vì hardcoded magic strings và enum trạng thái sự cố
    const snapshotEv = created.evidences?.find(
      (e: any) => e.evidenceType === EVIDENCE_TYPE.SNAPSHOT,
    );
    const refEv = created.evidences?.find(
      (e: any) => e.evidenceType === EVIDENCE_TYPE.REFERENCE_SNAPSHOT,
    );

    const snapshotDownloadUrl = snapshotEv?.storageKey
      ? `/api/v1/evidences/${snapshotEv.id}/download-url`
      : undefined;
    const referenceDownloadUrl = refEv?.storageKey
      ? `/api/v1/evidences/${refEv.id}/download-url`
      : undefined;

    this.notification
      .dispatchIncidentNotification({
        incidentId: created.id,
        siteId: created.siteId,
        cameraId: created.cameraId,
        cameraCode: context?.cameraCode,
        siteName: context?.siteName,
        violationType: created.violationType,
        severity: created.severity,
        description: created.description || undefined,
        detectedAt: created.detectedAt,
        snapshotUrl: snapshotDownloadUrl,
        referenceSnapshotUrl: referenceDownloadUrl,
        evidenceUrl: snapshotDownloadUrl,
        referenceEvidenceUrl: referenceDownloadUrl,
      })
      .catch((err) => {
        console.warn(
          "[IncidentService] Không thể tự động phát thông báo sự cố:",
          err?.message || err,
        );
      });

    return created;
  }

  private async getRawIncidentById(id: string) {
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

  private async fetchSiteUserMap(
    siteId?: string,
  ): Promise<Map<string, IncidentSiteUserInfo>> {
    if (typeof this.identityDirectory?.getSiteUserMap !== "function") {
      return new Map();
    }
    try {
      return await this.identityDirectory.getSiteUserMap(siteId);
    } catch (err: any) {
      console.warn(
        "[IncidentService] Không thể tải danh bạ người dùng công trường:",
        err?.message || err,
      );
      return new Map();
    }
  }

  private enrichComment<T extends Record<string, any>>(
    comment: T,
    userMap: Map<string, IncidentSiteUserInfo>,
    fallback?: { fullName?: string; email?: string; role?: string },
  ): T & { userName?: string; userRole?: string } {
    if (!comment || typeof comment !== "object") {
      return comment;
    }
    const matched =
      typeof comment.userId === "string" ? userMap.get(comment.userId) : undefined;
    const userName =
      matched?.fullName?.trim() ||
      fallback?.fullName?.trim() ||
      matched?.email?.trim() ||
      fallback?.email?.trim() ||
      (typeof comment.userName === "string" ? comment.userName.trim() : "");
    const userRole =
      matched?.role?.trim() ||
      fallback?.role?.trim() ||
      (typeof comment.userRole === "string" ? comment.userRole.trim() : "");

    const enriched: Record<string, any> = { ...comment };
    if (userName) {
      enriched.userName = userName;
    }
    if (userRole) {
      enriched.userRole = userRole;
    }
    return enriched as T & { userName?: string; userRole?: string };
  }

  private enrichAssignment<T extends Record<string, any>>(
    assignment: T,
    userMap: Map<string, IncidentSiteUserInfo>,
  ): T & { assignedToName?: string } {
    if (!assignment || typeof assignment !== "object") {
      return assignment;
    }
    const matched =
      typeof assignment.assignedTo === "string"
        ? userMap.get(assignment.assignedTo)
        : undefined;
    const assignedToName =
      matched?.fullName?.trim() ||
      matched?.email?.trim() ||
      (typeof assignment.assignedToName === "string"
        ? assignment.assignedToName.trim()
        : "");

    if (!assignedToName) {
      return assignment;
    }
    return {
      ...assignment,
      assignedToName,
    };
  }

  async getIncidentById(id: string) {
    const incident = await this.getRawIncidentById(id);
    const hasComments =
      Array.isArray(incident.comments) && incident.comments.length > 0;
    const hasAssignments =
      Array.isArray(incident.assignments) && incident.assignments.length > 0;

    if (!hasComments && !hasAssignments) {
      return incident;
    }

    const userMap = await this.fetchSiteUserMap(incident.siteId);
    if (userMap.size === 0) {
      return incident;
    }

    return {
      ...incident,
      ...(hasComments
        ? {
            comments: incident.comments.map((c: any) =>
              this.enrichComment(c, userMap),
            ),
          }
        : {}),
      ...(hasAssignments
        ? {
            assignments: incident.assignments.map((a: any) =>
              this.enrichAssignment(a, userMap),
            ),
          }
        : {}),
    };
  }

  /**
   * Trích xuất danh sách siteId được phép truy cập cho người dùng non-admin.
   * Trả về `undefined` cho ADMIN hoặc ngữ cảnh nội bộ không truyền userContext.
   */
  private resolveAllowedSiteIds(
    userContext?: IncidentUserContext,
  ): string[] | undefined {
    if (
      !userContext ||
      userContext.role === ROLES.ADMIN ||
      userContext.role === "ADMIN"
    ) {
      return undefined;
    }

    return Array.from(
      new Set([
        ...(userContext.siteId ? [userContext.siteId] : []),
        ...(Array.isArray(userContext.siteIds) ? userContext.siteIds : []),
      ]),
    );
  }

  private emptyIncidentPage(
    query: IncidentQueryDto,
  ): PaginatedResultDto<IncidentItemDto> {
    return {
      data: [],
      meta: {
        total: 0,
        page: query.page || 1,
        limit: query.limit || 20,
        totalPages: 0,
      },
    };
  }

  async getAllIncidents(
    query: IncidentQueryDto,
    userContext?: IncidentUserContext,
  ): Promise<PaginatedResultDto<IncidentItemDto>> {
    let effectiveQuery = query;

    if (query.assignedToMe) {
      if (!userContext?.id) {
        throw new AppError(
          "Không xác định được người dùng hiện tại để lọc việc được giao",
          401,
          ERROR_CODE.UNAUTHORIZED,
        );
      }
      if (query.assignedTo && query.assignedTo !== userContext.id) {
        return this.emptyIncidentPage(query);
      }
      effectiveQuery = {
        ...query,
        assignedTo: userContext.id,
      };
    }

    const siteFilter = this.resolveAllowedSiteIds(userContext);
    if (siteFilter !== undefined) {
      if (siteFilter.length === 0) {
        return this.emptyIncidentPage(effectiveQuery);
      }
      if (
        effectiveQuery.siteId &&
        !siteFilter.includes(effectiveQuery.siteId)
      ) {
        return this.emptyIncidentPage(effectiveQuery);
      }
    }

    if (
      effectiveQuery.search?.trim() &&
      typeof this.repository.searchFts === "function"
    ) {
      return this.repository.searchFts(effectiveQuery, siteFilter);
    }
    return this.repository.findAllIncidents(effectiveQuery, siteFilter);
  }

  async getStatusCounts(
    query: IncidentStatusCountsQueryDto,
    userContext?: IncidentUserContext,
  ): Promise<IncidentStatusCountsDto> {
    const siteFilter = this.resolveAllowedSiteIds(userContext);

    if (siteFilter !== undefined) {
      if (siteFilter.length === 0) {
        return {
          total: 0,
          pendingReview: 0,
          confirmed: 0,
          critical: 0,
          resolved: 0,
          closed: 0,
          dismissed: 0,
        };
      }

      if (query.siteId && !siteFilter.includes(query.siteId)) {
        return {
          total: 0,
          pendingReview: 0,
          confirmed: 0,
          critical: 0,
          resolved: 0,
          closed: 0,
          dismissed: 0,
        };
      }
    }

    return this.repository.getStatusCounts(query, siteFilter);
  }

  async getFeedbackDataset(
    query: FeedbackDatasetQueryDto,
    userContext?: IncidentUserContext,
  ): Promise<PaginatedResultDto<FeedbackDatasetItemDto>> {
    const siteFilter = this.resolveAllowedSiteIds(userContext);
    if (siteFilter !== undefined) {
      if (siteFilter.length === 0) {
        return {
          data: [],
          meta: {
            total: 0,
            page: query.page || 1,
            limit: query.limit || 50,
            totalPages: 0,
          },
        };
      }
      if (query.siteId && !siteFilter.includes(query.siteId)) {
        return {
          data: [],
          meta: {
            total: 0,
            page: query.page || 1,
            limit: query.limit || 50,
            totalPages: 0,
          },
        };
      }
    }

    return this.repository.findFeedbackDataset(query, siteFilter);
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
    const incident = await this.getIncidentById(id);

    // SEC-03: Dọn dẹp toàn bộ tệp bằng chứng liên quan trên Object Storage (MinIO/S3)
    // để tránh rò rỉ hoặc để lại tệp mồ côi (orphaned objects) khi bản ghi bị xóa khỏi CSDL
    if (incident.evidences && incident.evidences.length > 0) {
      await Promise.all(
        incident.evidences.map(async (ev: any) => {
          if (ev.storageKey) {
            try {
              await this.storage.deleteObject(ev.storageKey);
            } catch (err) {
              console.warn(
                `[IncidentService] Không thể dọn dẹp tệp MinIO '${ev.storageKey}' khi xóa sự cố:`,
                err,
              );
            }
          }
        }),
      );
    }

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

  async batchReviewIncidents(
    dto: BatchReviewIncidentDto,
    actorId: string,
    userContext?: IncidentUserContext,
  ): Promise<BatchReviewResultDto> {
    const uniqueIds = Array.from(new Set(dto.ids));
    const siteFilter = this.resolveAllowedSiteIds(userContext);

    if (siteFilter !== undefined && siteFilter.length === 0) {
      return {
        total: uniqueIds.length,
        updatedCount: 0,
        action: dto.action,
        newStatus:
          dto.action === "CONFIRM"
            ? INCIDENT_STATUS.CONFIRMED
            : INCIDENT_STATUS.DISMISSED,
        updatedIds: [],
      };
    }

    return this.repository.batchTransitionStatus({
      incidentIds: uniqueIds,
      action: dto.action,
      changedBy: actorId,
      reason: dto.resolutionNote,
      siteFilter,
    });
  }

  async resolveIncident(
    id: string,
    dto: ResolveIncidentDto,
    actorId: string,
    userRole?: string,
  ) {
    const incident = await this.getIncidentById(id);

    if (userRole) {
      const isManagerOrAdmin =
        userRole === ROLES.ADMIN ||
        userRole === ROLES.SAFETY_MANAGER ||
        userRole === ROLES.MANAGER;

      if (!isManagerOrAdmin) {
        const isAssigned = await this.repository.isUserAssignedToIncident(id, actorId);
        if (!isAssigned) {
          throw new AppError(
            "Bạn không có quyền xử lý sự cố này (chỉ người được phân công hoặc quản lý mới có quyền)",
            403,
            ERROR_CODE.FORBIDDEN,
          );
        }
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

    if (userRole) {
      const isManagerOrAdmin =
        userRole === ROLES.ADMIN ||
        userRole === ROLES.SAFETY_MANAGER ||
        userRole === ROLES.MANAGER;

      if (!isManagerOrAdmin) {
        const isAssigned = await this.repository.isUserAssignedToIncident(id, actorId);
        if (!isAssigned) {
          throw new AppError(
            "Bạn không có quyền đóng sự cố này (chỉ người được phân công hoặc quản lý mới có quyền)",
            403,
            ERROR_CODE.FORBIDDEN,
          );
        }
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
    const incident = await this.getRawIncidentById(id);
    const assignments = await this.repository.findAssignmentsByIncidentId(id);
    if (!Array.isArray(assignments) || assignments.length === 0) {
      return assignments;
    }

    const userMap = await this.fetchSiteUserMap(incident.siteId);
    if (userMap.size === 0) {
      return assignments;
    }

    return assignments.map((a: any) => this.enrichAssignment(a, userMap));
  }

  async addIncidentComment(
    id: string,
    dto: CreateIncidentCommentDto,
    actorId: string,
    actorContext?: { email?: string; role?: string; fullName?: string },
  ) {
    const incident = await this.getRawIncidentById(id);

    if (incident.status === INCIDENT_STATUS.CLOSED) {
      throw new AppError(
        "Không thể bình luận cho sự cố đã đóng",
        400,
        ERROR_CODE.BAD_REQUEST,
      );
    }

    const createdComment = await this.repository.addComment(
      id,
      actorId,
      dto.comment,
      incident.siteId,
    );

    const userMap = await this.fetchSiteUserMap(incident.siteId);
    const enrichedComment = this.enrichComment(
      createdComment,
      userMap,
      actorContext,
    );

    const assignedUserIds = Array.from(
      new Set(
        (incident.assignments || [])
          .filter(
            (a: any) =>
              typeof a?.assignedTo === "string" &&
              isUuid(a.assignedTo) &&
              a.status !== "COMPLETED",
          )
          .map((a: any) => a.assignedTo as string),
      ),
    );

    const participantUserIds = Array.from(
      new Set(
        (incident.comments || [])
          .filter((c: any) => typeof c?.userId === "string" && isUuid(c.userId))
          .map((c: any) => c.userId as string),
      ),
    );

    const resolvedAuthorName =
      enrichedComment?.userName || actorContext?.fullName;
    const resolvedAuthorRole =
      enrichedComment?.userRole || actorContext?.role;

    if (typeof this.notification.dispatchIncidentCommentNotification === "function") {
      this.notification
        .dispatchIncidentCommentNotification({
          incidentId: incident.id,
          commentId: createdComment?.id,
          siteId: incident.siteId,
          cameraId: incident.cameraId,
          violationType: incident.violationType,
          authorId: actorId,
          ...(resolvedAuthorName ? { authorName: resolvedAuthorName } : {}),
          ...(actorContext?.email ? { authorEmail: actorContext.email } : {}),
          ...(resolvedAuthorRole ? { authorRole: resolvedAuthorRole } : {}),
          comment: dto.comment,
          assignedUserIds,
          participantUserIds,
          createdAt: createdComment?.createdAt || new Date(),
        })
        .catch((err) => {
          console.warn(
            "[IncidentService] Không thể phát thông báo bình luận sự cố:",
            err?.message || err,
          );
        });
    }

    return enrichedComment;
  }

  async getIncidentComments(id: string) {
    const incident = await this.getRawIncidentById(id);
    const comments = await this.repository.findCommentsByIncidentId(id);
    if (!Array.isArray(comments) || comments.length === 0) {
      return comments;
    }

    const userMap = await this.fetchSiteUserMap(incident.siteId);
    if (userMap.size === 0) {
      return comments;
    }

    return comments.map((c: any) => this.enrichComment(c, userMap));
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

    // SEC-04: Phòng thủ chống tráo đổi bằng chứng xuyên công trường (Cross-Tenant/Cross-Incident Substitution)
    if (!dto.storageKey.startsWith("evidences/")) {
      throw new AppError(
        "storageKey phải bắt đầu bằng tiền tố 'evidences/'",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    if (incident.siteId) {
      const parts = dto.storageKey.split("/");
      if (parts.length >= 3 && isUuid(parts[1])) {
        if (parts[1] !== incident.siteId) {
          throw new AppError(
            "storageKey không thuộc phạm vi công trường của sự cố này",
            400,
            ERROR_CODE.VALIDATION_ERROR,
          );
        }
      }
      if (parts.length >= 7 && isUuid(parts[6])) {
        if (parts[6] !== incident.id) {
          throw new AppError(
            "storageKey không thuộc phạm vi sự cố này",
            400,
            ERROR_CODE.VALIDATION_ERROR,
          );
        }
      }
    }

    return this.repository.createEvidence({
      ...dto,
      incidentId,
    });
  }

  private assertEvidenceSiteAccess(
    evidence: { incident?: { siteId?: string | null } | null },
    userContext?: IncidentUserContext,
  ): void {
    const allowedSiteIds = this.resolveAllowedSiteIds(userContext);
    if (allowedSiteIds === undefined) {
      return;
    }

    const evidenceSiteId = evidence.incident?.siteId;
    if (
      allowedSiteIds.length === 0 ||
      !evidenceSiteId ||
      !allowedSiteIds.includes(evidenceSiteId)
    ) {
      throw new AppError(
        "Bạn không có quyền truy cập hoặc tải bằng chứng thuộc công trường này",
        403,
        ERROR_CODE.FORBIDDEN,
      );
    }
  }

  async getEvidenceById(
    id: string,
    actorId?: string,
    userContext?: IncidentUserContext,
  ) {
    const evidence = await this.repository.findEvidenceById(id);
    if (!evidence) {
      throw new AppError(
        "Không tìm thấy bằng chứng vi phạm",
        404,
        ERROR_CODE.EVIDENCE_NOT_FOUND,
      );
    }

    // SEC-09 / Issue #3: Fail-closed Site-level Ownership / BOLA guard
    this.assertEvidenceSiteAccess(evidence, userContext);

    if (actorId && typeof this.repository.logEvidenceAccess === "function") {
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

  async getAllEvidences(
    query: EvidenceQueryDto,
    userContext?: IncidentUserContext,
  ) {
    const siteFilter = this.resolveAllowedSiteIds(userContext);
    if (siteFilter !== undefined) {
      if (
        siteFilter.length === 0 ||
        (query.siteId && !siteFilter.includes(query.siteId))
      ) {
        return {
          data: [],
          meta: {
            total: 0,
            page: query.page || 1,
            limit: query.limit || 20,
            totalPages: 0,
          },
        };
      }
    }

    return this.repository.findAllEvidences(query, siteFilter);
  }

  async getEvidencesSummary(
    query: EvidenceSummaryQueryDto,
    userContext?: IncidentUserContext,
  ): Promise<EvidenceSummaryDto> {
    const siteFilter = this.resolveAllowedSiteIds(userContext);
    if (siteFilter !== undefined) {
      if (
        siteFilter.length === 0 ||
        (query.siteId && !siteFilter.includes(query.siteId))
      ) {
        return {
          total: 0,
          byType: {
            [EVIDENCE_TYPE.SNAPSHOT]: 0,
            [EVIDENCE_TYPE.REFERENCE_SNAPSHOT]: 0,
            [EVIDENCE_TYPE.VIDEO_CLIP]: 0,
          },
          totalBytes: 0,
          withChecksumCount: 0,
        };
      }
    }

    return this.repository.getEvidencesSummary(query, siteFilter);
  }

  async deleteEvidence(id: string, userContext?: IncidentUserContext) {
    const evidence = await this.getEvidenceById(id, undefined, userContext);

    if (evidence.incident?.status === INCIDENT_STATUS.CLOSED) {
      throw new AppError(
        "Không thể xóa bằng chứng thuộc sự cố đã đóng",
        400,
        ERROR_CODE.BAD_REQUEST,
      );
    }

    const actorId = userContext?.id;
    if (actorId && typeof this.repository.logEvidenceAccess === "function") {
      await this.repository
        .logEvidenceAccess({
          evidenceId: id,
          userId: actorId,
          action: EVIDENCE_ACCESS_ACTION.DELETE,
        })
        .catch((err) => {
          console.warn(
            "[IncidentService] Không thể ghi log DELETE bằng chứng:",
            err?.message || err,
          );
        });
    }

    const deleted = await this.repository.deleteEvidence(id);
    if (evidence.storageKey) {
      await this.storage.deleteObject(evidence.storageKey);
    }
    return deleted;
  }

  async batchDeleteEvidences(
    dto: BatchDeleteEvidencesDto,
    userContext?: IncidentUserContext,
  ): Promise<BatchDeleteEvidencesResultDto> {
    const uniqueIds = Array.from(new Set(dto.ids));
    const siteFilter = this.resolveAllowedSiteIds(userContext);

    if (siteFilter !== undefined && siteFilter.length === 0) {
      return {
        total: uniqueIds.length,
        deletedCount: 0,
        deletedIds: [],
        skippedIds: uniqueIds,
      };
    }

    const foundEvidences = await this.repository.findEvidencesByIds(uniqueIds);
    const foundMap = new Map<string, any>(
      foundEvidences.map((ev: any) => [ev.id, ev]),
    );

    const deletableEvidences: any[] = [];
    const skippedIds: string[] = [];

    for (const id of uniqueIds) {
      const ev = foundMap.get(id);
      if (!ev) {
        skippedIds.push(id);
        continue;
      }
      if (
        siteFilter !== undefined &&
        (!ev.incident?.siteId || !siteFilter.includes(ev.incident.siteId))
      ) {
        skippedIds.push(id);
        continue;
      }
      if (ev.incident?.status === INCIDENT_STATUS.CLOSED) {
        skippedIds.push(id);
        continue;
      }
      deletableEvidences.push(ev);
    }

    const deletableIds = deletableEvidences.map((ev) => ev.id);

    if (deletableIds.length > 0) {
      const actorId = userContext?.id;
      if (actorId && typeof this.repository.logEvidenceAccess === "function") {
        await Promise.allSettled(
          deletableIds.map((evidenceId) =>
            this.repository.logEvidenceAccess({
              evidenceId,
              userId: actorId,
              action: EVIDENCE_ACCESS_ACTION.DELETE,
            }),
          ),
        );
      }

      await this.repository.deleteEvidencesByIds(deletableIds);

      await Promise.allSettled(
        deletableEvidences
          .filter((ev) => Boolean(ev.storageKey))
          .map((ev) => this.storage.deleteObject(ev.storageKey)),
      );
    }

    return {
      total: uniqueIds.length,
      deletedCount: deletableIds.length,
      deletedIds: deletableIds,
      skippedIds,
    };
  }

  async getEvidenceAccessLogs(
    evidenceId: string,
    query: EvidenceAccessLogsQueryDto = {},
    userContext?: IncidentUserContext,
  ): Promise<PaginatedResultDto<EvidenceAccessLogItemDto>> {
    const evidence = await this.getEvidenceById(
      evidenceId,
      undefined,
      userContext,
    );
    const logsResult = await this.repository.findEvidenceAccessLogs(
      evidenceId,
      query,
    );

    if (!logsResult.data || logsResult.data.length === 0) {
      return logsResult;
    }

    const userMap = await this.fetchSiteUserMap(evidence.incident?.siteId);
    if (userMap.size === 0) {
      return logsResult;
    }

    return {
      ...logsResult,
      data: logsResult.data.map((log) => {
        const matched = userMap.get(log.userId);
        const userName =
          matched?.fullName?.trim() || matched?.email?.trim() || log.userName;
        const userRole = matched?.role?.trim() || log.userRole;
        return {
          ...log,
          ...(userName ? { userName } : {}),
          ...(userRole ? { userRole } : {}),
        };
      }),
    };
  }

  // ── Evidence Storage Abstraction Operations (BE-07) ────────────────────────
  /**
   * Sinh Presigned Upload PUT URL để AI Vision / Client tải trực tiếp tệp lên Object Storage (MinIO/S3)
   */
  async requestEvidenceUploadUrl(
    dto: RequestEvidenceUploadUrlDto,
    _actorId: string,
    userContext?: IncidentUserContext,
  ): Promise<EvidenceUploadUrlResponseDto> {
    const incident = await this.getIncidentById(dto.incidentId);
    this.assertEvidenceSiteAccess({ incident }, userContext);

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
    userContext?: IncidentUserContext,
  ) {
    if (!file || !file.buffer || file.buffer.length === 0) {
      throw new AppError(
        "Tệp tải lên không hợp lệ hoặc dữ liệu rỗng",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    const incident = await this.getIncidentById(dto.incidentId);
    this.assertEvidenceSiteAccess({ incident }, userContext);
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
    userContext?: IncidentUserContext,
  ): Promise<EvidenceDownloadUrlResponseDto> {
    // 1. Chỉ tìm bằng chứng và kiểm tra quyền công trường, không truyền actorId vào getEvidenceById để tránh ghi log VIEW kép
    const evidence = await this.getEvidenceById(evidenceId, undefined, userContext);

    // 2. Sinh presigned URL với content-disposition tương ứng (inline vs attachment)
    const downloadUrl = await this.storage.getPresignedDownloadUrl(
      evidence.storageKey,
      expiresInSeconds,
      evidence.fileName,
      action,
    );

    // 3. Ghi nhận log truy vết theo đúng action thực tế được yêu cầu
    if (actorId && typeof this.repository.logEvidenceAccess === "function") {
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
    userContext?: IncidentUserContext,
    actorId?: string,
  ): Promise<VerifyEvidenceChecksumResponseDto> {
    const evidence = await this.getEvidenceById(evidenceId, undefined, userContext);
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

    const resolvedActorId = actorId || userContext?.id;
    if (
      resolvedActorId &&
      typeof this.repository.logEvidenceAccess === "function"
    ) {
      this.repository
        .logEvidenceAccess({
          evidenceId,
          userId: resolvedActorId,
          action: EVIDENCE_ACCESS_ACTION.VERIFY,
        })
        .catch((err) => {
          console.warn(
            "[IncidentService] Không thể ghi log VERIFY bằng chứng:",
            err?.message || err,
          );
        });
    }

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
