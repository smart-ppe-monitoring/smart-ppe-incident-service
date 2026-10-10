import {
  type PrismaClient as IncidentPrismaClient,
  Prisma as IncidentPrisma,
} from "@prisma/client-incident";
import { buildTsQuery } from "../../common/helpers/fts.helper";
import {
  incidentPrisma,
  DEFAULT_INCIDENT_TRANSACTION_OPTIONS,
} from "../../database/incident.client";
import {
  calculatePaginationSkip,
  formatPaginationMeta,
} from "../../common/helpers/pagination.helper";
import {
  CreateIncidentDto,
  UpdateIncidentDto,
  IncidentQueryDto,
  CreateEvidenceDto,
  EvidenceQueryDto,
  CreateEvidenceAccessLogDto,
  PaginatedResultDto,
  IncidentItemDto,
} from "./incident.dto";
import {
  INCIDENT_STATUS,
  ASSIGNMENT_STATUS,
} from "../../common/constants/incident.constant";

/**
 * Chuyển đổi dữ liệu Evidence an toàn với kiểu BigInt của trường fileSize
 */
export function serializeEvidence<T extends Record<string, unknown>>(evidence: T): T {
  if (!evidence || typeof evidence !== "object") return evidence;
  const clone = { ...evidence };
  if (typeof clone.fileSize === "bigint") {
    (clone as Record<string, unknown>).fileSize = Number(clone.fileSize);
  }
  return clone;
}

export function serializeIncident<T extends Record<string, unknown>>(incident: T): T {
  if (!incident || typeof incident !== "object") return incident;
  const clone = { ...incident };
  if (Array.isArray(clone.evidences)) {
    (clone as Record<string, unknown>).evidences = clone.evidences.map((ev: unknown) =>
      typeof ev === "object" && ev !== null
        ? serializeEvidence(ev as Record<string, unknown>)
        : ev,
    );
  }
  return clone;
}

export class IncidentRepository {
  private readonly db: IncidentPrismaClient;

  constructor(dbClient?: any) {
    this.db = dbClient || incidentPrisma;
  }

  // ── Incident CRUD & Lifecycle ──────────────────────────────────────────────
  async createIncident(data: CreateIncidentDto, actorId: string) {
    return this.db.$transaction(
      async (tx: any) => {
        const initialStatus = data.status || INCIDENT_STATUS.PENDING_REVIEW;

        const incident = await tx.incident.create({
          data: {
            siteId: data.siteId,
            cameraId: data.cameraId,
            violationId: data.violationId || null,
            violationType: data.violationType,
            severity: data.severity || "HIGH",
            status: initialStatus,
            detectedAt: new Date(data.detectedAt),
            description: data.description || null,
          },
        });

        // Ghi lại bản ghi khởi tạo trạng thái đầu tiên
        await tx.incidentStatusHistory.create({
          data: {
            incidentId: incident.id,
            oldStatus: "INITIAL",
            newStatus: initialStatus,
            changedBy: actorId,
            reason: "Hệ thống ghi nhận sự cố vi phạm PPE mới",
          },
        });

        // Nếu có bằng chứng ban đầu (ảnh/video chụp từ camera AI)
        if (data.initialEvidence) {
          const ev = data.initialEvidence;
          const evidence = await tx.evidence.create({
            data: {
              incidentId: incident.id,
              cameraId: ev.cameraId || data.cameraId,
              evidenceType: ev.evidenceType,
              storageKey: ev.storageKey,
              fileName: ev.fileName,
              mimeType: ev.mimeType,
              fileSize: ev.fileSize ? BigInt(ev.fileSize) : BigInt(0),
              capturedAt: new Date(ev.capturedAt),
            },
          });

          if (ev.metadata) {
            await tx.evidenceMetadata.create({
              data: {
                evidenceId: evidence.id,
                width: ev.metadata.width ?? null,
                height: ev.metadata.height ?? null,
                durationSeconds: ev.metadata.durationSeconds ?? null,
                frameRate: ev.metadata.frameRate ?? null,
                checksum: ev.metadata.checksum ?? null,
                aiDetections: ev.metadata.aiDetections ?? undefined,
              },
            });
          }
        }

        const created = await tx.incident.findUnique({
          where: { id: incident.id },
          include: {
            evidences: {
              include: { metadata: true },
            },
            statusHistory: {
              orderBy: { changedAt: "desc" },
            },
            assignments: true,
            comments: true,
          },
        });

        return serializeIncident(created);
      },
      DEFAULT_INCIDENT_TRANSACTION_OPTIONS,
    );
  }

  async findIncidentById(id: string) {
    const incident = await this.db.incident.findUnique({
      where: { id },
      include: {
        evidences: {
          include: { metadata: true },
          orderBy: { capturedAt: "desc" },
        },
        statusHistory: {
          orderBy: { changedAt: "desc" },
        },
        assignments: {
          orderBy: { assignedAt: "desc" },
        },
        comments: {
          orderBy: { createdAt: "asc" },
        },
      },
    });

    return incident ? serializeIncident(incident) : null;
  }

  async findAllIncidents(
    query: IncidentQueryDto,
  ): Promise<PaginatedResultDto<IncidentItemDto>> {
    const page = query.page || 1;
    const limit = query.limit || 20;
    const pagination = calculatePaginationSkip(page, limit);

    const where: IncidentPrisma.IncidentWhereInput = {};

    if (query.siteId) {
      where.siteId = query.siteId;
    }
    if (query.cameraId) {
      where.cameraId = query.cameraId;
    }
    if (query.violationType) {
      where.violationType = query.violationType;
    }
    if (query.severity) {
      where.severity = query.severity;
    }
    if (query.status) {
      where.status = query.status;
    }
    if (query.search) {
      where.description = { contains: query.search, mode: "insensitive" };
    }
    if (query.fromDate || query.toDate) {
      where.detectedAt = {};
      if (query.fromDate) {
        where.detectedAt.gte = new Date(query.fromDate);
      }
      if (query.toDate) {
        where.detectedAt.lte = new Date(query.toDate);
      }
    }

    const sortOrder: IncidentPrisma.SortOrder = query.sortOrder || "desc";
    const orderBy: IncidentPrisma.IncidentOrderByWithRelationInput = query.sortBy
      ? { [query.sortBy]: sortOrder }
      : { detectedAt: "desc" };

    const [total, items] = await Promise.all([
      this.db.incident.count({ where }),
      this.db.incident.findMany({
        where,
        skip: pagination.skip,
        take: pagination.take,
        orderBy,
        include: {
          evidences: {
            take: 1,
            include: { metadata: true },
          },
          _count: {
            select: { evidences: true, comments: true, assignments: true },
          },
        },
      }),
    ]);

    return {
      data: items.map((item) => serializeIncident(item) as unknown as IncidentItemDto),
      meta: formatPaginationMeta(pagination.page, pagination.limit, total),
    };
  }

  /**
   * Tìm kiếm sự cố vi phạm bằng PostgreSQL Full-Text Search (tsvector, tsquery & GIN index)
   * Tự động xếp hạng độ tương đồng bằng hàm ts_rank trên trường description và violation_type,
   * đồng thời hỗ trợ linh hoạt tiêu chí sắp xếp tùy chỉnh khi người dùng chỉ định.
   */
  async searchFts(
    query: IncidentQueryDto,
  ): Promise<PaginatedResultDto<IncidentItemDto>> {
    const search = query.search?.trim();
    if (!search) {
      return this.findAllIncidents(query);
    }

    const tsQuery = buildTsQuery(search, "prefix");
    if (!tsQuery) {
      return this.findAllIncidents(query);
    }

    const page = query.page || 1;
    const limit = query.limit || 20;
    const pagination = calculatePaginationSkip(page, limit);

    const whereConditions: IncidentPrisma.Sql[] = [
      IncidentPrisma.sql`to_tsvector('simple', coalesce(i.description, '') || ' ' || coalesce(i.violation_type, '')) @@ to_tsquery('simple', ${tsQuery})`,
    ];

    if (query.siteId) {
      whereConditions.push(IncidentPrisma.sql`i.site_id = ${query.siteId}::uuid`);
    }

    if (query.cameraId) {
      whereConditions.push(IncidentPrisma.sql`i.camera_id = ${query.cameraId}::uuid`);
    }

    if (query.violationType) {
      whereConditions.push(IncidentPrisma.sql`i.violation_type = ${query.violationType}`);
    }

    if (query.severity) {
      whereConditions.push(IncidentPrisma.sql`i.severity = ${query.severity}`);
    }

    if (query.status) {
      whereConditions.push(IncidentPrisma.sql`i.status = ${query.status}`);
    }

    if (query.fromDate) {
      whereConditions.push(IncidentPrisma.sql`i.detected_at >= ${new Date(query.fromDate)}`);
    }

    if (query.toDate) {
      whereConditions.push(IncidentPrisma.sql`i.detected_at <= ${new Date(query.toDate)}`);
    }

    const whereClause = IncidentPrisma.sql`WHERE ${IncidentPrisma.join(whereConditions, " AND ")}`;

    let orderByClause: IncidentPrisma.Sql;
    const sortOrderSql =
      query.sortOrder === "asc"
        ? IncidentPrisma.sql`ASC`
        : IncidentPrisma.sql`DESC`;

    if (query.sortBy === "detectedAt") {
      orderByClause = IncidentPrisma.sql`ORDER BY i.detected_at ${sortOrderSql}, rank DESC`;
    } else if (query.sortBy === "createdAt") {
      orderByClause = IncidentPrisma.sql`ORDER BY i.created_at ${sortOrderSql}, rank DESC`;
    } else if (query.sortBy === "severity") {
      orderByClause = IncidentPrisma.sql`ORDER BY i.severity ${sortOrderSql}, rank DESC`;
    } else if (query.sortBy === "status") {
      orderByClause = IncidentPrisma.sql`ORDER BY i.status ${sortOrderSql}, rank DESC`;
    } else {
      orderByClause = IncidentPrisma.sql`ORDER BY rank DESC, i.detected_at DESC`;
    }

    const [rankedRows, countResult] = await Promise.all([
      this.db.$queryRaw<Array<{ id: string; rank: number }>>`
        SELECT
          i.id,
          ts_rank(to_tsvector('simple', coalesce(i.description, '') || ' ' || coalesce(i.violation_type, '')), to_tsquery('simple', ${tsQuery})) as rank
        FROM incidents i
        ${whereClause}
        ${orderByClause}
        OFFSET ${pagination.skip}
        LIMIT ${pagination.take}
      `,
      this.db.$queryRaw<Array<{ count: bigint }>>`
        SELECT COUNT(*)::bigint as count
        FROM incidents i
        ${whereClause}
      `,
    ]);

    const total = Number(countResult[0]?.count ?? 0);
    const ids = rankedRows.map((r) => r.id);

    if (ids.length === 0) {
      return {
        data: [],
        meta: formatPaginationMeta(pagination.page, pagination.limit, total),
      };
    }

    const items = await this.db.incident.findMany({
      where: { id: { in: ids } },
      include: {
        evidences: {
          take: 1,
          include: { metadata: true },
        },
        _count: {
          select: { evidences: true, comments: true, assignments: true },
        },
      },
    });

    const itemMap = new Map(items.map((item) => [item.id, item]));
    const orderedItems = ids
      .map((id) => itemMap.get(id))
      .filter((item): item is NonNullable<typeof item> => Boolean(item))
      .map((item) => serializeIncident(item) as unknown as IncidentItemDto);

    return {
      data: orderedItems,
      meta: formatPaginationMeta(pagination.page, pagination.limit, total),
    };
  }

  async updateIncident(id: string, data: UpdateIncidentDto) {
    const updated = await this.db.incident.update({
      where: { id },
      data: {
        violationType: data.violationType,
        severity: data.severity,
        description: data.description !== undefined ? data.description : undefined,
      },
      include: {
        evidences: {
          include: { metadata: true },
        },
        statusHistory: {
          orderBy: { changedAt: "desc" },
        },
      },
    });

    return serializeIncident(updated);
  }

  async transitionStatus(params: {
    incidentId: string;
    oldStatus: string;
    newStatus: string;
    changedBy: string;
    reason?: string | null;
    resolvedAt?: Date | null;
  }) {
    return this.db.$transaction(
      async (tx: any) => {
        const updateData: any = {
          status: params.newStatus,
        };
        if (params.resolvedAt !== undefined) {
          updateData.resolvedAt = params.resolvedAt;
        }

        const incident = await tx.incident.update({
          where: { id: params.incidentId },
          data: updateData,
        });

        await tx.incidentStatusHistory.create({
          data: {
            incidentId: params.incidentId,
            oldStatus: params.oldStatus,
            newStatus: params.newStatus,
            changedBy: params.changedBy,
            reason: params.reason || null,
          },
        });

        const reloaded = await tx.incident.findUnique({
          where: { id: params.incidentId },
          include: {
            evidences: {
              include: { metadata: true },
            },
            statusHistory: {
              orderBy: { changedAt: "desc" },
            },
            assignments: true,
            comments: true,
          },
        });

        return serializeIncident(reloaded);
      },
      DEFAULT_INCIDENT_TRANSACTION_OPTIONS,
    );
  }

  async deleteIncident(id: string) {
    return this.db.incident.delete({
      where: { id },
    });
  }

  // ── Assignment Operations ──────────────────────────────────────────────────
  async assignIncident(incidentId: string, assignedTo: string) {
    return this.db.$transaction(
      async (tx: any) => {
        // Đóng các phân công đang active trước đó nếu có
        await tx.incidentAssignment.updateMany({
          where: {
            incidentId,
            status: ASSIGNMENT_STATUS.ACTIVE,
          },
          data: {
            status: ASSIGNMENT_STATUS.COMPLETED,
            unassignedAt: new Date(),
          },
        });

        return tx.incidentAssignment.create({
          data: {
            incidentId,
            assignedTo,
            status: ASSIGNMENT_STATUS.ACTIVE,
          },
        });
      },
      DEFAULT_INCIDENT_TRANSACTION_OPTIONS,
    );
  }

  async findAssignmentsByIncidentId(incidentId: string) {
    return this.db.incidentAssignment.findMany({
      where: { incidentId },
      orderBy: { assignedAt: "desc" },
    });
  }

  // ── Comment Operations ─────────────────────────────────────────────────────
  async addComment(incidentId: string, userId: string, comment: string) {
    return this.db.incidentComment.create({
      data: {
        incidentId,
        userId,
        comment,
      },
    });
  }

  async findCommentsByIncidentId(incidentId: string) {
    return this.db.incidentComment.findMany({
      where: { incidentId },
      orderBy: { createdAt: "asc" },
    });
  }

  // ── Evidence Operations ────────────────────────────────────────────────────
  async createEvidence(data: CreateEvidenceDto) {
    if (!data.incidentId) {
      throw new Error("incidentId là bắt buộc khi tạo Evidence");
    }

    return this.db.$transaction(
      async (tx: any) => {
        const evidence = await tx.evidence.create({
          data: {
            incidentId: data.incidentId,
            cameraId: data.cameraId,
            evidenceType: data.evidenceType,
            storageKey: data.storageKey,
            fileName: data.fileName,
            mimeType: data.mimeType,
            fileSize: data.fileSize ? BigInt(data.fileSize) : BigInt(0),
            capturedAt: new Date(data.capturedAt),
          },
        });

        let metadata = null;
        if (data.metadata) {
          metadata = await tx.evidenceMetadata.create({
            data: {
              evidenceId: evidence.id,
              width: data.metadata.width ?? null,
              height: data.metadata.height ?? null,
              durationSeconds: data.metadata.durationSeconds ?? null,
              frameRate: data.metadata.frameRate ?? null,
              checksum: data.metadata.checksum ?? null,
              aiDetections: data.metadata.aiDetections ?? undefined,
            },
          });
        }

        return serializeEvidence({
          ...evidence,
          metadata,
        });
      },
      DEFAULT_INCIDENT_TRANSACTION_OPTIONS,
    );
  }

  async findEvidenceById(id: string) {
    const evidence = await this.db.evidence.findUnique({
      where: { id },
      include: {
        metadata: true,
        incident: {
          select: {
            id: true,
            siteId: true,
            cameraId: true,
            violationType: true,
            status: true,
          },
        },
      },
    });

    return evidence ? serializeEvidence(evidence) : null;
  }

  async findAllEvidences(
    query: EvidenceQueryDto,
  ): Promise<PaginatedResultDto<any>> {
    const page = query.page || 1;
    const limit = query.limit || 20;
    const pagination = calculatePaginationSkip(page, limit);

    const where: IncidentPrisma.EvidenceWhereInput = {};
    if (query.incidentId) {
      where.incidentId = query.incidentId;
    }
    if (query.cameraId) {
      where.cameraId = query.cameraId;
    }
    if (query.evidenceType) {
      where.evidenceType = query.evidenceType;
    }

    const sortOrder: IncidentPrisma.SortOrder = query.sortOrder || "desc";
    const orderBy: IncidentPrisma.EvidenceOrderByWithRelationInput = query.sortBy
      ? { [query.sortBy]: sortOrder }
      : { capturedAt: "desc" };

    const [total, items] = await Promise.all([
      this.db.evidence.count({ where }),
      this.db.evidence.findMany({
        where,
        skip: pagination.skip,
        take: pagination.take,
        orderBy,
        include: {
          metadata: true,
        },
      }),
    ]);

    return {
      data: items.map((item: any) => serializeEvidence(item)),
      meta: formatPaginationMeta(pagination.page, pagination.limit, total),
    };
  }

  async deleteEvidence(id: string) {
    const deleted = await this.db.evidence.delete({
      where: { id },
    });
    return serializeEvidence(deleted);
  }

  async logEvidenceAccess(data: CreateEvidenceAccessLogDto) {
    return this.db.evidenceAccessLog.create({
      data: {
        evidenceId: data.evidenceId,
        userId: data.userId,
        action: data.action,
      },
    });
  }
}

export const incidentRepository = new IncidentRepository();
