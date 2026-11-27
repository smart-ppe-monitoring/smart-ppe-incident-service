import { openapiRegistry } from "../../config/openapi/openapi.registry";
import {
  createIncidentSchema,
  updateIncidentSchema,
  incidentQuerySchema,
  incidentStatusCountsQuerySchema,
  feedbackDatasetQuerySchema,
  incidentIdParamSchema,
  batchReviewIncidentsSchema,
  batchAssignIncidentsSchema,
  batchResolveIncidentsSchema,
  batchCloseIncidentsSchema,
  reviewIncidentSchema,
  resolveIncidentSchema,
  closeIncidentSchema,
  createIncidentAssignmentSchema,
  createIncidentCommentSchema,
  createEvidenceSchema,
  evidenceIdParamSchema,
  evidenceQuerySchema,
  evidenceSummaryQuerySchema,
  evidenceAccessLogsQuerySchema,
  batchDeleteEvidencesSchema,
} from "./incident.validation";
import {
  requestEvidenceUploadUrlSchema,
  directUploadEvidenceSchema,
  downloadUrlQuerySchema,
} from "./evidence-storage.validation";
import { z } from "zod";

export function registerIncidentOpenApi(): void {
  openapiRegistry.register("CreateIncidentRequest", createIncidentSchema);
  openapiRegistry.register("UpdateIncidentRequest", updateIncidentSchema);
  openapiRegistry.register("BatchReviewIncidentRequest", batchReviewIncidentsSchema);
  openapiRegistry.register("BatchAssignIncidentRequest", batchAssignIncidentsSchema);
  openapiRegistry.register("BatchResolveIncidentRequest", batchResolveIncidentsSchema);
  openapiRegistry.register("BatchCloseIncidentRequest", batchCloseIncidentsSchema);
  openapiRegistry.register("ReviewIncidentRequest", reviewIncidentSchema);
  openapiRegistry.register("ResolveIncidentRequest", resolveIncidentSchema);
  openapiRegistry.register("CloseIncidentRequest", closeIncidentSchema);
  openapiRegistry.register("CreateIncidentAssignmentRequest", createIncidentAssignmentSchema);
  openapiRegistry.register("CreateIncidentCommentRequest", createIncidentCommentSchema);
  openapiRegistry.register("CreateEvidenceRequest", createEvidenceSchema);
  openapiRegistry.register("RequestEvidenceUploadUrlRequest", requestEvidenceUploadUrlSchema);
  openapiRegistry.register("DirectUploadEvidenceRequest", directUploadEvidenceSchema);

  const batchReviewResultSchema = z.object({
    total: z.number().openapi({ example: 5, description: "Tổng số bản ghi yêu cầu cập nhật" }),
    updatedCount: z.number().openapi({ example: 5, description: "Số bản ghi được cập nhật thành công" }),
    action: z.enum(["CONFIRM", "REJECT"]).openapi({ example: "CONFIRM", description: "Hành động phê duyệt áp dụng" }),
    newStatus: z.string().openapi({ example: "CONFIRMED", description: "Trạng thái mới sau cập nhật" }),
    updatedIds: z.array(z.string().uuid()).openapi({
      example: ["019313a4-23b4-7890-8123-456789abcdef"],
      description: "Danh sách ID các sự cố đã cập nhật thành công",
    }),
  });

  const batchReviewResponseSchema = z.object({
    success: z.boolean().openapi({ example: true }),
    message: z.string().openapi({ example: "Đã duyệt thành công 5/5 sự cố" }),
    data: batchReviewResultSchema,
  });

  const incidentStatusCountsDtoSchema = z.object({
    total: z.number().openapi({ example: 48, description: "Tổng số sự cố thỏa mãn bộ lọc" }),
    pendingReview: z.number().openapi({ example: 6, description: "Số sự cố đang chờ người dùng kiểm duyệt" }),
    confirmed: z.number().openapi({ example: 5, description: "Số sự cố đã xác nhận vi phạm (CONFIRMED)" }),
    critical: z.number().openapi({ example: 5, description: "Số sự cố ở mức độ nghiêm trọng CRITICAL" }),
    resolved: z.number().openapi({ example: 37, description: "Số sự cố đã xử lý xong (RESOLVED hoặc CLOSED)" }),
    closed: z.number().openapi({ example: 12, description: "Số sự cố đã đóng hồ sơ (CLOSED)" }),
    dismissed: z.number().openapi({ example: 4, description: "Số sự cố đã bác bỏ cảnh báo sai (DISMISSED)" }),
  });

  const incidentStatusCountsResponseSchema = z.object({
    success: z.boolean().openapi({ example: true }),
    data: incidentStatusCountsDtoSchema,
  });

  openapiRegistry.register("BatchReviewResultDto", batchReviewResultSchema);
  openapiRegistry.register("BatchReviewResponse", batchReviewResponseSchema);
  openapiRegistry.register("IncidentStatusCountsDto", incidentStatusCountsDtoSchema);
  openapiRegistry.register("IncidentStatusCountsResponse", incidentStatusCountsResponseSchema);

  // ── Incidents ──────────────────────────────────────────────────────────────
  openapiRegistry.registerPath({
    method: "get",
    path: "/incidents",
    tags: ["Incidents"],
    summary: "Danh sách sự cố vi phạm PPE (phân trang & bộ lọc)",
    security: [{ BearerAuth: [] }],
    request: { query: incidentQuerySchema },
    responses: {
      200: {
        description: "Lấy danh sách sự cố thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.array(z.any()),
              meta: z.object({
                total: z.number(),
                page: z.number(),
                limit: z.number(),
                totalPages: z.number(),
              }),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/incidents",
    tags: ["Incidents"],
    summary: "Ghi nhận sự cố vi phạm PPE mới",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": { schema: createIncidentSchema },
        },
      },
    },
    responses: {
      201: {
        description: "Tạo sự cố vi phạm thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.any(),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/incidents/batch-review",
    tags: ["Incidents"],
    summary: "Duyệt hàng loạt sự cố vi phạm PPE (CONFIRM hoặc REJECT)",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": {
            schema: batchReviewIncidentsSchema,
          },
        },
      },
    },
    responses: {
      200: {
        description: "Duyệt hàng loạt sự cố thành công",
        content: {
          "application/json": {
            schema: batchReviewResponseSchema,
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/incidents/batch-assign",
    tags: ["Incidents"],
    summary: "Phân công hàng loạt sự cố CONFIRMED cho người xử lý thuộc công trường",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": {
            schema: batchAssignIncidentsSchema,
          },
        },
      },
    },
    responses: {
      200: {
        description: "Phân công hàng loạt sự cố thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              message: z.string(),
              data: z.object({
                total: z.number(),
                assignedCount: z.number(),
                assignedTo: z.string().uuid(),
                assignedToName: z.string().optional(),
                assignedIds: z.array(z.string().uuid()),
                skippedIds: z.array(z.string().uuid()),
              }),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/incidents/batch-resolve",
    tags: ["Incidents"],
    summary: "Báo cáo khắc phục hàng loạt sự cố CONFIRMED (hỗ trợ dùng chung 1 bằng chứng sau khắc phục)",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": {
            schema: batchResolveIncidentsSchema,
          },
        },
      },
    },
    responses: {
      200: {
        description: "Khắc phục hàng loạt sự cố thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              message: z.string(),
              data: z.object({
                total: z.number(),
                resolvedCount: z.number(),
                newStatus: z.string(),
                resolvedIds: z.array(z.string().uuid()),
                skippedIds: z.array(z.string().uuid()),
                sharedEvidenceStorageKey: z.string().optional(),
              }),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/incidents/batch-close",
    tags: ["Incidents"],
    summary: "Đóng hồ sơ hàng loạt sự cố ở trạng thái RESOLVED hoặc DISMISSED",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": {
            schema: batchCloseIncidentsSchema,
          },
        },
      },
    },
    responses: {
      200: {
        description: "Đóng hàng loạt sự cố thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              message: z.string(),
              data: z.object({
                total: z.number(),
                closedCount: z.number(),
                newStatus: z.string(),
                closedIds: z.array(z.string().uuid()),
                skippedIds: z.array(z.string().uuid()),
              }),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "get",
    path: "/incidents/status-counts",
    tags: ["Incidents"],
    summary: "Thống kê số lượng sự cố theo trạng thái cho thẻ KPI (tổng số, chờ duyệt, đã xác nhận, nguy cấp, đã xử lý, đã đóng, bác bỏ)",
    security: [{ BearerAuth: [] }],
    request: { query: incidentStatusCountsQuerySchema },
    responses: {
      200: {
        description: "Lấy thống kê số lượng sự cố thành công",
        content: {
          "application/json": {
            schema: incidentStatusCountsResponseSchema,
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "get",
    path: "/incidents/feedback-dataset",
    tags: ["Incidents"],
    summary: "Truy xuất tập mẫu phản hồi True Violation / False Alarm kèm ảnh & aiDetections phục vụ huấn luyện lại mô hình AI (D08)",
    security: [{ BearerAuth: [] }],
    request: { query: feedbackDatasetQuerySchema },
    responses: {
      200: {
        description: "Lấy tập dữ liệu phản hồi AI thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.array(z.any()),
              meta: z.object({
                total: z.number(),
                page: z.number(),
                limit: z.number(),
                totalPages: z.number(),
              }),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "get",
    path: "/incidents/{id}",
    tags: ["Incidents"],
    summary: "Chi tiết sự cố vi phạm PPE kèm bằng chứng và lịch sử",
    security: [{ BearerAuth: [] }],
    request: { params: incidentIdParamSchema },
    responses: {
      200: {
        description: "Lấy chi tiết sự cố thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.any(),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "put",
    path: "/incidents/{id}",
    tags: ["Incidents"],
    summary: "Cập nhật thông tin sự cố",
    security: [{ BearerAuth: [] }],
    request: {
      params: incidentIdParamSchema,
      body: {
        content: {
          "application/json": { schema: updateIncidentSchema },
        },
      },
    },
    responses: {
      200: {
        description: "Cập nhật sự cố thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.any(),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "delete",
    path: "/incidents/{id}",
    tags: ["Incidents"],
    summary: "Xóa hồ sơ sự cố vi phạm",
    security: [{ BearerAuth: [] }],
    request: { params: incidentIdParamSchema },
    responses: {
      200: {
        description: "Xóa sự cố thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.any(),
            }),
          },
        },
      },
    },
  });

  // ── Lifecycle Transitions ──────────────────────────────────────────────────
  openapiRegistry.registerPath({
    method: "post",
    path: "/incidents/{id}/review",
    tags: ["Incidents"],
    summary: "Duyệt sự cố vi phạm (CONFIRMED vi phạm thật hoặc DISMISSED cảnh báo sai)",
    security: [{ BearerAuth: [] }],
    request: {
      params: incidentIdParamSchema,
      body: {
        content: {
          "application/json": { schema: reviewIncidentSchema },
        },
      },
    },
    responses: {
      200: {
        description: "Duyệt sự cố thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.any(),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/incidents/{id}/resolve",
    tags: ["Incidents"],
    summary: "Giải quyết sự cố vi phạm (RESOLVED)",
    security: [{ BearerAuth: [] }],
    request: {
      params: incidentIdParamSchema,
      body: {
        content: {
          "application/json": { schema: resolveIncidentSchema },
        },
      },
    },
    responses: {
      200: {
        description: "Giải quyết sự cố thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.any(),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/incidents/{id}/close",
    tags: ["Incidents"],
    summary: "Đóng hồ sơ sự cố (CLOSED)",
    security: [{ BearerAuth: [] }],
    request: {
      params: incidentIdParamSchema,
      body: {
        content: {
          "application/json": { schema: closeIncidentSchema },
        },
      },
    },
    responses: {
      200: {
        description: "Đóng hồ sơ sự cố thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.any(),
            }),
          },
        },
      },
    },
  });

  // ── Assignments & Comments ─────────────────────────────────────────────────
  openapiRegistry.registerPath({
    method: "get",
    path: "/incidents/{id}/assignments",
    tags: ["Incidents"],
    summary: "Lịch sử phân công người xử lý sự cố",
    security: [{ BearerAuth: [] }],
    request: { params: incidentIdParamSchema },
    responses: {
      200: {
        description: "Lấy lịch sử phân công thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.array(z.any()),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/incidents/{id}/assignments",
    tags: ["Incidents"],
    summary: "Phân công người xử lý sự cố mới",
    security: [{ BearerAuth: [] }],
    request: {
      params: incidentIdParamSchema,
      body: {
        content: {
          "application/json": { schema: createIncidentAssignmentSchema },
        },
      },
    },
    responses: {
      201: {
        description: "Phân công thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.any(),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "get",
    path: "/incidents/{id}/comments",
    tags: ["Incidents"],
    summary: "Danh sách bình luận/trao đổi về sự cố (kèm userName, userRole)",
    security: [{ BearerAuth: [] }],
    request: { params: incidentIdParamSchema },
    responses: {
      200: {
        description: "Lấy danh sách bình luận thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.array(z.any()),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/incidents/{id}/comments",
    tags: ["Incidents"],
    summary: "Thêm bình luận trao đổi về sự cố (chặn nếu sự cố đã CLOSED)",
    security: [{ BearerAuth: [] }],
    request: {
      params: incidentIdParamSchema,
      body: {
        content: {
          "application/json": { schema: createIncidentCommentSchema },
        },
      },
    },
    responses: {
      201: {
        description: "Thêm bình luận thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.any(),
            }),
          },
        },
      },
    },
  });

  // ── Evidences ──────────────────────────────────────────────────────────────
  openapiRegistry.registerPath({
    method: "post",
    path: "/incidents/{id}/evidences",
    tags: ["Evidences"],
    summary: "Đính kèm thêm bằng chứng số vào sự cố",
    security: [{ BearerAuth: [] }],
    request: {
      params: incidentIdParamSchema,
      body: {
        content: {
          "application/json": { schema: createEvidenceSchema },
        },
      },
    },
    responses: {
      201: {
        description: "Đính kèm bằng chứng thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.any(),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "get",
    path: "/evidences/summary",
    tags: ["Evidences"],
    summary: "Thống kê tổng hợp bằng chứng số theo loại, dung lượng và checksum (tuân thủ site-scoping)",
    security: [{ BearerAuth: [] }],
    request: { query: evidenceSummaryQuerySchema },
    responses: {
      200: {
        description: "Lấy thống kê bằng chứng thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.object({
                total: z.number(),
                byType: z.record(z.number()),
                totalBytes: z.number(),
                withChecksumCount: z.number(),
              }),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/evidences/batch-delete",
    tags: ["Evidences"],
    summary: "Xóa hàng loạt bằng chứng số (giới hạn 100, kiểm tra site-scoping & chặn sự cố CLOSED)",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": { schema: batchDeleteEvidencesSchema },
        },
      },
    },
    responses: {
      200: {
        description: "Xóa hàng loạt bằng chứng thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              message: z.string(),
              data: z.object({
                total: z.number(),
                deletedCount: z.number(),
                deletedIds: z.array(z.string()),
                skippedIds: z.array(z.string()),
              }),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "get",
    path: "/evidences",
    tags: ["Evidences"],
    summary: "Danh sách bằng chứng số (phân trang, lọc site/sự cố/checksum/thời gian, kèm tóm tắt incident)",
    security: [{ BearerAuth: [] }],
    request: { query: evidenceQuerySchema },
    responses: {
      200: {
        description: "Lấy danh sách bằng chứng thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.array(z.any()),
              meta: z.object({
                total: z.number(),
                page: z.number(),
                limit: z.number(),
                totalPages: z.number(),
              }),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "get",
    path: "/evidences/{id}/access-logs",
    tags: ["Evidences"],
    summary: "Nhật ký truy vết truy cập bằng chứng số (VIEW / DOWNLOAD / VERIFY / DELETE)",
    security: [{ BearerAuth: [] }],
    request: {
      params: evidenceIdParamSchema,
      query: evidenceAccessLogsQuerySchema,
    },
    responses: {
      200: {
        description: "Lấy nhật ký truy cập bằng chứng thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.array(z.any()),
              meta: z.object({
                total: z.number(),
                page: z.number(),
                limit: z.number(),
                totalPages: z.number(),
              }),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "get",
    path: "/evidences/{id}",
    tags: ["Evidences"],
    summary: "Chi tiết bằng chứng số kèm metadata và tự động ghi log truy cập",
    security: [{ BearerAuth: [] }],
    request: { params: evidenceIdParamSchema },
    responses: {
      200: {
        description: "Lấy thông tin bằng chứng thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.any(),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "delete",
    path: "/evidences/{id}",
    tags: ["Evidences"],
    summary: "Xóa bằng chứng số",
    security: [{ BearerAuth: [] }],
    request: { params: evidenceIdParamSchema },
    responses: {
      200: {
        description: "Xóa bằng chứng thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.any(),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/evidences/upload-url",
    tags: ["Evidences"],
    summary: "Yêu cầu Presigned Upload URL có hạn định để tải trực tiếp lên MinIO/S3",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": { schema: requestEvidenceUploadUrlSchema },
        },
      },
    },
    responses: {
      200: {
        description: "Sinh Presigned Upload URL thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.object({
                uploadUrl: z.string(),
                storageKey: z.string(),
                expiresInSeconds: z.number(),
              }),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "post",
    path: "/evidences/direct-upload",
    tags: ["Evidences"],
    summary: "Tải lên tệp bằng chứng số trực tiếp dạng multipart/form-data vào MinIO",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "multipart/form-data": { schema: directUploadEvidenceSchema },
        },
      },
    },
    responses: {
      201: {
        description: "Tải lên bằng chứng và lưu CSDL thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.any(),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "get",
    path: "/evidences/{id}/download-url",
    tags: ["Evidences"],
    summary: "Lấy Presigned URL xem hoặc tải bằng chứng số có hạn định (kèm ghi log truy vết)",
    security: [{ BearerAuth: [] }],
    request: {
      params: evidenceIdParamSchema,
      query: downloadUrlQuerySchema,
    },
    responses: {
      200: {
        description: "Sinh Presigned Download URL thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.object({
                downloadUrl: z.string(),
                expiresInSeconds: z.number(),
                fileName: z.string(),
                mimeType: z.string(),
              }),
            }),
          },
        },
      },
    },
  });

  openapiRegistry.registerPath({
    method: "get",
    path: "/evidences/{id}/verify-checksum",
    tags: ["Evidences"],
    summary: "Kiểm tra toàn vẹn và chống giả mạo bằng chứng số (Tamper Evidence Verification)",
    security: [{ BearerAuth: [] }],
    request: {
      params: evidenceIdParamSchema,
    },
    responses: {
      200: {
        description: "Kiểm tra checksum thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean(),
              data: z.object({
                evidenceId: z.string(),
                expectedChecksum: z.string(),
                actualChecksum: z.string(),
                isValid: z.boolean(),
                verifiedAt: z.string(),
              }),
            }),
          },
        },
      },
    },
  });

  // ── Diagnostics & Health Endpoints ─────────────────────────────────────────
  openapiRegistry.registerPath({
    method: "get",
    path: "/incidents/health",
    tags: ["Incidents"],
    summary: "Kiểm tra trạng thái hoạt động của Incident Service",
    responses: {
      200: {
        description: "Dịch vụ hoạt động bình thường",
        content: {
          "application/json": {
            schema: z.object({
              status: z.string().openapi({ example: "ok" }),
              service: z.string().openapi({ example: "incident-service" }),
              timestamp: z.string().datetime(),
              uptime: z.number(),
            }),
          },
        },
      },
    },
  });
}
