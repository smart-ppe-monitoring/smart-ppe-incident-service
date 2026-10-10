import { openapiRegistry } from "../../config/openapi/openapi.registry";
import {
  createIncidentSchema,
  updateIncidentSchema,
  incidentQuerySchema,
  incidentIdParamSchema,
  reviewIncidentSchema,
  resolveIncidentSchema,
  closeIncidentSchema,
  createIncidentAssignmentSchema,
  createIncidentCommentSchema,
  createEvidenceSchema,
  evidenceIdParamSchema,
  evidenceQuerySchema,
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
  openapiRegistry.register("ReviewIncidentRequest", reviewIncidentSchema);
  openapiRegistry.register("ResolveIncidentRequest", resolveIncidentSchema);
  openapiRegistry.register("CloseIncidentRequest", closeIncidentSchema);
  openapiRegistry.register("CreateIncidentAssignmentRequest", createIncidentAssignmentSchema);
  openapiRegistry.register("CreateIncidentCommentRequest", createIncidentCommentSchema);
  openapiRegistry.register("CreateEvidenceRequest", createEvidenceSchema);
  openapiRegistry.register("RequestEvidenceUploadUrlRequest", requestEvidenceUploadUrlSchema);
  openapiRegistry.register("DirectUploadEvidenceRequest", directUploadEvidenceSchema);

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
    summary: "Danh sách bình luận/trao đổi về sự cố",
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
    summary: "Thêm bình luận trao đổi về sự cố",
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
    path: "/evidences",
    tags: ["Evidences"],
    summary: "Danh sách bằng chứng số (phân trang & lọc)",
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
}
