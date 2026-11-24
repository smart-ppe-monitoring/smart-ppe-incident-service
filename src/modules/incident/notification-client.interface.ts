import { envConfig } from "../../config/env.config";
import { GATEWAY_HEADERS } from "../../common/constants/gateway.constant";

export interface IncidentNotificationPayload {
  incidentId: string;
  siteId: string;
  cameraId: string;
  cameraCode?: string;
  siteName?: string;
  violationType: string;
  severity: string;
  description?: string;
  detectedAt: Date | string;
  snapshotUrl?: string;
  referenceSnapshotUrl?: string;
  evidenceUrl?: string;
  referenceEvidenceUrl?: string;
  recipientUserIds?: string[];
}

export interface IncidentCommentNotificationPayload {
  incidentId: string;
  commentId?: string;
  siteId?: string;
  cameraId?: string;
  cameraCode?: string;
  siteName?: string;
  violationType?: string;
  authorId: string;
  authorName?: string;
  authorEmail?: string;
  authorRole?: string;
  comment: string;
  assignedUserIds?: string[];
  participantUserIds?: string[];
  createdAt?: Date | string;
}

export interface NotificationService {
  dispatchIncidentNotification(payload: IncidentNotificationPayload): Promise<any>;
  dispatchIncidentCommentNotification?(
    payload: IncidentCommentNotificationPayload,
  ): Promise<any>;
}

export interface HttpNotificationClientOptions {
  baseUrl?: string;
  internalToken?: string;
  gatewaySecret?: string;
  timeoutMs?: number;
  fetcher?: typeof fetch;
}

export function isAutomatedTestRuntime(): boolean {
  return (
    process.env.NODE_ENV === "test" ||
    Boolean(process.env.NODE_TEST_CONTEXT)
  );
}

/**
 * HTTP Client M2M đẩy sự kiện vi phạm PPE mới sang Notification Service (:8889)
 * qua endpoint nội bộ `POST /api/v1/notifications/internal/trigger-incident`.
 */
export class HttpNotificationServiceClient implements NotificationService {
  private readonly customBaseUrl?: string;
  private readonly customInternalToken?: string;
  private readonly customGatewaySecret?: string;
  private readonly timeoutMs: number;
  private readonly customFetcher?: typeof fetch;

  constructor(options: HttpNotificationClientOptions = {}) {
    this.customBaseUrl = options.baseUrl;
    this.customInternalToken = options.internalToken;
    this.customGatewaySecret = options.gatewaySecret;
    this.timeoutMs = options.timeoutMs ?? 4000;
    this.customFetcher = options.fetcher;
  }

  async dispatchIncidentNotification(payload: IncidentNotificationPayload) {
    const evidenceUrl = payload.evidenceUrl || payload.snapshotUrl;
    const referenceEvidenceUrl =
      payload.referenceEvidenceUrl || payload.referenceSnapshotUrl;

    const requestBody = {
      incidentId: payload.incidentId,
      siteId: payload.siteId,
      cameraId: payload.cameraId,
      ...(payload.cameraCode ? { cameraCode: payload.cameraCode } : {}),
      ...(payload.siteName ? { siteName: payload.siteName } : {}),
      violationType: payload.violationType,
      severity: payload.severity,
      ...(payload.description ? { description: payload.description } : {}),
      detectedAt:
        payload.detectedAt instanceof Date
          ? payload.detectedAt.toISOString()
          : payload.detectedAt,
      ...(evidenceUrl ? { evidenceUrl } : {}),
      ...(referenceEvidenceUrl ? { referenceEvidenceUrl } : {}),
      ...(payload.recipientUserIds !== undefined
        ? { recipientUserIds: payload.recipientUserIds }
        : {}),
    };

    return this.postInternal(
      "/api/v1/notifications/internal/trigger-incident",
      payload.incidentId,
      requestBody,
    );
  }

  async dispatchIncidentCommentNotification(
    payload: IncidentCommentNotificationPayload,
  ) {
    const requestBody = {
      incidentId: payload.incidentId,
      ...(payload.commentId ? { commentId: payload.commentId } : {}),
      ...(payload.siteId ? { siteId: payload.siteId } : {}),
      ...(payload.cameraId ? { cameraId: payload.cameraId } : {}),
      ...(payload.cameraCode ? { cameraCode: payload.cameraCode } : {}),
      ...(payload.siteName ? { siteName: payload.siteName } : {}),
      ...(payload.violationType ? { violationType: payload.violationType } : {}),
      authorId: payload.authorId,
      ...(payload.authorName ? { authorName: payload.authorName } : {}),
      ...(payload.authorEmail ? { authorEmail: payload.authorEmail } : {}),
      ...(payload.authorRole ? { authorRole: payload.authorRole } : {}),
      comment: payload.comment,
      ...(payload.assignedUserIds !== undefined
        ? { assignedUserIds: payload.assignedUserIds }
        : {}),
      ...(payload.participantUserIds !== undefined
        ? { participantUserIds: payload.participantUserIds }
        : {}),
      ...(payload.createdAt
        ? {
            createdAt:
              payload.createdAt instanceof Date
                ? payload.createdAt.toISOString()
                : payload.createdAt,
          }
        : {}),
    };

    return this.postInternal(
      "/api/v1/notifications/internal/trigger-incident-comment",
      payload.incidentId,
      requestBody,
    );
  }

  private async postInternal(
    path: string,
    incidentId: string,
    requestBody: Record<string, unknown>,
  ) {
    // Trong unit tests chạy offline mà không inject mock fetcher, bỏ qua gọi HTTP thật tránh lỗi kết nối
    if (!this.customFetcher && isAutomatedTestRuntime()) {
      return {
        dispatched: false,
        skipped: true,
        incidentId,
      };
    }

    const baseUrl = (
      this.customBaseUrl ?? envConfig.notification.serviceUrl
    ).replace(/\/+$/, "");
    const internalToken = (
      this.customInternalToken ?? envConfig.internalService.token
    ).trim();
    const gatewaySecret = (
      this.customGatewaySecret ?? envConfig.gateway.internalSecret
    ).trim();

    if (!baseUrl || !internalToken) {
      console.warn(
        "[NotificationClient] NOTIFICATION_SERVICE_URL hoặc INTERNAL_SERVICE_TOKEN chưa cấu hình, bỏ qua phát cảnh báo realtime.",
      );
      return {
        dispatched: false,
        incidentId,
      };
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
      [GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN]: internalToken,
    };
    if (gatewaySecret) {
      headers[GATEWAY_HEADERS.INTERNAL_SECRET] = gatewaySecret;
    }

    const fetcher = this.customFetcher || fetch;
    const response = await fetcher(`${baseUrl}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      throw new Error(
        `Notification Service responded with HTTP ${response.status}: ${errorText.slice(0, 300)}`,
      );
    }

    const result = await response.json().catch(() => ({}));
    return {
      dispatched: true,
      incidentId,
      data: (result as any)?.data ?? result,
    };
  }
}

export const notificationService: NotificationService =
  new HttpNotificationServiceClient();
