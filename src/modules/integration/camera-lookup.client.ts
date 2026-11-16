import { envConfig } from "../../config/env.config";
import { GATEWAY_HEADERS } from "../../common/constants/gateway.constant";
import { AppError } from "../../common/errors/app-error";
import { ERROR_CODE } from "../../common/errors/error-code";

export interface CameraIdentity {
  id: string;
  siteId: string;
  code: string;
  name?: string;
}

interface CacheEntry {
  value: CameraIdentity;
  expiresAt: number;
}

export class CameraLookupClient {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly TTL_MS = 60_000;

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: "application/json",
    };
    if (envConfig.internalService.token) {
      headers[GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN] =
        envConfig.internalService.token;
    }
    if (envConfig.gateway.internalSecret) {
      headers[GATEWAY_HEADERS.INTERNAL_SECRET] =
        envConfig.gateway.internalSecret;
    }
    return headers;
  }

  async lookupCamera(query: {
    id?: string;
    code?: string;
  }): Promise<CameraIdentity> {
    const cacheKey = query.id
      ? `id:${query.id}`
      : `code:${(query.code || "").trim().toUpperCase()}`;

    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.value;
    }

    const baseUrl = envConfig.camera.serviceUrl.replace(/\/+$/, "");
    const search = new URLSearchParams();
    if (query.id) search.set("id", query.id);
    if (query.code) search.set("code", query.code.trim().toUpperCase());

    const url = `${baseUrl}/api/v1/cameras/internal/lookup?${search.toString()}`;

    let response: Response;
    try {
      response = await fetch(url, {
        method: "GET",
        headers: this.buildHeaders(),
        signal: AbortSignal.timeout(4000),
      });
    } catch (error: any) {
      throw new AppError(
        `Không thể kết nối tới Camera Service để tra cứu camera: ${error?.message || "timeout"}`,
        503,
        ERROR_CODE.SERVICE_UNAVAILABLE,
      );
    }

    if (response.status === 404) {
      throw new AppError(
        `Không tìm thấy camera trong hệ thống (${query.code || query.id})`,
        422,
        ERROR_CODE.VALIDATION_ERROR,
      );
    }

    if (!response.ok) {
      throw new AppError(
        `Camera Service trả về lỗi HTTP ${response.status} khi tra cứu camera`,
        502,
        ERROR_CODE.SERVICE_UNAVAILABLE,
      );
    }

    const body = (await response.json()) as {
      success?: boolean;
      data?: Partial<CameraIdentity>;
    };
    const cam = body?.data;
    if (!cam?.id || !cam?.siteId) {
      throw new AppError(
        "Dữ liệu camera nội bộ không đầy đủ (thiếu id hoặc siteId)",
        502,
        ERROR_CODE.SERVICE_UNAVAILABLE,
      );
    }

    const identity: CameraIdentity = {
      id: cam.id,
      siteId: cam.siteId,
      code: cam.code || query.code || cam.id,
      name: cam.name,
    };

    const expiresAt = Date.now() + this.TTL_MS;
    this.cache.set(`id:${identity.id}`, { value: identity, expiresAt });
    this.cache.set(`code:${identity.code.toUpperCase()}`, {
      value: identity,
      expiresAt,
    });

    return identity;
  }

  clearCache(): void {
    this.cache.clear();
  }
}

export const cameraLookupClient = new CameraLookupClient();
