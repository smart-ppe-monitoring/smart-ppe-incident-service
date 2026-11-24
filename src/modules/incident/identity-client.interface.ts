import { envConfig } from "../../config/env.config";
import { GATEWAY_HEADERS } from "../../common/constants/gateway.constant";
import { isAutomatedTestRuntime } from "./notification-client.interface";

export interface IncidentSiteUserInfo {
  id: string;
  email: string | null;
  fullName: string | null;
  role: string | null;
}

export interface IdentityUserDirectory {
  getSiteUserMap(siteId?: string): Promise<Map<string, IncidentSiteUserInfo>>;
}

export interface HttpIdentityClientOptions {
  baseUrl?: string;
  internalToken?: string;
  gatewaySecret?: string;
  timeoutMs?: number;
  cacheTtlMs?: number;
  fetcher?: typeof fetch;
}

interface CacheEntry {
  expiresAt: number;
  users: Map<string, IncidentSiteUserInfo>;
}

const DEFAULT_CACHE_TTL_MS = 60_000;
const DEFAULT_TIMEOUT_MS = 3_000;
const MAX_CACHE_ENTRIES = 200;
const GLOBAL_CACHE_KEY = "__global__";

/**
 * HTTP Client M2M tra cứu danh bạ người dùng theo công trường từ Identity Service (:9999)
 * qua endpoint nội bộ `GET /api/v1/users/internal/incident-recipients?siteId=...`.
 * Thiết kế fail-open + cache 60s để enrich tên/vai trò hiển thị mà không cản trở luồng sự cố.
 */
export class HttpIdentityUserDirectory implements IdentityUserDirectory {
  private readonly customBaseUrl?: string;
  private readonly customInternalToken?: string;
  private readonly customGatewaySecret?: string;
  private readonly timeoutMs: number;
  private readonly cacheTtlMs: number;
  private readonly customFetcher?: typeof fetch;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(options: HttpIdentityClientOptions = {}) {
    this.customBaseUrl = options.baseUrl;
    this.customInternalToken = options.internalToken;
    this.customGatewaySecret = options.gatewaySecret;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.customFetcher = options.fetcher;
  }

  clearCache(): void {
    this.cache.clear();
  }

  async getSiteUserMap(
    siteId?: string,
  ): Promise<Map<string, IncidentSiteUserInfo>> {
    // Trong unit tests chạy offline mà không inject mock fetcher, bỏ qua gọi HTTP thật tránh lỗi kết nối
    if (!this.customFetcher && isAutomatedTestRuntime()) {
      return new Map();
    }

    const normalizedSiteId =
      typeof siteId === "string" && siteId.trim() ? siteId.trim() : undefined;
    const cacheKey = normalizedSiteId ?? GLOBAL_CACHE_KEY;
    const now = Date.now();

    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
      return cached.users;
    }
    if (cached) {
      this.cache.delete(cacheKey);
    }

    const baseUrl = (
      this.customBaseUrl ?? envConfig.identity.serviceUrl
    ).replace(/\/+$/, "");
    const internalToken = (
      this.customInternalToken ?? envConfig.internalService.token
    ).trim();
    const gatewaySecret = (
      this.customGatewaySecret ?? envConfig.gateway.internalSecret
    ).trim();

    if (!baseUrl || !internalToken) {
      return new Map();
    }

    try {
      const query = normalizedSiteId
        ? `?siteId=${encodeURIComponent(normalizedSiteId)}`
        : "";
      const headers: Record<string, string> = {
        Accept: "application/json",
        [GATEWAY_HEADERS.INTERNAL_SERVICE_TOKEN]: internalToken,
      };
      if (gatewaySecret) {
        headers[GATEWAY_HEADERS.INTERNAL_SECRET] = gatewaySecret;
      }

      const fetcher = this.customFetcher || fetch;
      const response = await fetcher(
        `${baseUrl}/api/v1/users/internal/incident-recipients${query}`,
        {
          method: "GET",
          headers,
          signal: AbortSignal.timeout(this.timeoutMs),
        },
      );

      if (!response.ok) {
        const errorText = await response.text().catch(() => "");
        console.warn(
          `[IdentityClient] M2M user lookup HTTP ${response.status}: ${errorText.slice(0, 200)}`,
        );
        return new Map();
      }

      const payload = (await response.json().catch(() => null)) as any;
      const rawUsers = Array.isArray(payload?.data)
        ? payload.data
        : Array.isArray(payload)
          ? payload
          : [];

      const userMap = new Map<string, IncidentSiteUserInfo>();
      for (const entry of rawUsers) {
        if (!entry || typeof entry !== "object" || typeof entry.id !== "string") {
          continue;
        }
        const id = entry.id.trim();
        if (!id) continue;
        userMap.set(id, {
          id,
          email: typeof entry.email === "string" ? entry.email : null,
          fullName: typeof entry.fullName === "string" ? entry.fullName : null,
          role: typeof entry.role === "string" ? entry.role : null,
        });
      }

      if (this.cacheTtlMs > 0) {
        if (this.cache.size >= MAX_CACHE_ENTRIES) {
          const oldestKey = this.cache.keys().next().value;
          if (oldestKey !== undefined) {
            this.cache.delete(oldestKey);
          }
        }
        this.cache.set(cacheKey, {
          expiresAt: Date.now() + this.cacheTtlMs,
          users: userMap,
        });
      }

      return userMap;
    } catch (err: any) {
      console.warn(
        "[IdentityClient] Không thể tra cứu tên/vai trò người dùng từ Identity Service:",
        err?.message || err,
      );
      return new Map();
    }
  }
}

export const identityUserDirectory: IdentityUserDirectory =
  new HttpIdentityUserDirectory();
