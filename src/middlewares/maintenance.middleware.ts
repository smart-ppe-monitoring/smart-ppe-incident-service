import { Request, Response, NextFunction } from "express";
import { AppError } from "../common/errors/app-error";
import { ERROR_CODE } from "../common/errors/error-code";
import { ROLES } from "../common/constants/role.constant";
import { getSharedRateLimitRedisClient } from "./rate-limit.middleware";

export interface MaintenanceGuardOptions {
  isMaintenanceMode?: boolean | (() => boolean | Promise<boolean>);
  exemptPaths?: (string | RegExp)[];
}

const DEFAULT_EXEMPT_PATHS: (string | RegExp)[] = [
  "/health",
  /^\/api\/v1\/incidents\/health/,
  /^\/incidents\/health/,
  /^\/openapi\.json/,
  /^\/api\/v1\/incidents\/openapi\.json/,
];

export function maintenanceGuard(options?: MaintenanceGuardOptions) {
  const exemptPaths = options?.exemptPaths ?? DEFAULT_EXEMPT_PATHS;

  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      let isMaintenance = false;

      // 1. Kiểm tra cấu hình override hoặc inject từ options (dành cho tests)
      if (typeof options?.isMaintenanceMode === "function") {
        isMaintenance = await options.isMaintenanceMode();
      } else if (typeof options?.isMaintenanceMode === "boolean") {
        isMaintenance = options.isMaintenanceMode;
      } else if (
        process.env.MAINTENANCE_MODE === "true" ||
        process.env.MAINTENANCE_ENABLED === "true"
      ) {
        // 2. Kiểm tra qua biến môi trường
        isMaintenance = true;
      } else {
        // 3. Kiểm tra qua Redis cache nếu khả dụng
        const redis = getSharedRateLimitRedisClient();
        if (redis) {
          try {
            const raw = await redis.get("system:maintenance");
            if (raw) {
              const parsed = JSON.parse(raw);
              if (parsed?.enabled === true || parsed?.status === "MAINTENANCE") {
                isMaintenance = true;
              }
            }
          } catch {
            // Lỗi đọc Redis không chặn luồng thông thường
          }
        }
      }

      if (!isMaintenance) {
        return next();
      }

      // Kiểm tra xem route hiện tại có thuộc danh sách miễn trừ không
      const path = req.originalUrl || req.url || req.path || "";
      const isExempt = exemptPaths.some((pattern) => {
        if (typeof pattern === "string") {
          return path.startsWith(pattern) || path === pattern;
        }
        return pattern.test(path);
      });

      if (isExempt) {
        return next();
      }

      // Kiểm tra quyền Admin / Maintenance Bypass
      const isAdmin =
        req.user?.role === ROLES.ADMIN ||
        req.user?.role === "ADMIN" ||
        req.user?.permissions?.includes("MAINTENANCE_BYPASS") ||
        req.user?.permissions?.includes("MAINTENANCE_MANAGE");

      if (isAdmin) {
        return next();
      }

      next(
        new AppError(
          "Hệ thống đang được bảo trì để nâng cấp dịch vụ. Vui lòng quay lại sau.",
          503,
          ERROR_CODE.SYSTEM_MAINTENANCE,
        ),
      );
    } catch (err) {
      next(err);
    }
  };
}
