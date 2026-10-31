import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { jwtConfig } from "../config/jwt.config";
import { AppError } from "../common/errors/app-error";
import { ERROR_CODE } from "../common/errors/error-code";
import { JWT_PURPOSE, JWT_ALGORITHM } from "../common/constants/jwt.constant";

export function extractTokenFromRequest(req: Request): string | undefined {
  let token = req.cookies?.accessToken;
  if (!token) {
    const authHeader = req.headers?.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    }
  }

  const cleanPath = (
    (req.baseUrl || "") + (req.path || req.originalUrl || "")
  ).split("?")[0];
  const isAllowedQueryTokenEndpoint =
    cleanPath.endsWith("/stream") || cleanPath.endsWith("/download");

  if (!token && isAllowedQueryTokenEndpoint) {
    const queryToken = req.query?.ticket || req.query?.token;
    if (typeof queryToken === "string") {
      token = queryToken;
    }
  }
  return token;
}

export async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const cleanPath = (
    (req.baseUrl || "") + (req.path || req.originalUrl || "")
  ).split("?")[0];
  const isAllowedQueryTokenEndpoint =
    cleanPath.endsWith("/stream") || cleanPath.endsWith("/download");

  if (!isAllowedQueryTokenEndpoint && req.query?.token) {
    next(
      new AppError(
        "Không được phép truyền token xác thực qua query string trên API thông thường để tránh rò rỉ qua log và browser history",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      ),
    );
    return;
  }

  const token = extractTokenFromRequest(req);

  if (!token) {
    next(new AppError("Unauthorized", 401, ERROR_CODE.UNAUTHORIZED));
    return;
  }

  try {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded !== "object" || !decoded.header) {
      next(new AppError("Token không hợp lệ", 401, ERROR_CODE.UNAUTHORIZED));
      return;
    }

    const { alg } = decoded.header;
    let payload: any;

    if (alg !== JWT_ALGORITHM.RS256) {
      next(
        new AppError(
          `Thuật toán '${alg}' không được chấp nhận. Hệ thống chỉ hỗ trợ RS256.`,
          401,
          ERROR_CODE.UNAUTHORIZED,
        ),
      );
      return;
    }

    if (!jwtConfig.publicKey) {
      next(
        new AppError(
          "Cấu hình khóa công khai RS256 chưa sẵn sàng",
          500,
          ERROR_CODE.INTERNAL_SERVER_ERROR,
        ),
      );
      return;
    }

    payload = jwt.verify(token, jwtConfig.publicKey, {
      algorithms: [JWT_ALGORITHM.RS256],
    });

    if (!payload || typeof payload !== "object") {
      next(new AppError("Token không hợp lệ", 401, ERROR_CODE.UNAUTHORIZED));
      return;
    }

    // SEC-01: Chặn tuyệt đối token tạm thời (2FA verification / temp token) truy cập tài nguyên bảo vệ
    const jwtPayload = payload as Record<string, unknown>;
    if (
      jwtPayload.purpose === JWT_PURPOSE.TWO_FACTOR ||
      jwtPayload.type === "TEMP" ||
      (jwtPayload.purpose && jwtPayload.purpose !== JWT_PURPOSE.ACCESS)
    ) {
      next(
        new AppError(
          "Token không hợp lệ để truy cập tài nguyên được bảo vệ",
          401,
          ERROR_CODE.UNAUTHORIZED,
        ),
      );
      return;
    }

    // SEC-06: Chặn token có cờ mustChangePassword truy cập satellite services
    if (
      jwtPayload.mustChangePassword === true ||
      jwtPayload.mustChangePassword === "true"
    ) {
      next(
        new AppError(
          "Bạn bắt buộc phải đổi mật khẩu trước khi thực hiện các thao tác khác trên hệ thống",
          403,
          ERROR_CODE.FORBIDDEN,
        ),
      );
      return;
    }

    req.user = {
      id: payload.id || payload.sub,
      email: payload.email,
      role: payload.role,
      roleId: payload.roleId,
      permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
    };

    next();
  } catch (error) {
    next(new AppError("Token xác thực không hợp lệ hoặc đã hết hạn", 401, ERROR_CODE.UNAUTHORIZED));
  }
}
