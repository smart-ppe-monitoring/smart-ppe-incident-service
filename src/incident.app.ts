import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import {
  errorMiddleware,
  notFoundMiddleware,
} from "./middlewares/error.middleware";
import {
  incidentRouter,
  evidenceRouter,
} from "./modules/incident/incident.route";
import { rateLimitMiddleware } from "./middlewares/rate-limit.middleware";
import { requestIdMiddleware } from "./middlewares/request-id.middleware";
import { maintenanceGuard } from "./middlewares/maintenance.middleware";
import { envConfig } from "./config/env.config";
import { buildOpenApiSpec } from "./config/openapi/openapi.registry";
import { registerIncidentOpenApi } from "./modules/incident/incident.openapi";

// Khởi tạo các định nghĩa OpenAPI
registerIncidentOpenApi();

/**
 * Express Application cho Incident Management Microservice (:8893)
 *
 * Đảm nhiệm:
 * - REST API cho sự cố vi phạm PPE (/api/v1/incidents/*)
 * - REST API cho bằng chứng số (/api/v1/evidences/*)
 * - Vòng đời sự cố (Review, Resolve, Close)
 * - Phân công xử lý và trao đổi bình luận
 * - Health check cho Traefik Reverse Proxy load balancer
 */
const incidentApp = express();

incidentApp.set("trust proxy", envConfig.trustProxy);

// 1. Distributed Tracing & Security Headers
incidentApp.use(requestIdMiddleware);
incidentApp.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
  }),
);

// 2. CORS Handling
const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    const allowed = envConfig.cors.allowedOrigins.map((o) =>
      o.replace(/\/+$/, ""),
    );
    if (!origin) {
      callback(null, true);
      return;
    }
    const cleanOrigin = origin.replace(/\/+$/, "");
    if (allowed.includes("*")) {
      if (envConfig.nodeEnv !== "production") {
        callback(null, true);
        return;
      }
      console.error(
        "[CORS] CORS_ALLOWED_ORIGINS=* is not permitted in production.",
      );
      callback(null, false);
      return;
    }
    if (allowed.includes(cleanOrigin)) {
      callback(null, true);
    } else {
      callback(null, false);
    }
  },
  credentials: true,
};
incidentApp.use(cors(corsOptions));
incidentApp.use(morgan(envConfig.nodeEnv === "production" ? "combined" : "dev"));
incidentApp.use(express.json({ limit: "2mb" }));
incidentApp.use(express.urlencoded({ extended: true, limit: "2mb" }));
incidentApp.use(cookieParser());

// 3. Health check endpoints cho Traefik Gateway & Monitoring
const healthHandler = (_req: express.Request, res: express.Response) => {
  res.status(200).json({
    status: "ok",
    service: "incident-service",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
};

incidentApp.get("/health", healthHandler);
incidentApp.get("/api/v1/incidents/health", healthHandler);
incidentApp.get("/incidents/health", healthHandler);

// 3.1 OpenAPI Specification Endpoint (Chỉ mở trên dev/staging, ẩn trên production)
if (envConfig.nodeEnv !== "production") {
  incidentApp.get("/openapi.json", (_req, res) => res.status(200).json(buildOpenApiSpec()));
  incidentApp.get("/api/v1/incidents/openapi.json", (_req, res) => res.status(200).json(buildOpenApiSpec()));
}

// 4. Mount Incident & Evidence Routes
// Hỗ trợ dual-mount cả prefix /api/v1/... và /... khi qua Gateway hoặc gọi trực tiếp
incidentApp.use(
  "/api/v1/incidents",
  rateLimitMiddleware,
  maintenanceGuard(),
  incidentRouter,
);
incidentApp.use(
  "/incidents",
  rateLimitMiddleware,
  maintenanceGuard(),
  incidentRouter,
);

incidentApp.use(
  "/api/v1/evidences",
  rateLimitMiddleware,
  maintenanceGuard(),
  evidenceRouter,
);
incidentApp.use(
  "/evidences",
  rateLimitMiddleware,
  maintenanceGuard(),
  evidenceRouter,
);

// 5. Error & 404 Handlers
incidentApp.use(notFoundMiddleware);
incidentApp.use(errorMiddleware);

export default incidentApp;
