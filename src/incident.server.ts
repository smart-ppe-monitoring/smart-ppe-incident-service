import "dotenv/config";
import dns from "node:dns";

// Force IPv4-first resolution in Node.js runtime to prevent ENETUNREACH on platforms without IPv6 routing
try {
  dns.setDefaultResultOrder("ipv4first");
} catch {
  // Graceful fallback if not supported in runtime
}

import incidentApp from "./incident.app";
import { envConfig } from "./config/env.config";
import { incidentPrisma } from "./database/incident.client";

const PORT = envConfig.incident.port || 8893;

/**
 * Incident Microservice Process (:8893)
 *
 * Chịu trách nhiệm độc quyền:
 * 1. Phục vụ HTTP API cho Incident, Lifecycle review/resolve/close, Evidence, Assignment và Comment
 * 2. Tương tác trực tiếp với cơ sở dữ liệu ppe_incident_db
 * 3. Hoạt động sau Traefik reverse proxy hoặc Standalone
 */
export const server = incidentApp.listen(PORT, () => {
  console.log(
    `[Incident Service] Running on http://localhost:${PORT} in ${envConfig.nodeEnv} mode`,
  );
  console.log(
    `[Incident Service] ✅ Listening for incidents, evidences and lifecycle transitions on port ${PORT}`,
  );
});

let isShuttingDown = false;

export async function handleIncidentShutdown(signal: string): Promise<void> {
  if (isShuttingDown) return;
  isShuttingDown = true;

  console.log(
    `\n[Incident Service] Received ${signal}. Starting graceful shutdown...`,
  );

  const forceExitTimer = setTimeout(() => {
    console.error(
      "[Incident Service] Graceful shutdown timed out (10s). Forcing termination.",
    );
    process.exit(1);
  }, 10000);
  forceExitTimer.unref();

  try {
    // 1. Close idle HTTP connections
    if (typeof server.closeIdleConnections === "function") {
      server.closeIdleConnections();
    }

    // 2. Stop accepting new HTTP requests
    await new Promise<void>((resolve) => {
      server.close((err) => {
        if (err) {
          console.error("[Incident Service] Error closing HTTP server:", err);
        } else {
          console.log("[Incident Service] Closed HTTP server successfully.");
        }
        resolve();
      });
    });

    // 3. Disconnect database client
    await incidentPrisma.$disconnect().catch((err: unknown) => {
      console.warn(
        "[Incident Service] Error disconnecting incidentPrisma:",
        (err as Error)?.message || err,
      );
    });
    console.log("[Incident Service] Disconnected from incident database.");

    clearTimeout(forceExitTimer);
    console.log("[Incident Service] Graceful shutdown completed.");
    process.exit(0);
  } catch (error) {
    console.error("[Incident Service] Error during graceful shutdown:", error);
    clearTimeout(forceExitTimer);
    process.exit(1);
  }
}

process.on("SIGTERM", () => void handleIncidentShutdown("SIGTERM"));
process.on("SIGINT", () => void handleIncidentShutdown("SIGINT"));
