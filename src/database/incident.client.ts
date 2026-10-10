import { PrismaClient as IncidentPrismaClient } from "@prisma/client-incident";
import { envConfig } from "../config/env.config";

/**
 * Cấu hình timeout mặc định cho interactive transactions của Incident Service
 */
export const DEFAULT_INCIDENT_TRANSACTION_OPTIONS = {
  maxWait: 10000,
  timeout: 15000,
} as const;

let _incidentPrisma: IncidentPrismaClient | null = null;

export function getIncidentPrisma(): IncidentPrismaClient {
  if (!_incidentPrisma) {
    _incidentPrisma = new IncidentPrismaClient({
      log:
        envConfig.nodeEnv === "development"
          ? ["query", "error", "warn"]
          : ["error", "warn"],
    });
  }
  return _incidentPrisma;
}

export const incidentPrisma = new Proxy({} as IncidentPrismaClient, {
  get(_target, prop) {
    return (getIncidentPrisma() as any)[prop];
  },
});
