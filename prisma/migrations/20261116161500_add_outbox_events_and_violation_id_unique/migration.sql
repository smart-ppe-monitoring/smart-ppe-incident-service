-- Migration: 20261116161500_add_outbox_events_and_violation_id_unique
-- Sync schema.prisma OutboxEvent model and incidents.violation_id unique constraint into migrations.

-- CreateTable
CREATE TABLE IF NOT EXISTS "outbox_events" (
    "id" UUID NOT NULL DEFAULT uuid_generate_v7(),
    "event_type" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "aggregate_id" TEXT,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "last_error" TEXT,
    "published_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "outbox_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX IF NOT EXISTS "outbox_events_status_created_at_idx" ON "outbox_events"("status", "created_at");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "outbox_events_event_type_idx" ON "outbox_events"("event_type");

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "incidents_violation_id_key" ON "incidents"("violation_id");
