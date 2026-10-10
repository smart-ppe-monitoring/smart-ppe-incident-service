-- CreateTable
CREATE TABLE "incidents" (
    "id" UUID NOT NULL DEFAULT uuid_generate_v7(),
    "site_id" UUID NOT NULL,
    "camera_id" UUID NOT NULL,
    "violation_id" UUID,
    "violation_type" VARCHAR(50) NOT NULL,
    "severity" VARCHAR(30) NOT NULL DEFAULT 'HIGH',
    "status" VARCHAR(30) NOT NULL DEFAULT 'PENDING_REVIEW',
    "detected_at" TIMESTAMP(3) NOT NULL,
    "resolved_at" TIMESTAMP(3),
    "description" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "incidents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "evidences" (
    "id" UUID NOT NULL DEFAULT uuid_generate_v7(),
    "incident_id" UUID NOT NULL,
    "camera_id" UUID NOT NULL,
    "evidence_type" VARCHAR(30) NOT NULL,
    "storage_key" TEXT NOT NULL,
    "file_name" VARCHAR(255) NOT NULL,
    "mime_type" VARCHAR(100) NOT NULL,
    "file_size" BIGINT NOT NULL DEFAULT 0,
    "captured_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "evidences_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "evidence_metadata" (
    "id" UUID NOT NULL DEFAULT uuid_generate_v7(),
    "evidence_id" UUID NOT NULL,
    "width" INTEGER,
    "height" INTEGER,
    "duration_seconds" INTEGER,
    "frame_rate" DECIMAL(6,2),
    "checksum" VARCHAR(128),
    "ai_detections" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "evidence_metadata_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "evidence_access_logs" (
    "id" UUID NOT NULL DEFAULT uuid_generate_v7(),
    "evidence_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "action" VARCHAR(30) NOT NULL,
    "accessed_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "evidence_access_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "incident_assignments" (
    "id" UUID NOT NULL DEFAULT uuid_generate_v7(),
    "incident_id" UUID NOT NULL,
    "assigned_to" UUID NOT NULL,
    "assigned_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "unassigned_at" TIMESTAMP(3),
    "status" VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',

    CONSTRAINT "incident_assignments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "incident_status_history" (
    "id" UUID NOT NULL DEFAULT uuid_generate_v7(),
    "incident_id" UUID NOT NULL,
    "old_status" VARCHAR(30) NOT NULL,
    "new_status" VARCHAR(30) NOT NULL,
    "changed_by" UUID NOT NULL,
    "changed_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reason" TEXT,

    CONSTRAINT "incident_status_history_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "incident_comments" (
    "id" UUID NOT NULL DEFAULT uuid_generate_v7(),
    "incident_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "comment" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "incident_comments_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "incidents_site_id_status_detected_at_idx" ON "incidents"("site_id", "status", "detected_at");

-- CreateIndex
CREATE INDEX "incidents_camera_id_detected_at_idx" ON "incidents"("camera_id", "detected_at");

-- CreateIndex
CREATE INDEX "incidents_status_idx" ON "incidents"("status");

-- CreateIndex
CREATE INDEX "evidences_incident_id_idx" ON "evidences"("incident_id");

-- CreateIndex
CREATE UNIQUE INDEX "evidence_metadata_evidence_id_key" ON "evidence_metadata"("evidence_id");

-- CreateIndex
CREATE INDEX "evidence_access_logs_evidence_id_idx" ON "evidence_access_logs"("evidence_id");

-- CreateIndex
CREATE INDEX "evidence_access_logs_user_id_idx" ON "evidence_access_logs"("user_id");

-- CreateIndex
CREATE INDEX "incident_assignments_incident_id_idx" ON "incident_assignments"("incident_id");

-- CreateIndex
CREATE INDEX "incident_assignments_assigned_to_idx" ON "incident_assignments"("assigned_to");

-- CreateIndex
CREATE INDEX "incident_status_history_incident_id_idx" ON "incident_status_history"("incident_id");

-- CreateIndex
CREATE INDEX "incident_comments_incident_id_idx" ON "incident_comments"("incident_id");

-- AddForeignKey
ALTER TABLE "evidences" ADD CONSTRAINT "evidences_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence_metadata" ADD CONSTRAINT "evidence_metadata_evidence_id_fkey" FOREIGN KEY ("evidence_id") REFERENCES "evidences"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence_access_logs" ADD CONSTRAINT "evidence_access_logs_evidence_id_fkey" FOREIGN KEY ("evidence_id") REFERENCES "evidences"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "incident_assignments" ADD CONSTRAINT "incident_assignments_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "incident_status_history" ADD CONSTRAINT "incident_status_history_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "incident_comments" ADD CONSTRAINT "incident_comments_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;
