-- Migration: 20261127163000_add_evidence_query_indexes
-- Add indexes on evidences(captured_at), evidences(evidence_type, captured_at), and evidences(camera_id, captured_at)

-- CreateIndex
CREATE INDEX IF NOT EXISTS "evidences_captured_at_idx" ON "evidences"("captured_at");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "evidences_evidence_type_captured_at_idx" ON "evidences"("evidence_type", "captured_at");

-- CreateIndex
CREATE INDEX IF NOT EXISTS "evidences_camera_id_captured_at_idx" ON "evidences"("camera_id", "captured_at");
