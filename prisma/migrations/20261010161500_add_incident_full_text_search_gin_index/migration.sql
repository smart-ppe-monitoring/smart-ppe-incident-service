-- Migration: 20261010161500_add_incident_full_text_search_gin_index
-- Description: Thêm chỉ mục GIN (Generalized Inverted Index) phục vụ tối ưu hóa PostgreSQL Full-Text Search cho bảng incidents (description, violation_type)

-- 1. Create GIN index for Full-Text Search on incidents table (description, violation_type)
CREATE INDEX IF NOT EXISTS "idx_incidents_fts" ON "incidents" USING gin (
    to_tsvector('simple', coalesce("description", '') || ' ' || coalesce("violation_type", ''))
);
