-- ===========================================================================
-- Anarmani Distribution Centre - Consumer Application Portal
-- Postgres schema for Supabase
-- Apply via: npm run db:setup   (or paste into Supabase SQL Editor)
-- ===========================================================================

-- Inspectors table (for dropdown in site inspection assignment)
CREATE TABLE IF NOT EXISTS inspectors (
  id              BIGSERIAL PRIMARY KEY,
  name            TEXT NOT NULL UNIQUE,
  email           TEXT,
  phone           TEXT,
  is_active       BOOLEAN NOT NULL DEFAULT true,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_inspectors_active ON inspectors (is_active);

-- Applications table
CREATE TABLE IF NOT EXISTS applications (
  id                  BIGSERIAL PRIMARY KEY,
  fiscal_year         TEXT NOT NULL,
  office_name         TEXT NOT NULL DEFAULT 'Anarmani Distribution Centre',
  applicant_name      TEXT NOT NULL,
  applicant_phone     TEXT NOT NULL,
  darta_number        TEXT NOT NULL UNIQUE,
  scanned_pdf_path    TEXT,
  inspection_pdf_path TEXT,
  inspection_assigned_to BIGINT REFERENCES inspectors(id) ON DELETE SET NULL,
  progress_status     TEXT NOT NULL DEFAULT 'Pending',
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_darta_number ON applications (darta_number);
CREATE INDEX IF NOT EXISTS idx_applicant_name ON applications (lower(applicant_name));
CREATE INDEX IF NOT EXISTS idx_fiscal_year ON applications (fiscal_year);
CREATE INDEX IF NOT EXISTS idx_progress_status ON applications (progress_status);
CREATE INDEX IF NOT EXISTS idx_office_name ON applications (office_name);
CREATE INDEX IF NOT EXISTS idx_inspection_assigned_to ON applications (inspection_assigned_to);

-- Row Level Security (RLS) for Supabase Auth integration
ALTER TABLE applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE inspectors ENABLE ROW LEVEL SECURITY;

-- Policy: authenticated users can read all applications
CREATE POLICY "Authenticated users can view applications"
  ON applications FOR SELECT
  TO authenticated
  USING (true);

-- Policy: authenticated users can insert applications
CREATE POLICY "Authenticated users can insert applications"
  ON applications FOR INSERT
  TO authenticated
  WITH CHECK (true);

-- Policy: authenticated users can update applications
CREATE POLICY "Authenticated users can update applications"
  ON applications FOR UPDATE
  TO authenticated
  USING (true)
  WITH CHECK (true);

-- Policy: authenticated users can delete applications
CREATE POLICY "Authenticated users can delete applications"
  ON applications FOR DELETE
  TO authenticated
  USING (true);

-- Policy: authenticated users can view inspectors
CREATE POLICY "Authenticated users can view inspectors"
  ON inspectors FOR SELECT
  TO authenticated
  USING (true);

-- Policy: authenticated users can manage inspectors
CREATE POLICY "Authenticated users can manage inspectors"
  ON inspectors FOR ALL
  TO authenticated
  USING (true)
  WITH CHECK (true);

-- Storage bucket RLS policy (documents bucket)
-- Public access denied, authenticated users can upload/read
-- Run these in Supabase Storage -> Policies:
-- CREATE POLICY "Authenticated users can upload" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = 'documents');
-- CREATE POLICY "Authenticated users can view" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'documents');
-- CREATE POLICY "Authenticated users can delete" ON storage.objects FOR DELETE TO authenticated USING (bucket_id = 'documents');