/**
 * Anarmani Distribution Centre - Consumer Application Portal
 * Backend (cloud version): Express + Supabase Postgres + Supabase Storage + Supabase Auth.
 *
 * - Exported as a Vercel serverless function (see vercel.json).
 * - For local dev, server.js requires this file and starts a listener.
 * - PDFs are uploaded DIRECTLY to Supabase Storage by the browser using
 *   signed URLs generated here (file bytes never pass through this server).
 *
 * Required env vars (see .env.example):
 *   DATABASE_URL               Postgres connection string (Supabase "Session pooler")
 *   SUPABASE_URL               e.g. https://xxxx.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY  service_role key (SECRET - server only)
 *   SUPABASE_ANON_KEY          anon/public key (for client-side auth)
 *   SUPABASE_STORAGE_BUCKET    (optional, default: documents)
 */

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const DATABASE_URL = process.env.DATABASE_URL;
const STORAGE_BUCKET = process.env.SUPABASE_STORAGE_BUCKET || 'documents';
const SIGNED_URL_TTL_SECONDS = 3600; // signed PDF links expire after 1 hour

const configured = Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY && DATABASE_URL && SUPABASE_ANON_KEY);

const PROGRESS_STATUSES = ['Pending', 'Under Review', 'Site Inspection Pending', 'Approved', 'Rejected', 'On Hold'];

// ---------------------------------------------------------------------------
// Lazy singletons (cached across warm serverless invocations)
// ---------------------------------------------------------------------------
let pool = null;
function getPool() {
  if (pool) return pool;
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 10000,
    max: 5,
  });
  pool.on('error', (err) => console.error('Idle DB pool error:', err.message));
  return pool;
}

let sb = null;
function getSupabase() {
  if (sb) return sb;
  sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return sb;
}

// Supabase client for auth (uses anon key, server-side session verification)
let sbAuth = null;
function getSupabaseAuth() {
  if (sbAuth) return sbAuth;
  sbAuth = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return sbAuth;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const clean = (v) => (typeof v === 'string' ? v.trim() : '');
const isId = (v) => /^\d+$/.test(v);

async function removeStorageObjects(paths) {
  const valid = (paths || []).filter(Boolean);
  if (!valid.length) return;
  const { error } = await getSupabase().storage.from(STORAGE_BUCKET).remove(valid);
  if (error) console.error('Storage cleanup failed:', error.message);
}

/** Enrich rows with expiring signed URLs for their PDFs. */
async function withSignedUrls(rows) {
  const list = Array.isArray(rows) ? rows : [rows];
  if (!list.length) return rows;

  const paths = [];
  for (const r of list) {
    if (r.scanned_pdf_path) paths.push(r.scanned_pdf_path);
    if (r.inspection_pdf_path) paths.push(r.inspection_pdf_path);
  }

  const map = new Map();
  if (paths.length) {
    const { data, error } = await getSupabase().storage.from(STORAGE_BUCKET).createSignedUrls(paths, SIGNED_URL_TTL_SECONDS);
    if (!error && data) for (const d of data) map.set(d.path, d.signedUrl);
  }

  const out = list.map((r) => ({
    ...r,
    scanned_pdf_url: r.scanned_pdf_path ? map.get(r.scanned_pdf_path) || null : null,
    inspection_pdf_url: r.inspection_pdf_path ? map.get(r.inspection_pdf_path) || null : null,
  }));
  return Array.isArray(rows) ? out : out[0];
}

// ---------------------------------------------------------------------------
// Auth Middleware
// ---------------------------------------------------------------------------
async function requireAuth(req, res, next) {
  if (!configured) {
    return res.status(503).json({
      error: 'Supabase not configured on the server. Set DATABASE_URL, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, and SUPABASE_ANON_KEY.',
    });
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required', code: 'UNAUTHORIZED' });
  }

  const token = authHeader.substring(7);
  const { data: { user }, error } = await getSupabaseAuth().auth.getUser(token);

  if (error || !user) {
    return res.status(401).json({ error: 'Invalid or expired session', code: 'UNAUTHORIZED' });
  }

  req.user = user;
  req.accessToken = token;
  next();
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// ---------------------------------------------------------------------------
// Auth Endpoints
// ---------------------------------------------------------------------------

// POST /api/auth/signup  { email, password, full_name }
app.post('/api/auth/signup', async (req, res) => {
  if (!configured) return res.status(503).json({ error: 'Supabase not configured' });
  try {
    const { email, password, full_name } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const { data, error } = await getSupabaseAuth().auth.signUp({
      email,
      password,
      options: { data: { full_name: full_name || '' } },
    });
    if (error) return res.status(400).json({ error: error.message });
    res.json({ user: data.user, session: data.session });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/login  { email, password }
app.post('/api/auth/login', async (req, res) => {
  if (!configured) return res.status(503).json({ error: 'Supabase not configured' });
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const { data, error } = await getSupabaseAuth().auth.signInWithPassword({
      email,
      password,
    });
    if (error) return res.status(401).json({ error: error.message });
    res.json({ user: data.user, session: data.session });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', requireAuth, async (req, res) => {
  try {
    await getSupabaseAuth().auth.signOut();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, async (req, res) => {
  res.json({ user: req.user });
});

// ---------------------------------------------------------------------------
// Upload signing (browser uploads PDFs directly to Supabase Storage)
// ---------------------------------------------------------------------------

// POST /api/uploads/sign  { filename, kind: "scanned" | "inspection" }
app.post('/api/uploads/sign', requireAuth, async (req, res) => {
  try {
    const { filename = '', kind = '' } = req.body || {};
    if (!['scanned', 'inspection'].includes(kind)) {
      return res.status(400).json({ error: 'kind must be "scanned" or "inspection"' });
    }
    const ext = path.extname(filename).toLowerCase();
    if (ext !== '.pdf') {
      return res.status(400).json({ error: 'Only PDF files are allowed' });
    }
    const storagePath = `${kind}/${crypto.randomUUID()}${ext}`;
    const { data, error } = await getSupabase()
      .storage.from(STORAGE_BUCKET)
      .createSignedUploadUrl(storagePath, { upsert: false });
    if (error) return res.status(500).json({ error: error.message });

    res.json({ url: data.signedUrl, path: data.path, token: data.token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/uploads/delete  { path }  (discard an uploaded-but-unsaved PDF)
app.post('/api/uploads/delete', requireAuth, async (req, res) => {
  try {
    const { path: p } = req.body || {};
    if (!p || typeof p !== 'string') return res.status(400).json({ error: 'path is required' });
    await removeStorageObjects([p]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// Inspectors CRUD
// ---------------------------------------------------------------------------

// GET /api/inspectors
app.get('/api/inspectors', requireAuth, async (req, res) => {
  try {
    const r = await getPool().query('SELECT id, name, email, phone, is_active FROM inspectors WHERE is_active = true ORDER BY name');
    res.json(r.rows);
  } catch (err) {
    console.error('List inspectors error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/inspectors/all (including inactive)
app.get('/api/inspectors/all', requireAuth, async (req, res) => {
  try {
    const r = await getPool().query('SELECT id, name, email, phone, is_active FROM inspectors ORDER BY is_active DESC, name');
    res.json(r.rows);
  } catch (err) {
    console.error('List all inspectors error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/inspectors  { name, email, phone }
app.post('/api/inspectors', requireAuth, async (req, res) => {
  try {
    const { name, email, phone } = req.body || {};
    const cleanName = clean(name);
    if (!cleanName) return res.status(400).json({ error: 'Inspector name is required' });

    const r = await getPool().query(
      `INSERT INTO inspectors (name, email, phone) VALUES ($1, $2, $3) RETURNING *`,
      [cleanName, clean(email) || null, clean(phone) || null]
    );
    res.status(201).json(r.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Inspector name already exists' });
    console.error('Create inspector error:', err);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/inspectors/:id
app.put('/api/inspectors/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isId(id)) return res.status(400).json({ error: 'Invalid id' });
    const { name, email, phone, is_active } = req.body || {};
    const cleanName = clean(name);
    if (!cleanName) return res.status(400).json({ error: 'Inspector name is required' });

    const r = await getPool().query(
      `UPDATE inspectors SET name = $1, email = $2, phone = $3, is_active = $4 WHERE id = $5 RETURNING *`,
      [cleanName, clean(email) || null, clean(phone) || null, is_active === true || is_active === 'true', id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Inspector not found' });
    res.json(r.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Inspector name already exists' });
    console.error('Update inspector error:', err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/inspectors/:id
app.delete('/api/inspectors/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isId(id)) return res.status(400).json({ error: 'Invalid id' });
    await getPool().query('DELETE FROM inspectors WHERE id = $1', [id]);
    res.json({ success: true, message: 'Inspector deleted' });
  } catch (err) {
    console.error('Delete inspector error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// Applications CRUD
// ---------------------------------------------------------------------------

// GET /api/applications  (filters: q, fiscalYear, status, office, page, limit)
app.get('/api/applications', requireAuth, async (req, res) => {
  try {
    const { q, fiscalYear, status, office } = req.query;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.max(1, parseInt(req.query.limit) || 50);
    const offset = (page - 1) * limit;

    const clauses = [];
    const params = [];

    if (q && q.trim()) {
      params.push(`%${q.trim()}%`);
      clauses.push(`(applicant_name ILIKE $${params.length} OR darta_number ILIKE $${params.length} OR applicant_phone ILIKE $${params.length} OR office_name ILIKE $${params.length})`);
    }
    if (fiscalYear && fiscalYear.trim()) {
      params.push(fiscalYear.trim());
      clauses.push(`fiscal_year = $${params.length}`);
    }
    if (status && status.trim()) {
      params.push(status.trim());
      clauses.push(`progress_status = $${params.length}`);
    }
    if (office && office.trim()) {
      params.push(office.trim());
      clauses.push(`office_name = $${params.length}`);
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

    const countRes = await getPool().query(`SELECT COUNT(*)::int AS total FROM applications ${where}`, params);
    const total = +countRes.rows[0].total;

    params.push(limit, offset);
    const dataRes = await getPool().query(
      `SELECT a.*, i.name AS inspector_name FROM applications a
       LEFT JOIN inspectors i ON a.inspection_assigned_to = i.id
       ${where}
       ORDER BY a.created_at DESC, a.id DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    const rows = await withSignedUrls(dataRes.rows);
    res.json({
      applications: rows,
      pagination: { total, page, limit, totalPages: total ? Math.ceil(total / limit) : 0 },
    });
  } catch (err) {
    console.error('List error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/applications/darta/:dartaNumber  (must come before /:id)
app.get('/api/applications/darta/:dartaNumber', requireAuth, async (req, res) => {
  try {
    const r = await getPool().query(
      `SELECT a.*, i.name AS inspector_name FROM applications a
       LEFT JOIN inspectors i ON a.inspection_assigned_to = i.id
       WHERE a.darta_number = $1`,
      [req.params.dartaNumber]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Application not found' });
    res.json(await withSignedUrls(r.rows[0]));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/applications/:id
app.get('/api/applications/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isId(id)) return res.status(400).json({ error: 'Invalid id' });
    const r = await getPool().query(
      `SELECT a.*, i.name AS inspector_name FROM applications a
       LEFT JOIN inspectors i ON a.inspection_assigned_to = i.id
       WHERE a.id = $1`,
      [id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Application not found' });
    res.json(await withSignedUrls(r.rows[0]));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/applications  (JSON; PDFs already in Storage, paths sent here)
app.post('/api/applications', requireAuth, async (req, res) => {
  let conn;
  try {
    const b = req.body || {};
    const fiscalYear = clean(b.fiscalYear);
    const officeName = clean(b.officeName) || 'Anarmani Distribution Centre';
    const applicantName = clean(b.applicantName);
    const applicantPhone = clean(b.applicantPhone);
    const dartaNumber = clean(b.dartaNumber);
    const progressStatus = clean(b.progressStatus) || 'Pending';
    const scannedPdfPath = clean(b.scannedPdfPath) || null;
    const inspectionPdfPath = clean(b.inspectionPdfPath) || null;
    const inspectionAssignedTo = b.inspectionAssignedTo ? parseInt(b.inspectionAssignedTo) : null;

    if (!fiscalYear || !applicantName || !applicantPhone || !dartaNumber) {
      return res.status(400).json({ error: 'Fiscal Year, Office, Applicant Name, Phone and Darta Number are required' });
    }
    if (!scannedPdfPath) {
      return res.status(400).json({ error: 'Scanned document PDF is required' });
    }
    if (!PROGRESS_STATUSES.includes(progressStatus)) {
      return res.status(400).json({ error: 'Invalid progress status' });
    }

    conn = await getPool().connect();
    const dup = await conn.query('SELECT id FROM applications WHERE darta_number = $1', [dartaNumber]);
    if (dup.rows.length) {
      await removeStorageObjects([scannedPdfPath, inspectionPdfPath]);
      return res.status(400).json({ error: 'Darta Number already exists' });
    }

    if (inspectionAssignedTo) {
      const insCheck = await conn.query('SELECT id FROM inspectors WHERE id = $1 AND is_active = true', [inspectionAssignedTo]);
      if (!insCheck.rows.length) {
        await removeStorageObjects([scannedPdfPath, inspectionPdfPath]);
        return res.status(400).json({ error: 'Selected inspector does not exist or is inactive' });
      }
    }

    const ins = await conn.query(
      `INSERT INTO applications
         (fiscal_year, office_name, applicant_name, applicant_phone, darta_number, scanned_pdf_path, inspection_pdf_path, inspection_assigned_to, progress_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [fiscalYear, officeName, applicantName, applicantPhone, dartaNumber, scannedPdfPath, inspectionPdfPath, inspectionAssignedTo, progressStatus]
    );
    res.status(201).json(await withSignedUrls(ins.rows[0]));
  } catch (err) {
    if (req.body) await removeStorageObjects([req.body.scannedPdfPath, req.body.inspectionPdfPath]).catch(() => {});
    console.error('Create error:', err);
    res.status(500).json({ error: err.message });
  } finally {
    if (conn) conn.release();
  }
});

// PUT /api/applications/:id  (JSON; only replace a PDF when a new path is supplied)
app.put('/api/applications/:id', requireAuth, async (req, res) => {
  let conn;
  try {
    const { id } = req.params;
    if (!isId(id)) return res.status(400).json({ error: 'Invalid id' });
    const b = req.body || {};

    conn = await getPool().connect();
    const existingRes = await conn.query('SELECT * FROM applications WHERE id = $1', [id]);
    if (!existingRes.rows.length) return res.status(404).json({ error: 'Application not found' });
    const old = existingRes.rows[0];

    const fiscalYear = clean(b.fiscalYear) || old.fiscal_year;
    const officeName = clean(b.officeName) || old.office_name;
    const applicantName = clean(b.applicantName) || old.applicant_name;
    const applicantPhone = clean(b.applicantPhone) || old.applicant_phone;
    const dartaNumber = clean(b.dartaNumber) || old.darta_number;
    const progressStatus = clean(b.progressStatus) || old.progress_status;
    const scannedPdfPath = clean(b.scannedPdfPath) || old.scanned_pdf_path;
    const inspectionPdfPath = clean(b.inspectionPdfPath) || old.inspection_pdf_path;
    const inspectionAssignedTo = b.inspectionAssignedTo !== undefined ? (b.inspectionAssignedTo ? parseInt(b.inspectionAssignedTo) : null) : old.inspection_assigned_to;

    if (!PROGRESS_STATUSES.includes(progressStatus)) {
      return res.status(400).json({ error: 'Invalid progress status' });
    }

    if (dartaNumber !== old.darta_number) {
      const dup = await conn.query('SELECT id FROM applications WHERE darta_number = $1 AND id != $2', [dartaNumber, id]);
      if (dup.rows.length) return res.status(400).json({ error: 'Darta Number already exists' });
    }

    if (inspectionAssignedTo) {
      const insCheck = await conn.query('SELECT id FROM inspectors WHERE id = $1 AND is_active = true', [inspectionAssignedTo]);
      if (!insCheck.rows.length) return res.status(400).json({ error: 'Selected inspector does not exist or is inactive' });
    }

    // Delete replaced files
    if (old.scanned_pdf_path && scannedPdfPath !== old.scanned_pdf_path) {
      await removeStorageObjects([old.scanned_pdf_path]);
    }
    if (old.inspection_pdf_path && inspectionPdfPath !== old.inspection_pdf_path) {
      await removeStorageObjects([old.inspection_pdf_path]);
    }

    const upd = await conn.query(
      `UPDATE applications
         SET fiscal_year = $1, office_name = $2, applicant_name = $3, applicant_phone = $4, darta_number = $5,
             scanned_pdf_path = $6, inspection_pdf_path = $7, inspection_assigned_to = $8, progress_status = $9,
             updated_at = now()
       WHERE id = $10
       RETURNING *`,
      [fiscalYear, officeName, applicantName, applicantPhone, dartaNumber, scannedPdfPath, inspectionPdfPath, inspectionAssignedTo, progressStatus, id]
    );
    res.json(await withSignedUrls(upd.rows[0]));
  } catch (err) {
    if (req.body) await removeStorageObjects([req.body.scannedPdfPath, req.body.inspectionPdfPath]).catch(() => {});
    console.error('Update error:', err);
    res.status(500).json({ error: err.message });
  } finally {
    if (conn) conn.release();
  }
});

// PATCH /api/applications/:id/status  { progressStatus }
app.patch('/api/applications/:id/status', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isId(id)) return res.status(400).json({ error: 'Invalid id' });
    const progressStatus = clean((req.body || {}).progressStatus);
    if (!PROGRESS_STATUSES.includes(progressStatus)) {
      return res.status(400).json({ error: 'Invalid progress status' });
    }
    const r = await getPool().query(
      `UPDATE applications SET progress_status = $1, updated_at = now() WHERE id = $2 RETURNING *`,
      [progressStatus, id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Application not found' });
    res.json(await withSignedUrls(r.rows[0]));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/applications/:id
app.delete('/api/applications/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isId(id)) return res.status(400).json({ error: 'Invalid id' });
    const sel = await getPool().query('SELECT scanned_pdf_path, inspection_pdf_path FROM applications WHERE id = $1', [id]);
    if (!sel.rows.length) return res.status(404).json({ error: 'Application not found' });

    await getPool().query('DELETE FROM applications WHERE id = $1', [id]);
    await removeStorageObjects([sel.rows[0].scanned_pdf_path, sel.rows[0].inspection_pdf_path]);
    res.json({ success: true, message: 'Application deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/fiscal-years
app.get('/api/fiscal-years', requireAuth, async (req, res) => {
  try {
    const r = await getPool().query('SELECT DISTINCT fiscal_year FROM applications ORDER BY fiscal_year DESC');
    res.json(r.rows.map((x) => x.fiscal_year));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/offices
app.get('/api/offices', requireAuth, async (req, res) => {
  try {
    const r = await getPool().query('SELECT DISTINCT office_name FROM applications ORDER BY office_name');
    res.json(r.rows.map((x) => x.office_name));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/progress-statuses
app.get('/api/progress-statuses', requireAuth, (req, res) => res.json(PROGRESS_STATUSES));

// GET /api/health
app.get('/api/health', (req, res) => res.json({ ok: true, configured }));

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

module.exports = app;