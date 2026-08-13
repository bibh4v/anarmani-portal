/**
 * One-time setup script: applies the Postgres schema and creates the private
 * storage bucket on your Supabase project.
 *
 * Prereq: a .env file with DATABASE_URL, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY.
 * Run:    npm run db:setup
 */
require('dotenv').config();

const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const { createClient } = require('@supabase/supabase-js');

(async () => {
  const { DATABASE_URL, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;
  const bucket = process.env.SUPABASE_STORAGE_BUCKET || 'documents';

  const missing = Object.entries({ DATABASE_URL, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY })
    .filter(([, v]) => !v)
    .map(([k]) => k);

  if (missing.length) {
    console.error('✗ Missing in .env: ' + missing.join(', '));
    console.error('  Copy .env.example to .env and fill in values from your Supabase dashboard.');
    process.exit(1);
  }

  console.log('Connecting to Supabase Postgres…');

  // 1) Apply schema
  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 15000,
  });
  const sql = fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8');
  await pool.query(sql);
  console.log('✓ Database schema applied (table "applications" ready)');
  await pool.end();

  // 2) Create private storage bucket (for PDFs)
  console.log('Checking storage bucket "' + bucket + '"…');
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data: existing } = await sb.storage.getBucket(bucket);
  if (existing) {
    console.log('✓ Storage bucket "' + bucket + '" already exists (private)');
  } else {
    const { error: createErr } = await sb.storage.createBucket(bucket, { public: false });
    if (createErr && !/already exists/i.test(createErr.message)) {
      console.error('✗ Could not create bucket: ' + createErr.message);
      process.exit(1);
    }
    console.log('✓ Storage bucket "' + bucket + '" created (private)');
  }

  console.log('');
  console.log('Setup complete. You can now run: npm start');
})().catch((err) => {
  console.error('Setup failed:', err.message);
  process.exit(1);
});
