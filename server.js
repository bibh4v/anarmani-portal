/**
 * Local development entry point.
 * Starts the same Express app that runs on Vercel, pointed at your
 * cloud Supabase database. Requires a .env file (see .env.example).
 */
const dotenv = require('dotenv');
dotenv.config();

const app = require('./api/index');

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log('=====================================================');
  console.log('  Anarmani Distribution Centre - Consumer Portal');
  console.log(`  Local dev server: http://localhost:${PORT}`);
  const ok = process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY && process.env.DATABASE_URL;
  console.log(
    ok
      ? '  Connected to cloud Supabase (Postgres + Storage)'
      : '  ⚠ Supabase not configured yet. Copy .env.example to .env and run npm run db:setup.'
  );
  console.log('=====================================================');
});
