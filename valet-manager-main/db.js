// db.js
const { Pool } = require('pg');
const { getDatabaseConnectionConfig } = require('./config/database');

const pool = new Pool(getDatabaseConnectionConfig());

// Simple helper to run queries (optional)
const query = (text, params) => pool.query(text, params);

// Retry wrapper for initial setup
async function waitForDbAndCreateTables(maxRetries = 15, baseDelayMs = 700) {
  let attempt = 0;

  // Tables
  const createUsers = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'valet',
      group_id INTEGER,
      profile_photo_url TEXT,
      contact_email TEXT,
      contact_phone TEXT,
      social_instagram TEXT,
      social_linkedin TEXT,
      social_x TEXT,
      bio TEXT,
      links TEXT
    );
  `;

  const createLocations = `
    CREATE TABLE IF NOT EXISTS locations (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      lot_fee REAL NOT NULL DEFAULT 0
    );
  `;

  const createGroups = `
    CREATE TABLE IF NOT EXISTS groups (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      visible_in_sidebar BOOLEAN DEFAULT TRUE
    );
  `;

  const createCommunityMessages = `
    CREATE TABLE IF NOT EXISTS community_messages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
      parent_message_id INTEGER REFERENCES community_messages(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `;

  const createShiftReports = `
    CREATE TABLE IF NOT EXISTS shift_reports (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      shift_date TIMESTAMP WITH TIME ZONE NOT NULL,
      hours REAL NOT NULL,
      online_tips REAL NOT NULL DEFAULT 0,
      cash_tips REAL NOT NULL DEFAULT 0,
      cars INTEGER NOT NULL DEFAULT 0,
      shift_notes TEXT,
      location_id INTEGER REFERENCES locations(id)
    );
  `;

  const createLocationWeeklyFees = `
    CREATE TABLE IF NOT EXISTS location_weekly_fees (
      id SERIAL PRIMARY KEY,
      location_id INTEGER NOT NULL REFERENCES locations(id) ON DELETE CASCADE,
      week_start_date DATE NOT NULL,
      lot_fee_amount REAL NOT NULL DEFAULT 0,
      UNIQUE (location_id, week_start_date)
    );
  `;

  const createLocationPayAllocations = `
    CREATE TABLE IF NOT EXISTS location_pay_allocations (
      id SERIAL PRIMARY KEY,
      location_id INTEGER NOT NULL REFERENCES locations(id) ON DELETE CASCADE,
      week_start_date DATE NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      allocated_amount REAL NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (location_id, week_start_date, user_id)
    );
  `;

  const createLocationRosters = `
    CREATE TABLE IF NOT EXISTS location_rosters (
      id SERIAL PRIMARY KEY,
      location_id INTEGER NOT NULL REFERENCES locations(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (location_id, user_id)
    );
  `;

  const createShiftScreenshots = `
    CREATE TABLE IF NOT EXISTS shift_screenshots (
      id SERIAL PRIMARY KEY,
      shift_report_id INTEGER NOT NULL REFERENCES shift_reports(id) ON DELETE CASCADE,
      file_path TEXT NOT NULL
    );
  `;

  while (attempt < maxRetries) {
    try {
      // Test connection
      await pool.query('SELECT 1');

      // Create tables idempotently
      await pool.query('BEGIN');
      await pool.query(createUsers);
      await pool.query(createLocations);
      await pool.query(createGroups);
      await pool.query(createCommunityMessages);
      await pool.query(createShiftReports);
      await pool.query(createShiftScreenshots);
      await pool.query(createLocationWeeklyFees);
      await pool.query(createLocationPayAllocations);
      await pool.query(createLocationRosters);

      // Backfill new columns if upgrading from older schema
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS group_id INTEGER`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_photo_url TEXT`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS contact_email TEXT`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS contact_phone TEXT`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS social_instagram TEXT`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS social_linkedin TEXT`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS social_x TEXT`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS links TEXT`);
      await pool.query(`ALTER TABLE locations ADD COLUMN IF NOT EXISTS lot_fee REAL NOT NULL DEFAULT 0`);
      await pool.query(`ALTER TABLE shift_reports ADD COLUMN IF NOT EXISTS shift_notes TEXT`);
      await pool.query(`ALTER TABLE community_messages ADD COLUMN IF NOT EXISTS parent_message_id INTEGER`);
      await pool.query(`ALTER TABLE community_messages DROP CONSTRAINT IF EXISTS community_messages_parent_message_id_fkey`);
      await pool.query(
        `ALTER TABLE community_messages
         ADD CONSTRAINT community_messages_parent_message_id_fkey
         FOREIGN KEY (parent_message_id)
         REFERENCES community_messages(id)
         ON DELETE CASCADE`
      );

      await pool.query(`ALTER TABLE groups ADD COLUMN IF NOT EXISTS visible_in_sidebar BOOLEAN DEFAULT TRUE`);
      await pool.query(`UPDATE groups SET visible_in_sidebar = TRUE WHERE visible_in_sidebar IS NULL`);

      await pool.query(`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_group_id_fkey`);
      await pool.query(
        `ALTER TABLE users ADD CONSTRAINT users_group_id_fkey FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL`
      );
      await pool.query('COMMIT');

      console.log('✅ Database ready and tables ensured.');
      return;
    } catch (err) {
      // 57P03 = “the database system is starting up”
      const retryable =
        err.code === '57P03' ||
        err.code === 'ECONNREFUSED' ||
        err.message?.includes('the database system is starting up');

      if (!retryable) {
        console.error('❌ Error creating tables (non-retryable):', err);
        throw err;
      }

      attempt += 1;
      const delay = baseDelayMs * Math.min(8, 2 ** attempt); // exponential backoff, capped
      console.warn(
        `DB not ready yet (attempt ${attempt}/${maxRetries}). Retrying in ${delay}ms...`,
        err.code || err.message
      );
      await new Promise(r => setTimeout(r, delay));
    }
  }

  throw new Error('Database did not become ready in time.');
}

// Kick off on import
waitForDbAndCreateTables().catch((e) => {
  console.error('Fatal DB init error:', e);
  process.exit(1); // Crash container so the process manager can restart it
});

module.exports = {
  pool,
  query
};
