function isTruthyEnv(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

function getDatabaseConnectionConfig() {
  if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL is required');
  }
  return {
    connectionString: process.env.DATABASE_URL,
    ssl: isTruthyEnv(process.env.DATABASE_SSL) ? { rejectUnauthorized: false } : undefined
  };
}

module.exports = {
  getDatabaseConnectionConfig
};
