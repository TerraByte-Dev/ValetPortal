// server.js
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs'); // using bcryptjs
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const csvWriter = require('csv-writer').createObjectCsvWriter;

// Your Postgres wrapper (pool + query helper)
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

/* ------------------------------
   Core Middleware
--------------------------------*/
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Ensure 'uploads' folder exists & serve uploaded images
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
app.use('/uploads', express.static(uploadDir));

/* ------------------------------
   Sessions (Production-ready)
--------------------------------*/
// If behind a proxy (Railway/Heroku/etc.), trust it so secure cookies work
app.set('trust proxy', 1);

// Configure session store in Postgres (no MemoryStore in prod)
const sessionStore = new pgSession({
  // Use connection string directly to avoid requiring db.pool export shapes
  conObject: {
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined
  },
  tableName: 'session',
  createTableIfMissing: true
});

app.use(
  session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET || 'change_this_secret_in_env',
    resave: false,
    saveUninitialized: false,
    cookie: {
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production', // only over HTTPS in prod
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    }
  })
);

/* ------------------------------
   View Engine
--------------------------------*/
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Make user available in all templates
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  res.locals.formatEstDate = formatEstDateLabel;
  next();
});

/* ------------------------------
   Auth Helpers
--------------------------------*/
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send('Access denied');
  }
  next();
}

function parseDateForEst(value) {
  if (!value) return null;
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)) {
    const [yyyy, mm, dd] = value.split('-').map(Number);
    return new Date(Date.UTC(yyyy, mm - 1, dd, 12, 0, 0, 0));
  }
  const parsed = value instanceof Date ? value : new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function formatEstDateLabel(value) {
  const parsed = parseDateForEst(value);
  if (!parsed) return '';
  const weekday = new Intl.DateTimeFormat('en-US', {
    weekday: 'short',
    timeZone: 'America/New_York'
  }).format(parsed).toUpperCase();
  const mdy = new Intl.DateTimeFormat('en-US', {
    month: 'numeric',
    day: 'numeric',
    year: '2-digit',
    timeZone: 'America/New_York'
  }).format(parsed);
  return `${weekday} ${mdy}`;
}

function selectedAttributeLabel(attribute) {
  if (attribute === 'online_tips') return 'Online Tips';
  if (attribute === 'cash_tips') return 'Cash Tips';
  if (attribute === 'total_tips') return 'Total Tips';
  return 'Hours';
}

function todayEstIsoDate() {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/New_York',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).formatToParts(new Date());
  const year = parts.find((p) => p.type === 'year')?.value;
  const month = parts.find((p) => p.type === 'month')?.value;
  const day = parts.find((p) => p.type === 'day')?.value;
  return `${year}-${month}-${day}`;
}

function addDaysToIsoDate(isoDate, days) {
  const [yyyy, mm, dd] = isoDate.split('-').map(Number);
  const dt = new Date(Date.UTC(yyyy, mm - 1, dd, 12, 0, 0, 0));
  dt.setUTCDate(dt.getUTCDate() + days);
  const y = dt.getUTCFullYear();
  const m = String(dt.getUTCMonth() + 1).padStart(2, '0');
  const d = String(dt.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function getRequestedWeekRange(weekStartParam) {
  const baseIso = /^\d{4}-\d{2}-\d{2}$/.test(weekStartParam || '')
    ? weekStartParam
    : todayEstIsoDate();
  const [yyyy, mm, dd] = baseIso.split('-').map(Number);
  const baseUtcNoon = new Date(Date.UTC(yyyy, mm - 1, dd, 12, 0, 0, 0));
  const diffToMonday = (baseUtcNoon.getUTCDay() + 6) % 7;
  const weekStartDate = addDaysToIsoDate(baseIso, -diffToMonday);
  const weekEndDate = addDaysToIsoDate(weekStartDate, 7);
  const weekStart = parseDateForEst(weekStartDate);
  const weekEnd = parseDateForEst(weekEndDate);
  return {
    weekStart,
    weekEnd,
    weekStartDate,
    weekEndDate
  };
}

/* ------------------------------
   Multer (File Uploads)
--------------------------------*/
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, 'shift-' + uniqueSuffix + '-' + file.originalname);
  }
});
const upload = multer({ storage });

const profileStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, 'profile-' + uniqueSuffix + ext);
  }
});
const profileUpload = multer({ storage: profileStorage });

/* ------------------------------
   Routes
--------------------------------*/

// Home
app.get('/', (req, res) => {
  if (req.session.user) {
    if (req.session.user.role === 'admin') return res.redirect('/admin');
    return res.redirect('/dashboard');
  }
  res.render('index');
});

app.get('/about', (req, res) => {
  res.render('about');
});

// Register
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});
app.post('/register', async (req, res) => {
  const { first_name, last_initial, phone, password, confirm_password } = req.body;
  if (!first_name || !last_initial || !phone || !password || !confirm_password) {
    return res.render('register', { error: 'All fields are required' });
  }
  if (password !== confirm_password) {
    return res.render('register', { error: 'Passwords do not match' });
  }
  const cleanFirst = String(first_name).trim();
  const cleanLastInitial = String(last_initial).trim().charAt(0).toUpperCase();
  const name = `${cleanFirst} ${cleanLastInitial}.`;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const queryText = `
      INSERT INTO users (name, phone, password)
      VALUES ($1, $2, $3)
      RETURNING id
    `;
    await db.query(queryText, [name, phone, hashedPassword]);
    res.redirect('/login');
  } catch (err) {
    if (
      (err.code === '23505') || // unique_violation
      (err.message && err.message.includes('duplicate key value'))
    ) {
      return res.render('register', { error: 'Phone number is already registered!' });
    }
    return res.render('register', { error: 'Registration error: ' + err.message });
  }
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});
app.post('/login', (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) {
    return res.render('login', { error: 'All fields are required' });
  }
  const queryText = 'SELECT * FROM users WHERE phone = $1';
  db.query(queryText, [phone])
    .then(async (result) => {
      if (result.rowCount === 0) return res.render('login', { error: 'Invalid credentials' });
      const user = result.rows[0];
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.render('login', { error: 'Invalid credentials' });
      req.session.user = user;
      if (user.role === 'admin') res.redirect('/admin');
      else res.redirect('/dashboard');
    })
    .catch(() => res.render('login', { error: 'Invalid credentials' }));
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

/* ------------------------------
   Dashboard (valet)
--------------------------------*/
app.get('/dashboard', requireLogin, (req, res) => {
  db.query('SELECT * FROM locations')
    .then((r) => res.render('dashboard', { error: null, message: null, locations: r.rows }))
    .catch((err) =>
      res.render('dashboard', { error: 'Error loading locations: ' + err.message, message: null, locations: [] })
    );
});

app.post('/dashboard', requireLogin, upload.array('screenshots', 10), (req, res) => {
  const { shift_date, hours, online_tips, cash_tips, location_id, cars, shift_notes } = req.body;
  if (!shift_date || online_tips === undefined || cash_tips === undefined || !location_id) {
    return res.render('dashboard', { error: 'All fields are required', message: null, locations: [] });
  }
  const hoursValue = hours ? Number(hours) : 0;
  const carsValue = cars ? Number(cars) : 0;
  const insertQuery = `
    INSERT INTO shift_reports (user_id, shift_date, hours, online_tips, cash_tips, location_id, cars, shift_notes)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id
  `;
  db.query(insertQuery, [
    req.session.user.id,
    shift_date,
    hoursValue,
    online_tips,
    cash_tips,
    location_id,
    carsValue,
    shift_notes ? String(shift_notes).trim() : null
  ])
    .then((result) => {
      const shiftReportId = result.rows[0].id;
      if (req.files && req.files.length > 0) {
        const promises = req.files.map((file) =>
          db.query('INSERT INTO shift_screenshots (shift_report_id, file_path) VALUES ($1, $2)', [
            shiftReportId,
            file.filename
          ])
        );
        return Promise.all(promises);
      }
    })
    .then(() => db.query('SELECT * FROM locations'))
    .then((r) => res.render('dashboard', { error: null, message: 'Shift report submitted successfully!', locations: r.rows }))
    .catch((err) =>
      res.render('dashboard', { error: 'Error saving report: ' + err.message, message: null, locations: [] })
    );
});

app.get('/profile', requireLogin, (req, res) => {
  db.query('SELECT * FROM users WHERE id = $1', [req.session.user.id])
    .then((r) => {
      if (!r.rowCount) return res.redirect('/dashboard');
      res.render('profile', { userProfile: r.rows[0], error: null, message: null });
    })
    .catch((err) => res.render('profile', { userProfile: req.session.user, error: err.message, message: null }));
});

app.post('/profile', requireLogin, profileUpload.single('profile_photo'), async (req, res) => {
  const { contact_phone, social_linkedin, bio, links, existing_photo, current_password, new_password, confirm_new_password } = req.body;
  try {
    const currentUserRes = await db.query('SELECT * FROM users WHERE id = $1', [req.session.user.id]);
    if (!currentUserRes.rowCount) return res.redirect('/dashboard');
    const currentUser = currentUserRes.rows[0];

    let passwordToSave = currentUser.password;
    const wantsPasswordChange = current_password || new_password || confirm_new_password;
    if (wantsPasswordChange) {
      if (!current_password || !new_password || !confirm_new_password) {
        return res.render('profile', {
          userProfile: currentUser,
          error: 'To change password, fill current password and both new password fields.',
          message: null
        });
      }
      if (new_password !== confirm_new_password) {
        return res.render('profile', {
          userProfile: currentUser,
          error: 'New password confirmation does not match.',
          message: null
        });
      }
      const matchesCurrent = await bcrypt.compare(current_password, currentUser.password);
      if (!matchesCurrent) {
        return res.render('profile', {
          userProfile: currentUser,
          error: 'Current password is incorrect.',
          message: null
        });
      }
      passwordToSave = await bcrypt.hash(new_password, 10);
    }

    const profilePhoto = req.file ? req.file.filename : (existing_photo || null);
    const updateQuery = `
      UPDATE users
      SET profile_photo_url = $1,
          contact_phone = $2,
          social_linkedin = $3,
          bio = $4,
          links = $5,
          password = $6
      WHERE id = $7
      RETURNING *
    `;
    const updatedRes = await db.query(updateQuery, [
      profilePhoto,
      contact_phone || null,
      social_linkedin || null,
      bio || null,
      links || null,
      passwordToSave,
      req.session.user.id
    ]);
    if (updatedRes.rowCount) req.session.user = updatedRes.rows[0];
    return res.render('profile', { userProfile: updatedRes.rows[0], error: null, message: 'Profile updated.' });
  } catch (err) {
    return res.render('profile', {
      userProfile: req.session.user,
      error: 'Error updating profile: ' + err.message,
      message: null
    });
  }
});

app.get('/messages', requireLogin, (req, res) => {
  res.redirect('/community');
});

/* ------------------------------
   Community: Team Board
--------------------------------*/
app.get('/community', requireLogin, (req, res) => {
  const messagesQuery = `
    SELECT cm.id, cm.body, cm.created_at, cm.updated_at,
           u.name, u.profile_photo_url, g.name AS group_name
    FROM community_messages cm
    JOIN users u ON cm.user_id = u.id
    LEFT JOIN groups g ON u.group_id = g.id
    ORDER BY cm.created_at DESC
  `;
  const usersQuery = `
    SELECT u.id, u.name, u.profile_photo_url, g.name AS group_name
    FROM users u
    LEFT JOIN groups g ON u.group_id = g.id
    WHERE (g.visible_in_sidebar IS TRUE OR g.visible_in_sidebar IS NULL)
    ORDER BY u.name ASC
  `;
  Promise.all([db.query(messagesQuery), db.query(usersQuery)])
    .then(([messages, users]) =>
      res.render('community', {
        messages: messages.rows,
        users: users.rows,
        error: null
      })
    )
    .catch((err) =>
      res.render('community', { messages: [], users: [], error: 'Error loading community: ' + err.message })
    );
});

app.post('/community', requireLogin, (req, res) => {
  const body = String(req.body.body || '').trim();
  if (!body) return res.redirect('/community');
  db.query('INSERT INTO community_messages (user_id, body) VALUES ($1, $2)', [req.session.user.id, body])
    .then(() => res.redirect('/community'))
    .catch(() => res.redirect('/community'));
});

/* ------------------------------
   Admin: Reports
--------------------------------*/
app.get('/admin', requireAdmin, (req, res) => {
  const { weekStart, weekEnd, weekStartDate, weekEndDate } = getRequestedWeekRange(req.query.week_start);
  const previousWeekStart = new Date(weekStart);
  previousWeekStart.setDate(previousWeekStart.getDate() - 7);
  const nextWeekStart = new Date(weekStart);
  nextWeekStart.setDate(nextWeekStart.getDate() + 7);
  const weekDisplayEnd = new Date(weekEnd);
  weekDisplayEnd.setDate(weekDisplayEnd.getDate() - 1);

  const topHoursQuery = `
    SELECT u.id, u.name, COALESCE(SUM(sr.hours), 0) AS total_hours
    FROM users u
    LEFT JOIN shift_reports sr
      ON sr.user_id = u.id
      AND DATE(sr.shift_date AT TIME ZONE 'America/New_York') >= $1
      AND DATE(sr.shift_date AT TIME ZONE 'America/New_York') < $2
    WHERE u.role = 'valet'
    GROUP BY u.id
    ORDER BY total_hours DESC
    LIMIT 1
  `;

  const topTipsQuery = `
    SELECT u.id, u.name,
      COALESCE(SUM(sr.online_tips) + SUM(sr.cash_tips), 0) AS total_tips
    FROM users u
    LEFT JOIN shift_reports sr
      ON sr.user_id = u.id
      AND DATE(sr.shift_date AT TIME ZONE 'America/New_York') >= $1
      AND DATE(sr.shift_date AT TIME ZONE 'America/New_York') < $2
    WHERE u.role = 'valet'
    GROUP BY u.id
    ORDER BY total_tips DESC
    LIMIT 1
  `;

  const recentQuery = `
    SELECT sr.id, sr.shift_date, sr.online_tips, sr.cash_tips, sr.shift_notes,
           u.name AS valet_name, l.name AS location_name
    FROM shift_reports sr
    JOIN users u ON sr.user_id = u.id
    LEFT JOIN locations l ON sr.location_id = l.id
    ORDER BY sr.shift_date DESC
    LIMIT 6
  `;

  Promise.all([
    db.query(topHoursQuery, [weekStartDate, weekEndDate]),
    db.query(topTipsQuery, [weekStartDate, weekEndDate]),
    db.query(recentQuery)
  ])
    .then(([topHours, topTips, recent]) => {
      res.render('admin_dashboard', {
        weekStart,
        weekDisplayEnd,
        topHours: topHours.rows[0] || null,
        topTips: topTips.rows[0] || null,
        recentReports: recent.rows,
        previousWeekStartDate: formatDate(previousWeekStart),
        nextWeekStartDate: formatDate(nextWeekStart)
      });
    })
    .catch((err) => res.send('Error retrieving admin dashboard: ' + err.message));
});

app.get('/admin/reports', requireAdmin, (req, res) => {
  const sort = req.query.sort || 'recent';
  const locationFilter = req.query.location_id || '';
  const valetFilter = req.query.valet_id || '';

  const sortMap = {
    recent: 'sr.shift_date DESC',
    location: 'l.name ASC, sr.shift_date DESC',
    valet: 'u.name ASC, sr.shift_date DESC',
    cash: 'sr.cash_tips DESC',
    digital: 'sr.online_tips DESC'
  };
  const orderBy = sortMap[sort] || sortMap.recent;

  let query = `
    SELECT sr.id, sr.shift_date, sr.online_tips, sr.cash_tips, sr.shift_notes,
           u.name AS valet_name, l.name AS location_name
    FROM shift_reports sr
    JOIN users u ON sr.user_id = u.id
    LEFT JOIN locations l ON sr.location_id = l.id
  `;
  const params = [];
  const where = [];
  if (locationFilter) {
    params.push(locationFilter);
    where.push(`sr.location_id = $${params.length}`);
  }
  if (valetFilter) {
    params.push(valetFilter);
    where.push(`sr.user_id = $${params.length}`);
  }
  if (where.length) query += ' WHERE ' + where.join(' AND ');
  query += ` ORDER BY ${orderBy}`;

  Promise.all([
    db.query(query, params),
    db.query('SELECT * FROM locations ORDER BY name ASC'),
    db.query("SELECT id, name FROM users WHERE role = 'valet' ORDER BY name ASC")
  ])
    .then(([reports, locations, valets]) =>
      res.render('admin_reports', {
        reports: reports.rows,
        locations: locations.rows,
        valets: valets.rows,
        sort,
        selectedLocation: locationFilter,
        selectedValet: valetFilter
      })
    )
    .catch((err) => res.send('Error retrieving reports: ' + err.message));
});

app.get('/admin/reports/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const query = `
    SELECT sr.*, u.name AS valet_name, u.phone,
           l.name AS location_name
    FROM shift_reports sr
    JOIN users u ON sr.user_id = u.id
    LEFT JOIN locations l ON sr.location_id = l.id
    WHERE sr.id = $1
  `;
  db.query(query, [id])
    .then((r) => {
      if (!r.rowCount) return res.send('Shift report not found.');
      return db
        .query('SELECT file_path FROM shift_screenshots WHERE shift_report_id = $1', [id])
        .then((sr) =>
          res.render('admin_report_view', {
            report: r.rows[0],
            screenshots: sr.rows.map((row) => row.file_path)
          })
        );
    })
    .catch((err) => res.send('Error retrieving shift report: ' + err.message));
});

/* ------------------------------
   Admin: Edit Shift
--------------------------------*/
app.get('/admin/edit/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const query = `
    SELECT sr.*, u.name AS valet_name, u.phone, l.name AS location_name
    FROM shift_reports sr
    JOIN users u ON sr.user_id = u.id
    LEFT JOIN locations l ON sr.location_id = l.id
    WHERE sr.id = $1
  `;
  db.query(query, [id])
    .then((r) => {
      if (r.rowCount === 0) return res.send('Shift report not found.');
      res.render('admin_edit', { report: r.rows[0] });
    })
    .catch((err) => res.send('Error retrieving shift report: ' + err.message));
});

app.post('/admin/edit/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { shift_date, hours, cars, online_tips, cash_tips, shift_notes } = req.body;
  const updateQuery = `
    UPDATE shift_reports
    SET shift_date = $1, hours = $2, cars = $3, online_tips = $4, cash_tips = $5, shift_notes = $6
    WHERE id = $7
  `;
  db.query(updateQuery, [shift_date, hours, cars, online_tips, cash_tips, shift_notes || null, id])
    .then(() => res.redirect('/admin/reports'))
    .catch((err) => res.send('Error updating shift report: ' + err.message));
});

/* ------------------------------
   Admin: Export CSV (All)
--------------------------------*/
app.get('/admin/export', requireAdmin, (req, res) => {
  const query = `
    SELECT sr.*, u.name, u.phone, l.name AS location_name
    FROM shift_reports sr
    JOIN users u ON sr.user_id = u.id
    LEFT JOIN locations l ON sr.location_id = l.id
    ORDER BY sr.shift_date DESC
  `;
  db.query(query)
    .then(async (r) => {
      const reports = r.rows.map((report) => ({
        ...report,
        total: Number(report.online_tips) + Number(report.cash_tips)
      }));
      const csvPath = 'shift_reports.csv';
      const writer = csvWriter({
        path: csvPath,
        header: [
          { id: 'id', title: 'ID' },
          { id: 'name', title: 'Name' },
          { id: 'phone', title: 'Phone' },
          { id: 'shift_date', title: 'Shift Date' },
          { id: 'hours', title: 'Hours' },
          { id: 'cars', title: '# of Cars' },
          { id: 'online_tips', title: 'Online Payments' },
          { id: 'cash_tips', title: 'Cash Payments' },
          { id: 'total', title: 'Total' },
          { id: 'location_name', title: 'Location' }
        ]
      });
      await writer.writeRecords(reports);
      res.download(csvPath, 'shift_reports.csv');
    })
    .catch((err) => res.send('Error retrieving reports: ' + err.message));
});

/* ------------------------------
   Admin: Locations
--------------------------------*/
app.get('/admin/locations', requireAdmin, (req, res) => {
  const { weekStartDate, weekEndDate, weekStart, weekEnd } = getRequestedWeekRange(req.query.week_start);
  const reportsQuery = `
    SELECT sr.location_id, u.name AS valet_name,
           COALESCE(SUM(sr.hours), 0) AS total_hours,
           COALESCE(SUM(sr.cars), 0) AS total_cars,
           COALESCE(SUM(sr.cash_tips), 0) AS total_cash,
           COALESCE(SUM(sr.online_tips), 0) AS total_online
    FROM shift_reports sr
    JOIN users u ON sr.user_id = u.id
    WHERE DATE(sr.shift_date) >= $1
      AND DATE(sr.shift_date) < $2
    GROUP BY sr.location_id, u.name
    ORDER BY u.name ASC
  `;

  Promise.all([
    db.query('SELECT * FROM locations ORDER BY name ASC'),
    db.query(reportsQuery, [weekStartDate, weekEndDate])
  ])
    .then(([locationsRes, reportsRes]) => {
      const locations = locationsRes.rows.map((loc) => ({
        id: loc.id,
        name: loc.name,
        lot_fee: Number(loc.lot_fee) || 0,
        total_hours: 0,
        total_cars: 0,
        total_cash: 0,
        total_online: 0,
        valets: []
      }));
      const byLocation = new Map(locations.map((l) => [l.id, l]));
      reportsRes.rows.forEach((row) => {
        const summary = byLocation.get(row.location_id);
        if (!summary) return;
        const hours = Number(row.total_hours) || 0;
        const cars = Number(row.total_cars) || 0;
        const cash = Number(row.total_cash) || 0;
        const online = Number(row.total_online) || 0;
        summary.total_hours += hours;
        summary.total_cars += cars;
        summary.total_cash += cash;
        summary.total_online += online;
        summary.valets.push({
          name: row.valet_name,
          hours
        });
      });
      locations.forEach((loc) => loc.valets.sort((a, b) => b.hours - a.hours));
      res.render('admin_locations', {
        locations,
        weekStart,
        weekEnd
      });
    })
    .catch((err) => res.send('Error retrieving location overview: ' + err.message));
});

app.get('/admin/locations/manage', requireAdmin, (req, res) => {
  db.query('SELECT * FROM locations ORDER BY name ASC')
    .then((r) => res.render('admin_locations_manage', { locations: r.rows, error: null, message: null }))
    .catch((err) => res.send('Error retrieving locations: ' + err.message));
});

app.post('/admin/locations/manage', requireAdmin, (req, res) => {
  const { locationName, lot_fee } = req.body;
  if (!locationName) {
    return db
      .query('SELECT * FROM locations ORDER BY name ASC')
      .then((r) => res.render('admin_locations_manage', { locations: r.rows, error: 'Location name is required.', message: null }));
  }
  db.query('INSERT INTO locations (name, lot_fee) VALUES ($1, $2)', [locationName, Number(lot_fee) || 0])
    .then(() => db.query('SELECT * FROM locations ORDER BY name ASC'))
    .then((r) => res.render('admin_locations_manage', { locations: r.rows, error: null, message: 'Location added.' }))
    .catch((err) =>
      res.render('admin_locations_manage', { locations: [], error: 'Error adding location: ' + err.message, message: null })
    );
});

app.post('/admin/locations/manage/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { locationName, lot_fee } = req.body;
  if (!locationName) return res.redirect('/admin/locations/manage');
  db.query('UPDATE locations SET name = $1, lot_fee = $2 WHERE id = $3', [locationName, Number(lot_fee) || 0, id])
    .then(() => res.redirect('/admin/locations/manage'))
    .catch((err) => res.send('Error updating location: ' + err.message));
});

app.post('/admin/locations/manage/delete/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { confirm_text } = req.body;
  if (confirm_text !== 'DELETE') {
    return db
      .query('SELECT * FROM locations ORDER BY name ASC')
      .then((r) =>
        res.render('admin_locations_manage', {
          locations: r.rows,
          error: 'Type DELETE to confirm location removal.',
          message: null
        })
      );
  }
  db.query('DELETE FROM locations WHERE id = $1', [id])
    .then(() => db.query('SELECT * FROM locations ORDER BY name ASC'))
    .then((r) => res.render('admin_locations_manage', { locations: r.rows, error: null, message: 'Location removed.' }))
    .catch((err) =>
      res.render('admin_locations_manage', { locations: [], error: 'Error removing location: ' + err.message, message: null })
    );
});

app.get('/admin/locations/:id/pay', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { weekStartDate, weekEndDate, weekStart, weekEnd } = getRequestedWeekRange(req.query.week_start);

  const valetsQuery = `
    SELECT sr.user_id, u.name,
           COALESCE(SUM(sr.hours), 0) AS total_hours,
           COALESCE(SUM(sr.cash_tips), 0) AS total_cash,
           COALESCE(SUM(sr.online_tips), 0) AS total_online
    FROM shift_reports sr
    JOIN users u ON sr.user_id = u.id
    WHERE sr.location_id = $1
      AND DATE(sr.shift_date) >= $2
      AND DATE(sr.shift_date) < $3
    GROUP BY sr.user_id, u.name
    ORDER BY u.name ASC
  `;

  Promise.all([
    db.query('SELECT * FROM locations WHERE id = $1', [id]),
    db.query(valetsQuery, [id, weekStartDate, weekEndDate]),
    db.query('SELECT user_id, allocated_amount FROM location_pay_allocations WHERE location_id = $1 AND week_start_date = $2', [id, weekStartDate]),
    db.query('SELECT lot_fee_amount FROM location_weekly_fees WHERE location_id = $1 AND week_start_date = $2', [id, weekStartDate])
  ])
    .then(([locationRes, valetsRes, allocationsRes, weeklyFeeRes]) => {
      if (!locationRes.rowCount) return res.send('Location not found.');
      const location = locationRes.rows[0];
      const weeklyLotFee = weeklyFeeRes.rowCount ? Number(weeklyFeeRes.rows[0].lot_fee_amount) : Number(location.lot_fee || 0);
      const allocationMap = new Map(allocationsRes.rows.map((row) => [Number(row.user_id), Number(row.allocated_amount) || 0]));
      const valets = valetsRes.rows.map((row) => ({
        user_id: Number(row.user_id),
        name: row.name,
        total_hours: Number(row.total_hours) || 0,
        total_cash: Number(row.total_cash) || 0,
        total_online: Number(row.total_online) || 0,
        allocated_amount: allocationMap.get(Number(row.user_id)) || 0
      }));
      const grossTotal = valets.reduce((sum, v) => sum + v.total_cash + v.total_online, 0);
      const allocatedTotal = valets.reduce((sum, v) => sum + v.allocated_amount, 0);
      const distributable = Math.max(0, grossTotal - weeklyLotFee);
      const remaining = distributable - allocatedTotal;
      return res.render('admin_location_pay', {
        location,
        valets,
        weekStart,
        weekEnd,
        weekStartDate,
        grossTotal,
        weeklyLotFee,
        distributable,
        allocatedTotal,
        remaining
      });
    })
    .catch((err) => res.send('Error loading location pay page: ' + err.message));
});

app.post('/admin/locations/:id/pay/lot-fee', requireAdmin, (req, res) => {
  const { id } = req.params;
  const weekStartDate = req.body.week_start;
  const lotFee = Number(req.body.lot_fee_amount) || 0;
  if (!weekStartDate) return res.redirect(`/admin/locations/${id}/pay`);
  db.query(
    `
      INSERT INTO location_weekly_fees (location_id, week_start_date, lot_fee_amount)
      VALUES ($1, $2, $3)
      ON CONFLICT (location_id, week_start_date)
      DO UPDATE SET lot_fee_amount = EXCLUDED.lot_fee_amount
    `,
    [id, weekStartDate, lotFee]
  )
    .then(() => res.redirect(`/admin/locations/${id}/pay?week_start=${weekStartDate}`))
    .catch((err) => res.send('Error saving lot fee: ' + err.message));
});

app.post('/admin/locations/:id/pay', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const weekStartDate = req.body.week_start;
  if (!weekStartDate) return res.redirect(`/admin/locations/${id}/pay`);
  try {
    const weekStart = new Date(`${weekStartDate}T12:00:00`);
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekEnd.getDate() + 7);
    const weekEndDate = formatDate(weekEnd);
    const valetsRes = await db.query(
      `
        SELECT DISTINCT sr.user_id
        FROM shift_reports sr
        WHERE sr.location_id = $1
          AND DATE(sr.shift_date) >= $2
          AND DATE(sr.shift_date) < $3
      `,
      [id, weekStartDate, weekEndDate]
    );
    await db.query('DELETE FROM location_pay_allocations WHERE location_id = $1 AND week_start_date = $2', [id, weekStartDate]);
    for (const row of valetsRes.rows) {
      const userId = Number(row.user_id);
      const amount = Number(req.body[`alloc_${userId}`]) || 0;
      if (amount <= 0) continue;
      await db.query(
        `
          INSERT INTO location_pay_allocations (location_id, week_start_date, user_id, allocated_amount, updated_at)
          VALUES ($1, $2, $3, $4, NOW())
        `,
        [id, weekStartDate, userId, amount]
      );
    }
    return res.redirect(`/admin/locations/${id}/pay?week_start=${weekStartDate}`);
  } catch (err) {
    return res.send('Error saving pay allocations: ' + err.message);
  }
});

app.post('/admin/locations/:id/pay/autosplit', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const weekStartDate = req.body.week_start;
  if (!weekStartDate) return res.redirect(`/admin/locations/${id}/pay`);
  try {
    const weekStart = new Date(`${weekStartDate}T12:00:00`);
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekEnd.getDate() + 7);
    const weekEndDate = formatDate(weekEnd);

    const [locationRes, valetsRes, weeklyFeeRes] = await Promise.all([
      db.query('SELECT lot_fee FROM locations WHERE id = $1', [id]),
      db.query(
        `
          SELECT sr.user_id,
                 COALESCE(SUM(sr.cash_tips), 0) AS total_cash,
                 COALESCE(SUM(sr.online_tips), 0) AS total_online
          FROM shift_reports sr
          WHERE sr.location_id = $1
            AND DATE(sr.shift_date) >= $2
            AND DATE(sr.shift_date) < $3
          GROUP BY sr.user_id
          ORDER BY sr.user_id
        `,
        [id, weekStartDate, weekEndDate]
      ),
      db.query('SELECT lot_fee_amount FROM location_weekly_fees WHERE location_id = $1 AND week_start_date = $2', [id, weekStartDate])
    ]);

    if (!locationRes.rowCount) return res.send('Location not found.');
    const lotFee = weeklyFeeRes.rowCount ? Number(weeklyFeeRes.rows[0].lot_fee_amount) : Number(locationRes.rows[0].lot_fee || 0);
    const grossTotal = valetsRes.rows.reduce(
      (sum, row) => sum + (Number(row.total_cash) || 0) + (Number(row.total_online) || 0),
      0
    );
    const distributable = Math.max(0, grossTotal - lotFee);

    const valetIds = valetsRes.rows.map((row) => Number(row.user_id));
    await db.query('DELETE FROM location_pay_allocations WHERE location_id = $1 AND week_start_date = $2', [id, weekStartDate]);
    if (valetIds.length > 0 && distributable > 0) {
      let running = 0;
      const perValet = Number((distributable / valetIds.length).toFixed(2));
      for (let i = 0; i < valetIds.length; i++) {
        const amount = i === valetIds.length - 1 ? Number((distributable - running).toFixed(2)) : perValet;
        running += amount;
        await db.query(
          `
            INSERT INTO location_pay_allocations (location_id, week_start_date, user_id, allocated_amount, updated_at)
            VALUES ($1, $2, $3, $4, NOW())
          `,
          [id, weekStartDate, valetIds[i], amount]
        );
      }
    }
    return res.redirect(`/admin/locations/${id}/pay?week_start=${weekStartDate}`);
  } catch (err) {
    return res.send('Error auto-splitting pay: ' + err.message);
  }
});

/* ------------------------------
   Admin: Delete Shift
--------------------------------*/
app.post('/admin/delete/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM shift_reports WHERE id = $1', [id])
    .then(() => res.redirect('/admin/reports'))
    .catch((err) => res.send('Error deleting entry: ' + err.message));
});

/* ------------------------------
   Admin: Users
--------------------------------*/
app.get('/admin/users', requireAdmin, (req, res) => {
  Promise.all([
    db.query(`
      SELECT u.*, g.name AS group_name
      FROM users u
      LEFT JOIN groups g ON u.group_id = g.id
      ORDER BY u.role DESC, u.name ASC
    `),
    db.query('SELECT * FROM groups ORDER BY name ASC')
  ])
    .then(([users, groups]) =>
      res.render('admin_users', {
        users: users.rows,
        groups: groups.rows,
        error: null,
        message: null
      })
    )
    .catch((err) => res.send('Error retrieving users: ' + err.message));
});

app.post('/admin/users', requireAdmin, async (req, res) => {
  const { first_name, last_initial, phone, password, role, group_id } = req.body;
  if (!first_name || !last_initial || !phone || !password || !role) {
    const [users, groups] = await Promise.all([
      db.query(`
        SELECT u.*, g.name AS group_name
        FROM users u
        LEFT JOIN groups g ON u.group_id = g.id
        ORDER BY u.role DESC, u.name ASC
      `),
      db.query('SELECT * FROM groups ORDER BY name ASC')
    ]);
    return res.render('admin_users', {
      users: users.rows,
      groups: groups.rows,
      error: 'All fields are required.',
      message: null
    });
  }
  const cleanFirst = String(first_name).trim();
  const cleanLastInitial = String(last_initial).trim().charAt(0).toUpperCase();
  const name = `${cleanFirst} ${cleanLastInitial}.`;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query(
      `INSERT INTO users (name, phone, password, role, group_id)
       VALUES ($1, $2, $3, $4, $5)`,
      [name, phone, hashedPassword, role, group_id || null]
    );
    const [users, groups] = await Promise.all([
      db.query(`
        SELECT u.*, g.name AS group_name
        FROM users u
        LEFT JOIN groups g ON u.group_id = g.id
        ORDER BY u.role DESC, u.name ASC
      `),
      db.query('SELECT * FROM groups ORDER BY name ASC')
    ]);
    return res.render('admin_users', {
      users: users.rows,
      groups: groups.rows,
      error: null,
      message: 'User created successfully.'
    });
  } catch (err) {
    const [users, groups] = await Promise.all([
      db.query(`
        SELECT u.*, g.name AS group_name
        FROM users u
        LEFT JOIN groups g ON u.group_id = g.id
        ORDER BY u.role DESC, u.name ASC
      `),
      db.query('SELECT * FROM groups ORDER BY name ASC')
    ]);
    return res.render('admin_users', {
      users: users.rows,
      groups: groups.rows,
      error: err.code === '23505' ? 'Phone number already exists.' : 'Error creating user: ' + err.message,
      message: null
    });
  }
});

app.get('/admin/users/edit/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  Promise.all([
    db.query('SELECT * FROM users WHERE id = $1', [id]),
    db.query('SELECT * FROM groups ORDER BY name ASC')
  ])
    .then(([user, groups]) => {
      if (!user.rowCount) return res.send('User not found.');
      res.render('admin_user_edit', { user: user.rows[0], groups: groups.rows, error: null });
    })
    .catch((err) => res.send('Error loading user: ' + err.message));
});

app.post('/admin/users/edit/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, phone, role, group_id } = req.body;
  const updateQuery = `
    UPDATE users
    SET name = $1, phone = $2, role = $3, group_id = $4
    WHERE id = $5
  `;
  db.query(updateQuery, [name, phone, role, group_id || null, id])
    .then(() => res.redirect('/admin/users'))
    .catch((err) => res.send('Error updating user: ' + err.message));
});

app.post('/admin/users/delete/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { confirm_text } = req.body;
  if (confirm_text !== 'DELETE') {
    return Promise.all([
      db.query(`
        SELECT u.*, g.name AS group_name
        FROM users u
        LEFT JOIN groups g ON u.group_id = g.id
        ORDER BY u.role DESC, u.name ASC
      `),
      db.query('SELECT * FROM groups ORDER BY name ASC')
    ]).then(([users, groups]) =>
      res.render('admin_users', {
        users: users.rows,
        groups: groups.rows,
        error: 'Type DELETE to confirm user removal.',
        message: null
      })
    );
  }
  db.query('DELETE FROM users WHERE id = $1', [id])
    .then(() => res.redirect('/admin/users'))
    .catch((err) => res.send('Error deleting user: ' + err.message));
});

/* ------------------------------
   Admin: Groups
--------------------------------*/
app.get('/admin/groups', requireAdmin, (req, res) => {
  db.query('SELECT * FROM groups ORDER BY name ASC')
    .then((r) => res.render('admin_groups', { groups: r.rows, error: null, message: null }))
    .catch((err) => res.send('Error retrieving groups: ' + err.message));
});

app.post('/admin/groups', requireAdmin, (req, res) => {
  const { groupName, description } = req.body;
  if (!groupName) {
    return db
      .query('SELECT * FROM groups ORDER BY name ASC')
      .then((r) => res.render('admin_groups', { groups: r.rows, error: 'Group name is required.', message: null }));
  }
  db.query('INSERT INTO groups (name, description) VALUES ($1, $2)', [groupName, description || null])
    .then(() => db.query('SELECT * FROM groups ORDER BY name ASC'))
    .then((r) => res.render('admin_groups', { groups: r.rows, error: null, message: 'Group added.' }))
    .catch((err) =>
      res.render('admin_groups', { groups: [], error: 'Error adding group: ' + err.message, message: null })
    );
});

app.get('/admin/groups/edit/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  db.query('SELECT * FROM groups WHERE id = $1', [id])
    .then((r) => {
      if (!r.rowCount) return res.send('Group not found.');
      res.render('admin_group_edit', { group: r.rows[0], error: null });
    })
    .catch((err) => res.send('Error loading group: ' + err.message));
});

app.post('/admin/groups/edit/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, description } = req.body;
  db.query('UPDATE groups SET name = $1, description = $2 WHERE id = $3', [name, description || null, id])
    .then(() => res.redirect('/admin/groups'))
    .catch((err) => res.send('Error updating group: ' + err.message));
});

app.post('/admin/groups/delete/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { confirm_text } = req.body;
  if (confirm_text !== 'DELETE') {
    return db
      .query('SELECT * FROM groups ORDER BY name ASC')
      .then((r) =>
        res.render('admin_groups', { groups: r.rows, error: 'Type DELETE to confirm group removal.', message: null })
      );
  }
  db.query('DELETE FROM groups WHERE id = $1', [id])
    .then(() => res.redirect('/admin/groups'))
    .catch((err) => res.send('Error deleting group: ' + err.message));
});

/* ------------------------------
   Admin: Community Moderation
--------------------------------*/
app.get('/admin/community', requireAdmin, (req, res) => {
  const messagesQuery = `
    SELECT cm.id, cm.body, cm.created_at, cm.updated_at,
           u.name, u.profile_photo_url, g.name AS group_name
    FROM community_messages cm
    JOIN users u ON cm.user_id = u.id
    LEFT JOIN groups g ON u.group_id = g.id
    ORDER BY cm.created_at DESC
  `;
  Promise.all([db.query(messagesQuery), db.query('SELECT * FROM groups ORDER BY name ASC')])
    .then(([messages, groups]) =>
      res.render('admin_community', {
        messages: messages.rows,
        groups: groups.rows,
        error: null,
        message: null
      })
    )
    .catch((err) => res.send('Error loading community admin: ' + err.message));
});

app.post('/admin/community/clear', requireAdmin, (req, res) => {
  db.query('DELETE FROM community_messages')
    .then(() => res.redirect('/admin/community'))
    .catch((err) => res.send('Error clearing messages: ' + err.message));
});

app.post('/admin/community/delete/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  db.query('DELETE FROM community_messages WHERE id = $1', [id])
    .then(() => res.redirect('/admin/community'))
    .catch((err) => res.send('Error deleting message: ' + err.message));
});

app.post('/admin/community/edit/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const body = String(req.body.body || '').trim();
  if (!body) return res.redirect('/admin/community');
  db.query('UPDATE community_messages SET body = $1, updated_at = NOW() WHERE id = $2', [body, id])
    .then(() => res.redirect('/admin/community'))
    .catch((err) => res.send('Error updating message: ' + err.message));
});

app.post('/admin/community/groups/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const visible = req.body.visible === 'true';
  db.query('UPDATE groups SET visible_in_sidebar = $1 WHERE id = $2', [visible, id])
    .then(() => res.redirect('/admin/community'))
    .catch((err) => res.send('Error updating group visibility: ' + err.message));
});

/* ------------------------------
   Admin: Analytics Landing
--------------------------------*/
app.get('/admin/analytics', requireAdmin, (req, res) => {
  db.query('SELECT COUNT(*)::int AS count FROM shift_reports')
    .then((r) => res.render('admin_analytics', { reportCount: r.rows[0].count }))
    .catch((err) => res.send('Error loading analytics: ' + err.message));
});

/* ------------------------------
   Admin: Valet Submission
--------------------------------*/
app.get('/admin/valet-submission', requireAdmin, (req, res) => {
  Promise.all([
    db.query('SELECT * FROM locations ORDER BY name ASC'),
    db.query("SELECT id, name FROM users WHERE role = 'valet' ORDER BY name ASC")
  ])
    .then(([locations, valets]) =>
      res.render('admin_valet_submit', {
        locations: locations.rows,
        valets: valets.rows,
        error: null,
        message: null
      })
    )
    .catch((err) => res.send('Error loading valet submission: ' + err.message));
});

app.post('/admin/valet-submission', requireAdmin, upload.array('screenshots', 10), (req, res) => {
  const { shift_date, hours, online_tips, cash_tips, location_id, cars, valet_id, shift_notes } = req.body;
  if (!shift_date || online_tips === undefined || cash_tips === undefined || !location_id || !valet_id) {
    return Promise.all([
      db.query('SELECT * FROM locations ORDER BY name ASC'),
      db.query("SELECT id, name FROM users WHERE role = 'valet' ORDER BY name ASC")
    ]).then(([locations, valets]) =>
      res.render('admin_valet_submit', {
        locations: locations.rows,
        valets: valets.rows,
        error: 'All fields are required.',
        message: null
      })
    );
  }
  const hoursValue = hours ? Number(hours) : 0;
  const carsValue = cars ? Number(cars) : 0;
  const insertQuery = `
    INSERT INTO shift_reports (user_id, shift_date, hours, online_tips, cash_tips, location_id, cars, shift_notes)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id
  `;
  db.query(insertQuery, [
    valet_id,
    shift_date,
    hoursValue,
    online_tips,
    cash_tips,
    location_id,
    carsValue,
    shift_notes ? String(shift_notes).trim() : null
  ])
    .then((result) => {
      const shiftReportId = result.rows[0].id;
      if (req.files && req.files.length > 0) {
        const promises = req.files.map((file) =>
          db.query('INSERT INTO shift_screenshots (shift_report_id, file_path) VALUES ($1, $2)', [
            shiftReportId,
            file.filename
          ])
        );
        return Promise.all(promises);
      }
    })
    .then(() =>
      Promise.all([
        db.query('SELECT * FROM locations ORDER BY name ASC'),
        db.query("SELECT id, name FROM users WHERE role = 'valet' ORDER BY name ASC")
      ])
    )
    .then(([locations, valets]) =>
      res.render('admin_valet_submit', {
        locations: locations.rows,
        valets: valets.rows,
        error: null,
        message: 'Shift report submitted.'
      })
    )
    .catch((err) => res.send('Error saving report: ' + err.message));
});

/* ------------------------------
   Admin: Leaderboard
--------------------------------*/
app.get('/admin/leaderboard', requireAdmin, (req, res) => {
  const allowedSortColumns = ['total_hours', 'total_online', 'total_cash', 'total_tips'];
  let sort = req.query.sort || 'total_hours';
  let order = req.query.order || 'desc';
  if (!allowedSortColumns.includes(sort)) sort = 'total_hours';
  if (order !== 'asc' && order !== 'desc') order = 'desc';

  const locationFilter = req.query.location_id;
  let query = '';
  let params = [];

  if (locationFilter) {
    query = `
      SELECT u.id, u.name, u.phone,
        COALESCE(SUM(sr.hours), 0) AS total_hours,
        COALESCE(SUM(sr.online_tips), 0) AS total_online,
        COALESCE(SUM(sr.cash_tips), 0) AS total_cash,
        COALESCE(SUM(sr.online_tips) + SUM(sr.cash_tips), 0) AS total_tips
      FROM users u
      LEFT JOIN shift_reports sr ON sr.user_id = u.id AND sr.location_id = $1
      WHERE u.role = 'valet'
      GROUP BY u.id
      ORDER BY ${sort} ${order}
    `;
    params.push(locationFilter);
  } else {
    query = `
      SELECT u.id, u.name, u.phone,
        COALESCE(SUM(sr.hours), 0) AS total_hours,
        COALESCE(SUM(sr.online_tips), 0) AS total_online,
        COALESCE(SUM(sr.cash_tips), 0) AS total_cash,
        COALESCE(SUM(sr.online_tips) + SUM(sr.cash_tips), 0) AS total_tips
      FROM users u
      LEFT JOIN shift_reports sr ON sr.user_id = u.id
      WHERE u.role = 'valet'
      GROUP BY u.id
      ORDER BY ${sort} ${order}
    `;
  }

  db.query('SELECT * FROM locations')
    .then((lr) => {
      const locations = lr.rows;
      return db.query(query, params).then((qr) =>
        res.render('admin_leaderboard', {
          leaderboard: qr.rows,
          sort,
          order,
          locations,
          selectedLocation: locationFilter
        })
      );
    })
    .catch((err) => res.send('Error retrieving leaderboard/locations: ' + err.message));
});

/* ------------------------------
   Admin: Charts
--------------------------------*/
app.get('/admin/charts', requireAdmin, (req, res) => {
  const locationFilter = req.query.location_id || '';
  const attribute = req.query.attribute || 'hours';
  const { weekStart, weekEnd, weekStartDate, weekEndDate } = getRequestedWeekRange(req.query.week_start);
  const weekDisplayEnd = new Date(weekEnd);
  weekDisplayEnd.setDate(weekDisplayEnd.getDate() - 1);
  const previousWeekStart = new Date(weekStart);
  previousWeekStart.setDate(previousWeekStart.getDate() - 7);
  const nextWeekStart = new Date(weekStart);
  nextWeekStart.setDate(nextWeekStart.getDate() + 7);
  const allowedAttributes = ['hours', 'online_tips', 'cash_tips', 'total_tips'];
  if (!allowedAttributes.includes(attribute)) return res.send('Invalid attribute selected.');

  db.query('SELECT * FROM locations')
    .then((lr) => {
      const locations = lr.rows;
      let query = '';
      let params = [weekStartDate, weekEndDate];
      const columnSelect =
        attribute === 'total_tips'
          ? 'COALESCE(SUM(sr.online_tips) + SUM(sr.cash_tips), 0)'
          : `COALESCE(SUM(sr.${attribute}), 0)`;

      if (locationFilter) {
        query = `
          SELECT TO_CHAR(DATE(sr.shift_date), 'YYYY-MM-DD') AS date_key, ${columnSelect} as value
          FROM shift_reports sr
          WHERE DATE(sr.shift_date) >= $1
            AND DATE(sr.shift_date) < $2
            AND sr.location_id = $3
          GROUP BY DATE(sr.shift_date)
          ORDER BY DATE(sr.shift_date) ASC
        `;
        params.push(Number(locationFilter));
      } else {
        query = `
          SELECT TO_CHAR(DATE(sr.shift_date), 'YYYY-MM-DD') AS date_key,
                 COALESCE(l.id, 0) AS location_id,
                 COALESCE(l.name, 'Unassigned') AS location_name,
                 ${columnSelect} as value
          FROM shift_reports sr
          LEFT JOIN locations l ON sr.location_id = l.id
          WHERE DATE(sr.shift_date) >= $1
            AND DATE(sr.shift_date) < $2
          GROUP BY DATE(sr.shift_date), l.id, l.name
          ORDER BY DATE(sr.shift_date) ASC
        `;
      }

      return db.query(query, params).then((qr) => {
        const rows = qr.rows;
        const orderedDateKeys = Array.from(new Set(rows.map((r) => r.date_key))).sort();
        const labels = orderedDateKeys.map((d) => formatEstDateLabel(d));
        const palette = [
          'rgba(79,140,255,0.78)',
          'rgba(31,209,195,0.78)',
          'rgba(255,176,91,0.78)',
          'rgba(224,117,255,0.78)',
          'rgba(255,107,107,0.78)',
          'rgba(142,221,109,0.78)',
          'rgba(255,214,102,0.78)',
          'rgba(120,170,255,0.78)'
        ];
        let datasets = [];
        if (locationFilter) {
          datasets = [{
            label: selectedAttributeLabel(attribute),
            data: rows.map((r) => Number(r.value) || 0),
            backgroundColor: palette[0],
            borderColor: palette[0].replace('0.78', '1'),
            borderWidth: 1
          }];
        } else {
          const byLocation = new Map();
          rows.forEach((row) => {
            const lid = Number(row.location_id);
            if (!byLocation.has(lid)) {
              byLocation.set(lid, {
                label: row.location_name,
                dataByDate: new Map()
              });
            }
            byLocation.get(lid).dataByDate.set(row.date_key, Number(row.value) || 0);
          });
          let idx = 0;
          datasets = Array.from(byLocation.values()).map((series) => {
            const color = palette[idx % palette.length];
            idx += 1;
            return {
              label: series.label,
              data: orderedDateKeys.map((d) => series.dataByDate.get(d) || 0),
              backgroundColor: color,
              borderColor: color.replace('0.78', '1'),
              borderWidth: 1
            };
          });
        }
        res.render('admin_charts', {
          locations,
          labels,
          datasets,
          selectedLocation: locationFilter,
          selectedAttribute: attribute,
          weekStart,
          weekDisplayEnd,
          selectedWeekStartDate: weekStartDate,
          previousWeekStartDate: formatDate(previousWeekStart),
          nextWeekStartDate: formatDate(nextWeekStart)
        });
      });
    })
    .catch((err) => res.send('Error retrieving chart data: ' + err.message));
});

/* ------------------------------
   Admin: Charts Compare
--------------------------------*/
app.get('/admin/charts-compare', requireAdmin, (req, res) => {
  const locationFilter = req.query.location_id || '';
  const attribute = req.query.attribute || 'hours';
  const valetFilter = req.query.valet_id || 'all';
  const { weekStart, weekEnd, weekStartDate, weekEndDate } = getRequestedWeekRange(req.query.week_start);
  const weekDisplayEnd = new Date(weekEnd);
  weekDisplayEnd.setDate(weekDisplayEnd.getDate() - 1);
  const previousWeekStart = new Date(weekStart);
  previousWeekStart.setDate(previousWeekStart.getDate() - 7);
  const nextWeekStart = new Date(weekStart);
  nextWeekStart.setDate(nextWeekStart.getDate() + 7);
  const allowedAttributes = ['hours', 'online_tips', 'cash_tips', 'total_tips'];
  if (!allowedAttributes.includes(attribute)) return res.send('Invalid attribute selected.');

  db.query('SELECT * FROM locations')
    .then((lr) => {
      const locations = lr.rows;
      return db.query(`SELECT id, name FROM users WHERE role='valet'`).then((vr) => ({ locations, valets: vr.rows }));
    })
    .then(({ locations, valets }) => {
      const sumExpression =
        attribute === 'total_tips'
          ? 'COALESCE(SUM(sr.online_tips) + SUM(sr.cash_tips), 0) AS value'
          : `COALESCE(SUM(sr.${attribute}), 0) AS value`;

      const whereClauses = [
        'DATE(sr.shift_date) >= $1',
        'DATE(sr.shift_date) < $2'
      ];
      const queryParams = [weekStartDate, weekEndDate];
      if (locationFilter) {
        whereClauses.push(`sr.location_id = $${queryParams.length + 1}`);
        queryParams.push(Number(locationFilter));
      }
      let groupBy = 'sr.shift_date';
      let selectUser = '';
      let joinUser = 'JOIN users u ON sr.user_id = u.id';
      if (valetFilter !== 'all') {
        whereClauses.push(`sr.user_id = $${queryParams.length + 1}`);
        queryParams.push(valetFilter);
      } else {
        groupBy = 'sr.shift_date, sr.user_id';
        selectUser = ', u.id AS user_id, u.name AS user_name';
      }
      const whereSql = whereClauses.length ? 'WHERE ' + whereClauses.join(' AND ') : '';
      const query = `
        SELECT TO_CHAR(DATE(sr.shift_date), 'YYYY-MM-DD') AS date_key
        ${selectUser},
        ${sumExpression}
        FROM shift_reports sr
        ${joinUser}
        ${whereSql}
        GROUP BY ${groupBy.replace(/sr\.shift_date/g, 'DATE(sr.shift_date)')}
        ORDER BY DATE(sr.shift_date) ASC
      `;

      return db.query(query, queryParams).then((qr) => {
        const rows = qr.rows;
        const uniqueDateKeys = Array.from(new Set(rows.map((r) => r.date_key))).sort();
        const labels = uniqueDateKeys.map((d) => formatEstDateLabel(d));
        if (valetFilter !== 'all') {
          const dataMap = new Map();
          rows.forEach((r) => dataMap.set(r.date_key, r.value));
          const dataValues = uniqueDateKeys.map((d) => dataMap.get(d) || 0);
          const datasets = [{ label: 'Valet Performance', data: dataValues }];
          return res.render('admin_charts_compare', {
            locations,
            valets,
            selectedLocation: locationFilter,
            selectedValet: valetFilter,
            selectedAttribute: attribute,
            labels,
            datasets,
            weekStart,
            weekDisplayEnd,
            selectedWeekStartDate: weekStartDate,
            previousWeekStartDate: formatDate(previousWeekStart),
            nextWeekStartDate: formatDate(nextWeekStart)
          });
        } else {
          const userMap = new Map();
          rows.forEach((r) => {
            const uid = r.user_id;
            if (!userMap.has(uid)) {
              userMap.set(uid, { userName: r.user_name, dataMap: new Map() });
            }
            userMap.get(uid).dataMap.set(r.date_key, r.value);
          });
          const datasets = [];
          for (let [, info] of userMap.entries()) {
            const dataArray = uniqueDateKeys.map((d) => info.dataMap.get(d) || 0);
            datasets.push({ label: info.userName, data: dataArray });
          }
          return res.render('admin_charts_compare', {
            locations,
            valets,
            selectedLocation: locationFilter,
            selectedValet: 'all',
            selectedAttribute: attribute,
            labels,
            datasets,
            weekStart,
            weekDisplayEnd,
            selectedWeekStartDate: weekStartDate,
            previousWeekStartDate: formatDate(previousWeekStart),
            nextWeekStartDate: formatDate(nextWeekStart)
          });
        }
      });
    })
    .catch((err) => res.send('Error retrieving chart data: ' + err.message));
});

/* ------------------------------
   Admin: Screenshots
--------------------------------*/
app.get('/admin/screenshots', requireAdmin, (req, res) => {
  const locationFilter = req.query.location_id || '';
  db.query('SELECT * FROM locations')
    .then((lr) => {
      const locations = lr.rows;
      let query = `
        SELECT sr.id AS shift_report_id,
               sr.shift_date,
               l.name AS location_name,
               u.name AS valet_name,
               sc.file_path
        FROM shift_reports sr
        JOIN users u ON sr.user_id = u.id
        LEFT JOIN locations l ON sr.location_id = l.id
        LEFT JOIN shift_screenshots sc ON sc.shift_report_id = sr.id
      `;
      const queryParams = [];
      if (locationFilter) {
        query += ' WHERE sr.location_id = $1';
        queryParams.push(locationFilter);
      }
      query += ' ORDER BY sr.shift_date DESC';
      return db.query(query, queryParams).then((qr) => {
        const reportMap = new Map();
        qr.rows.forEach((r) => {
          if (!reportMap.has(r.shift_report_id)) {
            reportMap.set(r.shift_report_id, {
              shift_report_id: r.shift_report_id,
              shift_date: r.shift_date,
              location_name: r.location_name,
              valet_name: r.valet_name,
              screenshots: []
            });
          }
          if (r.file_path) {
            reportMap.get(r.shift_report_id).screenshots.push(r.file_path);
          }
        });
        const reports = Array.from(reportMap.values());
        res.render('admin_screenshots', { locations, reports, selectedLocation: locationFilter });
      });
    })
    .catch((err) => res.send('Error retrieving screenshots: ' + err.message));
});

/* ------------------------------
   Weekly Export helpers & route
--------------------------------*/
function getValetWeekStart(dateTime) {
  const d = new Date(dateTime);
  // Shift reports are entered as dates; normalize midnight-only values so Monday dates
  // are treated as the current week instead of rolling to the previous week window.
  if (d.getHours() === 0 && d.getMinutes() === 0 && d.getSeconds() === 0 && d.getMilliseconds() === 0) {
    d.setHours(12, 0, 0, 0);
  }
  const day = d.getDay();
  const hour = d.getHours();
  if (day === 1 && hour < 6) d.setDate(d.getDate() - 1);
  const day2 = d.getDay();
  const normalizedDay = day2 === 0 ? 7 : day2;
  let diff = normalizedDay - 1;
  if (day === 1 && hour < 6) diff = 7;
  d.setDate(d.getDate() - diff);
  d.setHours(6, 0, 0, 0);
  return d;
}
function formatDate(dateObj) {
  const yyyy = dateObj.getFullYear();
  const mm = String(dateObj.getMonth() + 1).padStart(2, '0');
  const dd = String(dateObj.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}
function groupReportsByWeek(reports) {
  const map = new Map();
  reports.forEach((r) => {
    const weekStart = getValetWeekStart(r.shift_date);
    const sunday = new Date(weekStart);
    sunday.setDate(sunday.getDate() + 6);
    const label = `${formatDate(weekStart)} to ${formatDate(sunday)}`;
    if (!map.has(label)) map.set(label, []);
    map.get(label).push(r);
  });
  return map;
}

app.get('/admin/export-weekly', requireAdmin, (req, res) => {
  const query = `
    SELECT sr.*, u.name AS valet_name, u.phone, l.name AS location_name
    FROM shift_reports sr
    JOIN users u ON sr.user_id = u.id
    LEFT JOIN locations l ON sr.location_id = l.id
    ORDER BY l.id, sr.shift_date ASC
  `;
  db.query(query)
    .then((r) => {
      const reports = r.rows;
      const locationMap = new Map();
      reports.forEach((row) => {
        const loc = row.location_name || 'Unspecified';
        if (!locationMap.has(loc)) locationMap.set(loc, []);
        locationMap.get(loc).push(row);
      });

      let csvLines = [];
      csvLines.push('ID,Valet Name,Phone,Shift Date,Hours,# of Cars,Online Tips,Cash Tips,Total,Location');
      for (const [locName, reportsForLoc] of locationMap.entries()) {
        csvLines.push(`Location: ${locName}`);
        const groupedByWeek = groupReportsByWeek(reportsForLoc);
        for (const [weekLabel, items] of groupedByWeek) {
          csvLines.push(`  Week: ${weekLabel}`);
          items.forEach((r) => {
            const total = Number(r.online_tips) + Number(r.cash_tips);
            const line = [
              r.id,
              `"${r.valet_name}"`,
              r.phone,
              r.shift_date,
              r.hours,
              r.cars,
              r.online_tips,
              r.cash_tips,
              total,
              `"${r.location_name || ''}"`
            ].join(',');
            csvLines.push(line);
          });
          csvLines.push('');
        }
        csvLines.push('');
      }
      const csvContent = csvLines.join('\n');
      res.setHeader('Content-disposition', 'attachment; filename=weekly_shift_reports.csv');
      res.setHeader('Content-Type', 'text/csv');
      res.send(csvContent);
    })
    .catch((err) => res.send('Error retrieving reports: ' + err.message));
});

/* ------------------------------
   TrevorView
--------------------------------*/
app.get(['/admin/trevor', '/admin/trevorview'], requireAdmin, (req, res) => {
  const query = `
    SELECT sr.*, u.name AS valet_name, u.phone, l.name AS location_name
    FROM shift_reports sr
    JOIN users u ON sr.user_id = u.id
    LEFT JOIN locations l ON sr.location_id = l.id
    ORDER BY sr.shift_date ASC
  `;
  const toDateStr = (value) => {
    if (!value) return '';
    if (typeof value === 'string') return value.includes('T') ? value.split('T')[0] : value;
    if (value instanceof Date) return value.toISOString().slice(0, 10);
    return '';
  };
  const toLocalDate = (dateStr) => {
    const parts = dateStr.split('-').map(Number);
    if (parts.length !== 3) return new Date(dateStr);
    return new Date(parts[0], parts[1] - 1, parts[2], 12, 0, 0, 0);
  };

  db.query(query)
    .then((r) => {
      const groupMap = new Map();
      r.rows.forEach((rec) => {
        const location = rec.location_name || 'Unspecified';
        const dayStr = toDateStr(rec.shift_date);
        if (!dayStr) return;
        const dayDate = toLocalDate(dayStr);
        const weekStart = getValetWeekStart(dayDate);
        const weekStartStr = formatDate(weekStart);
        const weekEnd = new Date(weekStart);
        weekEnd.setDate(weekEnd.getDate() + 6);
        const weekEndStr = formatDate(weekEnd);
        const key = `${location}__${weekStartStr}`;

        if (!groupMap.has(key)) {
          groupMap.set(key, {
            location,
            weekStart,
            weekStartStr,
            weekEnd,
            weekEndStr,
            days: new Map(),
            valetTotals: new Map()
          });
        }

        const group = groupMap.get(key);
        if (!group.days.has(dayStr)) {
          group.days.set(dayStr, {
            dateStr: dayStr,
            displayLabel: dayDate.toLocaleDateString('en-US', { weekday: 'short' }),
            displayDate: dayDate.toLocaleDateString('en-US', { month: 'numeric', day: 'numeric' }),
            shifts: [],
            totalHours: 0,
            totalCash: 0,
            totalOnline: 0,
            totalCars: 0
          });
        }
        const dayObj = group.days.get(dayStr);

        const hours = Number(rec.hours) || 0;
        const cash = Number(rec.cash_tips) || 0;
        const online = Number(rec.online_tips) || 0;
        const cars = Number(rec.cars) || 0;

        dayObj.shifts.push({
          name: rec.valet_name,
          hours,
          cash,
          online,
          cars
        });
        dayObj.totalHours += hours;
        dayObj.totalCash += cash;
        dayObj.totalOnline += online;
        dayObj.totalCars += cars;

        if (!group.valetTotals.has(rec.valet_name)) {
          group.valetTotals.set(rec.valet_name, { name: rec.valet_name, hours: 0, cash: 0, online: 0, cars: 0 });
        }
        const valetTotal = group.valetTotals.get(rec.valet_name);
        valetTotal.hours += hours;
        valetTotal.cash += cash;
        valetTotal.online += online;
        valetTotal.cars += cars;
      });

      const groups = Array.from(groupMap.values()).map((group) => {
        const days = Array.from(group.days.values()).sort((a, b) => new Date(a.dateStr) - new Date(b.dateStr));
        days.forEach((day) => day.shifts.sort((a, b) => a.name.localeCompare(b.name)));
        const weeklyTotals = days.reduce(
          (acc, day) => {
            acc.hours += day.totalHours;
            acc.cash += day.totalCash;
            acc.online += day.totalOnline;
            acc.cars += day.totalCars;
            return acc;
          },
          { hours: 0, cash: 0, online: 0, cars: 0 }
        );
        const valetTotals = Array.from(group.valetTotals.values()).sort((a, b) => a.name.localeCompare(b.name));
        return { ...group, days, weeklyTotals, valetTotals };
      });

      groups.sort((a, b) => {
        if (a.weekStartStr === b.weekStartStr) return a.location.localeCompare(b.location);
        return new Date(b.weekStartStr) - new Date(a.weekStartStr);
      });

      res.render('admin_trevor', { groups });
    })
    .catch((err) => res.send('Error retrieving shift reports: ' + err.message));
});

/* ------------------------------
   Start Server after DB Ready
--------------------------------*/
async function waitForDbReady(retries = 12, delayMs = 2500) {
  for (let i = 1; i <= retries; i++) {
    try {
      await db.query('SELECT 1');
      return;
    } catch (err) {
      if (i === retries) throw err;
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}

(async () => {
  try {
    await waitForDbReady();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Could not connect to database after retries:', err);
    process.exit(1);
  }
})();
