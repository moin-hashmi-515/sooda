// Sooda — OLX-style classifieds platform. Run: npm start
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'sooda-dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 }, // 7 days
  })
);

// ---------- helpers ----------
const LOCATIONS = [
  'Karachi', 'Lahore', 'Islamabad', 'Rawalpindi', 'Faisalabad',
  'Multan', 'Peshawar', 'Quetta', 'Hyderabad', 'Sialkot',
];

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Please log in first.' });
  }
  next();
}

function publicUser(u) {
  return u ? {
    id: u.id, name: u.name, email: u.email, phone: u.phone,
    phone_verified: !!u.phone_verified,
  } : null;
}

// ---------- phone verification (Twilio SMS / WhatsApp) ----------
function normalizePhone(p) {
  let d = String(p || '').replace(/\D/g, '');
  if (/^0/.test(d)) d = '92' + d.slice(1); // Pakistani 03xx -> +92
  if (d.length < 10 || d.length > 15) return null;
  return '+' + d;
}

let twilioClient = null;
function getTwilio() {
  const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN } = process.env;
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN) return null;
  if (!twilioClient) {
    twilioClient = require('twilio')(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
  }
  return twilioClient;
}

async function sendOtp(channel, to, code) {
  const client = getTwilio();
  if (!client) {
    const err = new Error(
      'Phone sending is not configured. Set TWILIO_ACCOUNT_SID, ' +
      'TWILIO_AUTH_TOKEN and TWILIO_SMS_NUMBER / TWILIO_WHATSAPP_NUMBER.'
    );
    err.status = 501;
    throw err;
  }
  const body = `Your Sooda verification code is ${code}. It expires in 10 minutes.`;
  if (channel === 'whatsapp') {
    const from = String(process.env.TWILIO_WHATSAPP_NUMBER || '')
      .replace(/^whatsapp:/, '');
    if (!from) throw Object.assign(new Error('TWILIO_WHATSAPP_NUMBER is not set.'), { status: 501 });
    await client.messages.create({
      body, from: 'whatsapp:' + from, to: 'whatsapp:' + to,
    });
  } else {
    const from = process.env.TWILIO_SMS_NUMBER;
    if (!from) throw Object.assign(new Error('TWILIO_SMS_NUMBER is not set.'), { status: 501 });
    await client.messages.create({ body, from, to });
  }
}

function newOtpCode() {
  return String(crypto.randomInt(100000, 1000000));
}

// Request a one-time code via SMS or WhatsApp (logged in).
app.post('/api/auth/phone/request', requireAuth, async (req, res) => {
  try {
    const { channel } = req.body || {};
    if (!['sms', 'whatsapp'].includes(channel)) {
      return res.status(400).json({ error: 'Choose SMS or WhatsApp.' });
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
    if (user.phone_verified) {
      return res.status(400).json({ error: 'Phone already verified.' });
    }
    const to = normalizePhone(user.phone);
    if (!to) return res.status(400).json({ error: 'Your phone number looks invalid.' });

    // 60-second resend cooldown.
    const last = db.prepare(
      "SELECT created_at FROM phone_otps WHERE user_id = ? ORDER BY id DESC LIMIT 1"
    ).get(user.id);
    if (last && Date.now() - new Date(last.created_at + 'Z').getTime() < 60000) {
      return res.status(429).json({ error: 'Please wait a minute before requesting a new code.' });
    }

    const code = newOtpCode();
    db.prepare('DELETE FROM phone_otps WHERE user_id = ?').run(user.id);
    db.prepare(
      `INSERT INTO phone_otps (user_id, code_hash, channel, expires_at)
       VALUES (?, ?, ?, datetime('now', '+10 minutes'))`
    ).run(user.id, crypto.createHash('sha256').update(code).digest('hex'), channel);

    // Test mode (never in production): return the code for automated checks.
    if (process.env.TWILIO_TEST_MODE === '1') {
      return res.json({ ok: true, channel, test_code: code });
    }
    await sendOtp(channel, to, code);
    res.json({ ok: true, channel });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Could not send code.' });
  }
});

// Verify the one-time code.
app.post('/api/auth/phone/verify', requireAuth, (req, res) => {
  const { code } = req.body || {};
  const clean = String(code || '').replace(/\D/g, '');
  if (!/^\d{6}$/.test(clean)) {
    return res.status(400).json({ error: 'Enter the 6-digit code.' });
  }
  const otp = db.prepare(
    `SELECT * FROM phone_otps
     WHERE user_id = ? AND expires_at > datetime('now')
     ORDER BY id DESC LIMIT 1`
  ).get(req.session.userId);
  if (!otp) {
    return res.status(400).json({ error: 'Code expired — request a new one.' });
  }
  if (otp.attempts >= 5) {
    db.prepare('DELETE FROM phone_otps WHERE user_id = ?').run(req.session.userId);
    return res.status(400).json({ error: 'Too many tries — request a new code.' });
  }
  const hash = crypto.createHash('sha256').update(clean).digest('hex');
  if (hash !== otp.code_hash) {
    db.prepare('UPDATE phone_otps SET attempts = attempts + 1 WHERE id = ?').run(otp.id);
    return res.status(400).json({ error: 'Wrong code — try again.' });
  }
  db.prepare('DELETE FROM phone_otps WHERE user_id = ?').run(req.session.userId);
  db.prepare('UPDATE users SET phone_verified = 1 WHERE id = ?').run(req.session.userId);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  res.json({ ok: true, user: publicUser(user) });
});

function adRowToAd(row) {
  const images = db
    .prepare('SELECT filename FROM ad_images WHERE ad_id = ? ORDER BY position')
    .all(row.id)
    .map((r) => '/' + r.filename.replace(/^\//, ''));
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    price: row.price,
    negotiable: !!row.negotiable,
    condition: row.condition,
    location: row.location,
    status: row.status,
    views: row.views,
    created_at: row.created_at,
    category: { id: row.cat_id, name: row.cat_name, slug: row.cat_slug },
    seller: { id: row.user_id, name: row.seller_name },
    images,
    thumbnail: images[0] || null,
  };
}

const AD_SELECT = `
  SELECT ads.*, c.id AS cat_id, c.name AS cat_name, c.slug AS cat_slug,
         u.name AS seller_name
  FROM ads
  JOIN categories c ON c.id = ads.category_id
  JOIN users u ON u.id = ads.user_id
`;

// ---------- uploads ----------
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) =>
    cb(null, crypto.randomBytes(16).toString('hex') +
      path.extname(file.originalname || '')),
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024, files: 6 },
  fileFilter: (req, file, cb) =>
    cb(null, /^image\//.test(file.mimetype)),
});

// ---------- auth ----------
app.post('/api/auth/signup', (req, res) => {
  const { name, email, phone, password } = req.body || {};
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be 6+ characters.' });
  }
  const exists = db
    .prepare('SELECT id FROM users WHERE email = ?')
    .get(email.trim().toLowerCase());
  if (exists) {
    return res.status(409).json({ error: 'Email already registered.' });
  }
  const r = db
    .prepare(
      'INSERT INTO users (name, email, phone, password_hash) VALUES (?, ?, ?, ?)'
    )
    .run(
      name.trim(), email.trim().toLowerCase(), phone.trim(),
      bcrypt.hashSync(password, 10)
    );
  req.session.userId = Number(r.lastInsertRowid);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(
    req.session.userId
  );
  res.json({ user: publicUser(user) });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = db
    .prepare('SELECT * FROM users WHERE email = ?')
    .get((email || '').trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
    return res.status(401).json({ error: 'Wrong email or password.' });
  }
  req.session.userId = user.id;
  res.json({ user: publicUser(user) });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(
    req.session.userId
  );
  res.json({ user: publicUser(user) });
});

// ---------- meta ----------
app.get('/api/categories', (req, res) => {
  res.json(db.prepare('SELECT * FROM categories ORDER BY name').all());
});

app.get('/api/locations', (req, res) => res.json(LOCATIONS));

// ---------- ads ----------
app.get('/api/ads', (req, res) => {
  const {
    q, category, location, min_price, max_price, condition, sort,
    page = 1, limit = 24,
  } = req.query;
  const where = ["ads.status = 'active'"];
  const params = [];

  if (q) {
    where.push('(ads.title LIKE ? OR ads.description LIKE ?)');
    params.push(`%${q}%`, `%${q}%`);
  }
  if (category) {
    where.push('c.slug = ?');
    params.push(category);
  }
  if (location) {
    where.push('ads.location = ?');
    params.push(location);
  }
  if (min_price) {
    where.push('ads.price >= ?');
    params.push(Number(min_price));
  }
  if (max_price) {
    where.push('ads.price <= ?');
    params.push(Number(max_price));
  }
  if (condition && condition !== 'any') {
    where.push('ads.condition = ?');
    params.push(condition);
  }

  const order =
    sort === 'price_asc' ? 'ads.price ASC'
    : sort === 'price_desc' ? 'ads.price DESC'
    : 'ads.created_at DESC';

  const total = db
    .prepare(
      `SELECT COUNT(*) AS n FROM ads
       JOIN categories c ON c.id = ads.category_id
       WHERE ${where.join(' AND ')}`
    )
    .get(...params).n;

  const pg = Math.max(1, Number(page) || 1);
  const lim = Math.min(60, Math.max(1, Number(limit) || 24));
  const rows = db
    .prepare(
      `${AD_SELECT} WHERE ${where.join(' AND ')}
       ORDER BY ${order} LIMIT ? OFFSET ?`
    )
    .all(...params, lim, (pg - 1) * lim);

  res.json({
    ads: rows.map(adRowToAd),
    total,
    page: pg,
    pages: Math.ceil(total / lim),
  });
});

app.get('/api/ads/:id', (req, res) => {
  const row = db.prepare(`${AD_SELECT} WHERE ads.id = ?`).get(req.params.id);
  if (!row || row.status !== 'active') {
    return res.status(404).json({ error: 'Ad not found.' });
  }
  db.prepare('UPDATE ads SET views = views + 1 WHERE id = ?').run(row.id);
  const ad = adRowToAd(row);
  ad.views += 1;
  ad.is_owner = req.session.userId === row.user_id;
  ad.is_favorited = req.session.userId
    ? !!db
        .prepare('SELECT 1 FROM favorites WHERE user_id = ? AND ad_id = ?')
        .get(req.session.userId, row.id)
    : false;
  // Phone number is only revealed to logged-in users.
  const seller = db.prepare('SELECT phone FROM users WHERE id = ?')
    .get(row.user_id);
  ad.seller_phone = req.session.userId ? seller.phone : null;
  res.json({ ad });
});

app.post('/api/ads', requireAuth, upload.array('images', 6), (req, res) => {
  const me = db.prepare('SELECT phone_verified FROM users WHERE id = ?').get(req.session.userId);
  if (!me.phone_verified) {
    return res.status(403).json({ error: 'Please verify your phone number before posting ads.' });
  }
  const { category_id, title, description, price, negotiable, condition,
    location } = req.body || {};
  if (!category_id || !title || !description || !price || !location) {
    return res.status(400).json({ error: 'Please fill all required fields.' });
  }
  const cat = db.prepare('SELECT id FROM categories WHERE id = ?')
    .get(category_id);
  if (!cat) return res.status(400).json({ error: 'Invalid category.' });

  const r = db
    .prepare(
      `INSERT INTO ads (user_id, category_id, title, description, price,
        negotiable, condition, location)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      req.session.userId, cat.id, title.trim(), description.trim(),
      Math.max(0, Math.round(Number(price) || 0)),
      negotiable === '1' || negotiable === true ? 1 : 0,
      ['new', 'used'].includes(condition) ? condition : 'used',
      location
    );
  const adId = Number(r.lastInsertRowid);
  const insImg = db.prepare(
    'INSERT INTO ad_images (ad_id, filename, position) VALUES (?, ?, ?)'
  );
  (req.files || []).forEach((f, i) =>
    insImg.run(adId, 'uploads/' + f.filename, i)
  );
  res.status(201).json({ id: adId });
});

app.put('/api/ads/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM ads WHERE id = ?').get(req.params.id);
  if (!row || row.user_id !== req.session.userId) {
    return res.status(404).json({ error: 'Ad not found.' });
  }
  const { title, description, price, negotiable, condition, location,
    category_id, status } = req.body || {};
  db.prepare(
    `UPDATE ads SET title = COALESCE(?, title),
      description = COALESCE(?, description), price = COALESCE(?, price),
      negotiable = COALESCE(?, negotiable), condition = COALESCE(?, condition),
      location = COALESCE(?, location), category_id = COALESCE(?, category_id),
      status = COALESCE(?, status), updated_at = datetime('now')
     WHERE id = ?`
  ).run(
    title?.trim() || null, description?.trim() || null,
    price != null ? Math.max(0, Math.round(Number(price))) : null,
    negotiable != null ? (negotiable ? 1 : 0) : null,
    condition || null, location || null, category_id || null,
    ['active', 'sold', 'paused'].includes(status) ? status : null,
    row.id
  );
  res.json({ ok: true });
});

app.delete('/api/ads/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM ads WHERE id = ?').get(req.params.id);
  if (!row || row.user_id !== req.session.userId) {
    return res.status(404).json({ error: 'Ad not found.' });
  }
  const imgs = db.prepare('SELECT filename FROM ad_images WHERE ad_id = ?')
    .all(row.id);
  db.prepare('DELETE FROM ad_images WHERE ad_id = ?').run(row.id);
  db.prepare('DELETE FROM favorites WHERE ad_id = ?').run(row.id);
  db.prepare('DELETE FROM ads WHERE id = ?').run(row.id);
  for (const im of imgs) {
    const p = path.join(__dirname, im.filename);
    if (p.startsWith(UPLOAD_DIR)) fs.unlink(p, () => {});
  }
  res.json({ ok: true });
});

app.get('/api/my/ads', requireAuth, (req, res) => {
  const rows = db
    .prepare(`${AD_SELECT} WHERE ads.user_id = ? ORDER BY ads.created_at DESC`)
    .all(req.session.userId);
  res.json({ ads: rows.map(adRowToAd) });
});

// ---------- favorites ----------
app.get('/api/favorites', requireAuth, (req, res) => {
  const rows = db
    .prepare(
      `${AD_SELECT} JOIN favorites f
         ON f.ad_id = ads.id AND f.user_id = ?
       ORDER BY f.created_at DESC`
    )
    .all(req.session.userId);
  res.json({ ads: rows.map(adRowToAd) });
});

app.post('/api/favorites/:adId', requireAuth, (req, res) => {
  db.prepare(
    'INSERT OR IGNORE INTO favorites (user_id, ad_id) VALUES (?, ?)'
  ).run(req.session.userId, req.params.adId);
  res.json({ ok: true });
});

app.delete('/api/favorites/:adId', requireAuth, (req, res) => {
  db.prepare('DELETE FROM favorites WHERE user_id = ? AND ad_id = ?')
    .run(req.session.userId, req.params.adId);
  res.json({ ok: true });
});

// ---------- pages ----------
app.get('/', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () =>
  console.log(`Sooda running at http://localhost:${PORT}`)
);
