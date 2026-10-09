// Sooda — database layer (Node's built-in SQLite, no native deps).
const { DatabaseSync } = require('node:sqlite');
const path = require('path');

const db = new DatabaseSync(path.join(__dirname, 'sooda.db'));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  phone TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  icon TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  category_id INTEGER NOT NULL REFERENCES categories(id),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  price INTEGER NOT NULL,
  negotiable INTEGER NOT NULL DEFAULT 0,
  condition TEXT NOT NULL DEFAULT 'used',
  location TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  views INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ad_images (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ad_id INTEGER NOT NULL REFERENCES ads(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  position INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS favorites (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ad_id INTEGER NOT NULL REFERENCES ads(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, ad_id)
);

CREATE INDEX IF NOT EXISTS idx_ads_category ON ads(category_id);
CREATE INDEX IF NOT EXISTS idx_ads_location ON ads(location);
CREATE INDEX IF NOT EXISTS idx_ads_created ON ads(created_at DESC);

CREATE TABLE IF NOT EXISTS phone_otps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  channel TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_otps_user ON phone_otps(user_id);
`);

// Migration for databases created before phone verification existed.
const userCols = db.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
if (!userCols.includes('phone_verified')) {
  db.exec('ALTER TABLE users ADD COLUMN phone_verified INTEGER NOT NULL DEFAULT 0');
}

// Seed categories once.
const CATEGORIES = [
  ['Mobiles', 'mobiles', 'mobile'],
  ['Vehicles', 'vehicles', 'car'],
  ['Property for Sale', 'property-sale', 'house'],
  ['Property for Rent', 'property-rent', 'key'],
  ['Electronics & Appliances', 'electronics', 'tv'],
  ['Bikes', 'bikes', 'bike'],
  ['Furniture & Home Decor', 'furniture', 'sofa'],
  ['Fashion & Beauty', 'fashion', 'shirt'],
  ['Animals', 'animals', 'paw'],
  ['Books, Sports & Hobbies', 'hobbies', 'book'],
  ['Jobs', 'jobs', 'briefcase'],
  ['Services', 'services', 'wrench'],
  ['Business & Agriculture', 'business', 'factory'],
  ['Kids', 'kids', 'blocks'],
];

const count = db.prepare('SELECT COUNT(*) AS n FROM categories').get().n;
if (count === 0) {
  const ins = db.prepare(
    'INSERT INTO categories (name, slug, icon) VALUES (?, ?, ?)'
  );
  for (const c of CATEGORIES) ins.run(...c);
}

module.exports = db;
