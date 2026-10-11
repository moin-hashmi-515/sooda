// Sooda — builds the public site into dist/ as separate files.
//
// Public (upload to Hostinger): dist/index.html, dist/assets/css/style.css,
//   dist/assets/js/app.js, plus sitemap.xml and the Search Console file.
// Private (NEVER upload): sooda.db, single/, server.js, node_modules/.
// The client bundle contains no API keys or secrets (verified); user data
// lives in each visitor's own browser localStorage, never in these files.
// Usage: node single/build.js
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const ROOT = path.join(__dirname, '..');
const DIST = path.join(ROOT, 'dist');
const db = new DatabaseSync(path.join(ROOT, 'sooda.db'));

const categories = db
  .prepare('SELECT id, name, slug, icon FROM categories ORDER BY name')
  .all();
const locations = [
  'Karachi', 'Lahore', 'Islamabad', 'Rawalpindi', 'Faisalabad',
  'Multan', 'Peshawar', 'Quetta', 'Hyderabad', 'Sialkot',
];
const ads = db
  .prepare(
    `SELECT ads.*, c.name AS cat_name, c.slug AS cat_slug
     FROM ads JOIN categories c ON c.id = ads.category_id
     ORDER BY ads.created_at DESC`
  )
  .all()
  .map((r) => {
    const images = db
      .prepare('SELECT filename FROM ad_images WHERE ad_id = ? ORDER BY position')
      .all(r.id)
      .map((x) => 'img_' + path.basename(x.filename, '.svg').replace(/-/g, '_'));
    return {
      id: r.id,
      title: r.title,
      description: r.description,
      price: r.price,
      negotiable: r.negotiable,
      condition: r.condition,
      location: r.location,
      views: r.views,
      created_at: r.created_at,
      status: 'active',
      sellerName: 'Ahmed Raza',
      category: { id: r.category_id, name: r.cat_name, slug: r.cat_slug },
      images,
    };
  });

// Image files -> data URIs.
const IMG = {};
for (const f of fs.readdirSync(path.join(ROOT, 'public/img/seed'))) {
  if (!f.endsWith('.svg')) continue;
  const key = 'img_' + path.basename(f, '.svg').replace(/-/g, '_');
  const b64 = fs
    .readFileSync(path.join(ROOT, 'public/img/seed', f))
    .toString('base64');
  IMG[key] = 'data:image/svg+xml;base64,' + b64;
}

const css = fs.readFileSync(path.join(ROOT, 'public/css/style.css'), 'utf8');
let appJs = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
appJs = appJs.replace('/*__DB__*/ null', JSON.stringify({ categories, locations, ads }));
appJs = appJs.replace('/*__IMG__*/ {}', JSON.stringify(IMG));

fs.mkdirSync(path.join(DIST, 'assets/css'), { recursive: true });
fs.mkdirSync(path.join(DIST, 'assets/js'), { recursive: true });
fs.writeFileSync(path.join(DIST, 'assets/css/style.css'), css);
fs.writeFileSync(path.join(DIST, 'assets/js/app.js'), appJs);

const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sooda — Buy & Sell in Pakistan</title>
<meta name="description" content="Sooda is Pakistan's friendly marketplace. Buy and sell mobiles, cars, property, electronics and more.">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns%3D%27http://www.w3.org/2000/svg%27 viewBox%3D%270 0 64 64%27%3E  %3Crect width%3D%2764%27 height%3D%2764%27 rx%3D%2714%27 fill%3D%27%230e5c46%27/%3E  %3Ctext x%3D%2732%27 y%3D%2745%27 font-family%3D%27Arial, Helvetica, sans-serif%27 font-size%3D%2738%27 font-weight%3D%27bold%27 fill%3D%27%23ffffff%27 text-anchor%3D%27middle%27%3ES%3C/text%3E  %3Crect x%3D%2718%27 y%3D%2748%27 width%3D%2728%27 height%3D%274%27 rx%3D%272%27 fill%3D%27%23f2a007%27/%3E%3C/svg%3E">
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<div id="app"></div>
<script src="assets/js/app.js"></script>
</body>
</html>
`;
fs.writeFileSync(path.join(DIST, 'index.html'), html);

// Copy root-level public files into dist.
for (const f of ['sitemap.xml', 'google047701a9e4c928a6.html']) {
  const src = path.join(ROOT, f);
  if (fs.existsSync(src)) fs.copyFileSync(src, path.join(DIST, f));
}

console.log('wrote dist/ | html:', (html.length / 1024).toFixed(1) + 'KB',
  '| css:', (css.length / 1024).toFixed(1) + 'KB',
  '| js:', (appJs.length / 1024).toFixed(1) + 'KB',
  '| ads:', ads.length, '| images:', Object.keys(IMG).length);
console.log('Upload the CONTENTS of dist/ to Hostinger public_html. Do not upload sooda.db or single/.');
