/* Sooda single-file app — all logic. DB + IMG are injected at build time. */
const DB = /*__DB__*/ null;
const IMG = /*__IMG__*/ {};

/* ---------- helpers ---------- */
const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;')
  .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const fmtPrice = (n) => 'Rs ' + Number(n).toLocaleString('en-PK');
function timeAgo(iso) {
  const s = Math.floor((Date.now() - new Date(String(iso).replace(' ', 'T') + 'Z').getTime()) / 1000);
  if (s < 60) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return m + ' min ago';
  const h = Math.floor(m / 60);
  if (h < 24) return h + ' hours ago';
  const d = Math.floor(h / 24);
  if (d < 30) return d + (d === 1 ? ' day ago' : ' days ago');
  return Math.floor(d / 30) + ' months ago';
}
let toastTimer;
function toast(msg) {
  let t = document.getElementById('toast');
  if (!t) { t = document.createElement('div'); t.id = 'toast'; document.body.appendChild(t); }
  t.textContent = msg; t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}

const ICONS = {
  mobile: '<rect x="7" y="2" width="10" height="20" rx="2"/><line x1="11" y1="18" x2="13" y2="18"/>',
  car: '<path d="M3 16v-4l2-5a2 2 0 0 1 1.9-1.3h10.2A2 2 0 0 1 19 7l2 5v4"/><circle cx="7.5" cy="16" r="1.8"/><circle cx="16.5" cy="16" r="1.8"/>',
  house: '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/><rect x="10" y="14" width="4" height="6"/>',
  key: '<circle cx="8" cy="8" r="4"/><line x1="11" y1="11" x2="20" y2="20"/>',
  tv: '<rect x="2" y="4" width="20" height="13" rx="2"/><line x1="12" y1="17" x2="12" y2="21"/>',
  bike: '<circle cx="6" cy="17" r="3.5"/><circle cx="18" cy="17" r="3.5"/><path d="M6 17l4-8h5l3 8"/>',
  sofa: '<path d="M4 11V7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v4"/><path d="M2 11a2 2 0 0 1 4 0v1h12v-1a2 2 0 0 1 4 0v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2z"/>',
  shirt: '<path d="M9 3L3 7l2.5 3L9 8v13h6V8l3.5 2L21 7l-6-4a3 3 0 0 1-6 0z"/>',
  paw: '<circle cx="7" cy="9" r="1.8"/><circle cx="12" cy="7" r="1.8"/><circle cx="17" cy="9" r="1.8"/><path d="M12 11c-3 0-5.5 2.5-5.5 5.2 0 1.6 1.2 2.8 2.8 2.8 1 0 1.8-.5 2.7-.5s1.7.5 2.7.5c1.6 0 2.8-1.2 2.8-2.8C17.5 13.5 15 11 12 11z"/>',
  book: '<path d="M4 4a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z"/><path d="M4 20a2 2 0 0 1 2-2h13"/>',
  briefcase: '<rect x="3" y="7" width="18" height="13" rx="2"/><path d="M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/>',
  wrench: '<path d="M14.5 6.5a4.5 4.5 0 0 0-6 6L3 18l3 3 5.5-5.5a4.5 4.5 0 0 0 6-6L14 13l-3-3z"/>',
  factory: '<path d="M3 21V10l5 3v-3l5 3V7l4 2.5V21z"/>',
  blocks: '<rect x="3" y="13" width="8" height="8" rx="1"/><rect x="13" y="13" width="8" height="8" rx="1"/><rect x="8" y="3" width="8" height="8" rx="1"/>',
};
const icon = (n) =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:34px;height:34px;color:#0e5c46">${ICONS[n] || ICONS.blocks}</svg>`;

/* ---------- TOTP two-factor auth (RFC 6238, pure JS) ---------- */
function sha1(msg) {
  const ml = msg.length;
  const padded = new Uint8Array((((ml + 8) >> 6) + 1) * 64);
  padded.set(msg);
  padded[ml] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 4, (ml * 8) >>> 0);
  dv.setUint32(padded.length - 8, Math.floor((ml * 8) / 4294967296));
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe,
      h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 80; i++) {
      const x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = (x << 1) | (x >>> 31);
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const t = (((a << 5) | (a >>> 27)) + f + e + k + w[i]) | 0;
      e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0;
    h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
  }
  const out = new Uint8Array(20);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, h0); odv.setUint32(4, h1); odv.setUint32(8, h2);
  odv.setUint32(12, h3); odv.setUint32(16, h4);
  return out;
}
function hmacSha1(key, msg) {
  if (key.length > 64) key = sha1(key);
  const k = new Uint8Array(64);
  k.set(key);
  const inner = new Uint8Array(64 + msg.length);
  const outer = new Uint8Array(64 + 20);
  for (let i = 0; i < 64; i++) {
    inner[i] = k[i] ^ 0x36;
    outer[i] = k[i] ^ 0x5c;
  }
  inner.set(msg, 64);
  const ih = sha1(inner);
  outer.set(ih, 64);
  return sha1(outer);
}
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32encode(bytes) {
  let out = '', bits = 0, val = 0;
  for (const b of bytes) {
    val = (val << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  while (out.length % 8) out += '=';
  return out;
}
function b32decode(s) {
  s = String(s).replace(/=+$/, '').toUpperCase();
  const out = [];
  let bits = 0, val = 0;
  for (const ch of s) {
    const i = B32.indexOf(ch);
    if (i < 0) continue;
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
function genTfaSecret() {
  const b = new Uint8Array(20);
  crypto.getRandomValues(b);
  return b32encode(b).replace(/=+$/, '');
}
function totpCode(secret, when) {
  let t = Math.floor((when == null ? Date.now() : when) / 30000);
  const msg = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) { msg[i] = t & 255; t = Math.floor(t / 256); }
  const h = hmacSha1(b32decode(secret), msg);
  const o = h[19] & 15;
  const n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1000000).padStart(6, '0');
}
function verifyTotp(secret, code) {
  code = String(code).replace(/\D/g, '');
  if (!/^\d{6}$/.test(code)) return false;
  const now = Date.now();
  return totpCode(secret, now) === code ||
    totpCode(secret, now - 30000) === code ||
    totpCode(secret, now + 30000) === code;
}

/* ---------- local store (replaces the server) ---------- */
const LS = {
  read(k, d) { try { const v = localStorage.getItem('sooda_' + k); return v ? JSON.parse(v) : d; } catch (e) { return d; } },
  write(k, v) { try { localStorage.setItem('sooda_' + k, JSON.stringify(v)); } catch (e) { toast('Browser storage is full'); } },
};
const DEMO_USER = { name: 'Ahmed Raza', email: 'demo@sooda.pk', phone: '0300-1234567', pass: 'demo1234' };
if (!LS.read('users', null)) LS.write('users', [DEMO_USER]);

const currentUser = () => {
  const email = LS.read('session', null);
  return LS.read('users', []).find((u) => u.email === email) || null;
};
const allAds = () => {
  const mine = LS.read('myads', []);
  const deleted = LS.read('deleted', []);
  return DB.ads.filter((a) => !deleted.includes(String(a.id))).concat(mine);
};
const getAd = (id) => allAds().find((a) => String(a.id) === String(id));
const adSeller = (ad) => {
  if (ad.sellerEmail) {
    const u = LS.read('users', []).find((x) => x.email === ad.sellerEmail);
    if (u) return u;
  }
  return { name: ad.sellerName || 'Sooda Seller', phone: '0300-0000000' };
};
const adViews = (ad) => (ad.views || 0) + (LS.read('views', {})[String(ad.id)] || 0);
const isFav = (id) => {
  const u = currentUser();
  return u ? (LS.read('favs', {})[u.email] || []).includes(String(id)) : false;
};
function toggleFav(id) {
  const u = currentUser();
  if (!u) { location.hash = '#/login?next=' + encodeURIComponent(location.hash); return false; }
  const favs = LS.read('favs', {});
  const list = favs[u.email] || [];
  const sid = String(id);
  favs[u.email] = list.includes(sid) ? list.filter((x) => x !== sid) : list.concat([sid]);
  LS.write('favs', favs);
  return favs[u.email].includes(sid);
}

/* ---------- header / footer ---------- */
function headerHtml() {
  const u = currentUser();
  const authArea = u
    ? `<a href="#/favorites">Favorites</a><a href="#/my-ads">My Ads</a>
       <span class="user-chip"><span class="avatar">${esc(u.name[0].toUpperCase())}</span>${esc(u.name.split(' ')[0])}</span>
       <a href="#" id="logout-link">Logout</a>`
    : `<a href="#/login">Login</a><a href="#/signup">Sign up</a>`;
  return `<header class="site-header"><div class="header-inner">
    <a class="logo" href="#/"><svg class="logo-mark" viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="14" fill="#ffffff"/><text x="32" y="45" font-family="Arial, Helvetica, sans-serif" font-size="38" font-weight="bold" fill="#0e5c46" text-anchor="middle">S</text><rect x="18" y="48" width="28" height="4" rx="2" fill="#f2a007"/></svg>Sooda<span>.</span></a>
    <form class="searchbar" id="search-form">
      <select id="search-loc"><option value="">All Pakistan</option>
      ${DB.locations.map((l) => `<option ${filters.location === l ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>
      <input id="search-q" placeholder="Find cars, mobiles, property..." value="${esc(filters.q || '')}">
      <button type="submit">Search</button>
    </form>
    <nav class="nav-links">${authArea}<a class="sell-btn" href="#/post">+ SELL</a></nav>
  </div></header>`;
}
function footerHtml() {
  return `<footer class="site-footer"><div class="footer-grid">
    <div><h4>Sooda.</h4><p>Pakistan's friendly marketplace. Buy and sell mobiles, cars, property and more.</p></div>
    <div><h4>Marketplace</h4>${DB.categories.slice(0, 4).map((c) => `<a href="#/" data-cat="${c.slug}">${esc(c.name)}</a>`).join('')}</div>
    <div><h4>Sell</h4><a href="#/post">Post a free ad</a><a href="#/my-ads">My ads</a><a href="#/favorites">Favorites</a></div>
    <div><h4>Account</h4><a href="#/login">Login</a><a href="#/signup">Sign up</a></div>
  </div><div class="copyright">© 2026 Sooda · Single-file demo — your ads are saved in this browser.</div></footer>`;
}
function bindCommon() {
  const sf = document.getElementById('search-form');
  if (sf) sf.addEventListener('submit', (e) => {
    e.preventDefault();
    filters.q = document.getElementById('search-q').value.trim();
    filters.location = document.getElementById('search-loc').value;
    location.hash = '#/';
  });
  const lo = document.getElementById('logout-link');
  if (lo) lo.addEventListener('click', (e) => { e.preventDefault(); LS.write('session', null); navigate(); });
  document.querySelectorAll('[data-cat]').forEach((a) => a.addEventListener('click', () => {
    filters = { q: '', category: a.dataset.cat, location: '', condition: 'any', min: '', max: '', sort: 'newest' };
  }));
}
// Favorite buttons: delegated once on #app (which persists across renders).
function bindFavDelegation() {
  document.getElementById('app').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-fav]');
    if (!btn) return;
    e.preventDefault();
    const added = toggleFav(btn.dataset.fav);
    if (added === false && !currentUser()) return;
    btn.classList.toggle('active', added);
    btn.textContent = added ? '♥' : '♡';
    if (added) toast('Saved to favorites');
    if (btn.dataset.favPage === '1' && !added) setTimeout(navigate, 350);
  });
}

/* ---------- router ---------- */
let filters = { q: '', category: '', location: '', condition: 'any', min: '', max: '', sort: 'newest' };
function parseHash() {
  const h = location.hash.replace(/^#\/?/, '');
  const qi = h.indexOf('?');
  return { path: qi === -1 ? h : h.slice(0, qi), params: new URLSearchParams(qi === -1 ? '' : h.slice(qi + 1)) };
}
/* ---------- 3D category carousel ----------
   Same stepped timing as the promo video: each category holds still
   for 1s, then the ring spins one step (0.7s out + 0.7s in). */
function initCatCarousel() {
  const viewport = document.getElementById('cat-carousel');
  const ring = document.getElementById('cat-ring');
  if (!viewport || !ring) return;
  if (window.__catRaf) {
    cancelAnimationFrame(window.__catRaf);
    window.__catRaf = 0;
  }
  const faces = Array.from(ring.children);
  const n = faces.length;
  if (!n) return;
  const reduced =
    window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const FOCAL = 950;
  let R = 300;
  const measure = () => {
    R = Math.max(170, Math.min(440, viewport.clientWidth * 0.42));
  };
  measure();
  const HOLD = 1000, OUT = 700, IN = 700, STEP = HOLD + OUT + IN;
  let t0 = performance.now(), pausedAt = 0, running = !reduced;
  const paint = (now) => {
    const t = (now - t0) % (n * STEP);
    const step = Math.floor(t / STEP);
    const fin = t % STEP;
    let e;
    if (fin < HOLD) {
      e = step;
    } else {
      const u = (fin - HOLD) / (OUT + IN);
      e = step + u * u * (3 - 2 * u);
    }
    const rot = (2 * Math.PI * e) / n;
    const dist = R + 940;
    for (let i = 0; i < n; i++) {
      const th = (2 * Math.PI * i) / n + rot;
      const x = R * Math.sin(th), z = R * Math.cos(th);
      const s = FOCAL / (dist - z);
      const front = (z + R) / (2 * R);
      const el = faces[i];
      el.style.transform =
        'translate(-50%,-50%) translate(' + (x * s).toFixed(1) + 'px,0) scale(' +
        s.toFixed(3) + ')';
      el.style.opacity = (0.3 + 0.7 * front).toFixed(2);
      el.style.zIndex = String(Math.round(front * 1000));
    }
  };
  const loop = (now) => {
    paint(now);
    if (running) window.__catRaf = requestAnimationFrame(loop);
  };
  const onResize = () => {
    if (!viewport.isConnected) {
      window.removeEventListener('resize', onResize);
      return;
    }
    measure();
  };
  window.addEventListener('resize', onResize);
  viewport.addEventListener('pointerenter', () => {
    if (!running || reduced) return;
    running = false;
    pausedAt = performance.now();
    if (window.__catRaf) {
      cancelAnimationFrame(window.__catRaf);
      window.__catRaf = 0;
    }
  });
  viewport.addEventListener('pointerleave', () => {
    if (running || reduced) return;
    t0 += performance.now() - pausedAt;
    running = true;
    window.__catRaf = requestAnimationFrame(loop);
  });
  paint(t0);
  if (running) window.__catRaf = requestAnimationFrame(loop);
}

const routes = {};
function navigate() {
  const { path, params } = parseHash();
  const view = routes[path] || routes[''];
  window.scrollTo(0, 0);
  document.getElementById('app').innerHTML = headerHtml() + view.html(params) + footerHtml();
  bindCommon();
  if (view.bind) view.bind(params);
}
window.addEventListener('hashchange', navigate);

function adCard(a) {
  const fav = isFav(a.id);
  const thumb = a.images[0] ? `<img src="${IMG[a.images[0]] || a.images[0]}" alt="" loading="lazy">` : '';
  return `<div class="ad-card">
    <button class="fav-btn${fav ? ' active' : ''}" data-fav="${a.id}">${fav ? '♥' : '♡'}</button>
    <a href="#/ad?id=${a.id}"><div class="thumb">${thumb}</div>
    <div class="body"><div class="price">${fmtPrice(a.price)}${a.negotiable ? '<span class="neg">Negotiable</span>' : ''}</div>
    <div class="title">${esc(a.title)}</div>
    <div class="meta">${esc(a.location)} · ${timeAgo(a.created_at)}</div></div></a></div>`;
}

/* ---------- home ---------- */
routes[''] = {
  html() {
    const cats = DB.categories.map((c) =>
      `<a class="cat-face" href="#/" data-catlink="${c.slug}" aria-label="${esc(c.name)}">${icon(c.icon)}<span>${esc(c.name)}</span></a>`).join('');
    return `<section class="hero"><div class="wrap">
      <h1>Buy and sell anything, anywhere in Pakistan</h1>
      <p>Post your ad for free — reach millions of buyers in your city.</p>
      <a class="btn amber" href="#/post">+ Post a Free Ad</a>
      <div class="stats"><div><b>${allAds().length * 137}</b><small>Live ads</small></div>
      <div><b>${DB.categories.length}</b><small>Categories</small></div>
      <div><b>100%</b><small>Free to post</small></div></div></div></section>
    <main class="wrap"><section class="section"><h2>Browse categories</h2>
      <div class="cat-carousel" id="cat-carousel"><div class="cat-ring" id="cat-ring">${cats}</div></div></section>
    <section class="section"><div class="browse">
      <aside class="filters"><h3>Filters</h3>
        <label>Category</label><select id="f-category"><option value="">All categories</option>
        ${DB.categories.map((c) => `<option value="${c.slug}" ${filters.category === c.slug ? 'selected' : ''}>${esc(c.name)}</option>`).join('')}</select>
        <label>Location</label><select id="f-location"><option value="">All Pakistan</option>
        ${DB.locations.map((l) => `<option ${filters.location === l ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>
        <label>Condition</label><select id="f-condition">
        <option value="any"${filters.condition === 'any' ? ' selected' : ''}>Any</option>
        <option value="new"${filters.condition === 'new' ? ' selected' : ''}>New</option>
        <option value="used"${filters.condition === 'used' ? ' selected' : ''}>Used</option></select>
        <label>Price range (Rs)</label><div class="price-row">
        <input id="f-min" type="number" placeholder="Min" value="${esc(filters.min)}">
        <input id="f-max" type="number" placeholder="Max" value="${esc(filters.max)}"></div>
        <button class="btn block" id="f-apply" style="margin-top:16px">Apply</button>
        <button class="btn ghost block" id="f-clear" style="margin-top:8px">Clear</button>
      </aside>
      <div class="results"><div class="results-head"><h2 id="results-title"></h2>
        <select id="sort">
        <option value="newest"${filters.sort === 'newest' ? ' selected' : ''}>Newest first</option>
        <option value="price_asc"${filters.sort === 'price_asc' ? ' selected' : ''}>Price: low to high</option>
        <option value="price_desc"${filters.sort === 'price_desc' ? ' selected' : ''}>Price: high to low</option></select></div>
        <div class="ads-grid" id="ads-grid"></div>
      </div></div></section></main>`;
  },
  bind() {
    document.querySelectorAll('[data-catlink]').forEach((a) => a.addEventListener('click', () => {
      filters = { q: '', category: a.dataset.catlink, location: '', condition: 'any', min: '', max: '', sort: 'newest' };
    }));
    initCatCarousel();
    const render = () => {
      const f = filters;
      let list = allAds().filter((a) => (a.status || 'active') === 'active');
      if (f.q) { const q = f.q.toLowerCase(); list = list.filter((a) => (a.title + ' ' + a.description).toLowerCase().includes(q)); }
      if (f.category) list = list.filter((a) => a.category.slug === f.category);
      if (f.location) list = list.filter((a) => a.location === f.location);
      if (f.condition !== 'any') list = list.filter((a) => a.condition === f.condition);
      if (f.min !== '') list = list.filter((a) => a.price >= Number(f.min));
      if (f.max !== '') list = list.filter((a) => a.price <= Number(f.max));
      list.sort((a, b) => f.sort === 'price_asc' ? a.price - b.price : f.sort === 'price_desc' ? b.price - a.price : 0);
      const grid = document.getElementById('ads-grid');
      grid.innerHTML = list.length ? list.map(adCard).join('')
        : `<div class="empty" style="grid-column:1/-1"><h3>No ads found</h3><p>Try a different search or clear the filters.</p></div>`;
      const cat = DB.categories.find((c) => c.slug === f.category);
      document.getElementById('results-title').textContent =
        f.q ? `Results for "${f.q}" (${list.length})` : cat ? `${cat.name} (${list.length})` : `Fresh recommendations (${list.length})`;
    };
    document.getElementById('f-apply').addEventListener('click', () => {
      filters.category = document.getElementById('f-category').value;
      filters.location = document.getElementById('f-location').value;
      filters.condition = document.getElementById('f-condition').value;
      filters.min = document.getElementById('f-min').value;
      filters.max = document.getElementById('f-max').value;
      render();
    });
    document.getElementById('f-clear').addEventListener('click', () => {
      filters = { q: '', category: '', location: '', condition: 'any', min: '', max: '', sort: 'newest' };
      navigate();
    });
    document.getElementById('sort').addEventListener('change', (e) => { filters.sort = e.target.value; render(); });
    render();
  },
};

/* ---------- ad detail ---------- */
routes['ad'] = {
  html(params) {
    const ad = getAd(params.get('id'));
    if (!ad) return `<main class="wrap"><div class="empty" style="margin:30px 0"><h3>Ad not found</h3><a class="btn" href="#/">Back to home</a></div></main>`;
    const u = currentUser();
    const views = LS.read('views', {});
    views[String(ad.id)] = (views[String(ad.id)] || 0) + 1;
    LS.write('views', views);
    const imgs = ad.images.map((k) => IMG[k] || k).filter(Boolean);
    const thumbs = imgs.map((src, i) => `<img src="${src}" class="${i === 0 ? 'sel' : ''}" alt="">`).join('');
    const seller = adSeller(ad);
    const mine = u && ad.sellerEmail && ad.sellerEmail === u.email;
    const fav = isFav(ad.id);
    const similar = allAds().filter((a) => String(a.id) !== String(ad.id) && a.category.slug === ad.category.slug).slice(0, 4);
    return `<main class="wrap"><div class="ad-detail"><div>
      <div class="gallery"><div class="main">${imgs[0] ? `<img id="main-img" src="${imgs[0]}" alt="">` : ''}</div>
      ${thumbs ? `<div class="thumbs" id="thumbs">${thumbs}</div>` : ''}</div>
      <div class="detail-box"><h3>Details</h3>
      <div class="spec"><span>Category</span><b>${esc(ad.category.name)}</b></div>
      <div class="spec"><span>Condition</span><b>${ad.condition === 'new' ? 'New' : 'Used'}</b></div>
      <div class="spec"><span>Location</span><b>${esc(ad.location)}</b></div>
      <div class="spec"><span>Posted</span><b>${timeAgo(ad.created_at)}</b></div>
      <div class="spec"><span>Views</span><b>${adViews(ad)}</b></div>
      <div class="spec"><span>Ad ID</span><b>${ad.id}</b></div></div>
      <div class="detail-box"><h3>Description</h3><p style="white-space:pre-wrap">${esc(ad.description)}</p></div>
    </div><div class="sidebar"><div class="price-card">
      <div class="price">${fmtPrice(ad.price)}</div>
      <div class="ad-title">${esc(ad.title)}</div>
      <div class="loc">${esc(ad.location)} · ${timeAgo(ad.created_at)}</div>
      <div class="action-row"><button class="btn ghost block${fav ? ' active' : ''}" id="fav-toggle" data-fav="${ad.id}" data-fav-page="0">${fav ? '♥ Saved' : '♡ Save'}</button></div>
      ${mine ? `<div class="action-row"><a class="btn ghost block" href="#/post?edit=${ad.id}">Edit</a></div>` : ''}
    </div><div class="seller-card"><div class="avatar">${esc(seller.name[0].toUpperCase())}</div>
      <b>${esc(seller.name)}</b><div style="color:#66756f;font-size:13px;margin-bottom:12px">Seller</div>
      ${u ? `<button class="btn amber block" id="show-phone">Show phone number</button>
        <div id="phone-num" style="display:none;font-size:22px;font-weight:800;margin-top:10px">${esc(seller.phone)}</div>`
        : `<a class="btn amber block" href="#/login?next=${encodeURIComponent(location.hash)}">Login to see phone</a>`}
    </div></div></div>
    ${similar.length ? `<section class="section"><h2>Similar ads</h2><div class="ads-grid">${similar.map(adCard).join('')}</div></section>` : ''}
    </main>`;
  },
  bind() {
    const main = document.getElementById('main-img');
    const th = document.getElementById('thumbs');
    if (th && main) th.querySelectorAll('img').forEach((t) => t.addEventListener('click', () => {
      th.querySelectorAll('img').forEach((x) => x.classList.remove('sel'));
      t.classList.add('sel'); main.src = t.src;
    }));
    const sp = document.getElementById('show-phone');
    if (sp) sp.addEventListener('click', () => {
      document.getElementById('phone-num').style.display = '';
      sp.style.display = 'none';
    });
  },
};

/* ---------- post an ad (also edits) ---------- */
routes['post'] = {
  html(params) {
    const u = currentUser();
    if (!u) { setTimeout(() => { location.hash = '#/login?next=' + encodeURIComponent(location.hash); }, 0); return '<main class="wrap"><div class="empty" style="margin:30px 0">Please log in...</div></main>'; }
    const editId = params.get('edit');
    const existing = editId ? LS.read('myads', []).find((a) => String(a.id) === String(editId)) : null;
    return `<main class="wrap"><div class="form-card wide">
    <h2>${existing ? 'Edit your ad' : 'Post your ad'}</h2>
    <p class="sub">${existing ? 'Update the details below.' : "It's free — your ad goes live instantly."}</p>
    <div class="form-err" id="form-err"></div>
    <form id="ad-form">
      <div class="field-row"><div class="field"><label>Category *</label><select id="f-cat">
      ${DB.categories.map((c) => `<option value="${c.slug}" ${existing && existing.category.slug === c.slug ? 'selected' : ''}>${esc(c.name)}</option>`).join('')}</select></div>
      <div class="field"><label>Location *</label><select id="f-loc">
      ${DB.locations.map((l) => `<option ${existing && existing.location === l ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></div></div>
      <div class="field"><label>Ad title *</label><input id="f-title" maxlength="80" required value="${esc(existing ? existing.title : '')}" placeholder="e.g. iPhone 13 Pro 256GB, PTA approved"></div>
      <div class="field"><label>Description *</label><textarea id="f-desc" required placeholder="Describe your item...">${esc(existing ? existing.description : '')}</textarea></div>
      <div class="field-row"><div class="field"><label>Price (Rs) *</label><input id="f-price" type="number" min="0" required value="${existing ? existing.price : ''}" placeholder="e.g. 85000"></div>
      <div class="field"><label>Condition</label><select id="f-cond">
      <option value="used"${existing && existing.condition === 'used' ? ' selected' : ''}>Used</option>
      <option value="new"${existing && existing.condition === 'new' ? ' selected' : ''}>New</option></select></div></div>
      <div class="field"><label class="check-row"><input type="checkbox" id="f-neg" style="width:auto"${existing && existing.negotiable ? ' checked' : ''}> Price is negotiable</label></div>
      ${existing ? '' : `<div class="field"><label>Photos (up to 6)</label><input id="f-imgs" type="file" accept="image/*" multiple><div class="hint">Stored in your browser.</div><div class="img-preview" id="img-prev"></div></div>`}
      <button class="btn amber block" type="submit">${existing ? 'Save changes' : 'Post ad now'}</button>
    </form></div></main>`;
  },
  bind(params) {
    const u = currentUser();
    if (!u) return;
    const editId = params.get('edit');
    const prev = document.getElementById('img-prev');
    const fi = document.getElementById('f-imgs');
    if (fi) fi.addEventListener('change', () => {
      prev.innerHTML = '';
      [...fi.files].slice(0, 6).forEach((f) => {
        const img = document.createElement('img');
        img.src = URL.createObjectURL(f);
        prev.appendChild(img);
      });
    });
    document.getElementById('ad-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const cat = DB.categories.find((c) => c.slug === document.getElementById('f-cat').value);
      const base = {
        title: document.getElementById('f-title').value.trim(),
        description: document.getElementById('f-desc').value.trim(),
        price: Math.max(0, Math.round(Number(document.getElementById('f-price').value) || 0)),
        condition: document.getElementById('f-cond').value,
        negotiable: document.getElementById('f-neg').checked ? 1 : 0,
        location: document.getElementById('f-loc').value,
        category: { id: cat.id, name: cat.name, slug: cat.slug },
      };
      if (!base.title || !base.description || !base.price) { toast('Please fill all required fields'); return; }
      const done = (images) => {
        const myads = LS.read('myads', []);
        if (editId) {
          const ad = myads.find((a) => String(a.id) === String(editId));
          Object.assign(ad, base);
          LS.write('myads', myads);
          toast('Ad updated');
          location.hash = '#/ad?id=' + ad.id;
        } else {
          const ad = Object.assign({ id: 'u' + Date.now(), sellerEmail: u.email, created_at: new Date().toISOString().slice(0, 19).replace('T', ' '), views: 0, status: 'active', images }, base);
          myads.unshift(ad);
          LS.write('myads', myads);
          toast('Your ad is live!');
          location.hash = '#/ad?id=' + ad.id;
        }
      };
      if (editId || !fi || !fi.files.length) { done(editId ? undefined : []); return; }
      const files = [...fi.files].slice(0, 6);
      const out = [];
      let n = 0;
      files.forEach((f) => {
        const r = new FileReader();
        r.onload = () => { out.push(r.result); if (++n === files.length) done(out); };
        r.readAsDataURL(f);
      });
    });
  },
};

/* ---------- auth ---------- */
function nextParam(params) { return params.get('next') || '#/'; }
let pendingUser = null;   // signup waiting on 2FA setup
let pendingLogin = null;  // login waiting on 2FA code
routes['login'] = {
  html() {
    return `<main class="wrap"><div class="form-card"><h2>Welcome back</h2>
    <p class="sub">Log in to post ads and save favorites. Demo: demo@sooda.pk / demo1234</p>
    <div class="form-err" id="form-err"></div>
    <form id="auth-form"><div class="field"><label>Email</label><input id="a-email" type="email" required></div>
    <div class="field"><label>Password</label><input id="a-pass" type="password" required></div>
    <button class="btn block" type="submit">Login</button></form>
    <p style="margin-top:16px;font-size:14px;text-align:center">New here? <a href="#/signup" style="color:#0e5c46;font-weight:700">Create an account</a></p></div></main>`;
  },
  bind(params) {
    document.getElementById('auth-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const email = document.getElementById('a-email').value.trim().toLowerCase();
      const pass = document.getElementById('a-pass').value;
      const u = LS.read('users', []).find((x) => x.email === email && x.pass === pass);
      if (!u) { const er = document.getElementById('form-err'); er.textContent = 'Wrong email or password.'; er.style.display = 'block'; return; }
      if (u.tfa) {
        pendingLogin = { email, next: nextParam(params) };
        location.hash = '#/verify-2fa';
      } else {
        LS.write('session', email);
        location.hash = nextParam(params);
      }
    });
  },
};
routes['verify-2fa'] = {
  html() {
    if (!pendingLogin) { setTimeout(() => { location.hash = '#/login'; }, 0); return '<main class="wrap"><div class="empty" style="margin:30px 0">Please log in first.</div></main>'; }
    return `<main class="wrap"><div class="form-card"><h2>Two-factor authentication</h2>
    <p class="sub">Enter the 6-digit code from your authenticator app.</p>
    <div class="form-err" id="form-err"></div>
    <form id="tfa-form"><div class="field"><label>6-digit code</label>
    <input id="tfa-code" inputmode="numeric" maxlength="6" required placeholder="123456" style="text-align:center;font-size:20px;letter-spacing:4px"></div>
    <button class="btn block" type="submit">Verify</button></form></div></main>`;
  },
  bind() {
    if (!pendingLogin) return;
    document.getElementById('tfa-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const u = LS.read('users', []).find((x) => x.email === pendingLogin.email);
      if (u && u.tfa && verifyTotp(u.tfa, document.getElementById('tfa-code').value)) {
        LS.write('session', pendingLogin.email);
        const next = pendingLogin.next;
        pendingLogin = null;
        location.hash = next;
      } else {
        const er = document.getElementById('form-err');
        er.textContent = 'Wrong code — check your authenticator app and try again.';
        er.style.display = 'block';
      }
    });
  },
};
routes['signup'] = {
  html() {
    return `<main class="wrap"><div class="form-card"><h2>Create your account</h2>
    <p class="sub">Free forever. Saved in this browser. Optional 2FA on the next step.</p>
    <div class="form-err" id="form-err"></div>
    <form id="auth-form"><div class="field"><label>Full name</label><input id="a-name" required></div>
    <div class="field"><label>Email</label><input id="a-email" type="email" required></div>
    <div class="field"><label>Phone / WhatsApp</label><input id="a-phone" required></div>
    <div class="field"><label>Password</label><input id="a-pass" type="password" required minlength="6"></div>
    <button class="btn block" type="submit">Continue</button></form>
    <p style="margin-top:16px;font-size:14px;text-align:center">Already have an account? <a href="#/login" style="color:#0e5c46;font-weight:700">Log in</a></p></div></main>`;
  },
  bind() {
    document.getElementById('auth-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const email = document.getElementById('a-email').value.trim().toLowerCase();
      const users = LS.read('users', []);
      if (users.find((x) => x.email === email)) { const er = document.getElementById('form-err'); er.textContent = 'Email already registered.'; er.style.display = 'block'; return; }
      pendingUser = {
        name: document.getElementById('a-name').value.trim(),
        email,
        phone: document.getElementById('a-phone').value.trim(),
        pass: document.getElementById('a-pass').value,
        tfaSecret: genTfaSecret(),
      };
      location.hash = '#/setup-2fa';
    });
  },
};
routes['setup-2fa'] = {
  html() {
    if (!pendingUser) { setTimeout(() => { location.hash = '#/signup'; }, 0); return '<main class="wrap"><div class="empty" style="margin:30px 0">Please sign up first.</div></main>'; }
    const s = pendingUser.tfaSecret;
    return `<main class="wrap"><div class="form-card"><h2>Secure your account</h2>
    <p class="sub">Add this key to your authenticator app (Google Authenticator, Authy, 1Password): choose <b>"Enter setup key"</b> and name it <b>Sooda</b>.</p>
    <div class="field"><label>Your setup key</label>
    <div style="font-family:monospace;font-size:17px;letter-spacing:2px;background:#f4f6f4;border:1.5px dashed #0e5c46;border-radius:8px;padding:12px 8px;text-align:center;user-select:all;word-break:break-all">${esc(s)}</div></div>
    <div class="form-err" id="form-err"></div>
    <form id="tfa-form"><div class="field"><label>6-digit code from the app</label>
    <input id="tfa-code" inputmode="numeric" maxlength="6" required placeholder="123456" style="text-align:center;font-size:20px;letter-spacing:4px"></div>
    <button class="btn block" type="submit">Verify & enable 2FA</button></form>
    <p style="margin-top:14px;text-align:center"><a href="#" id="skip-tfa" style="color:#66756f;font-size:14px">Skip for now</a></p></div></main>`;
  },
  bind() {
    if (!pendingUser) return;
    const finish = (withTfa) => {
      const users = LS.read('users', []);
      const nu = { name: pendingUser.name, email: pendingUser.email, phone: pendingUser.phone, pass: pendingUser.pass };
      if (withTfa) nu.tfa = pendingUser.tfaSecret;
      users.push(nu);
      LS.write('users', users);
      LS.write('session', pendingUser.email);
      pendingUser = null;
      toast(withTfa ? 'Account created — 2FA enabled' : 'Account created — welcome!');
      setTimeout(() => { location.hash = '#/'; }, 700);
    };
    document.getElementById('tfa-form').addEventListener('submit', (e) => {
      e.preventDefault();
      if (verifyTotp(pendingUser.tfaSecret, document.getElementById('tfa-code').value)) finish(true);
      else {
        const er = document.getElementById('form-err');
        er.textContent = 'Wrong code — check your authenticator app and try again.';
        er.style.display = 'block';
      }
    });
    document.getElementById('skip-tfa').addEventListener('click', (e) => { e.preventDefault(); finish(false); });
  },
};

/* ---------- my ads ---------- */
routes['my-ads'] = {
  html() {
    const u = currentUser();
    if (!u) { setTimeout(() => { location.hash = '#/login?next=' + encodeURIComponent('#/my-ads'); }, 0); return '<main class="wrap"><div class="empty" style="margin:30px 0">Please log in...</div></main>'; }
    const mine = allAds().filter((a) => a.sellerEmail === u.email || (u.email === DEMO_USER.email && !a.sellerEmail));
    const rows = mine.map((a) => {
      const thumb = a.images[0] ? `<img src="${IMG[a.images[0]] || a.images[0]}" alt="">` : '';
      return `<div class="myad"><a href="#/ad?id=${a.id}">${thumb}</a>
      <div class="info"><b>${esc(a.title)}</b><small>${fmtPrice(a.price)} · ${esc(a.location)} · ${adViews(a)} views</small>
      <div style="margin-top:6px"><span class="badge ${(a.status || 'active') !== 'active' ? 'sold' : ''}">${esc(a.status || 'active')}</span></div></div>
      <div class="actions">${a.sellerEmail ? `<a class="btn sm ghost" href="#/post?edit=${a.id}">Edit</a>` : ''}
      <button class="btn sm ghost" data-sold="${a.id}">${(a.status || 'active') === 'active' ? 'Mark sold' : 'Reactivate'}</button>
      <button class="btn sm danger" data-del="${a.id}">Delete</button></div></div>`;
    }).join('');
    return `<main class="wrap"><section class="section"><div class="results-head"><h2>My ads</h2>
    <a class="btn amber" href="#/post">+ Post new ad</a></div>
    ${mine.length ? rows : `<div class="empty"><h3>No ads yet</h3><a class="btn amber" href="#/post" style="margin-top:12px">Post a free ad</a></div>`}
    </section></main>`;
  },
  bind() {
    document.getElementById('app').addEventListener('click', function h(e) {
      const del = e.target.closest('[data-del]');
      const sold = e.target.closest('[data-sold]');
      if (del) {
        if (!confirm('Delete this ad permanently?')) return;
        const id = String(del.dataset.del);
        if (/^u/.test(id)) LS.write('myads', LS.read('myads', []).filter((a) => String(a.id) !== id));
        else LS.write('deleted', LS.read('deleted', []).concat([id]));
        toast('Ad deleted'); navigate();
      } else if (sold) {
        const id = String(sold.dataset.sold);
        const ad = getAd(id);
        const to = (ad.status || 'active') === 'active' ? 'sold' : 'active';
        if (/^u/.test(id)) { const m = LS.read('myads', []); m.find((a) => String(a.id) === id).status = to; LS.write('myads', m); }
        else { const st = LS.read('status', {}); st[id] = to; LS.write('status', st); }
        toast(to === 'sold' ? 'Marked as sold' : 'Ad reactivated');
        setTimeout(navigate, 500);
      }
    }, { once: true });
  },
};

/* ---------- favorites ---------- */
routes['favorites'] = {
  html() {
    const u = currentUser();
    if (!u) { setTimeout(() => { location.hash = '#/login?next=' + encodeURIComponent('#/favorites'); }, 0); return '<main class="wrap"><div class="empty" style="margin:30px 0">Please log in...</div></main>'; }
    const list = (LS.read('favs', {})[u.email] || []).map(getAd).filter(Boolean);
    return `<main class="wrap"><section class="section"><h2>My favorites</h2>
    ${list.length ? `<div class="ads-grid">${list.map((a) => adCard(a).replace('data-fav=', 'data-fav-page="1" data-fav=')).join('')}</div>`
      : `<div class="empty"><h3>No favorites yet</h3><p>Tap ♡ on any ad to save it here.</p><a class="btn" href="#/" style="margin-top:12px">Browse ads</a></div>`}
    </section></main>`;
  },
};

/* ---------- init ---------- */
bindFavDelegation();
if (!location.hash) location.hash = '#/';
navigate();
