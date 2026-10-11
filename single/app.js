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
const DEMO_GONE = (() => {
  const users = LS.read('users', []);
  const clean = users.filter((x) => x.email !== 'demo@sooda.pk');
  if (clean.length !== users.length) LS.write('users', clean);
  return true;
})();
if (!LS.read('users', null)) LS.write('users', []);
/* SHA-256 password hashing (async; falls back to a non-crypto hash off secure contexts) */
const hashPass = async (pw) => {
  const input = 'sooda-v1:' + pw;
  try {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch (e) {
    let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
    for (let i = 0; i < input.length; i++) {
      const ch = input.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761); h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    return (h1 >>> 0).toString(16) + (h2 >>> 0).toString(16);
  }
};

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
/* bidding helpers: ad.bidding = { bids: [{name, email, amount, at}] }, ad.price = starting bid */
const bidList = (ad) => (ad.bidding && ad.bidding.bids) || [];
const currentBid = (ad) => {
  const bids = bidList(ad);
  return bids.length ? Math.max(...bids.map((b) => b.amount)) : ad.price;
};
const bidHistoryHtml = (ad) => {
  const bids = [...bidList(ad)].sort((x, y) => y.amount - x.amount).slice(0, 5);
  if (!bids.length) return '<div class="bid-note">No bids yet. Be the first.</div>';
  return '<div class="bid-history">' + bids.map((b, i) =>
    `<div class="bid-row${i === 0 ? ' bid-lead' : ''}"><span>${esc(b.name)}<small>${timeAgo(b.at)}</small></span><b>${fmtPrice(b.amount)}</b></div>`
  ).join('') + '</div>';
};
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
  return `<a class="skip-link" href="#app">Skip to content</a><header class="site-header"><div class="header-inner">
    <a class="logo" href="#/"><svg class="logo-mark" viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="14" fill="#ffffff"/><text x="32" y="45" font-family="Arial, Helvetica, sans-serif" font-size="38" font-weight="bold" fill="#0e5c46" text-anchor="middle">S</text><rect x="18" y="48" width="28" height="4" rx="2" fill="#f2a007"/></svg>Sooda<span>.</span></a>
    <form class="searchbar" id="search-form" role="search">
      <select id="search-loc" aria-label="Location"><option value="">All Pakistan</option>
      ${DB.locations.map((l) => `<option ${filters.location === l ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>
      <input id="search-q" placeholder="Find cars, mobiles, property..." value="${esc(filters.q || '')}" aria-label="Search ads">
      <button type="submit">Search</button>
    </form>
    <button class="theme-toggle" id="theme-toggle" aria-label="Toggle dark mode">☾</button>
    <button class="menu-toggle" id="menu-toggle" aria-label="Open menu">☰</button>
    <nav class="nav-links" aria-label="Main navigation">${authArea}<a class="sell-btn" href="#/post">+ SELL</a></nav>
  </div></header>`;
}
function footerHtml() {
  return `<footer class="site-footer"><div class="footer-grid">
    <div><h4>Sooda.</h4><p>Pakistan's friendly marketplace. Buy and sell mobiles, cars, property and more.</p><p class="acronym-foot"><b>S</b>eek <b>O</b>ffers, <b>O</b>rder <b>D</b>eals <b>A</b>asaan</p></div>
    <div><h4>Marketplace</h4>${DB.categories.slice(0, 4).map((c) => `<a href="#/" data-cat="${c.slug}">${esc(c.name)}</a>`).join('')}</div>
    <div><h4>Sell</h4><a href="#/post">Post a free ad</a><a href="#/my-ads">My ads</a><a href="#/favorites">Favorites</a></div>
    <div><h4>Account</h4><a href="#/login">Login</a><a href="#/signup">Sign up</a></div>
    <div><h4>Legal</h4><a href="#/privacy">Privacy policy</a><a href="#/terms">Terms of use</a><a href="#/faq">FAQ</a></div>
  </div><div class="copyright">© 2026 Sooda · Your ads are saved in this browser.</div></footer>`;
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
  const sk = document.getElementById('skip-link');
  if (sk) sk.addEventListener('click', (e) => {
    e.preventDefault();
    const app = document.getElementById('app');
    app.setAttribute('tabindex', '-1'); app.focus({ preventScroll: true }); app.scrollIntoView();
  });
  const mt = document.getElementById('menu-toggle');
  if (mt) mt.addEventListener('click', () => document.querySelector('.nav-links').classList.toggle('open'));
  const th = document.getElementById('theme-toggle');
  if (th) {
    th.textContent = document.documentElement.dataset.theme === 'dark' ? '☀' : '☾';
    th.addEventListener('click', () => {
      const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
      document.documentElement.dataset.theme = next;
      LS.write('theme', next);
      th.textContent = next === 'dark' ? '☀' : '☾';
    });
  }
}
/* one-time page chrome: theme, scroll UI, cookies, UTM (checklist A) */
function initChrome() {
  const savedTheme = LS.read('theme', null) ||
    (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.dataset.theme = savedTheme;
  const sp = document.createElement('div');
  sp.id = 'scroll-progress'; sp.setAttribute('aria-hidden', 'true');
  document.body.appendChild(sp);
  const tt = document.createElement('button');
  tt.id = 'to-top'; tt.className = 'float-btn'; tt.textContent = '↑'; tt.setAttribute('aria-label', 'Back to top');
  tt.addEventListener('click', () => window.scrollTo({ top: 0, behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' }));
  document.body.appendChild(tt);
  const help = document.createElement('a');
  help.id = 'help-fab'; help.className = 'float-btn'; help.href = '#/faq'; help.textContent = '?';
  help.setAttribute('aria-label', 'Help and frequently asked questions');
  document.body.appendChild(help);
  window.addEventListener('scroll', () => {
    const h = document.documentElement;
    const max = h.scrollHeight - h.clientHeight;
    sp.style.width = (max > 0 ? (h.scrollTop / max) * 100 : 0) + '%';
    tt.classList.toggle('show', h.scrollTop > 500);
  }, { passive: true });
  if (!LS.read('cookies-ok', null)) {
    const cb = document.createElement('div');
    cb.id = 'cookie-banner';
    cb.innerHTML = '<span>We use only essential browser storage to keep you logged in and remember your ads. No tracking cookies.</span>';
    const ok = document.createElement('button');
    ok.className = 'btn sm'; ok.textContent = 'Got it';
    ok.addEventListener('click', () => { LS.write('cookies-ok', 1); cb.remove(); });
    cb.appendChild(ok);
    document.body.appendChild(cb);
  }
  try {
    const q = new URLSearchParams(location.search);
    const utm = {};
    ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'].forEach((k) => {
      const v = q.get(k); if (v) utm[k] = v;
    });
    if (Object.keys(utm).length) LS.write('utm', Object.assign(LS.read('utm', {}), utm));
  } catch (e) { /* URLSearchParams unavailable */ }
  // password visibility toggles + confirm-modal helper live here (delegated, survives re-renders)
  document.getElementById('app').addEventListener('click', (e) => {
    const pt = e.target.closest('.pass-toggle');
    if (pt) {
      const inp = document.getElementById(pt.dataset.pass);
      const show = inp.type === 'password';
      inp.type = show ? 'text' : 'password';
      pt.textContent = show ? 'Hide' : 'Show';
    }
  });
}
/* styled confirmation modal (replaces native confirm()) */
function confirmModal(title, msg, okLabel) {
  return new Promise((resolve) => {
    const back = document.createElement('div');
    back.className = 'modal-back';
    const box = document.createElement('div');
    box.className = 'modal'; box.setAttribute('role', 'dialog'); box.setAttribute('aria-modal', 'true');
    const h = document.createElement('h3'); h.textContent = title;
    const p = document.createElement('p'); p.textContent = msg;
    const row = document.createElement('div'); row.className = 'row';
    const cancel = document.createElement('button'); cancel.className = 'btn ghost'; cancel.textContent = 'Cancel';
    const ok = document.createElement('button'); ok.className = 'btn danger'; ok.textContent = okLabel;
    row.appendChild(cancel); row.appendChild(ok);
    box.appendChild(h); box.appendChild(p); box.appendChild(row);
    back.appendChild(box); document.body.appendChild(back);
    const done = (v) => { back.remove(); resolve(v); };
    cancel.addEventListener('click', () => done(false));
    ok.addEventListener('click', () => done(true));
    back.addEventListener('click', (e) => { if (e.target === back) done(false); });
    ok.focus();
  });
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

/* ---------- hero acronym animation ----------
   Mirrors the intro video: meanings on one line -> first letters ignite
   -> rest falls away -> letters gather into SOODA -> meanings return. */
function initAcronymHero() {
  const stage = document.getElementById('acStage');
  if (!stage) return;
  if (window.__acRaf) { cancelAnimationFrame(window.__acRaf); window.__acRaf = 0; }
  const canvas = document.getElementById('acFx');
  const ctx = canvas.getContext('2d');
  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const WORDS = ['Seek', 'Offers', 'Order', 'Deals', 'Aasaan'];
  const AMBER = '#f2a007';
  stage.querySelectorAll('.ac-el').forEach((e) => e.remove());
  const mk = (cls, text) => {
    const s = document.createElement('span');
    s.className = 'ac-el ' + cls;
    s.textContent = text;
    s.setAttribute('aria-hidden', 'true');
    stage.appendChild(s);
    return s;
  };
  const flEls = WORDS.map((w) => mk('ac-fl', w[0]));
  const restEls = WORDS.map((w) => mk('ac-w', w.slice(1)));
  const sepEls = [0, 1, 2, 3].map(() => mk('ac-sep', '•'));
  const meanEl = mk('ac-mean', 'Seek  •  Offers  •  Order  •  Deals  •  Aasaan');
  const meas = document.createElement('canvas').getContext('2d');
  const rnd = [];
  for (let i = 0; i < 22; i++) rnd.push({ x: Math.random(), y: Math.random(), r: 2 + Math.random() * 4, sp: 30 + Math.random() * 60, a: 25 + Math.random() * 45, ph: Math.random() * 6.28 });
  let L = null;
  // Fit text to the stage: shrink until the laid-out line fits (all screens).
  const measureWords = (px) => {
    meas.font = '800 ' + px + 'px sans-serif';
    const widths = WORDS.map((w) => meas.measureText(w).width);
    const firstW = WORDS.map((w) => meas.measureText(w[0]).width);
    const sepW = meas.measureText('•').width + px * 1.4;
    return { widths, firstW, sepW, total: widths.reduce((a, b) => a + b, 0) + sepW * 4 };
  };
  const layout = () => {
    const vw = Math.max(50, stage.clientWidth), sh = Math.max(50, stage.clientHeight);
    const avail = vw - 16;
    let fW = 34, wm = measureWords(fW);
    while (wm.total > avail && fW > 10) { fW -= 1; wm = measureWords(fW); }
    meas.font = '800 100px sans-serif';
    const soodaW100 = meas.measureText('SOODA').width;
    // include the 0.2*tracking per gap used in the line layout
    let fB = Math.min(76, avail / (soodaW100 / 100 + 0.8));
    fB = Math.max(fB, fW * 1.8);
    meas.font = '700 100px sans-serif';
    const meanW100 = meas.measureText('Seek • Offers • Order • Deals • Aasaan').width;
    const fM = Math.max(10, Math.min(20, (avail / meanW100) * 100));
    const { widths, firstW, sepW } = wm;
    const total = wm.total;
    const wordX = [], sepX = [];
    let acc = vw / 2 - total / 2;
    WORDS.forEach((w, i) => {
      wordX.push(acc + widths[i] / 2); acc += widths[i];
      if (i < 4) { sepX.push(acc + sepW / 2); acc += sepW; }
    });
    meas.font = '800 ' + fB + 'px sans-serif';
    const lw = 'SOODA'.split('').map((c) => meas.measureText(c).width);
    const track = fB * 0.2;
    const lt = lw.reduce((a, b) => a + b, 0) + track * 4;
    const lineX = [];
    let a2 = vw / 2 - lt / 2;
    lw.forEach((w) => { lineX.push(a2 + w / 2); a2 += w + track; });
    L = { vw, sh, fW, fB, wordX, sepX, lineX, widths, firstW,
          wordY: sh * 0.44, lineY: sh * 0.47, meanY: sh * 0.70, sWord: fW / fB };
    flEls.forEach((e) => e.style.fontSize = fB + 'px');
    restEls.forEach((e) => e.style.fontSize = fW + 'px');
    sepEls.forEach((e) => e.style.fontSize = fW + 'px');
    meanEl.style.fontSize = fM + 'px';
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = vw * dpr; canvas.height = sh * dpr;
  };
  layout();
  const P1 = 2.0, P2 = 3.2, P3 = 4.6, MEAN = 5.9;
  const clamp01 = (v) => Math.max(0, Math.min(1, v));
  const smooth = (u) => u * u * (3 - 2 * u);
  const setEl = (el, cx, cy, s, alpha) => {
    el.style.transform = 'translate(' + cx.toFixed(1) + 'px,' + cy.toFixed(1) + 'px) translate(-50%,-50%) scale(' + s.toFixed(3) + ')';
    el.style.opacity = alpha.toFixed(2);
  };
  const paintFx = (t) => {
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, L.vw, L.sh);
    rnd.forEach((p) => {
      const y = (((p.y * L.sh - t * p.sp) % (L.sh + 80)) + L.sh + 80) % (L.sh + 80) - 40;
      const x = p.x * L.vw + 24 * Math.sin(t * 0.7 + p.ph);
      ctx.fillStyle = 'rgba(242,160,7,' + (p.a / 255).toFixed(2) + ')';
      ctx.beginPath(); ctx.arc(x, y, p.r, 0, 6.283); ctx.fill();
    });
    const cyc = (t % 3) / 3;
    if (cyc < 0.4 && !reduced) {
      const u = 1 - Math.pow(1 - cyc / 0.4, 3);
      const sx = -320 + (L.vw + 640) * u;
      ctx.fillStyle = 'rgba(255,255,255,0.06)';
      ctx.beginPath();
      ctx.moveTo(sx, 0); ctx.lineTo(sx + 150, 0); ctx.lineTo(sx - 170, L.sh); ctx.lineTo(sx - 320, L.sh);
      ctx.closePath(); ctx.fill();
    }
  };
  const paint = (t) => {
    paintFx(t);
    WORDS.forEach((w, i) => {
      const a1 = clamp01((t - i * 0.12) / 0.5);
      const hi = clamp01((t - P1 - i * 0.08) / 0.4);
      const ro = clamp01((t - P2) / 0.7);
      const fle = smooth(clamp01((t - P3 - i * 0.06) / 0.8));
      const rise = (1 - a1) * 24;
      const yy = L.wordY + rise;
      if (i < 4) setEl(sepEls[i], L.sepX[i], yy, 1, a1 * (1 - ro));
      const restA = a1 * (1 - 0.65 * hi) * (1 - ro);
      const rcx = L.wordX[i] - L.widths[i] / 2 + L.firstW[i] + (L.widths[i] - L.firstW[i]) / 2;
      setEl(restEls[i], rcx, yy - 46 * ro, 1, restA);
      const s = L.sWord * (1 + 0.3 * hi) * (1 - fle) + fle;
      const lx0 = L.wordX[i] - L.widths[i] / 2 + L.firstW[i] / 2;
      const bob = (hi >= 1 && fle < 1 && !reduced) ? 8 * Math.sin(2 * Math.PI * 0.9 * t + i * 1.1) : 0;
      const holdBob = (fle >= 1 && !reduced) ? 6 * Math.sin(2 * Math.PI * 0.9 * t + i * 1.1) : 0;
      setEl(flEls[i], lx0 * (1 - fle) + L.lineX[i] * fle,
        (yy + bob) * (1 - fle) + (L.lineY + holdBob) * fle, s, a1);
      flEls[i].classList.toggle('hi', hi > 0.4);
    });
    const mu = clamp01((t - MEAN) / 0.6);
    setEl(meanEl, L.vw / 2, L.meanY + 30 * (1 - mu), 1, mu);
  };
  const onResize = () => {
    if (!stage.isConnected) { window.removeEventListener('resize', onResize); return; }
    layout(); paint(tNow());
  };
  window.addEventListener('resize', onResize);
  const t0 = performance.now();
  const tNow = () => (performance.now() - t0) / 1000;
  if (reduced) { paint(10); return; }
  const loop = () => { paint(tNow()); window.__acRaf = requestAnimationFrame(loop); };
  window.__acRaf = requestAnimationFrame(loop);
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
    <div class="body"><div class="price">${fmtPrice(a.price)}${a.negotiable ? '<span class="neg">Negotiable</span>' : ''}${a.bidding ? '<span class="bid-badge">Bidding</span>' : ''}</div>
    <div class="title">${esc(a.title)}</div>
    <div class="meta">${esc(a.location)} · ${timeAgo(a.created_at)}</div></div></a></div>`;
}

/* ---------- home ---------- */
routes[''] = {
  html() {
    const cats = DB.categories.map((c) =>
      `<a class="cat-face" href="#/category?slug=${c.slug}" aria-label="${esc(c.name)}">${icon(c.icon)}<span>${esc(c.name)}</span></a>`).join('');
    const bidAds = allAds().filter((a) => a.bidding).slice(0, 8);
    return `<section class="hero hero-anim"><div class="wrap">
      <div class="ac-stage" id="acStage" role="img" aria-label="SOODA — Seek Offers, Order Deals Aasaan"><canvas id="acFx"></canvas></div>
      <div class="hero-fade">
      <a class="btn amber" href="#/post">+ Post a Free Ad</a>
      </div></div></section>
    <main class="wrap"><section class="section"><h2>Browse categories</h2>
      <div class="cat-carousel" id="cat-carousel"><div class="cat-ring" id="cat-ring">${cats}</div></div></section>
    ${bidAds.length ? `<section class="section"><h2>Open for bidding</h2><div class="ads-grid">${bidAds.map(adCard).join('')}</div></section>` : ''}
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
    initAcronymHero();
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
        f.q ? `Results for "${f.q}" (${list.length})` : cat ? `${esc(cat.name)} (${list.length})` : `Fresh recommendations (${list.length})`;
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

/* ---------- category page ---------- */
routes['category'] = {
  html(params) {
    const cat = DB.categories.find((c) => c.slug === params.get('slug'));
    if (!cat) return `<main class="wrap"><div class="empty" style="margin:30px 0"><h3>Category not found</h3><a class="btn" href="#/">Back to home</a></div></main>`;
    const others = DB.categories.filter((c) => c.slug !== cat.slug).map((c) =>
      `<a href="#/category?slug=${c.slug}">${icon(c.icon)}${esc(c.name)}</a>`).join('');
    return `<main class="wrap">
      <nav class="crumbs"><a href="#/">Home</a> &rsaquo; ${esc(cat.name)}</nav>
      <section class="cat-hero"><div class="cat-hero-icon">${icon(cat.icon)}</div>
        <div><h1>${esc(cat.name)}</h1><p id="cat-count"></p></div>
        <a class="btn amber" href="#/post?cat=${cat.slug}">+ Post a Free Ad</a></section>
      <section class="section"><div class="browse">
        <aside class="filters"><h3>Search ${esc(cat.name)}</h3>
          <label>Keywords</label><input id="cf-q" placeholder="e.g. iPhone, Honda...">
          <label>Location</label><select id="cf-location"><option value="">All Pakistan</option>
          ${DB.locations.map((l) => `<option>${esc(l)}</option>`).join('')}</select>
          <label>Condition</label><select id="cf-condition">
          <option value="any">Any</option><option value="new">New</option><option value="used">Used</option></select>
          <label>Price range (Rs)</label><div class="price-row">
          <input id="cf-min" type="number" placeholder="Min"><input id="cf-max" type="number" placeholder="Max"></div>
          <label>Sort</label><select id="cf-sort">
          <option value="newest">Newest first</option>
          <option value="price_asc">Price: low to high</option>
          <option value="price_desc">Price: high to low</option></select>
          <button class="btn block" id="cf-apply" style="margin-top:16px">Apply</button>
          <button class="btn ghost block" id="cf-clear" style="margin-top:8px">Clear</button>
        </aside>
        <div class="results"><div class="ads-grid" id="cat-grid"></div></div>
      </div></section>
      <section class="section"><h2>Other categories</h2><div class="cat-chips">${others}</div></section>
    </main>`;
  },
  bind(params) {
    const cat = DB.categories.find((c) => c.slug === params.get('slug'));
    if (!cat) return;
    const cf = { q: '', location: '', condition: 'any', min: '', max: '', sort: 'newest' };
    const render = () => {
      let list = allAds().filter((a) => (a.status || 'active') === 'active' && a.category.slug === cat.slug);
      const total = list.length;
      if (cf.q) { const q = cf.q.toLowerCase(); list = list.filter((a) => (a.title + ' ' + a.description).toLowerCase().includes(q)); }
      if (cf.location) list = list.filter((a) => a.location === cf.location);
      if (cf.condition !== 'any') list = list.filter((a) => a.condition === cf.condition);
      if (cf.min !== '') list = list.filter((a) => a.price >= Number(cf.min));
      if (cf.max !== '') list = list.filter((a) => a.price <= Number(cf.max));
      list.sort((a, b) => cf.sort === 'price_asc' ? a.price - b.price : cf.sort === 'price_desc' ? b.price - a.price : 0);
      document.getElementById('cat-grid').innerHTML = list.length ? list.map(adCard).join('')
        : `<div class="empty" style="grid-column:1/-1"><h3>No ads in ${esc(cat.name)} yet</h3><p>Be the first. Post your ad for free.</p><a class="btn amber" href="#/post?cat=${cat.slug}">+ Post a Free Ad</a></div>`;
      document.getElementById('cat-count').textContent =
        `${total} ad${total === 1 ? '' : 's'} · Buy and sell ${cat.name.toLowerCase()} across Pakistan`;
    };
    document.getElementById('cf-apply').addEventListener('click', () => {
      cf.q = document.getElementById('cf-q').value.trim();
      cf.location = document.getElementById('cf-location').value;
      cf.condition = document.getElementById('cf-condition').value;
      cf.min = document.getElementById('cf-min').value;
      cf.max = document.getElementById('cf-max').value;
      cf.sort = document.getElementById('cf-sort').value;
      render();
    });
    document.getElementById('cf-clear').addEventListener('click', () => { navigate(); });
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
    const bidPanel = (() => {
      if (!ad.bidding) return '';
      const cb = currentBid(ad), n = bidList(ad).length;
      let action;
      if (mine) action = `<div class="bid-note">${n ? `You have ${n} bid${n > 1 ? 's' : ''} on this ad.` : 'No bids yet. Share your ad to attract bids.'}</div>`;
      else if (u) action = `<form id="bid-form"><div class="field-row"><input id="bid-amount" type="number" min="${cb + 1}" placeholder="Your bid (Rs)" required><button class="btn amber" type="submit">Bid</button></div><div class="bid-note">Must be higher than ${fmtPrice(cb)}</div><div class="form-err" id="bid-err"></div></form>`;
      else action = `<a class="btn amber block" href="#/login?next=${encodeURIComponent(location.hash)}">Login to place a bid</a>`;
      return `<div class="bid-card"><h3>Bidding</h3>
        <div class="bid-now"><span>${n ? 'Current bid' : 'Starting bid'}</span><b>${fmtPrice(cb)}</b></div>
        <div class="bid-count">${n} bid${n === 1 ? '' : 's'} so far</div>
        ${bidHistoryHtml(ad)}${action}</div>`;
    })();
    return `<main class="wrap"><div class="ad-detail"><div>
      <div class="gallery"><div class="main">${imgs[0] ? `<img id="main-img" src="${imgs[0]}" alt="">` : ''}</div>
      ${thumbs ? `<div class="thumbs" id="thumbs">${thumbs}</div>` : ''}</div>
      <div class="detail-box"><h3>Details</h3>
      <div class="spec"><span>Category</span><b>${esc(ad.category.name)}</b></div>
      <div class="spec"><span>Condition</span><b>${ad.condition === 'new' ? 'New' : 'Used'}</b></div>
      <div class="spec"><span>Location</span><b>${esc(ad.location)}</b></div>
      <div class="spec"><span>Posted</span><b>${timeAgo(ad.created_at)}</b></div>
      ${ad.updated_at ? `<div class="spec"><span>Last updated</span><b>${timeAgo(ad.updated_at)}</b></div>` : ''}
      <div class="spec"><span>Views</span><b>${adViews(ad)}</b></div>
      <div class="spec"><span>Ad ID</span><b>${ad.id}</b></div></div>
      <div class="detail-box"><h3>Description</h3><p style="white-space:pre-wrap">${esc(ad.description)}</p></div>
    </div><div class="sidebar"><div class="price-card">
      <div class="price">${fmtPrice(ad.price)}</div>
      <div class="ad-title">${esc(ad.title)}</div>
      <div class="loc">${esc(ad.location)} · ${timeAgo(ad.created_at)}</div>
      <div class="action-row"><button class="btn ghost block${fav ? ' active' : ''}" id="fav-toggle" data-fav="${ad.id}" data-fav-page="0">${fav ? '♥ Saved' : '♡ Save'}</button></div>
      ${mine ? `<div class="action-row"><a class="btn ghost block" href="#/post?edit=${ad.id}">Edit</a></div>` : ''}
    </div>${bidPanel}<div class="seller-card"><div class="avatar">${esc(seller.name[0].toUpperCase())}</div>
      <b>${esc(seller.name)}</b><div style="color:#66756f;font-size:13px;margin-bottom:12px">Seller</div>
      ${u ? `<button class="btn amber block" id="show-phone">Show phone number</button>
        <div id="phone-num" style="display:none;margin-top:10px"><span style="font-size:22px;font-weight:800">${esc(seller.phone)}</span><button class="copy-btn" id="copy-phone">Copy</button></div>`
        : `<a class="btn amber block" href="#/login?next=${encodeURIComponent(location.hash)}">Login to see phone</a>`}
    </div></div></div>
    ${similar.length ? `<section class="section"><h2>Similar ads</h2><div class="ads-grid">${similar.map(adCard).join('')}</div></section>` : ''}
    </main>`;
  },
  bind(params) {
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
    const cp = document.getElementById('copy-phone');
    if (cp) cp.addEventListener('click', async () => {
      const num = document.querySelector('#phone-num span').textContent;
      try {
        if (!navigator.clipboard) throw new Error('no clipboard');
        await navigator.clipboard.writeText(num);
        toast('Phone number copied');
      } catch (e) { toast('Copy is not available in this browser'); }
    });
    const bidForm = document.getElementById('bid-form');
    if (bidForm) bidForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const u = currentUser();
      const err = document.getElementById('bid-err');
      if (!u) { location.hash = '#/login?next=' + encodeURIComponent(location.hash); return; }
      const myads = LS.read('myads', []);
      const target = myads.find((a) => String(a.id) === String(params.get('id')));
      if (!target || !target.bidding) { toast('Bidding is closed on this ad'); return; }
      if (target.sellerEmail === u.email) { toast("You can't bid on your own ad"); return; }
      const amt = Math.round(Number(document.getElementById('bid-amount').value) || 0);
      const cb = currentBid(target);
      if (amt <= cb) { err.textContent = 'Your bid must be higher than ' + fmtPrice(cb); return; }
      target.bidding.bids.push({ name: u.name, email: u.email, amount: amt, at: new Date().toISOString().slice(0, 19).replace('T', ' ') });
      LS.write('myads', myads);
      toast('Bid placed!');
      navigate();
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
    if (editId && existing && existing.sellerEmail !== u.email) {
      setTimeout(() => { location.hash = '#/my-ads'; }, 0);
      return '<main class="wrap"><div class="empty" style="margin:30px 0">You can only edit your own ads.</div></main>';
    }
    const preCat = params.get('cat');
    return `<main class="wrap"><div class="form-card wide">
    <h2>${existing ? 'Edit your ad' : 'Post your ad'}</h2>
    <p class="sub">${existing ? 'Update the details below.' : "It's free. Your ad goes live instantly."}</p>
    <div class="form-err" id="form-err"></div>
    <form id="ad-form">
      <div class="field-row"><div class="field"><label>Category *</label><select id="f-cat">
      ${DB.categories.map((c) => `<option value="${c.slug}"${(existing ? existing.category.slug === c.slug : preCat === c.slug) ? ' selected' : ''}>${esc(c.name)}</option>`).join('')}</select></div>
      <div class="field"><label>Location *</label><select id="f-loc">
      ${DB.locations.map((l) => `<option ${existing && existing.location === l ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></div></div>
      <div class="field"><label>Ad title *</label><input id="f-title" maxlength="80" required value="${esc(existing ? existing.title : '')}" placeholder="e.g. iPhone 13 Pro 256GB, PTA approved"></div>
      <div class="field"><label>Description *</label><textarea id="f-desc" required placeholder="Describe your item...">${esc(existing ? existing.description : '')}</textarea></div>
      <div class="field-row"><div class="field"><label id="f-pricelabel">Price (Rs) *</label><input id="f-price" type="number" min="0" required value="${existing ? existing.price : ''}" placeholder="e.g. 85000"></div>
      <div class="field"><label>Condition</label><select id="f-cond">
      <option value="used"${existing && existing.condition === 'used' ? ' selected' : ''}>Used</option>
      <option value="new"${existing && existing.condition === 'new' ? ' selected' : ''}>New</option></select></div></div>
      <div class="field"><label class="check-row"><input type="checkbox" id="f-neg" style="width:auto"${existing && existing.negotiable ? ' checked' : ''}> Price is negotiable</label></div>
      <div class="field"><label class="check-row"><input type="checkbox" id="f-bid" style="width:auto"${existing && existing.bidding ? ' checked' : ''}> Accept bids on this ad</label><div class="hint">Buyers bid above your price. The highest bid shows on your ad.</div></div>
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
    const bidBox = document.getElementById('f-bid');
    const priceLabel = document.getElementById('f-pricelabel');
    const syncBidLabel = () => { priceLabel.textContent = bidBox.checked ? 'Starting bid (Rs) *' : 'Price (Rs) *'; };
    bidBox.addEventListener('change', syncBidLabel);
    syncBidLabel();
    if (fi) fi.addEventListener('change', () => {
      prev.innerHTML = '';
      const valid = [...fi.files].slice(0, 6).filter((f) => {
        if (!f.type.startsWith('image/')) { toast('Only image files are allowed'); return false; }
        if (f.size > 5 * 1024 * 1024) { toast('Each photo must be under 5MB'); return false; }
        return true;
      });
      valid.forEach((f) => {
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
        bidding: document.getElementById('f-bid').checked
          ? { bids: (existing && existing.bidding && existing.bidding.bids) || [] }
          : null,
        location: document.getElementById('f-loc').value,
        category: { id: cat.id, name: cat.name, slug: cat.slug },
      };
      if (!base.title || !base.description || !base.price) { toast('Please fill all required fields'); return; }
      const done = (images) => {
        const myads = LS.read('myads', []);
        if (editId) {
          const ad = myads.find((a) => String(a.id) === String(editId));
          Object.assign(ad, base);
          ad.updated_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
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
      const files = [...fi.files].slice(0, 6).filter((f) => f.type.startsWith('image/') && f.size <= 5 * 1024 * 1024);
      if (!files.length) { toast('Please choose valid image files (under 5MB each)'); return; }
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
    <p class="sub">Log in to post ads and save favorites.</p>
    <div class="form-err" id="form-err"></div>
    <form id="auth-form"><div class="field"><label>Email</label><input id="a-email" type="email" required></div>
    <div class="field"><label>Password</label><div class="pass-wrap"><input id="a-pass" type="password" required><button type="button" class="pass-toggle" data-pass="a-pass">Show</button></div></div>
    <button class="btn block" type="submit">Login</button></form>
    <p style="margin-top:12px;font-size:14px;text-align:center"><a href="#/forgot" style="color:#0e5c46;font-weight:700">Forgot password?</a></p>
    <p style="margin-top:8px;font-size:14px;text-align:center">New here? <a href="#/signup" style="color:#0e5c46;font-weight:700">Create an account</a></p></div></main>`;
  },
  bind(params) {
    document.getElementById('auth-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('a-email').value.trim().toLowerCase();
      const pass = document.getElementById('a-pass').value;
      const er = document.getElementById('form-err');
      const showErr = (m) => { er.textContent = m; er.style.display = 'block'; };
      const rl = LS.read('login-rl', {});
      const rec = rl['rl-' + email];
      if (rec && Date.now() < rec.until) { showErr('Too many attempts. Please wait a minute and try again.'); return; }
      const users = LS.read('users', []);
      const u = users.find((x) => x.email === email);
      const fail = () => {
        const r = rl['rl-' + email] || { n: 0 };
        r.n += 1;
        if (r.n >= 5) { r.until = Date.now() + 60000; r.n = 0; }
        rl['rl-' + email] = r;
        LS.write('login-rl', rl);
        showErr('Wrong email or password.');
      };
      if (!u) { fail(); return; }
      let ok = false;
      if (u.passHash) ok = (await hashPass(pass)) === u.passHash;
      else if (u.pass) {
        ok = u.pass === pass;
        if (ok) { u.passHash = await hashPass(pass); delete u.pass; LS.write('users', users); }
      }
      if (!ok) { fail(); return; }
      delete rl['rl-' + email];
      LS.write('login-rl', rl);
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
routes['forgot'] = {
  html() {
    return `<main class="wrap"><div class="form-card"><h2>Reset password</h2>
    <p class="sub">Enter your account email, the phone number you signed up with, and a new password.</p>
    <div class="form-err" id="form-err"></div>
    <form id="auth-form"><div class="field"><label>Email</label><input id="a-email" type="email" required></div>
    <div class="field"><label>Phone / WhatsApp</label><input id="a-phone" required></div>
    <div class="field"><label>New password</label><div class="pass-wrap"><input id="a-pass" type="password" required minlength="6"><button type="button" class="pass-toggle" data-pass="a-pass">Show</button></div></div>
    <button class="btn block" type="submit">Set new password</button></form>
    <p style="margin-top:16px;font-size:14px;text-align:center"><a href="#/login" style="color:#0e5c46;font-weight:700">Back to login</a></p></div></main>`;
  },
  bind() {
    document.getElementById('auth-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('a-email').value.trim().toLowerCase();
      const phone = document.getElementById('a-phone').value.trim();
      const er = document.getElementById('form-err');
      const users = LS.read('users', []);
      const u = users.find((x) => x.email === email && x.phone === phone);
      if (!u) { er.textContent = 'No account matches that email and phone number.'; er.style.display = 'block'; return; }
      u.passHash = await hashPass(document.getElementById('a-pass').value);
      delete u.pass;
      LS.write('users', users);
      toast('Password updated. Please log in.');
      setTimeout(() => { location.hash = '#/login'; }, 700);
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
        er.textContent = 'Wrong code. Check your authenticator app and try again.';
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
    <div class="field"><label>Password</label><div class="pass-wrap"><input id="a-pass" type="password" required minlength="6"><button type="button" class="pass-toggle" data-pass="a-pass">Show</button></div></div>
    <button class="btn block" type="submit">Continue</button></form>
    <p style="margin-top:16px;font-size:14px;text-align:center">Already have an account? <a href="#/login" style="color:#0e5c46;font-weight:700">Log in</a></p></div></main>`;
  },
  bind() {
    document.getElementById('auth-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('a-email').value.trim().toLowerCase();
      const users = LS.read('users', []);
      if (users.find((x) => x.email === email)) { const er = document.getElementById('form-err'); er.textContent = 'Email already registered.'; er.style.display = 'block'; return; }
      pendingUser = {
        name: document.getElementById('a-name').value.trim(),
        email,
        phone: document.getElementById('a-phone').value.trim(),
        passHash: await hashPass(document.getElementById('a-pass').value),
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
      const nu = { name: pendingUser.name, email: pendingUser.email, phone: pendingUser.phone, passHash: pendingUser.passHash };
      if (withTfa) nu.tfa = pendingUser.tfaSecret;
      users.push(nu);
      LS.write('users', users);
      LS.write('session', pendingUser.email);
      pendingUser = null;
      toast(withTfa ? 'Account created. 2FA is on' : 'Account created. Welcome!');
      setTimeout(() => { location.hash = '#/'; }, 700);
    };
    document.getElementById('tfa-form').addEventListener('submit', (e) => {
      e.preventDefault();
      if (verifyTotp(pendingUser.tfaSecret, document.getElementById('tfa-code').value)) finish(true);
      else {
        const er = document.getElementById('form-err');
        er.textContent = 'Wrong code. Check your authenticator app and try again.';
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
        const id = String(del.dataset.del);
        confirmModal('Delete this ad?', 'This removes your ad permanently. You cannot undo this.', 'Delete').then((ok) => {
          if (!ok) return;
          if (/^u/.test(id)) LS.write('myads', LS.read('myads', []).filter((a) => String(a.id) !== id));
          else LS.write('deleted', LS.read('deleted', []).concat([id]));
          toast('Ad deleted'); navigate();
        });
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

/* ---------- static info pages ---------- */
const infoPage = (title, body) => `<main class="wrap"><div class="form-card wide"><h2>${title}</h2>${body}</div></main>`;
routes['privacy'] = {
  html() {
    return infoPage('Privacy policy', `<p class="sub">Last updated: October 2026</p>
    <h3>What we store</h3>
    <p>Your account details (name, email, phone) and the ads you post are saved in your own browser's local storage. Sooda does not run its own servers for this version, so your data never leaves your device except when you choose to share it (for example, showing your phone number to a logged-in buyer).</p>
    <h3>What we do not do</h3>
    <p>We do not sell your data, run advertising trackers, or share your information with third parties. There are no analytics cookies watching your browsing.</p>
    <h3>Your control</h3>
    <p>You can delete your ads at any time from My Ads. Clearing your browser's site data removes everything Sooda stored, including your account.</p>
    <h3>Contact</h3>
    <p>Questions about privacy: reach us through the <a href="#/faq">FAQ</a> page.</p>`);
  },
};
routes['terms'] = {
  html() {
    return infoPage('Terms of use', `<p class="sub">Last updated: October 2026</p>
    <h3>The basics</h3>
    <p>Sooda is a free marketplace for Pakistan. Posting ads, browsing, and bidding cost nothing.</p>
    <h3>Your responsibilities</h3>
    <p>Post only items you own or are allowed to sell. Describe them honestly, use your own photos, and set fair prices. Fraud, stolen goods, weapons, and prohibited items are not allowed and will be removed.</p>
    <h3>Bidding</h3>
    <p>Bids are expressions of interest, not binding contracts. The seller decides whom to deal with. Sooda does not handle payments or delivery.</p>
    <h3>Safety</h3>
    <p>Meet buyers in public places, verify items before paying, and never share bank details or OTP codes with strangers.</p>
    <h3>Availability</h3>
    <p>Sooda is provided as is. We may update these terms as the platform grows.</p>`);
  },
};
routes['faq'] = {
  html() {
    const qa = [
      ['Is posting an ad really free?', 'Yes. Posting, browsing, and bidding are all free. There are no hidden charges.'],
      ['How does bidding work?', 'When posting, tick "Accept bids on this ad". Buyers then place bids above your starting price. The highest bid is shown on your ad, and you contact the bidder directly to close the deal.'],
      ['Where are my ads and account stored?', 'In your own browser (local storage). That means your ads only appear on the device where you posted them, and clearing browser data removes them.'],
      ['How do I contact a seller?', 'Open the ad and tap "Show phone number" (you need to be logged in). Then call or message the seller directly.'],
      ['Is my phone number public?', 'No. It is only shown to logged-in users on your own ad pages.'],
      ['How do I edit or delete my ad?', 'Go to My Ads, then use Edit or Delete on the ad. Deleting asks for confirmation first.'],
      ['Which cities does Sooda cover?', 'All of Pakistan. Filter by your city from the location menu.'],
      ['I forgot my password. What now?', 'Use the "Forgot password" option on the login page to reset it with your registered phone number.'],
    ];
    return `<main class="wrap"><section class="section"><h2>Frequently asked questions</h2>
      <div class="faq">${qa.map(([q, a], i) => `<div class="faq-item"><button class="faq-q" data-faq="${i}">${esc(q)}<span>+</span></button><div class="faq-a" id="faq-a-${i}">${esc(a)}</div></div>`).join('')}</div>
    </section></main>`;
  },
  bind() {
    document.getElementById('app').addEventListener('click', function h(e) {
      const q = e.target.closest('[data-faq]');
      if (!q) return;
      const a = document.getElementById('faq-a-' + q.dataset.faq);
      const open = a.classList.toggle('open');
      q.querySelector('span').textContent = open ? '−' : '+';
    });
  },
};

/* ---------- init ---------- */
bindFavDelegation();
initChrome();
if (!location.hash) location.hash = '#/';
navigate();
