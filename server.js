'use strict';
/**
 * Кофе & Точка — бэкенд.
 * Работает на чистом Node.js (без npm install и внешних пакетов) —
 * это осознанный выбор: чтобы сайт можно было поднять на любом сервере
 * командой `node server.js` без сборки и без риска, что npm install
 * что-то не докачает. Хранилище — JSON-файл (data/db.json). Для сети
 * из 3 кофеен с невысоким потоком заказов этого достаточно с запасом;
 * при росте — миграция на Postgres/MySQL делается без изменения API.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'data', 'db.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SALT = 'coffee-i-tochka-static-salt-v1'; // прототип: см. README про продакшн-безопасность

// ---------- ХРАНИЛИЩЕ ----------
let db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));

// На старте досчитываем хэши паролей для пользователей, у которых задан
// открытый пароль (это только для первого запуска — дальше он не хранится).
let dbDirty = false;
db.users.forEach(function (u) {
  if (!u.passwordHash && u.password) {
    u.passwordHash = hashPassword(u.password);
    delete u.password;
    dbDirty = true;
  }
});
if (dbDirty) saveDb();

function hashPassword(pw) {
  return crypto.createHash('sha256').update(SALT + ':' + pw).digest('hex');
}

function saveDb() {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
}

// ---------- СЕССИИ (в памяти процесса) ----------
const sessions = new Map(); // token -> { username, role }

function createSession(user) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { username: user.username, role: user.role });
  return token;
}

function getSession(req) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return null;
  return sessions.get(token) || null;
}

// ---------- УТИЛИТЫ ----------
function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function readJsonBody(req) {
  return new Promise(function (resolve, reject) {
    let chunks = [];
    let size = 0;
    req.on('data', function (chunk) {
      size += chunk.length;
      if (size > 1e6) { // 1MB защита от неадекватных тел запроса
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', function () {
      if (chunks.length === 0) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (e) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function dateKey(ts) {
  const d = new Date(ts);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}
function monthKey(ts) {
  const d = new Date(ts);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
}

function publicItem(item) {
  return {
    id: item.id, category: item.category, name: item.name,
    price: item.price, desc: item.desc, icon: item.icon, soldOut: !!item.soldOut
  };
}

// ---------- СТАТИКА ----------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function serveStatic(req, res, pathname) {
  let filePath = pathname === '/' ? '/index.html' : pathname;
  filePath = path.normalize(filePath).replace(/^(\.\.[\/\\])+/, '');
  const full = path.join(PUBLIC_DIR, filePath);
  if (!full.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(full, function (err, data) {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    const ext = path.extname(full);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------- API HANDLERS ----------
const routes = [];
function route(method, pattern, handler) {
  routes.push({ method: method, regex: pattern, handler: handler });
}

route('GET', /^\/api\/menu$/, function (req, res) {
  sendJson(res, 200, {
    categories: db.categories,
    items: db.items.map(publicItem),
  });
});

route('GET', /^\/api\/locations$/, function (req, res) {
  sendJson(res, 200, { locations: db.locations });
});

route('POST', /^\/api\/orders$/, async function (req, res) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendJson(res, 400, { error: 'bad_json' }); }

  if (body.source === 'cashier') {
    const session = getSession(req);
    if (!session || (session.role !== 'cashier' && session.role !== 'admin')) return sendJson(res, 403, { error: 'forbidden' });
  }

  const loc = db.locations.find(function (l) { return l.id === body.locationId; });
  if (!loc) return sendJson(res, 400, { error: 'invalid_location' });
  if (!Array.isArray(body.items) || body.items.length === 0) return sendJson(res, 400, { error: 'empty_cart' });
  // Телефон обязателен только для заказов с сайта (клиента нужно предупредить,
  // если что-то пойдёт не так); у кассира это часто гость без телефона.
  if (body.source !== 'cashier') {
    if (!body.customerName || !String(body.customerName).trim()) return sendJson(res, 400, { error: 'name_required' });
    if (!body.phone || !String(body.phone).trim()) return sendJson(res, 400, { error: 'phone_required' });
  }

  const orderItems = [];
  let total = 0;
  for (const line of body.items) {
    const item = db.items.find(function (i) { return i.id === line.id; });
    if (!item) return sendJson(res, 400, { error: 'unknown_item', itemId: line.id });
    if (item.soldOut) return sendJson(res, 409, { error: 'sold_out', itemId: line.id, itemName: item.name });
    const qty = Math.max(1, Math.min(20, parseInt(line.qty, 10) || 1));
    orderItems.push({ id: item.id, name: item.name, price: item.price, qty: qty });
    total += item.price * qty;
  }

  const order = {
    id: 'o' + (db.nextOrderSeq++),
    createdAt: Date.now(),
    locationId: loc.id,
    locationName: loc.name,
    customerName: String(body.customerName).trim().slice(0, 120),
    phone: String(body.phone).trim().slice(0, 40),
    comment: body.comment ? String(body.comment).trim().slice(0, 300) : '',
    items: orderItems,
    total: total,
    source: body.source === 'cashier' ? 'cashier' : 'customer',
  };
  db.orders.push(order);
  saveDb();
  sendJson(res, 201, { ok: true, order: order });
});

route('POST', /^\/api\/login$/, async function (req, res) {
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendJson(res, 400, { error: 'bad_json' }); }
  const user = db.users.find(function (u) { return u.username === body.username; });
  if (!user || user.passwordHash !== hashPassword(body.password || '')) {
    return sendJson(res, 401, { error: 'invalid_credentials' });
  }
  const token = createSession(user);
  sendJson(res, 200, { token: token, role: user.role, username: user.username });
});

route('POST', /^\/api\/logout$/, function (req, res) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (token) sessions.delete(token);
  sendJson(res, 200, { ok: true });
});

route('GET', /^\/api\/me$/, function (req, res) {
  const session = getSession(req);
  if (!session) return sendJson(res, 401, { error: 'unauthorized' });
  sendJson(res, 200, { username: session.username, role: session.role });
});

// ---- Требуют авторизации (admin или cashier) ----
route('POST', /^\/api\/items\/([\w-]+)\/toggle-sold-out$/, function (req, res, match) {
  const session = getSession(req);
  if (!session || (session.role !== 'admin' && session.role !== 'cashier')) return sendJson(res, 403, { error: 'forbidden' });
  const item = db.items.find(function (i) { return i.id === match[1]; });
  if (!item) return sendJson(res, 404, { error: 'not_found' });
  item.soldOut = !item.soldOut;
  saveDb();
  sendJson(res, 200, { ok: true, item: publicItem(item) });
});

// ---- Только admin: управление меню ----
route('POST', /^\/api\/items$/, async function (req, res) {
  const session = getSession(req);
  if (!session || session.role !== 'admin') return sendJson(res, 403, { error: 'forbidden' });
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendJson(res, 400, { error: 'bad_json' }); }

  const name = (body.name || '').trim();
  const category = (body.category || '').trim();
  const price = parseInt(body.price, 10);
  if (!name) return sendJson(res, 400, { error: 'name_required' });
  if (!db.categories.some(function (c) { return c.id === category; })) return sendJson(res, 400, { error: 'invalid_category' });
  if (!Number.isFinite(price) || price <= 0) return sendJson(res, 400, { error: 'invalid_price' });

  const item = {
    id: 'i' + (db.nextItemSeq++),
    category: category,
    name: name,
    price: price,
    desc: (body.desc || '').trim().slice(0, 200),
    icon: body.icon && window_ICONS_has(body.icon) ? body.icon : 'star',
    soldOut: false,
  };
  db.items.push(item);
  saveDb();
  sendJson(res, 201, { ok: true, item: publicItem(item) });
});

const KNOWN_ICONS = ['coffee-cup','coffee-cup-milk','coffee-mug','coffee-choc','cake','croissant','cookie','muffin','sandwich','cheese','avocado','drumstick','star','leaf'];
function window_ICONS_has(key) { return KNOWN_ICONS.indexOf(key) !== -1; }

route('PUT', /^\/api\/items\/([\w-]+)$/, async function (req, res, match) {
  const session = getSession(req);
  if (!session || session.role !== 'admin') return sendJson(res, 403, { error: 'forbidden' });
  const item = db.items.find(function (i) { return i.id === match[1]; });
  if (!item) return sendJson(res, 404, { error: 'not_found' });
  let body;
  try { body = await readJsonBody(req); } catch (e) { return sendJson(res, 400, { error: 'bad_json' }); }

  if (typeof body.name === 'string' && body.name.trim()) item.name = body.name.trim().slice(0, 80);
  if (typeof body.desc === 'string') item.desc = body.desc.trim().slice(0, 200);
  if (body.price !== undefined) {
    const price = parseInt(body.price, 10);
    if (!Number.isFinite(price) || price <= 0) return sendJson(res, 400, { error: 'invalid_price' });
    item.price = price;
  }
  if (typeof body.category === 'string') {
    if (!db.categories.some(function (c) { return c.id === body.category; })) return sendJson(res, 400, { error: 'invalid_category' });
    item.category = body.category;
  }
  if (typeof body.icon === 'string' && window_ICONS_has(body.icon)) item.icon = body.icon;
  if (typeof body.soldOut === 'boolean') item.soldOut = body.soldOut;

  saveDb();
  sendJson(res, 200, { ok: true, item: publicItem(item) });
});

route('DELETE', /^\/api\/items\/([\w-]+)$/, function (req, res, match) {
  const session = getSession(req);
  if (!session || session.role !== 'admin') return sendJson(res, 403, { error: 'forbidden' });
  const idx = db.items.findIndex(function (i) { return i.id === match[1]; });
  if (idx === -1) return sendJson(res, 404, { error: 'not_found' });
  db.items.splice(idx, 1);
  saveDb();
  sendJson(res, 200, { ok: true });
});

route('GET', /^\/api\/orders$/, function (req, res) {
  const session = getSession(req);
  if (!session || session.role !== 'admin') return sendJson(res, 403, { error: 'forbidden' });
  const list = db.orders.slice(-200).reverse();
  sendJson(res, 200, { orders: list });
});

route('GET', /^\/api\/stats\/summary$/, function (req, res) {
  const session = getSession(req);
  if (!session || session.role !== 'admin') return sendJson(res, 403, { error: 'forbidden' });

  const now = Date.now();
  const todayKey = dateKey(now);
  const thisMonthKey = monthKey(now);

  let todayRevenue = 0, todayOrders = 0, monthRevenue = 0, monthOrders = 0;
  const byDay = {};   // last 14 days
  const byMonth = {}; // last 12 months

  db.orders.forEach(function (o) {
    const dKey = dateKey(o.createdAt);
    const mKey = monthKey(o.createdAt);
    if (dKey === todayKey) { todayRevenue += o.total; todayOrders++; }
    if (mKey === thisMonthKey) { monthRevenue += o.total; monthOrders++; }
    byDay[dKey] = (byDay[dKey] || 0) + o.total;
    byMonth[mKey] = (byMonth[mKey] || 0) + o.total;
  });

  const dailySeries = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(now - i * 86400000);
    const key = dateKey(d.getTime());
    dailySeries.push({ label: String(d.getDate()).padStart(2, '0') + '.' + String(d.getMonth() + 1).padStart(2, '0'), value: byDay[key] || 0 });
  }
  const monthNames = ['янв','фев','мар','апр','май','июн','июл','авг','сен','окт','ноя','дек'];
  const monthlySeries = [];
  for (let i = 11; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(1);
    d.setMonth(d.getMonth() - i);
    const key = monthKey(d.getTime());
    monthlySeries.push({ label: monthNames[d.getMonth()], value: byMonth[key] || 0 });
  }

  sendJson(res, 200, {
    todayRevenue: todayRevenue, todayOrders: todayOrders,
    monthRevenue: monthRevenue, monthOrders: monthOrders,
    dailySeries: dailySeries, monthlySeries: monthlySeries,
  });
});

// ---------- HTTP-СЕРВЕР ----------
const server = http.createServer(async function (req, res) {
  const parsed = new URL(req.url, 'http://localhost');
  const pathname = parsed.pathname;

  if (pathname.startsWith('/api/')) {
    for (const r of routes) {
      if (r.method !== req.method) continue;
      const match = pathname.match(r.regex);
      if (match) {
        try {
          await r.handler(req, res, match);
        } catch (e) {
          sendJson(res, 500, { error: 'internal_error', message: e.message });
        }
        return;
      }
    }
    return sendJson(res, 404, { error: 'not_found' });
  }

  serveStatic(req, res, pathname);
});

server.listen(PORT, function () {
  console.log('Кофе & Точка сервер запущен: http://localhost:' + PORT);
  console.log('Клиентский сайт: /  |  Касса: /cashier.html  |  Админка: /admin.html');
});
