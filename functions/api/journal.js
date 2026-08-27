// 道牍 · Cloudflare Pages Function (/api/journal)
// 绑定：env.DAODU_DB（D1 数据库）
const TOKEN_TTL = 60 * 60 * 24 * 30; // 30 天
const MAX_ADMINS = 5;
const PBKDF2_ITER = 100000;
const enc = new TextEncoder();

function b64(u8) { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); }
function b64ToBytes(s) { const bin = atob(s); const u8 = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i); return u8; }

async function hmacSign(secret, payload) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  return b64(new Uint8Array(sig));
}
async function signToken(secret, username) {
  const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL;
  const payload = username + '.' + exp;
  const sig = await hmacSign(secret, payload);
  return payload + '.' + sig;
}
async function verifyToken(secret, token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const payload = parts[0] + '.' + parts[1];
    const sig = await hmacSign(secret, payload);
    if (sig !== parts[2]) return null;
    const exp = parseInt(parts[1], 10);
    if (!exp || exp < Math.floor(Date.now() / 1000)) return null;
    return parts[0];
  } catch (e) { return null; }
}
async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: PBKDF2_ITER, hash: 'SHA-256' }, key, 256);
  return b64(new Uint8Array(bits));
}
function randomSalt() { const u8 = new Uint8Array(16); crypto.getRandomValues(u8); return b64(u8); }

/* ---------- D1 kv ---------- */
async function dbInit(env) {
  await env.DAODU_DB.prepare('CREATE TABLE IF NOT EXISTS kv (key text PRIMARY KEY, value text NOT NULL)').run();
}
async function dbGet(env, key) {
  const row = await env.DAODU_DB.prepare('SELECT value FROM kv WHERE key = ?').bind(key).first();
  return row ? row.value : null;
}
async function dbSet(env, key, value) {
  await env.DAODU_DB.prepare('INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value').bind(key, value).run();
}
async function dbDel(env, key) {
  await env.DAODU_DB.prepare('DELETE FROM kv WHERE key = ?').bind(key).run();
}
async function dbKeys(env, prefix) {
  const rows = await env.DAODU_DB.prepare('SELECT key, value FROM kv WHERE key LIKE ?').bind(prefix + '%').all();
  return rows.results || [];
}

/* ---------- meta ---------- */
async function getMeta(env) {
  const raw = await dbGet(env, 'meta');
  if (raw) { try { return JSON.parse(raw); } catch (e) {} }
  return { owner: null, admins: [], users: {} };
}
async function saveMeta(env, meta) { await dbSet(env, 'meta', JSON.stringify(meta)); }
function roleOf(meta, username) {
  if (meta.owner === username) return 'owner';
  if ((meta.admins || []).indexOf(username) >= 0) return 'admin';
  return 'user';
}

/* ---------- actions ---------- */
async function register(env, body) {
  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  if (!username || username.length > 20) return err('用户名不能为空且不超过 20 个字符');
  if (password.length < 4) return err('密码至少 4 位');
  const meta = await getMeta(env);
  if (meta.users[username]) return err('该用户名已存在，请直接登录');
  const salt = randomSalt();
  meta.users[username] = { salt: salt, passHash: await hashPassword(password, salt) };
  if (!meta.owner) meta.owner = username;
  await saveMeta(env, meta);
  const secret = env.AUTH_SECRET || 'daodu-dev-secret';
  return ok({ token: await signToken(secret, username), username: username, role: roleOf(meta, username) });
}
async function login(env, body) {
  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  const meta = await getMeta(env);
  const u = meta.users[username];
  if (!u) return err('账号不存在，请先注册');
  if (await hashPassword(password, u.salt) !== u.passHash) return err('密码错误');
  const secret = env.AUTH_SECRET || 'daodu-dev-secret';
  return ok({ token: await signToken(secret, username), username: username, role: roleOf(meta, username) });
}
async function loadEntries(env, username) {
  const rows = await dbKeys(env, 'entry:' + username + ':');
  const entries = {};
  rows.forEach(function (r) { const day = r.key.split(':').pop(); try { entries[day] = JSON.parse(r.value); } catch (e) {} });
  const meta = await getMeta(env);
  return ok({ entries: entries, role: roleOf(meta, username), owner: meta.owner });
}
async function saveEntry(env, body, username) {
  const day = String(body.day || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return err('日期格式错误');
  const payload = String(body.payload || '');
  const mood = String(body.mood || '');
  const statsRaw = String(body.stats || '');
  let statsData = null;
  if (statsRaw) { try { statsData = JSON.parse(statsRaw); } catch (e) { statsData = null; } }
  const hasText = payload && payload.trim();
  if (hasText) await dbSet(env, 'entry:' + username + ':' + day, JSON.stringify({ payload: payload, mood: mood, updatedAt: Date.now() }));
  else await dbDel(env, 'entry:' + username + ':' + day);
  const statsKey = 'stats:' + day;
  let dayStats = {};
  const raw = await dbGet(env, statsKey);
  if (raw) { try { dayStats = JSON.parse(raw); } catch (e) {} }
  if (hasText && statsData) dayStats[username] = statsData;
  else delete dayStats[username];
  if (Object.keys(dayStats).length) await dbSet(env, statsKey, JSON.stringify(dayStats));
  else await dbDel(env, statsKey);
  return ok({ saved: true });
}
async function statsDay(env, day, username) {
  const meta = await getMeta(env);
  const role = roleOf(meta, username);
  if (role !== 'owner' && role !== 'admin') return err('没有权限查看全体统计');
  const raw = await dbGet(env, 'stats:' + day);
  return ok({ day: day, users: raw ? JSON.parse(raw) : {} });
}
async function listUsers(env, username) {
  const meta = await getMeta(env);
  if (roleOf(meta, username) !== 'owner') return err('没有权限');
  const out = {};
  Object.keys(meta.users).forEach(function (n) { out[n] = roleOf(meta, n); });
  return ok({ owner: meta.owner, admins: meta.admins || [], users: out });
}
async function setAdmin(env, body, username) {
  const meta = await getMeta(env);
  if (roleOf(meta, username) !== 'owner') return err('没有权限');
  const target = String(body.username || '').trim();
  if (!meta.users[target]) return err('账号不存在');
  if ((meta.admins || []).indexOf(target) >= 0) return ok({ done: true });
  if ((meta.admins || []).length >= MAX_ADMINS) return err('管理员名额已满（最多 ' + MAX_ADMINS + ' 名）');
  meta.admins = meta.admins || [];
  meta.admins.push(target);
  await saveMeta(env, meta);
  return ok({ done: true });
}
async function removeAdmin(env, body, username) {
  const meta = await getMeta(env);
  if (roleOf(meta, username) !== 'owner') return err('没有权限');
  const target = String(body.username || '').trim();
  meta.admins = (meta.admins || []).filter(function (n) { return n !== target; });
  await saveMeta(env, meta);
  return ok({ done: true });
}
async function transferOwner(env, body, username) {
  const meta = await getMeta(env);
  if (roleOf(meta, username) !== 'owner') return err('没有权限');
  const target = String(body.username || '').trim();
  if (!meta.users[target]) return err('账号不存在');
  meta.owner = target;
  meta.admins = (meta.admins || []).filter(function (n) { return n !== target; });
  await saveMeta(env, meta);
  return ok({ done: true });
}
async function deleteDay(env, body, username) {
  const day = String(body.day || '');
  await dbDel(env, 'entry:' + username + ':' + day);
  const statsKey = 'stats:' + day;
  const raw = await dbGet(env, statsKey);
  if (raw) {
    const dayStats = JSON.parse(raw);
    delete dayStats[username];
    if (Object.keys(dayStats).length) await dbSet(env, statsKey, JSON.stringify(dayStats));
    else await dbDel(env, statsKey);
  }
  return ok({ deleted: true });
}

function ok(data) { return { status: 200, data: data }; }
function err(msg) { return { status: 400, data: { error: msg } }; }

/* ---------- 入口 ---------- */
async function handle(env, request) {
  await dbInit(env);
  const url = new URL(request.url);
  const action = url.searchParams.get('action') || '';
  let body = {};
  try { body = await request.json(); } catch (e) {}
  const token = body.token || url.searchParams.get('token') || '';
  try {
    switch (action) {
      case 'ping': return ok({ db: 'd1' });
      case 'register': return await register(env, body);
      case 'login': return await login(env, body);
      case 'load': {
        const username = await verifyToken(env.AUTH_SECRET || 'daodu-dev-secret', token);
        if (!username) return err('未登录或登录已过期');
        return await loadEntries(env, username);
      }
      case 'save': {
        const username = await verifyToken(env.AUTH_SECRET || 'daodu-dev-secret', token);
        if (!username) return err('未登录或登录已过期');
        return await saveEntry(env, body, username);
      }
      case 'del': {
        const username = await verifyToken(env.AUTH_SECRET || 'daodu-dev-secret', token);
        if (!username) return err('未登录或登录已过期');
        return await deleteDay(env, body, username);
      }
      case 'stats': {
        const username = await verifyToken(env.AUTH_SECRET || 'daodu-dev-secret', token);
        if (!username) return err('未登录或登录已过期');
        return await statsDay(env, String(body.day || ''), username);
      }
      case 'users': {
        const username = await verifyToken(env.AUTH_SECRET || 'daodu-dev-secret', token);
        if (!username) return err('未登录或登录已过期');
        return await listUsers(env, username);
      }
      case 'setadmin': {
        const username = await verifyToken(env.AUTH_SECRET || 'daodu-dev-secret', token);
        if (!username) return err('未登录或登录已过期');
        return await setAdmin(env, body, username);
      }
      case 'removeadmin': {
        const username = await verifyToken(env.AUTH_SECRET || 'daodu-dev-secret', token);
        if (!username) return err('未登录或登录已过期');
        return await removeAdmin(env, body, username);
      }
      case 'transfer': {
        const username = await verifyToken(env.AUTH_SECRET || 'daodu-dev-secret', token);
        if (!username) return err('未登录或登录已过期');
        return await transferOwner(env, body, username);
      }
      default: return err('未知操作');
    }
  } catch (e) {
    return { status: 500, data: { error: '服务器错误：' + (e && e.message ? e.message : e) } };
  }
}

export async function onRequest(context) {
  const r = await handle(context.env, context.request);
  return new Response(JSON.stringify(r.data), { status: r.status, headers: { 'Content-Type': 'application/json' } });
}
