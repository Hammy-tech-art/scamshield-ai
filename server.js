const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 5173;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'scamshield.json');
const SESSIONS = new Map();
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], scans: [], shares: [] }, null, 2));

function db() { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
function save(data) { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }
function json(res, code, data) { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(data)); }
function readBody(req) { return new Promise((resolve, reject) => { let raw = ''; req.on('data', c => { raw += c; if (raw.length > 150000) req.destroy(); }); req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('Invalid request.')); } }); }); }
function hash(password, salt = crypto.randomBytes(16).toString('hex')) { return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (e, key) => e ? reject(e) : resolve(`${salt}:${key.toString('hex')}`))); }
async function verify(password, stored) { const [salt, value] = stored.split(':'); const candidate = await hash(password, salt); return crypto.timingSafeEqual(Buffer.from(candidate.split(':')[1], 'hex'), Buffer.from(value, 'hex')); }
function tokenFor(req) { const auth = req.headers.authorization || ''; const token = auth.startsWith('Bearer ') ? auth.slice(7) : ''; return SESSIONS.get(token); }
function newToken(userId) { const token = crypto.randomBytes(32).toString('hex'); SESSIONS.set(token, userId); return token; }
function cleanText(value) { return String(value || '').replace(/[<>]/g, '').trim().slice(0, 12000); }
function assess(text, type) {
  const patterns = [[/urgent|immediately|today|act quickly|expires/i, 'Creates false urgency'], [/suspend|locked|lose access/i, 'Uses a threat to pressure you'], [/fee|payment|deposit|registration/i, 'Requests money or an upfront payment'], [/password|verify.*account|login|code/i, 'May be attempting to collect credentials'], [/http:\/\/|bit\.ly|tinyurl|secure-login/i, 'Contains a potentially misleading link'], [/no interview|required.*pay/i, 'Job offer has unusual hiring or payment terms'], [/guaranteed|risk-free|double your|crypto/i, 'Makes investment claims that need verification']];
  const findings = patterns.flatMap(([regex, reason]) => regex.test(text) ? [{ phrase: text.match(regex)?.[0], reason }] : []);
  let score = Math.min(98, Math.max(6, findings.length * 19 + (type === 'website' ? 12 : 0) + (type === 'investment' ? 10 : 0)));
  if (/official mobile app|monthly statement/i.test(text)) score = Math.min(score, 18);
  return { score, findings, text, type, id: `SS-${crypto.randomBytes(3).toString('hex').toUpperCase()}`, date: new Date().toISOString() };
}
function safeScan(scan) { const { text, userId, ...report } = scan; return report; }
async function api(req, res, url) {
  const route = url.pathname;
  if (req.method === 'POST' && route === '/api/auth/register') {
    const { name, email, password } = await readBody(req); const normalized = cleanText(email).toLowerCase();
    if (!/^\S+@\S+\.\S+$/.test(normalized) || String(password || '').length < 8) return json(res, 400, { error: 'Use a valid email and a password of at least 8 characters.' });
    const data = db(); if (data.users.some(u => u.email === normalized)) return json(res, 409, { error: 'An account already exists with this email.' });
    const user = { id: crypto.randomUUID(), name: cleanText(name) || 'ScamShield member', email: normalized, passwordHash: await hash(password), createdAt: new Date().toISOString() }; data.users.push(user); save(data);
    return json(res, 201, { token: newToken(user.id), user: { id: user.id, name: user.name, email: user.email } });
  }
  if (req.method === 'POST' && route === '/api/auth/login') {
    const { email, password } = await readBody(req); const user = db().users.find(u => u.email === cleanText(email).toLowerCase());
    if (!user || !(await verify(String(password || ''), user.passwordHash))) return json(res, 401, { error: 'Email or password is incorrect.' });
    return json(res, 200, { token: newToken(user.id), user: { id: user.id, name: user.name, email: user.email } });
  }
  if (req.method === 'POST' && route === '/api/auth/logout') { SESSIONS.delete((req.headers.authorization || '').replace('Bearer ', '')); return json(res, 200, { ok: true }); }
  if (req.method === 'POST' && route === '/api/analyze') {
    const { text, type } = await readBody(req); const cleaned = cleanText(text); if (!cleaned) return json(res, 400, { error: 'Add content to analyze.' });
    const scan = assess(cleaned, cleanText(type)); const userId = tokenFor(req); if (userId) { const data = db(); data.scans.unshift({ ...scan, userId, createdAt: new Date().toISOString() }); save(data); }
    return json(res, 200, safeScan(scan));
  }
  if (req.method === 'GET' && route === '/api/scans') { const userId = tokenFor(req); if (!userId) return json(res, 401, { error: 'Sign in to view saved scans.' }); return json(res, 200, db().scans.filter(s => s.userId === userId).map(safeScan)); }
  if (req.method === 'POST' && route.startsWith('/api/scans/') && route.endsWith('/share')) { const userId = tokenFor(req); const id = route.split('/')[3]; const data = db(); const scan = data.scans.find(s => s.id === id && s.userId === userId); if (!scan) return json(res, 404, { error: 'Saved scan not found.' }); const share = { token: crypto.randomBytes(12).toString('base64url'), scanId: id, userId, createdAt: new Date().toISOString() }; data.shares.push(share); save(data); return json(res, 201, { url: `/report/${share.token}` }); }
  if (req.method === 'GET' && route.startsWith('/api/report/')) { const token = route.split('/').pop(); const data = db(); const share = data.shares.find(s => s.token === token); const scan = share && data.scans.find(s => s.id === share.scanId); if (!scan) return json(res, 404, { error: 'Report not found.' }); return json(res, 200, { id: scan.id, score: scan.score, type: scan.type, findings: scan.findings, date: scan.date, disclaimer: 'This shared summary intentionally excludes submitted content.' }); }
  return false;
}
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8' };
const server = http.createServer(async (req, res) => {
  try { const url = new URL(req.url, `http://${req.headers.host}`); if (url.pathname.startsWith('/api/')) { const handled = await api(req, res, url); if (handled !== false) return; return json(res, 404, { error: 'Not found.' }); }
    const filePath = path.normalize(path.join(ROOT, url.pathname === '/' ? 'index.html' : url.pathname)); if (!filePath.startsWith(ROOT)) return json(res, 403, { error: 'Forbidden.' }); fs.readFile(filePath, (err, content) => { if (err) { res.writeHead(404); return res.end('Not found'); } res.writeHead(200, { 'Content-Type': mime[path.extname(filePath)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' }); res.end(content); });
  } catch (error) { json(res, 500, { error: 'The server could not process that request.' }); }
});
server.listen(PORT, () => console.log(`ScamShield AI running at http://localhost:${PORT}`));
