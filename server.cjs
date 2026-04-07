const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DIST = path.join(__dirname, 'dist');
const DB_FILE = path.join(__dirname, 'shared-db.bin');

// ============================================================
//  Authentication config (use env vars or defaults)
// ============================================================
const USERS = JSON.parse(process.env.USERS_JSON || '{"dov":"yunis2026","talia":"yunis2026"}');
const SESSION_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7 days

// In-memory session store
const sessions = new Map();

function createSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username, expires: Date.now() + SESSION_EXPIRY });
  return token;
}

function validateSession(token) {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expires) {
    sessions.delete(token);
    return null;
  }
  return session.username;
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(c => {
    const [key, val] = c.trim().split('=');
    if (key && val) cookies[key] = val;
  });
  return cookies;
}

const MIME = {
  '.html': 'text/html',
  '.js':   'application/javascript',
  '.css':  'text/css',
  '.json': 'application/json',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
  '.wasm': 'application/wasm',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
};

// ============================================================
//  Login page HTML
// ============================================================
const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>התחברות - YunisHome</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'Segoe UI', 'Rubik', Tahoma, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      padding: 20px;
    }
    .login-card {
      background: #fff;
      border-radius: 20px;
      padding: 40px 36px;
      max-width: 380px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      text-align: center;
    }
    .login-icon { font-size: 48px; margin-bottom: 16px; }
    h1 { font-size: 22px; color: #1a1a2e; margin-bottom: 6px; }
    .subtitle { color: #6b7280; font-size: 14px; margin-bottom: 28px; }
    .form-group { margin-bottom: 16px; text-align: right; }
    label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      color: #374151;
      margin-bottom: 6px;
    }
    input {
      width: 100%;
      padding: 12px 16px;
      border: 2px solid #e5e7eb;
      border-radius: 12px;
      font-size: 15px;
      font-family: inherit;
      direction: rtl;
      transition: border-color 0.2s;
    }
    input:focus {
      outline: none;
      border-color: #6366f1;
      box-shadow: 0 0 0 3px rgba(99,102,241,0.15);
    }
    .login-btn {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #6366f1, #8b5cf6);
      color: #fff;
      border: none;
      border-radius: 12px;
      font-size: 16px;
      font-weight: 700;
      font-family: inherit;
      cursor: pointer;
      margin-top: 8px;
      transition: opacity 0.2s, transform 0.1s;
    }
    .login-btn:hover { opacity: 0.9; }
    .login-btn:active { transform: scale(0.98); }
    .error {
      background: #fef2f2;
      color: #dc2626;
      padding: 10px 16px;
      border-radius: 10px;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 16px;
      display: none;
    }
    .error.show { display: block; }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="login-icon">📊</div>
    <h1>YunisHome</h1>
    <p class="subtitle">התחבר כדי להמשיך</p>
    <div id="error" class="error">שם משתמש או סיסמה שגויים</div>
    <form id="loginForm">
      <div class="form-group">
        <label for="username">שם משתמש</label>
        <input type="text" id="username" name="username" autocomplete="username" required autofocus>
      </div>
      <div class="form-group">
        <label for="password">סיסמה</label>
        <input type="password" id="password" name="password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="login-btn">🔐 התחבר</button>
    </form>
  </div>
  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      if (res.ok) {
        window.location.href = '/';
      } else {
        document.getElementById('error').classList.add('show');
      }
    });
  </script>
</body>
</html>`;

// ============================================================
//  Server
// ============================================================
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // --- Login API (public) ---
  if (req.url === '/api/login' && req.method === 'POST') {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      try {
        const { username, password } = JSON.parse(Buffer.concat(chunks).toString());
        if (USERS[username] && USERS[username] === password) {
          const token = createSession(username);
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_EXPIRY / 1000}`,
          });
          res.end(JSON.stringify({ ok: true, username }));
          console.log(`[AUTH] ${username} logged in from ${req.socket.remoteAddress}`);
        } else {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false }));
          console.log(`[AUTH] Failed login: ${username} from ${req.socket.remoteAddress}`);
        }
      } catch (e) {
        res.writeHead(400);
        res.end('Bad request');
      }
    });
    return;
  }

  // --- Logout API ---
  if (req.url === '/api/logout') {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies.session) sessions.delete(cookies.session);
    res.writeHead(302, {
      'Set-Cookie': 'session=; Path=/; HttpOnly; Max-Age=0',
      'Location': '/login',
    });
    res.end();
    return;
  }

  // --- Login page (public) ---
  if (req.url === '/login') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(LOGIN_PAGE);
    return;
  }

  // --- Service worker, manifest & icons (public for PWA) ---
  if (req.url === '/sw.js' || req.url === '/manifest.json' || req.url === '/favicon.svg' || req.url.startsWith('/icons/')) {
    const filePath = path.join(DIST, req.url);
    if (fs.existsSync(filePath)) {
      const ext = path.extname(filePath);
      const data = fs.readFileSync(filePath);
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
      res.end(data);
      return;
    }
  }

  // --- Auth check for everything else ---
  const cookies = parseCookies(req.headers.cookie);
  const user = validateSession(cookies.session);
  if (!user) {
    if (req.url.startsWith('/api/')) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }
    res.writeHead(302, { 'Location': '/login' });
    res.end();
    return;
  }

  // --- API: sync database (authenticated) ---
  if (req.url === '/api/sync-db') {
    if (req.method === 'POST') {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const buf = Buffer.concat(chunks);
        fs.writeFileSync(DB_FILE, buf);
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('OK');
        console.log(`[SYNC POST] by ${user} from ${req.socket.remoteAddress} (${(buf.length / 1024).toFixed(1)} KB)`);
      });
      return;
    }
    if (req.method === 'GET') {
      if (fs.existsSync(DB_FILE)) {
        const data = fs.readFileSync(DB_FILE);
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Cache-Control': 'no-store',
        });
        res.end(data);
      } else {
        res.writeHead(404);
        res.end('No shared DB');
      }
      return;
    }
  }

  // --- API: get current user ---
  if (req.url === '/api/me') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ username: user }));
    return;
  }

  // --- Static file serving (authenticated) ---
  let filePath = path.join(DIST, req.url === '/' ? 'index.html' : req.url);

  if (!fs.existsSync(filePath)) {
    filePath = path.join(DIST, 'index.html');
  }

  const ext = path.extname(filePath);
  const mime = MIME[ext] || 'application/octet-stream';

  try {
    const data = fs.readFileSync(filePath);
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  } catch (e) {
    res.writeHead(404);
    res.end('Not found');
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Home Expenses server running on http://0.0.0.0:${PORT}`);
  console.log(`   Local:   http://localhost:${PORT}`);
  const nets = require('os').networkInterfaces();
  for (const iface of Object.values(nets)) {
    for (const addr of iface) {
      if (addr.family === 'IPv4' && !addr.internal) {
        console.log(`   Network: http://${addr.address}:${PORT}`);
      }
    }
  }
});
