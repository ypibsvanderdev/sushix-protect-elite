const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3050;
const BASE_URL = `https://sushix-protect-elite.onrender.com`;
const FIREBASE_URL = 'https://vanderhub-default-rtdb.firebaseio.com/sushix_hub.json';

// --- CLOUD SYNC ENGINE ---
const db = {
    vault: {},
    users: [],
    registry: { whitelist: [], blacklist: [] },
    threats: []
};

async function syncToCloud() {
    try {
        await axios.put(FIREBASE_URL, db);
        console.log("[CLOUD]: Data persisted to Firebase.");
    } catch (e) {
        console.error("[CLOUD]: Sync failed:", e.message);
    }
}

async function loadFromCloud() {
    try {
        const res = await axios.get(FIREBASE_URL);
        if (res.data) {
            db.vault = res.data.vault || {};
            db.users = res.data.users || [];
            db.registry = res.data.registry || { whitelist: [], blacklist: [] };
            db.threats = res.data.threats || [];
            console.log("[CLOUD]: Database loaded successfully.");
        } else {
            console.log("[CLOUD]: Initializing empty database...");
            await syncToCloud();
        }
    } catch (e) {
        console.error("[CLOUD]: Load failed:", e.message);
    }
}

// Initial Load
loadFromCloud();

const JWT_SECRET = 'VANDER-HUB-ULTRA-SECRET-777';
const GOOGLE_CLIENT_ID = '945575151017-o0mh8usjvn9r23lnid2th5g13qg8lpgv.apps.googleusercontent.com';
const gClient = new OAuth2Client(GOOGLE_CLIENT_ID);

app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname));

// --- AUTH MIDDLEWARE ---
const authenticate = (req, res, next) => {
    const token = req.cookies.vander_session;
    if (!token) return res.status(401).json({ error: "UNAUTHORIZED: Access via Google Login required." });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: "SESSION EXPIRED: Please re-login with Google." });
    }
};

// --- SUSHIX ELITE ENGINE V8.3 ---
class SushiXEliteEngine {
    constructor() {
        this.metrics = { total_crypts: 0, threats_neutralized: 0, active_users: 82 };
        setTimeout(() => this.updateTotalThreats(), 5000);
    }
    updateTotalThreats() {
        this.metrics.threats_neutralized = db.threats.length;
    }
    randomStr(l) { return crypto.randomBytes(l).toString('hex').substring(0, l); }
    protect(source, name, options = {}) {
        const scriptId = "SX_ELITE_" + this.randomStr(12).toUpperCase();
        const scriptName = name.endsWith('.lua') ? name : name + '.lua';

        // Save to Cloud Vault
        db.vault[scriptName.replace(/\./g, '_dot_')] = source;
        syncToCloud();

        this.metrics.total_crypts++;
        return { success: true, id: scriptId, size: source.length };
    }
}
const engine = new SushiXEliteEngine();

app.get('/api/analytics', authenticate, (req, res) => res.json({ ...engine.metrics, uptime: process.uptime(), server_status: "MONITORING" }));
app.get('/api/threats', authenticate, (req, res) => res.json(db.threats));

// Whitelist endpoints removed for simplicity

app.post('/api/obfuscate', authenticate, (req, res) => {
    const { script, name } = req.body;
    const data = engine.protect(script, name);
    // Simple loadstring that works in every executor
    const fileName = name.endsWith('.lua') ? name : name + '.lua';
    const loader = `loadstring(game:HttpGet("${BASE_URL}/raw/${fileName}"))()`;
    res.json({ ...data, loader });
});

// ==================== VANDER OBFUSCATOR ENGINE ====================
function obfuscateLua(source) {
    const randVar = () => "_" + crypto.randomBytes(4).toString('hex') + Math.floor(Math.random() * 999);
    const key = Math.floor(Math.random() * 200) + 50;
    const encrypted = [];
    for (let i = 0; i < source.length; i++) encrypted.push(source.charCodeAt(i) ^ key);

    let lua = `-- SECURED BY SUSHIX ELITE v8.5\n`;
    lua += `local _k=${key} local _t={${encrypted.join(',')}} local _r={} `;
    lua += `local _x=function(a,b) local r,m=0,1 while a>0 or b>0 do if a%2~=b%2 then r=r+m end a,b,m=math.floor(a/2),math.floor(b/2),m*2 end return r end `;
    lua += `for i=1,#_t do _r[i]=string.char(_x(_t[i],_k)) end (loadstring or load)(table.concat(_r))()`;
    return lua;
}

app.post('/api/obfuscate', (req, res) => {
    const { script, name } = req.body;
    const data = engine.protect(script, name);
    const fileName = name.endsWith('.lua') ? name : name + '.lua';
    const loader = `loadstring(game:HttpGet("${BASE_URL}/raw/${fileName}"))()`;
    res.json({ ...data, loader });
});

app.delete('/api/scripts/:name', authenticate, (req, res) => {
    const fileName = req.params.name.replace(/\./g, '_dot_');
    if (db.vault[fileName]) {
        delete db.vault[fileName];
        syncToCloud();
        res.json({ success: true });
    } else res.status(404).json({ error: "File not found" });
});

const PROTECTION_HTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Access Denied | SushiX Protector</title>
    <style>
        body { background: #000; color: #fff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; overflow: hidden; }
        .container { text-align: center; }
        .shield { font-size: 80px; margin-bottom: 20px; display: block; filter: drop-shadow(0 0 20px #4d94ff) drop-shadow(0 0 40px #ff4d00); animation: pulse 2s infinite ease-in-out; }
        h1 { font-size: 28px; letter-spacing: 2px; font-weight: 800; margin: 0; text-transform: uppercase; color: #fff; }
        p { color: #808080; font-size: 10px; letter-spacing: 1px; font-weight: 600; margin-top: 10px; text-transform: uppercase; }
        @keyframes pulse { 0% { transform: scale(1); opacity: 0.8; } 50% { transform: scale(1.05); opacity: 1; } 100% { transform: scale(1); opacity: 0.8; } }
    </style>
</head>
<body>
    <div class="container">
        <span class="shield">🛡️</span>
        <h1>SUSHIX PROTECTOR: ACCESS DENIED</h1>
        <p>BROWSER INTEGRITY VIOLATION | UNAUTHORIZED SOURCE REQUEST</p>
    </div>
</body>
</html>`;

function validateAccess(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const blacklist = ['discord', 'python', 'axios', 'fetch', 'curl', 'wget', 'postman', 'golang', 'libcurl', 'scraper', 'spider', 'bot', 'headless', 'browser'];
    const whitelist = ['roblox', 'delta', 'fluxus', 'codex', 'arceus', 'hydrogen', 'vegax', 'android', 'iphone', 'ipad', 'cfnetwork', 'robloxproxy', 'vander'];
    return !blacklist.some(k => ua.includes(k)) && whitelist.some(k => ua.includes(k));
}

app.get('/raw/:name', (req, res) => {
    if (!validateAccess(req)) {
        db.threats.unshift({ ip: req.ip, method: "ILLEGAL_BROWSER_FETCH", time: new Date().toISOString() });
        syncToCloud();
        engine.updateTotalThreats();
        return res.status(403).send(PROTECTION_HTML);
    }

    const fileName = (req.params.name.endsWith('.lua') ? req.params.name : req.params.name + '.lua').replace(/\./g, '_dot_');
    const source = db.vault[fileName];

    if (source) {
        res.setHeader('Content-Type', 'text/plain');
        res.send(obfuscateLua(source));
    } else res.status(404).send("-- SUSHIX: Asset not found.");
});

app.get('/api/scripts', authenticate, (req, res) => {
    if (!validateAccess(req) && !req.headers.referer) return res.status(403).send(PROTECTION_HTML);
    try {
        const scripts = Object.keys(db.vault).map(key => {
            return { name: key.replace(/_dot_/g, '.'), size: db.vault[key].length, date: new Date() };
        });
        res.json({ success: true, scripts });
    } catch (e) { res.json({ success: false, scripts: [] }); }
});

app.get('/api/scripts/:name', authenticate, (req, res) => {
    const fileName = (req.params.name.endsWith('.lua') ? req.params.name : req.params.name + '.lua').replace(/\./g, '_dot_');
    const source = db.vault[fileName];
    if (source) res.json({ success: true, content: source });
    else res.status(404).json({ error: "Script not found" });
});

// --- AUTH SYSTEM: EMAIL & PASSWORD ---
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required." });

    if (db.users.find(u => u.email === email)) return res.status(400).json({ error: "EMAIL ALREADY REGISTERED" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: crypto.randomUUID(),
        email,
        name: name || email.split('@')[0],
        password: hashedPassword,
        type: 'local',
        createdAt: new Date().toISOString()
    };

    db.users.push(newUser);
    syncToCloud();

    console.log(`[USER REGISTERED]: ${email}`);
    res.json({ success: true, message: "Account created successfully." });
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = db.users.find(u => u.email === email);

    if (!user || user.type === 'google') return res.status(401).json({ error: "INVALID CREDENTIALS" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "INVALID CREDENTIALS" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('vander_session', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });

    res.json({ success: true, user: { id: user.id, email: user.email, name: user.name } });
});

// --- GOOGLE AUTH ENDPOINTS ---
app.post('/api/auth/google', async (req, res) => {
    const { credential } = req.body;
    try {
        const ticket = await gClient.verifyIdToken({
            idToken: credential,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const { email, name, picture, sub: googleId } = payload;

        let user = db.users.find(u => u.email === email);
        if (!user) {
            user = { id: googleId, email, name, picture, type: 'google', createdAt: new Date().toISOString() };
            db.users.push(user);
            syncToCloud();
            console.log(`[USER SIGNUP]: ${email}`);
        } else {
            console.log(`[USER LOGIN]: ${email}`);
        }

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('vander_session', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
        res.json({ success: true, user });
    } catch (err) {
        console.error("Google Auth Error:", err);
        res.status(400).json({ success: false, error: "CREDENTIAL VALIDATION FAILED" });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('vander_session');
    res.json({ success: true });
});

app.get('/api/auth/me', authenticate, (req, res) => {
    const user = db.users.find(u => u.id === req.user.id);
    res.json({ success: true, user });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(` SUSHIX PROTECT ELITE V8.5.5 ONLINE`);
    console.log(` LOCAL: http://localhost:${PORT}`);
    console.log(` PUBLIC: ${BASE_URL}`);
    console.log(`========================================\n`);
});
