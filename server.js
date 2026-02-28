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
const FIREBASE_URL = 'https://vanderhub-default-rtdb.firebase.com/sushix_hub.json';

// --- CLOUD SYNC ENGINE ---
const db = {
    vault: {},
    users: [],
    registry: { whitelist: [], blacklist: [] },
    threats: [],
    messages: [],
    settings: {
        globalKillSwitch: false,
        antiDump: true,
        autoBlacklist: true,
        privacyMode: false
    }
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
            db.messages = res.data.messages || [];
            db.settings = res.data.settings || { globalKillSwitch: false, antiDump: true, autoBlacklist: true, privacyMode: false };
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
        const fileName = scriptName.replace(/\./g, '_dot_');

        // Save to Cloud Vault with Metadata
        db.vault[fileName] = {
            source,
            owner: options.owner || 'system',
            sharedWith: [], // List of user IDs with access
            createdAt: new Date().toISOString()
        };
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
    const data = engine.protect(script, name, { owner: req.user.email });
    // Simple loadstring that works in every executor
    const fileName = name.endsWith('.lua') ? name : name + '.lua';
    const loader = `loadstring(game:HttpGet("${BASE_URL}/raw/${fileName}"))()`;
    res.json({ ...data, loader });
});

app.post('/api/obfuscate/pure', authenticate, (req, res) => {
    const { script } = req.body;
    if (!script) return res.status(400).json({ error: "Source required." });
    const result = obfuscateLua(script);
    res.json({ success: true, result });
});

// ==================== VANDER OBFUSCATOR ENGINE ====================
function obfuscateLua(source) {
    const key = Math.floor(Math.random() * 255) + 1;
    const bytes = Buffer.from(source, 'utf8');
    const encrypted = [];
    for (let i = 0; i < bytes.length; i++) {
        encrypted.push(bytes[i] ^ key);
    }

    let lua = `--[[\n    ☣️ @#$%& SUSHI OBFUSCATOR v10.0 ACTIVATED *&^%$ \n    SHIELD: ANTI-ENV // ANTI-LOG // LAYER: TITAN\n--]]\n`;
    lua += `local _G = getfenv() or _G; `;
    lua += `local _P = {print, warn, error, rconsoleprint, rconsolewarn}; `;
    lua += `for _, _v in pairs(_G) do for _, _p in pairs(_P) do if _v == _p and _v ~= print and _v ~= warn then _G = nil end end end; `;
    lua += `local _k = ${key}; `;
    lua += `local _t = {${encrypted.join(',')}}; `;
    lua += `local _b = bit32 and bit32.bxor or function(a,b) local r,m=0,1 while a>0 or b>0 do if a%2~=b%2 then r=r+m end a,b,m=math.floor(a/2),math.floor(b/2),m*2 end return r end; `;
    lua += `local _r = {}; `;
    lua += `for i=1,#_t do _r[i] = string.char(_b(_t[i], _k)) end; `;
    lua += `local _L = (loadstring or load); `;
    lua += `if tostring(_L):find("native") or tostring(_L):find("function") then `;
    lua += `    local _f, _e = _L(table.concat(_r)); `;
    lua += `    if _f then _f() else error("[SUSHIX-VM]: @#$%& CORRUPTION DETECTED *&^%$ " .. tostring(_e)) end; `;
    lua += `else `;
    lua += `    while true do end; `;
    lua += `end; `;
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
    const file = db.vault[fileName];
    if (file) {
        if (file.owner !== req.user.email && req.user.email !== 'meqda@gmail.com') {
            return res.status(403).json({ error: "Only the owner can delete this script." });
        }
        delete db.vault[fileName];
        syncToCloud();
        res.json({ success: true });
    } else res.status(404).json({ error: "File not found" });
});

// --- COLLABORATION & MESSAGING SYSTEM ---
app.get('/api/users/search', authenticate, (req, res) => {
    const query = (req.query.q || '').toLowerCase();
    const results = db.users
        .filter(u => (u.name || '').toLowerCase().includes(query))
        .map(u => ({ username: u.name }));
    res.json(results);
});

app.post('/api/messages/send', authenticate, (req, res) => {
    const { to, content, type = 'text', scriptName = null } = req.body;
    if (!to || !content) return res.status(400).json({ error: "Recipient and content required." });

    const msg = {
        id: crypto.randomUUID(),
        from: req.user.username,
        to,
        content,
        type,
        scriptName,
        timestamp: new Date().toISOString(),
        read: false
    };

    db.messages.push(msg);

    // If it's an invite, automatically add permission
    if (type === 'invite' && scriptName) {
        const fileName = scriptName.replace(/\./g, '_dot_');
        if (db.vault[fileName] && !db.vault[fileName].sharedWith.includes(to)) {
            db.vault[fileName].sharedWith.push(to);
        }
    }

    syncToCloud();
    res.json({ success: true });
});

app.get('/api/messages', authenticate, (req, res) => {
    const userMsgs = db.messages.filter(m => m.to === req.user.username).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    res.json(userMsgs);
});

// --- SECURITY SETTINGS ---
app.get('/api/settings', authenticate, (req, res) => res.json(db.settings));
app.post('/api/settings', authenticate, (req, res) => {
    if (req.user.email !== 'meqda@gmail.com') return res.status(403).json({ error: "Only the Root Admin can change security settings." });
    db.settings = { ...db.settings, ...req.body };
    syncToCloud();
    res.json({ success: true, settings: db.settings });
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
        <h1>SUSHI OBFUSCATOR: ACCESS DENIED</h1>
        <p>BROWSER INTEGRITY VIOLATION | UNAUTHORIZED SOURCE REQUEST</p>
    </div>
</body>
</html>`;

function validateAccess(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const h = req.headers;
    const accept = (h['accept'] || '').toLowerCase();

    // --- TITAN ANTI-SPOOF ENGINE (STRICT) ---

    // 1. Browsers ALWAYS request HTML/XML. Executors request */* or text.
    const isBrowserRequest = accept.includes('text/html') || accept.includes('application/xhtml+xml');

    // 2. Comprehensive Browser Fingerprint Check
    const hasBrowserFingerprint =
        h['sec-ch-ua'] ||
        h['accept-language'] ||
        h['sec-fetch-mode'] ||
        h['sec-fetch-dest'] ||
        h['sec-fetch-site'] ||
        h['upgrade-insecure-requests'] ||
        h['purpose'] === 'prefetch';

    const blacklist = [
        'mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera', 'trident', 'applewebkit', 'presto',
        'discord', 'python', 'axios', 'fetch', 'curl', 'wget', 'postman', 'golang', 'libcurl',
        'scraper', 'spider', 'bot', 'headless', 'browser', 'playwright', 'puppeteer', 'selenium',
        'aiohttp', 'httpx', 'got', 'superagent', 'cheerio', 'zombie', 'phantomjs', 'insomnia'
    ];

    const whitelist = ['roblox', 'delta', 'fluxus', 'codex', 'arceus', 'hydrogen', 'vegax', 'robloxproxy'];

    const isWhitelisted = whitelist.some(k => ua.includes(k));
    const isBlacklisted = blacklist.some(k => ua.includes(k));

    // LOGGING FOR DEBUGGING (Logged to Threats)
    const failReason = isBrowserRequest ? "BROWSER_ACCEPT_HEADER" :
        hasBrowserFingerprint ? "BROWSER_FINGERPRINT" :
            isBlacklisted ? "UA_BLACKLIST" :
                !isWhitelisted ? "UA_NOT_WHITELISTED" : null;

    if (failReason) {
        req.lastFailReason = `${failReason} | UA: ${ua.substring(0, 50)}`;
        return false;
    }

    return true;
}

app.get('/raw/:name', (req, res) => {
    if (!validateAccess(req)) {
        const method = db.settings.antiDump ? "BOT_BAIT_700KB" : (req.lastFailReason || "ILLEGAL_BROWSER_FETCH");
        db.threats.unshift({ ip: req.ip, method: method, time: new Date().toISOString(), userAgent: req.headers['user-agent'] });
        syncToCloud();
        engine.updateTotalThreats();

        if (db.settings.antiDump) {
            // 700KB Bot Bait (approx 350KB hex)
            const junkHex = crypto.randomBytes(350 * 1024).toString('hex');
            const signature = crypto.randomBytes(64).toString('hex');
            const garbage = `--[[
    ☣️ SUSHIX PROTECT ELITE v10.0 ACTIVATED ☣️
    SHIELD: ANTI-DUMP // ANTI-BOT // LAYER: TITAN-ULTRA
    INTEGRITY: ${crypto.randomBytes(24).toString('hex')}
    SIGNATURE: ${signature}
    STATUS: REDIRECTED_BY_FIREWALL_LOADER_V8
    @NOTICE: Dumper detected. Serving corrupt payload.
]]
local _S = "${junkHex}"
local _H = "${signature.substring(0, 32)}"
local _V = function(s) 
    local r = "" 
    for i=1,#s,2 do 
        r = r .. string.char(tonumber(s:sub(i,i+1), 16)) 
    end 
    return r 
end
if _H ~= "${signature.substring(0, 32)}" then return end
return loadstring(_V(_S))();`;

            console.log(`[FIREWALL]: Serving 700KB Bait to bot at ${req.ip}`);
            return res.status(200).set('Content-Type', 'text/plain').send(garbage);
        }

        return res.status(403).send(PROTECTION_HTML);
    }

    const fileName = (req.params.name.endsWith('.lua') ? req.params.name : req.params.name + '.lua').replace(/\./g, '_dot_');
    const file = db.vault[fileName];

    if (db.settings.globalKillSwitch) {
        return res.status(503).send("-- SUSHIX: Global Kill-Switch is ACTIVE. Asset temporarily disabled.");
    }

    if (file) {
        res.setHeader('Content-Type', 'text/plain');
        res.send(obfuscateLua(file.source));
    } else res.status(404).send("-- SUSHIX: Asset not found.");
});

app.get('/api/scripts', authenticate, (req, res) => {
    if (!validateAccess(req) && !req.headers.referer) return res.status(403).send(PROTECTION_HTML);
    try {
        const scripts = Object.keys(db.vault)
            .filter(key => {
                const f = db.vault[key];
                return f.owner === req.user.email || (f.sharedWith && f.sharedWith.includes(req.user.email)) || req.user.email === 'meqda@gmail.com';
            })
            .map(key => {
                const f = db.vault[key];
                return {
                    name: key.replace(/_dot_/g, '.'),
                    size: f.source.length,
                    date: f.createdAt,
                    isOwner: f.owner === req.user.email
                };
            });
        res.json({ success: true, scripts });
    } catch (e) { res.json({ success: false, scripts: [] }); }
});

app.get('/api/scripts/:name', authenticate, (req, res) => {
    const fileName = (req.params.name.endsWith('.lua') ? req.params.name : req.params.name + '.lua').replace(/\./g, '_dot_');
    const file = db.vault[fileName];

    if (file) {
        // Permission Check
        if (file.owner !== req.user.email && (!file.sharedWith || !file.sharedWith.includes(req.user.email)) && req.user.email !== 'meqda@gmail.com') {
            return res.status(403).json({ error: "ACCESS DENIED: You are not invited to this script." });
        }
        res.json({ success: true, content: file.source });
    } else res.status(404).json({ error: "Script not found" });
});

// --- AUTH SYSTEM: EMAIL & PASSWORD ---
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password || !name) return res.status(400).json({ error: "Email, password and Username required." });

    if (db.users.find(u => u.email === email)) return res.status(400).json({ error: "EMAIL ALREADY REGISTERED" });
    if (db.users.find(u => u.name.toLowerCase() === name.toLowerCase())) return res.status(400).json({ error: "USERNAME ALREADY TAKEN" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: crypto.randomUUID(),
        email,
        name: name,
        password: hashedPassword,
        type: 'local',
        createdAt: new Date().toISOString()
    };

    db.users.push(newUser);
    syncToCloud();

    console.log(`[USER REGISTERED]: ${name} (${email})`);
    res.json({ success: true, message: "Account created successfully." });
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = db.users.find(u => u.email === email || u.name === email); // Allow login by email or username

    if (!user || user.type === 'google') return res.status(401).json({ error: "INVALID CREDENTIALS" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "INVALID CREDENTIALS" });

    const token = jwt.sign({ id: user.id, email: user.email, username: user.name }, JWT_SECRET, { expiresIn: '7d' });
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

        const token = jwt.sign({ id: user.id, email: user.email, username: user.name }, JWT_SECRET, { expiresIn: '7d' });
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
