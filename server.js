const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3050;
const BASE_URL = `https://sushix-protect-elite.onrender.com`;
const VAULT_PATH = path.join(__dirname, 'vault');
const LOGS_PATH = path.join(__dirname, 'logs');
const REGISTRY_PATH = path.join(__dirname, 'registry.json');
const THREATS_PATH = path.join(__dirname, 'threats.json');

if (!fs.existsSync(VAULT_PATH)) fs.mkdirSync(VAULT_PATH);
if (!fs.existsSync(LOGS_PATH)) fs.mkdirSync(LOGS_PATH);
if (!fs.existsSync(REGISTRY_PATH)) fs.writeFileSync(REGISTRY_PATH, JSON.stringify({ whitelist: [], blacklist: [] }));
if (!fs.existsSync(THREATS_PATH)) fs.writeFileSync(THREATS_PATH, JSON.stringify([]));

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// --- SUSHIX ELITE ENGINE V8.3 ---
class SushiXEliteEngine {
    constructor() {
        this.metrics = { total_crypts: 0, threats_neutralized: 0, active_users: 82 };
        this.updateTotalThreats();
    }
    updateTotalThreats() {
        const threats = JSON.parse(fs.readFileSync(THREATS_PATH));
        this.metrics.threats_neutralized = threats.length;
    }
    randomStr(l) { return crypto.randomBytes(l).toString('hex').substring(0, l); }
    protect(source, name, options = {}) {
        const scriptId = "SX_ELITE_" + this.randomStr(12).toUpperCase();
        const scriptName = name.endsWith('.lua') ? name : name + '.lua';

        // Obfuscation deactivated: Serving Raw Source
        const fullScript = `--[[ SUSHIX HOSTING: RAW ASSET [${scriptName}] ]]\n${source}`;

        fs.writeFileSync(path.join(VAULT_PATH, scriptName), fullScript);
        this.metrics.total_crypts++;
        return { success: true, id: scriptId, result: fullScript, path: `/vault/${name}`, size: fullScript.length };
    }
}
const engine = new SushiXEliteEngine();

function logThreat(ip, method, ua) {
    const threats = JSON.parse(fs.readFileSync(THREATS_PATH));
    threats.unshift({ ip, method, ua, time: new Date().toISOString() });
    fs.writeFileSync(THREATS_PATH, JSON.stringify(threats.slice(0, 50), null, 4));
    engine.updateTotalThreats();
}

app.get('/api/analytics', (req, res) => res.json({ ...engine.metrics, uptime: process.uptime(), server_status: "MONITORING" }));
app.get('/api/threats', (req, res) => res.json(JSON.parse(fs.readFileSync(THREATS_PATH))));

// Whitelist endpoints removed for simplicity

app.post('/api/obfuscate', (req, res) => {
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

app.delete('/api/scripts/:name', (req, res) => {
    const p = path.join(VAULT_PATH, req.params.name);
    if (fs.existsSync(p)) { fs.unlinkSync(p); res.json({ success: true }); }
    else res.status(404).json({ error: "File not found" });
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
    if (!validateAccess(req)) return res.status(403).send(PROTECTION_HTML);

    const fileName = req.params.name.endsWith('.lua') ? req.params.name : req.params.name + '.lua';
    const p = path.join(VAULT_PATH, fileName);

    if (fs.existsSync(p)) {
        res.setHeader('Content-Type', 'text/plain');
        const source = fs.readFileSync(p, 'utf8');
        res.send(obfuscateLua(source));
    } else res.status(404).send("-- SUSHIX: Asset not found.");
});

app.get('/api/scripts', (req, res) => {
    if (!validateAccess(req) && !req.headers.referer) return res.status(403).send(PROTECTION_HTML);
    try {
        const files = fs.readdirSync(VAULT_PATH).filter(f => f.endsWith('.lua'));
        res.json({
            success: true, scripts: files.map(name => {
                const stats = fs.statSync(path.join(VAULT_PATH, name));
                return { name, size: stats.size, date: stats.mtime };
            })
        });
    } catch (e) { res.json({ success: false, scripts: [] }); }
});

app.get('/api/scripts/:name', (req, res) => {
    if (!validateAccess(req) && !req.headers.referer) return res.status(403).send(PROTECTION_HTML);
    const p = path.join(VAULT_PATH, req.params.name.endsWith('.lua') ? req.params.name : req.params.name + '.lua');
    if (fs.existsSync(p)) res.json({ success: true, content: fs.readFileSync(p, 'utf8') });
    else res.status(404).json({ error: "Script not found" });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(` SUSHIX PROTECT ELITE V8.5.5 ONLINE`);
    console.log(` LOCAL: http://localhost:${PORT}`);
    console.log(` PUBLIC: ${BASE_URL}`);
    console.log(`========================================\n`);
});
