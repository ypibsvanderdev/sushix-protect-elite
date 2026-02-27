const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
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

const BASE_URL = `https://sushix-protect-elite.onrender.com`; // CLOUD DEPLOYED LINK

app.get('/api/analytics', (req, res) => res.json({ ...engine.metrics, uptime: process.uptime(), server_status: "MONITORING" }));
app.get('/api/threats', (req, res) => res.json(JSON.parse(fs.readFileSync(THREATS_PATH))));

// Whitelist endpoints removed for simplicity

app.get('/api/scripts', (req, res) => {
    const files = fs.readdirSync(VAULT_PATH);
    res.json(files.map(f => {
        const s = fs.statSync(path.join(VAULT_PATH, f));
        return { name: f, size: s.size, date: s.mtime };
    }));
});

app.post('/api/obfuscate', (req, res) => {
    const { script, name } = req.body;
    const data = engine.protect(script, name);
    // Simple loadstring that works in every executor
    const fileName = name.endsWith('.lua') ? name : name + '.lua';
    const loader = `loadstring(game:HttpGet("${BASE_URL}/raw/${fileName}"))()`;
    res.json({ ...data, loader });
});

app.get('/raw/:name', (req, res) => {
    const ua = req.headers['user-agent'] || "";
    const isExecutor = ua.includes("Roblox") || ua.includes("Synapse") || ua.includes("Fluxus") || ua.includes("Sentinel") || ua.includes("Electron") || ua.includes("Arceus") || ua.includes("Codex") || ua.includes("Delta") || ua.includes("Hydrogen") || ua.includes("Xeno") || ua.includes("Vander");
    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // Safety check bypass: More permissive for troubleshooting
    if (!isExecutor && !req.query.bypass && !ua.includes("http")) {
        logThreat(ip, "BROWSER_INTRUSION", ua);
        return res.status(403).send(`<!DOCTYPE html><html><head><title>SushiX Protection</title><style>body { background: #000; color: #fff; font-family: 'Segoe UI', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; } .vault { text-align: center; } .shield { font-size: 80px; margin-bottom: 20px; display: block; filter: drop-shadow(0 0 20px #ff4d00); } h1 { font-size: 24px; letter-spacing: 2px; text-transform: uppercase; }</style></head><body><div class="vault"><span class="shield">🛡️</span><h1>SushiX Protector: Access Denied</h1><p>Browser Integrity Violation | Request Logged: ${ip}</p></div></body></html>`);
    }
    const p = path.join(VAULT_PATH, req.params.name.endsWith('.lua') ? req.params.name : req.params.name + '.lua');
    if (fs.existsSync(p)) {
        res.setHeader('Content-Type', 'text/plain');
        res.send(fs.readFileSync(p, 'utf8'));
    } else res.status(404).send("-- SUSHIX: Script not found.");
});

app.delete('/api/scripts/:name', (req, res) => {
    const p = path.join(VAULT_PATH, req.params.name);
    if (fs.existsSync(p)) { fs.unlinkSync(p); res.json({ success: true }); }
    else res.status(404).json({ error: "File not found" });
});

app.get('/api/scripts/:name', (req, res) => {
    const p = path.join(VAULT_PATH, req.params.name);
    if (fs.existsSync(p)) res.json({ content: fs.readFileSync(p, 'utf8') });
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
