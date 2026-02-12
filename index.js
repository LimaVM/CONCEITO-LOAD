require('dotenv').config();
const net = require('net');
const cluster = require('cluster');
const os = require('os');
const http = require('http');
const querystring = require('querystring');
const fs = require('fs');
const path = require('path');

// Configuração
const envTargets = process.env.TARGETS ? process.env.TARGETS.split(',') : [];
const targets = envTargets.map(t => {
    const [host, port] = t.split(':');
    return { host: host.trim(), port: parseInt(port.trim()) || 3389 };
});
const ports = (process.env.PORTS || '3389').split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
const DASHBOARD_PORT = 3000;
const DATA_FILE = path.join(__dirname, 'concload-data.json');
const API_SECRET = process.env.API_SECRET; // AUTH TOKEN

// Parse Server Names (IP:Nome)
const SERVER_NAMES = new Map();
if (process.env.SERVER_NAMES) {
    process.env.SERVER_NAMES.split(',').forEach(pair => {
        const [ip, name] = pair.split(':');
        if (ip && name) SERVER_NAMES.set(ip.trim(), name.trim());
    });
}

if (!API_SECRET) {
    console.warn('[MASTER] ⚠️ AVISO: API_SECRET não definido no .env! A API está vulnerável.');
}

// Função de escape HTML para prevenir XSS
const escapeHtml = (str) => {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
};

const normalizeUsername = (value) => {
    if (!value) return '';
    let normalized = String(value).trim();
    if (normalized.includes('\\')) normalized = normalized.split('\\').pop();
    if (normalized.includes('@')) normalized = normalized.split('@')[0];
    return normalized.trim();
};

const usernamesMatch = (a, b) => {
    const left = normalizeUsername(a).toLowerCase();
    const right = normalizeUsername(b).toLowerCase();
    if (!left || !right) return false;
    return left === right || left.startsWith(right) || right.startsWith(left);
};

// === CLUSTERING ===
if (cluster.isMaster) {
    const numCPUs = os.cpus().length;

    // ESTADO GLOBAL
    const globalSessions = new Map();
    let manualRoutes = new Map();
    let serverWeights = new Map();
    let serverHealth = new Map();
    let manualAliases = new Map();
    const agentReports = new Map(); // serverIP -> { sessions: [...], lastReport: timestamp }
    const suspiciousActivity = new Map(); // key -> { ip, user, reason, count, firstSeen, lastSeen }
    let checkInterval = null;
    let balancingStrategy = 'NAME'; // 'NAME' | 'IP' | 'HYBRID'
    let blacklistedIPs = new Set(); // ANTI-SPAM IP
    let blacklistedUsers = new Set(); // ANTI-SPAM USUÁRIO (POISON)
    let isLearningMode = false; // MODO APRENDIZADO (AUTO-STICKY)

    // Inicializa
    targets.forEach(t => {
        const key = `${t.host}:${t.port}`;
        serverWeights.set(key, 1);
        serverHealth.set(key, { status: 'PENDING', lastCheck: Date.now(), latency: 0 });
    });

    // --- PERSISTÊNCIA ---
    const loadData = () => {
        try {
            if (fs.existsSync(DATA_FILE)) {
                const raw = fs.readFileSync(DATA_FILE, 'utf8');
                if (!raw || raw.trim() === '') {
                    console.log('[MASTER] Arquivo de dados vazio, usando padrões.');
                    return;
                }
                let data;
                try {
                    data = JSON.parse(raw);
                } catch (parseErr) {
                    console.error('[MASTER] JSON corrompido, criando backup e usando padrões.');
                    fs.renameSync(DATA_FILE, DATA_FILE + '.corrupted.' + Date.now());
                    return;
                }
                if (data && typeof data === 'object') {
                    if (Array.isArray(data.manualRoutes)) manualRoutes = new Map(data.manualRoutes);
                    if (Array.isArray(data.serverWeights)) serverWeights = new Map(data.serverWeights);
                    if (Array.isArray(data.manualAliases)) manualAliases = new Map(data.manualAliases);
                    if (data.balancingStrategy) balancingStrategy = data.balancingStrategy;
                    if (Array.isArray(data.blacklistedIPs)) blacklistedIPs = new Set(data.blacklistedIPs);
                    if (Array.isArray(data.blacklistedUsers)) blacklistedUsers = new Set(data.blacklistedUsers);
                    if (typeof data.isLearningMode === 'boolean') isLearningMode = data.isLearningMode;
                    console.log('[MASTER] Dados carregados.', { balancingStrategy, blockedIPs: blacklistedIPs.size, learning: isLearningMode });
                }
            }
        } catch (e) {
            console.error('[MASTER] Erro ao carregar dados:', e.message);
        }
    };

    const saveData = () => {
        try {
            const data = {
                manualRoutes: Array.from(manualRoutes.entries()),
                serverWeights: Array.from(serverWeights.entries()),
                manualAliases: Array.from(manualAliases.entries()),
                balancingStrategy,
                blacklistedIPs: Array.from(blacklistedIPs),
                blacklistedUsers: Array.from(blacklistedUsers),
                isLearningMode
            };
            const tempFile = `${DATA_FILE}.tmp`;
            fs.writeFileSync(tempFile, JSON.stringify(data, null, 2));
            fs.renameSync(tempFile, DATA_FILE);
        } catch (e) {
            console.error('[MASTER] Erro ao salvar dados:', e.message);
        }
    };

    loadData();

    // --- HEALTH CHECK (20s) ---
    const checkHealth = () => {
        targets.forEach(t => {
            const key = `${t.host}:${t.port}`;
            const start = Date.now();
            const socket = new net.Socket();
            socket.setTimeout(5000);

            socket.connect(t.port, t.host, () => {
                const latency = Date.now() - start;
                serverHealth.set(key, { status: 'ONLINE', lastCheck: Date.now(), latency });
                socket.destroy();
            });

            socket.on('timeout', () => {
                serverHealth.set(key, { status: 'OFFLINE', lastCheck: Date.now(), latency: -1 });
                socket.destroy();
            });

            socket.on('error', (err) => {
                serverHealth.set(key, { status: 'OFFLINE', lastCheck: Date.now(), latency: -1 });
                socket.destroy();
            });
        });
    };
    checkHealth();
    checkInterval = setInterval(() => {
        checkHealth();
        // Broadcast health status to workers after each check
        setTimeout(broadcastConfig, 1000);
    }, 20000);

    // Config Broadcast
    const broadcastConfig = () => {
        const config = {
            type: 'CMD_UPDATE_CONFIG',
            manualRoutes: Array.from(manualRoutes.entries()),
            serverWeights: Array.from(serverWeights.entries()),
            serverHealth: Array.from(serverHealth.entries()),
            balancingStrategy,
            blacklistedIPs: Array.from(blacklistedIPs),
            blacklistedUsers: Array.from(blacklistedUsers),
            isLearningMode
        };
        for (const id in cluster.workers) {
            cluster.workers[id].send(config);
        }
    };

    const handleMessage = (msg) => {
        if (msg.type === 'SESSION_CONNECTED') {
            globalSessions.set(msg.id, msg.data);
        } else if (msg.type === 'SESSION_DISCONNECTED') {
            globalSessions.delete(msg.id);
        }
        else if (msg.type === 'CMD_SUSPICIOUS_ACTIVITY') {
            const key = `${msg.ip || 'unknown'}_${msg.user || 'unknown'}_${msg.reason}`;
            const existing = suspiciousActivity.get(key);
            if (existing) {
                existing.count += (msg.count || 1);
                existing.lastSeen = Date.now();
            } else {
                suspiciousActivity.set(key, {
                    ip: msg.ip || 'N/A',
                    user: msg.user || 'N/A',
                    reason: msg.reason,
                    count: msg.count || 1,
                    firstSeen: Date.now(),
                    lastSeen: Date.now()
                });
            }
        }
        else if (msg.type === 'CMD_REGISTER_STICKY') {
            const { user, targetHost, targetPort } = msg;
            if (user && targetHost && isLearningMode) {
                const targetStr = `${targetHost}:${targetPort}`;
                if (!manualRoutes.has(user) || manualRoutes.get(user) !== targetStr) {
                    console.log(`[MASTER] 🧠 Aprendendo Rota: ${user} -> ${targetStr}`);
                    manualRoutes.set(user, targetStr);
                    saveData();
                    broadcastConfig();
                }
            }
        }
    };

    for (let i = 0; i < numCPUs; i++) {
        const worker = cluster.fork();
        worker.on('message', handleMessage);
    }

    setTimeout(broadcastConfig, 1000);

    cluster.on('exit', (worker, code, signal) => {
        console.log(`[MASTER] Worker ${worker.process.pid} morreu (Code: ${code}, Signal: ${signal}).`);

        for (const [key, value] of globalSessions.entries()) {
            if (key.startsWith(`${worker.id}_`)) {
                globalSessions.delete(key);
            }
        }

        if (code !== 0) {
            console.log('[MASTER] Aguardando 5s antes de reiniciar worker para evitar loop de crash...');
            setTimeout(() => {
                const newWorker = cluster.fork();
                newWorker.on('message', handleMessage);
                setTimeout(broadcastConfig, 1000);
            }, 5000);
        } else {
            const newWorker = cluster.fork();
            newWorker.on('message', handleMessage);
            setTimeout(broadcastConfig, 1000);
        }
    });

    // Graceful Shutdown
    const gracefulShutdown = (signal) => {
        console.log(`[MASTER] Recebido ${signal}, encerrando graciosamente...`);
        clearInterval(checkInterval);
        saveData();
        for (const id in cluster.workers) {
            cluster.workers[id].send({ type: 'CMD_SHUTDOWN' });
        }
        setTimeout(() => {
            console.log('[MASTER] Forçando encerramento.');
            process.exit(0);
        }, 5000);
    };
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    // === SERVIDOR DASHBOARD & API (MASTER) ===
    http.createServer((req, res) => {
        const requestUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
        const pathname = requestUrl.pathname;
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Referrer-Policy', 'no-referrer');

        // Middleware de Autenticação para APIs
        if (pathname.startsWith('/api/') && req.method !== 'POST') {
            const apiKey = req.headers['x-api-key'] || requestUrl.searchParams.get('key');
            if (API_SECRET && apiKey !== API_SECRET) {
                // Acesso negado
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Forbidden: Invalid API Key' }));
                console.log(`[MASTER] 🛡️ Acesso bloqueado à API ${pathname} (IP desconhecido)`);
                return;
            }
        }

        if (req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', () => {
                // === AGENT REPORT (JSON) ===
                if (pathname === '/api/agent-report') {
                    try {
                        const report = JSON.parse(body);
                        if (report.serverIPs && Array.isArray(report.sessions)) {
                            const normalizedSessions = report.sessions.map((session) => ({
                                ...session,
                                username: normalizeUsername(session.username)
                            }));

                            // Armazena report e ATUALIZA RAM no serverHealth
                            report.serverIPs.forEach(ip => {
                                agentReports.set(ip, {
                                    serverId: report.serverId,
                                    sessions: normalizedSessions,
                                    cpu: report.cpuUsage || 0,
                                    uptime: report.uptime || 0,
                                    ram: report.ramUsage || 0,
                                    lastReport: Date.now()
                                });

                                // Atualiza RAM no serverHealth se encontrar target correspondente
                                targets.forEach(t => {
                                    if (t.host === ip && report.ramUsage !== undefined) {
                                        const key = `${t.host}:${t.port}`;
                                        const health = serverHealth.get(key);
                                        if (health) {
                                            health.ram = report.ramUsage;
                                            serverHealth.set(key, health);
                                        }
                                    }
                                });
                            });

                            // Propaga atualização de RAM para workers imediatamente
                            broadcastConfig();

                            // DESAMBIGUAÇÃO DE USUÁRIOS (Time-Based)
                            const TOLERANCE = 60000; // 60s
                            for (const [id, session] of globalSessions.entries()) {
                                const agentData = agentReports.get(session.targetHost);
                                if (agentData && agentData.sessions) {
                                    const truncated = session.user;
                                    if (truncated && truncated !== 'Unknown/New') {
                                        // Encontra todos os candidatos que começam com o nome truncado
                                        const candidates = agentData.sessions.filter(s =>
                                            s.username.toLowerCase().startsWith(truncated.toLowerCase())
                                        );

                                        if (candidates.length > 0) {
                                            // Encontra o candidato com loginTime mais próximo do startTime da conexão
                                            let bestMatch = null;
                                            let minDiff = Infinity;

                                            for (const cand of candidates) {
                                                if (!cand.loginTime) continue;
                                                const diff = Math.abs(session.startTime - cand.loginTime);
                                                if (diff < minDiff) {
                                                    minDiff = diff;
                                                    bestMatch = cand;
                                                }
                                            }

                                            // Se o melhor match estiver dentro da tolerância, atualiza
                                            if (bestMatch && minDiff < TOLERANCE) {
                                                if (session.user !== bestMatch.username) {
                                                    // console.log(`[REQ] ${truncated} -> ${bestMatch.username} (Diff: ${minDiff}ms)`);
                                                    session.user = bestMatch.username;

                                                    // Persistência opcional (pode conflitar se nomes colidirem muito, mas ajuda)
                                                    if (!manualAliases.has(truncated)) {
                                                        manualAliases.set(truncated, bestMatch.username);
                                                        saveData();
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } catch (e) {
                        // JSON inválido - ignora
                    }
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        ok: true,
                        bannedUsers: Array.from(blacklistedUsers),
                        bannedIPs: Array.from(blacklistedIPs)
                    }));
                    return;
                }

                const post = querystring.parse(body);

                const postedApiKey = post.key;
                if (pathname.startsWith('/api/') && API_SECRET && postedApiKey !== API_SECRET && !requestUrl.searchParams.get('key') && !req.headers['x-api-key']) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Forbidden: Invalid API Key' }));
                    return;
                }

                if (pathname === '/api/kill') {
                    const { connectionId, workerId } = post;
                    if (cluster.workers[workerId]) {
                        cluster.workers[workerId].send({ type: 'CMD_KILL', connectionId });
                    }
                    globalSessions.delete(connectionId);
                }
                else if (pathname === '/api/route') {
                    const { username, target } = post;
                    const normalizedUser = normalizeUsername(username);
                    if (normalizedUser && target) {
                        if (target === 'CLEAR') manualRoutes.delete(normalizedUser);
                        else manualRoutes.set(normalizedUser, target);
                        saveData();
                        broadcastConfig();
                    }
                }
                else if (pathname === '/api/weight') {
                    const { target, weight } = post;
                    if (target && weight) {
                        serverWeights.set(target, parseInt(weight));
                        saveData();
                        broadcastConfig();
                    }
                }
                else if (pathname === '/api/strategy') {
                    const { strategy } = post;
                    if (strategy === 'NAME' || strategy === 'IP' || strategy === 'HYBRID' || strategy === 'RAM') {
                        balancingStrategy = strategy;
                        saveData();
                        broadcastConfig();
                    }
                }
                else if (pathname === '/api/alias') {
                    const { rawName, fullName } = post;
                    const normalizedRaw = normalizeUsername(rawName);
                    const normalizedFull = normalizeUsername(fullName);
                    if (normalizedRaw && fullName) {
                        if (fullName === 'CLEAR') manualAliases.delete(normalizedRaw);
                        else manualAliases.set(normalizedRaw, normalizedFull || normalizedRaw);
                        saveData();
                    }
                }
                else if (pathname === '/api/bulk-alias') {
                    const { userList } = post;
                    if (userList) {
                        const lines = userList.split(/\r?\n/);
                        let count = 0;
                        lines.forEach(line => {
                            const full = line.trim();
                            if (full.length > 0) {
                                const raw = full.substring(0, 9);
                                if (raw !== full) {
                                    if (manualAliases.has(raw)) {
                                        const existing = manualAliases.get(raw);
                                        if (!existing.includes(full)) {
                                            manualAliases.set(raw, existing + ' / ' + full);
                                        }
                                    } else {
                                        manualAliases.set(raw, full);
                                    }
                                    count++;
                                }
                            }
                        });
                        saveData();
                        console.log(`[MASTER] Importados ${count} aliases.`);
                    }
                }
                else if (pathname === '/api/blacklist') {
                    const { ip, user, action } = post;
                    if (action === 'UNBLOCK_IP' && ip) {
                        blacklistedIPs.delete(ip);
                        saveData();
                        broadcastConfig();
                    } else if (action === 'UNBLOCK_USER' && user) {
                        blacklistedUsers.delete(user);
                        saveData();
                        broadcastConfig();
                    } else if (action === 'CLEAR_IPS') {
                        blacklistedIPs.clear();
                        saveData();
                        broadcastConfig();
                    } else if (action === 'CLEAR_USERS') {
                        blacklistedUsers.clear();
                        saveData();
                        broadcastConfig();
                    }
                    else if (action === 'MANUAL_BAN_IP' && ip) {
                        if (!blacklistedIPs.has(ip)) {
                            blacklistedIPs.add(ip);
                            saveData();
                            broadcastConfig();

                            // Matar conexões instaneamente
                            for (const [id, session] of globalSessions.entries()) {
                                if (session.clientIp === ip) {
                                    if (cluster.workers[session.workerId]) {
                                        cluster.workers[session.workerId].send({ type: 'CMD_KILL', connectionId: id });
                                    }
                                    globalSessions.delete(id);
                                }
                            }
                        }
                    } else if (action === 'MANUAL_BAN_USER' && user) {
                        if (!blacklistedUsers.has(user)) {
                            blacklistedUsers.add(user);
                            saveData();
                            broadcastConfig();

                            // Matar conexões instaneamente (Case Insensitive e Robustez)
                            const bannedLower = normalizeUsername(user).toLowerCase();

                            for (const [id, session] of globalSessions.entries()) {
                                const sUser = normalizeUsername(session.user).toLowerCase();

                                // Busca alias case-insensitive
                                let sFull = sUser;
                                for (const [key, val] of manualAliases.entries()) {
                                    if (key.toLowerCase() === sUser) {
                                        sFull = val.toLowerCase();
                                        break;
                                    }
                                }

                                // Verifica user direto e via alias
                                if (sUser === bannedLower || sFull.includes(bannedLower)) {
                                    if (cluster.workers[session.workerId]) {
                                        cluster.workers[session.workerId].send({ type: 'CMD_KILL', connectionId: id });
                                    }
                                    globalSessions.delete(id);
                                }
                            }
                        }
                    }
                    else if (action === 'CLEAR_SUSPICIOUS') {
                        suspiciousActivity.clear();
                    }
                }
                else if (pathname === '/api/learning-mode') {
            const { enabled } = post;
            isLearningMode = (enabled === 'on');
            saveData();
            broadcastConfig();
                }

                res.writeHead(302, { 'Location': '/' });
                res.end();
            });
            return;
        }

// === API GET: Status dos Agents ===
if (pathname === '/api/agents') {
    const agents = {};
    for (const [ip, data] of agentReports.entries()) {
        agents[ip] = {
            serverId: data.serverId,
            sessions: data.sessions.length,
            lastReport: data.lastReport,
            ago: Math.floor((Date.now() - data.lastReport) / 1000) + 's'
        };
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(agents));
    return;
}

if (pathname === '/') {
    let html = `
            <!DOCTYPE html>
            <html lang="pt-br">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>ConceitoLoad Admin</title>
                <meta http-equiv="refresh" content="5"> 
                <style>
                    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; color: #333; margin: 0; padding: 0; }
                    .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
                    .container { max-width: 1200px; margin: 20px auto; padding: 20px; }
                    .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
                    h2 { margin-top: 0; border-bottom: 2px solid #eee; padding-bottom: 10px; color: #2c3e50; }
                    table { width: 100%; border-collapse: collapse; }
                    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
                    th { background-color: #34495e; color: white; }
                    .btn { padding: 5px 10px; text-decoration: none; border-radius: 4px; border: none; cursor: pointer; color: white; }
                    .btn-red { background-color: #e74c3c; } .btn-red:hover { background-color: #c0392b; }
                    .btn-blue { background-color: #3498db; } .btn-blue:hover { background-color: #2980b9; }
                    .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }
                    .stat-item { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; text-align: center; }
                    .stat-item h3 { margin: 0; font-size: 2.5em; }
                    .form-inline { display: flex; gap: 10px; align-items: center; margin-bottom: 10px; flex-wrap: wrap; }
                    input, select, textarea { padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
                    .tag { padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.9em; }
                    .tag-green { background: #27ae60; color: white; }
                    .tag-red { background: #c0392b; color: white; }
                    .tag-grey { background: #95a5a6; color: white; }
                    .switch-label { display: flex; align-items: center; gap: 10px; font-size: 1.1em; background: #e8f8f5; padding: 10px; border-radius: 5px; border: 1px solid #a2d9ce; color: #0e6655; font-weight: bold; }
                    .switch-on { color: #27ae60; }
                    .switch-off { color: #7f8c8d; }
                </style>
            </head>
            <body>
                <div class="header"><h1>ConceitoLoad / Painel Avançado</h1></div>
                <div class="container">
                    
                    <div class="status-grid">
                        <div class="stat-item"><h3>${globalSessions.size}</h3><p>Conexões Ativas</p></div>
                        <div class="stat-item"><h3>${blacklistedIPs.size}</h3><p>IPs Banidos</p></div>
                        <div class="stat-item"><h3>${manualRoutes.size}</h3><p>Rotas Fixas</p></div>
                    </div>

                     <div class="card" style="border: 2px solid #8e44ad;">
                        <h2>🧠 Persistência Inteligente (Modo Aprendizado)</h2>
                        <form action="/api/learning-mode" method="POST"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}">
                            <label class="switch-label">
                                <input type="checkbox" name="enabled" ${isLearningMode ? 'checked' : ''} onchange="this.form.submit()">
                                ${isLearningMode ? '<span class="switch-on">ATIVADO (Gravando Rotas Automaticamente)</span>' : '<span class="switch-off">DESATIVADO (Apenas Rotas Manuais)</span>'}
                            </label>
                             <p style="margin-top:5px; font-size:0.9em; color:#666;">Quando ativado, qualquer usuário que conectar será <b>fixado para sempre</b> no servidor que caiu. Isso cria persistência absoluta.</p>
                        </form>
                    </div>

                     <div class="card" style="border: 2px solid #e74c3c;">
                        <h2>🛡️ Segurança Anti-Spam</h2>
                        <div style="display:flex; gap:20px; flex-wrap:wrap;">
                            <!-- IPS -->
                            <div style="flex:1; min-width:300px;">
                                <h3>🚫 IPs Banidos</h3>
                                <form action="/api/blacklist" method="POST" class="form-inline" style="background:#fff0f0; padding:5px; border-radius:4px;"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}">
                                    <input type="text" name="ip" placeholder="Banir IP Manualmente" required>
                                    <input type="hidden" name="action" value="MANUAL_BAN_IP">
                                    <button type="submit" class="btn btn-red">Banir IP</button>
                                </form>
                                <div style="max-height: 100px; overflow-y: auto; background: #f9f9f9; padding: 10px; border: 1px solid #ddd;">
                                     ${Array.from(blacklistedIPs).map(ip => `<span>${escapeHtml(ip)}</span><br>`).join('') || 'Nenhum.'}
                                </div>
                                <form action="/api/blacklist" method="POST" style="margin-top:5px"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}"><input type="hidden" name="action" value="CLEAR_IPS"><button class="btn btn-blue" style="font-size:0.8em">Limpar IPs</button></form>
                            </div>

                            <!-- USERS -->
                            <div style="flex:1; min-width:300px;">
                                <h3>☠️ Usuários Envenenados</h3>
                                <form action="/api/blacklist" method="POST" class="form-inline" style="background:#fff0f0; padding:5px; border-radius:4px;"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}">
                                    <input type="text" name="user" placeholder="Banir Nome Manualmente" required>
                                    <input type="hidden" name="action" value="MANUAL_BAN_USER">
                                    <button type="submit" class="btn btn-red">Banir Nome</button>
                                </form>
                                <div style="max-height: 100px; overflow-y: auto; background: #f9f9f9; padding: 10px; border: 1px solid #ddd;">
                                     ${Array.from(blacklistedUsers).map(u => `<span><b>${escapeHtml(u)}</b></span><br>`).join('') || 'Nenhum.'}
                                </div>
                                <form action="/api/blacklist" method="POST" style="margin-top:5px"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}"><input type="hidden" name="action" value="CLEAR_USERS"><button class="btn btn-blue" style="font-size:0.8em">Limpar Users</button></form>
                            </div>
                        </div>
                    </div>

                     <div class="card" style="border: 2px solid #f39c12;">
                        <h2>⚠️ Atividade Suspeita (Tempo Real)</h2>
                        <table>
                            <thead><tr><th>IP</th><th>Usuário</th><th>Motivo</th><th>Tentativas</th><th>Último</th><th>Ação</th></tr></thead>
                            <tbody>
                                ${suspiciousActivity.size === 0 ? '<tr><td colspan="6" style="text-align:center">Nenhuma atividade suspeita.</td></tr>' :
            Array.from(suspiciousActivity.entries())
                .sort((a, b) => b[1].lastSeen - a[1].lastSeen)
                .slice(0, 50)
                .map(([key, a]) => {
                    const ago = Math.floor((Date.now() - a.lastSeen) / 1000);
                    const reasonLabel = a.reason === 'IP_FLOOD' ? '🔴 IP Flood' : a.reason === 'USER_FLOOD' ? '🟡 User Flood' : a.reason === 'BANNED_USER' ? '⛔ User Banido' : a.reason;
                    return `<tr>
                            <td>${escapeHtml(a.ip)}</td>
                            <td><b>${escapeHtml(a.user)}</b></td>
                            <td>${reasonLabel}</td>
                            <td><b>${a.count}</b></td>
                            <td>${ago}s atrás</td>
                            <td style="display:flex; gap:4px;">
                                ${a.ip !== 'N/A' ? `<form action="/api/blacklist" method="POST" style="margin:0"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}"><input type="hidden" name="ip" value="${escapeHtml(a.ip)}"><input type="hidden" name="action" value="MANUAL_BAN_IP"><button type="submit" class="btn btn-red" style="font-size:0.7em;padding:2px 6px">Ban IP</button></form>` : ''}
                                ${a.user !== 'N/A' ? `<form action="/api/blacklist" method="POST" style="margin:0"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}"><input type="hidden" name="user" value="${escapeHtml(a.user)}"><input type="hidden" name="action" value="MANUAL_BAN_USER"><button type="submit" class="btn btn-red" style="font-size:0.7em;padding:2px 6px">Ban User</button></form>` : ''}
                            </td>
                        </tr>`;
                }).join('')}
                            </tbody>
                        </table>
                        <form action="/api/blacklist" method="POST" style="margin-top:10px"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}"><input type="hidden" name="action" value="CLEAR_SUSPICIOUS"><button class="btn btn-blue" style="font-size:0.8em">Limpar Histórico</button></form>
                    </div>

                     <div class="card" style="border: 2px solid #3498db;">
                        <h2>⚙️ Estratégia de Balanceamento</h2>
                        <form action="/api/strategy" method="POST" class="form-inline"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}">
                            <label style="margin-right: 15px; cursor: pointer;">
                                <input type="radio" name="strategy" value="NAME" ${balancingStrategy === 'NAME' ? 'checked' : ''}>
                                <b>Por Nome (Padrão)</b>
                            </label>
                            <label style="margin-right: 15px; cursor: pointer;">
                                <input type="radio" name="strategy" value="IP" ${balancingStrategy === 'IP' ? 'checked' : ''}>
                                <b>Por IP de Origem</b>
                            </label>
                            <label style="margin-right: 15px; cursor: pointer;">
                                <input type="radio" name="strategy" value="HYBRID" ${balancingStrategy === 'HYBRID' ? 'checked' : ''}>
                                <b>Híbrido (Nome + IP)</b>
                            </label>
                            <label style="margin-right: 15px; cursor: pointer;">
                                <input type="radio" name="strategy" value="RAM" ${balancingStrategy === 'RAM' ? 'checked' : ''}>
                                <b>Menor Uso de RAM (Smart)</b>
                            </label>
                            <button type="submit" class="btn btn-blue">Salvar</button>
                        </form>
                    </div>

                    <div class="card">
                        <h2>Monitoramento Avançado</h2>
                        <table style="width:100%; border-collapse:collapse;">
                            <thead>
                                <tr style="background:#34495e; color:white;">
                                    <th style="padding:10px;">Nome / IP</th>
                                    <th style="padding:10px;">Status</th>
                                    <th style="padding:10px;">CPU</th>
                                    <th style="padding:10px;">RAM</th>
                                    <th style="padding:10px;">Sessões</th>
                                    <th style="padding:10px;">Uptime</th>
                                    <th style="padding:10px;">Último Report</th>
                                    <th style="padding:10px;">Peso / Config</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${targets.map(t => {
                    const key = `${t.host}:${t.port}`;
                    const w = serverWeights.get(key) || 1;
                    const health = serverHealth.get(key) || { status: 'PENDING', latency: 0 };
                    const agentData = agentReports.get(t.host) || {};

                    const name = SERVER_NAMES.get(t.host) || t.host;
                    const cpu = agentData.cpu || 0;
                    const ram = health.ram || agentData.ram || 0;

                    // Lista de Usuários com Status
                    let sessionsHtml = '<span style="color:#999">-</span>';
                    let activeCount = 0;

                    if (agentData.sessions && agentData.sessions.length > 0) {
                        const liveUsersOnTarget = Array.from(globalSessions.values())
                            .filter(gs => gs.targetHost === t.host && String(gs.targetPort) === String(t.port))
                            .map(gs => {
                                const raw = normalizeUsername(gs.user);
                                const aliasRaw = manualAliases.get(raw) || manualAliases.get(gs.user);
                                const aliasCandidates = aliasRaw
                                    ? aliasRaw.split('/').map(s => normalizeUsername(s)).filter(Boolean)
                                    : [];
                                return { raw, aliasCandidates };
                            });

                        const sortedSessions = [...agentData.sessions].sort((a, b) => {
                            const aActive = a.state === 'Active' ? 1 : 0;
                            const bActive = b.state === 'Active' ? 1 : 0;
                            return bActive - aActive;
                        });

                        const liveCount = sortedSessions.filter(s => {
                            const normalized = normalizeUsername(s.username);
                            return liveUsersOnTarget.some(live =>
                                usernamesMatch(normalized, live.raw) ||
                                live.aliasCandidates.some(alias => usernamesMatch(normalized, alias))
                            );
                        }).length;
                        activeCount = liveCount;
                        sessionsHtml = sortedSessions.map(s => {
                            const normalized = normalizeUsername(s.username);
                            const isLive = liveUsersOnTarget.some(live =>
                                usernamesMatch(normalized, live.raw) ||
                                live.aliasCandidates.some(alias => usernamesMatch(normalized, alias))
                            );
                            const isPinned = manualRoutes.has(normalized) || manualAliases.has(normalized);
                            const color = isLive ? '#2ecc71' : (s.state === 'Active' ? '#f39c12' : '#e74c3c');
                            const icon = isLive ? '🟢' : (s.state === 'Active' ? '🟡' : '🔴');
                            const badges = `${isLive ? '<span class="tag tag-green" style="font-size:0.7em; margin-left:6px;">LIVE</span>' : '<span class="tag tag-grey" style="font-size:0.7em; margin-left:6px;">AGENT</span>'}${isPinned ? '<span class="tag tag-grey" style="font-size:0.7em; margin-left:4px;">FIXO</span>' : ''}`;
                            const stateText = s.state === 'Active' ? '' : ' <span style="font-size:0.75em; color:#e74c3c;">(Disc)</span>';
                            return `<div style="margin-bottom:2px; white-space:nowrap;">
                                            <span style="color:${color}; font-size:0.8em;">${icon}</span> 
                                            <b>${escapeHtml(normalized)}</b>${stateText}${badges}
                                        </div>`;
                        }).join('');
                        sessionsHtml = `<div style="font-size:0.75em; color:#666; margin-bottom:4px;">LIVE ${liveCount} / AGENT ${sortedSessions.length}</div>${sessionsHtml}`;
                    } else if (agentData.sessions) {
                        sessionsHtml = '<span style="color:#999">Vazio</span>';
                    }

                    // Formata Uptime
                    let uptimeStr = '-';
                    if (agentData.uptime) {
                        const d = Math.floor(agentData.uptime / 86400);
                        const h = Math.floor((agentData.uptime % 86400) / 3600);
                        const m = Math.floor((agentData.uptime % 3600) / 60);
                        uptimeStr = `${d}d ${h}h ${m}m`;
                    }

                    let statusHtml = '';
                    if (health.status === 'ONLINE') statusHtml = `<span class="tag tag-green">ONLINE (${health.latency}ms)</span>`;
                    else if (health.status === 'OFFLINE') statusHtml = `<span class="tag tag-red">OFFLINE</span>`;
                    else statusHtml = `<span class="tag tag-grey">PENDING</span>`;

                    // Barras de Progresso
                    const cpuColor = cpu > 80 ? '#e74c3c' : cpu > 50 ? '#f39c12' : '#2ecc71';
                    const ramColor = ram > 80 ? '#e74c3c' : ram > 50 ? '#f39c12' : '#2ecc71';

                    // Formata Last Report (Heartbeat)
                    let lastReportStr = 'Nunca';
                    let rowStyle = 'border-bottom:1px solid #ddd;';
                    if (agentData.lastReport) {
                        const diff = Math.floor((Date.now() - agentData.lastReport) / 1000);
                        const time = new Date(agentData.lastReport).toLocaleTimeString('pt-BR');
                        lastReportStr = `${time} <span style="font-size:0.8em; color:#666;">(${diff}s atrás)</span>`;

                        // Alerta se > 15s sem report
                        if (diff > 15) {
                            rowStyle = 'border-bottom:1px solid #ddd; background-color: rgba(231, 76, 60, 0.1);';
                            lastReportStr += ' <span class="tag tag-red">⚠️ ATRASADADO</span>';
                        }
                    }

                    return `
                                    <tr style="${rowStyle}">
                                        <td style="padding:10px;">
                                            <b>${escapeHtml(name)}</b><br>
                                            <span style="font-size:0.8em; color:#666;">${t.host}:${t.port}</span>
                                        </td>
                                        <td style="padding:10px;">${statusHtml}</td>
                                        <td style="padding:10px; width:150px;">
                                            <div style="background:#eee; height:20px; border-radius:10px; overflow:hidden; position:relative;">
                                                <div style="background:${cpuColor}; width:${cpu}%; height:100%;"></div>
                                                <span style="position:absolute; top:0; left:0; width:100%; text-align:center; font-size:0.8em; line-height:20px; color:#333; font-weight:bold;">${cpu}%</span>
                                            </div>
                                        </td>
                                        <td style="padding:10px; width:150px;">
                                            <div style="background:#eee; height:20px; border-radius:10px; overflow:hidden; position:relative;">
                                                <div style="background:${ramColor}; width:${ram}%; height:100%;"></div>
                                                <span style="position:absolute; top:0; left:0; width:100%; text-align:center; font-size:0.8em; line-height:20px; color:#333; font-weight:bold;">${ram}%</span>
                                            </div>
                                        </td>
                                        <td style="padding:10px; font-size:0.9em;">${sessionsHtml}</td>
                                        <td style="padding:10px; font-size:0.9em;">${uptimeStr}</td>
                                        <td style="padding:10px; font-size:0.9em;">${lastReportStr}</td>
                                        <td style="padding:10px;">
                                            <form action="/api/weight" method="POST" class="form-inline" style="margin:0;"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}">
                                                <input type="hidden" name="target" value="${key}">
                                                <input type="number" name="weight" value="${w}" min="0" style="width: 50px; padding:4px;">
                                                <button type="submit" class="btn btn-blue" style="padding:4px 8px; font-size:0.8em;">ok</button>
                                            </form>
                                        </td>
                                    </tr>`;
                }).join('')}
                            </tbody>
                        </table>
                    </div>

                    <div class="card">
                        <h2>Configurações de Usuário</h2>
                        <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                            <div style="flex: 1; min-width: 300px; background: #f9f9f9; padding: 10px; border-radius: 5px;">
                                <h3>Apelido em Massa</h3>
                                <form action="/api/bulk-alias" method="POST"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}">
                                    <textarea name="userList" rows="3" style="width: 100%;" placeholder="Cole lista..."></textarea>
                                    <button type="submit" class="btn btn-blue">Importar</button>
                                </form>
                            </div>
                            <div style="flex: 1; min-width: 300px; background: #f9f9f9; padding: 10px; border-radius: 5px;">
                                <h3>Rota Fixa</h3>
                                <form action="/api/route" method="POST" class="form-inline"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}">
                                    <input type="text" name="username" placeholder="Usuário" required style="width:100px">
                                    <select name="target">
                                        <option value="CLEAR">-- Remover --</option>
                                        ${targets.map(t => `<option value="${t.host}:${t.port}">${t.host}:${t.port}</option>`).join('')}
                                    </select>
                                    <button type="submit" class="btn btn-blue">Salvar</button>
                                </form>
                                <div style="max-height: 200px; overflow-y: auto;">
                                    <ul>
                                        ${Array.from(manualRoutes.entries()).map(([u, t]) => `
                                            <li style="margin-bottom:5px; border-bottom:1px solid #ccc; padding:2px; display:flex; justify-content:space-between; align-items:center;">
                                                <span><b>${escapeHtml(u)}</b> -> ${escapeHtml(t)}</span>
                                                <form action="/api/route" method="POST" style="margin:0;"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}">
                                                    <input type="hidden" name="username" value="${escapeHtml(u)}">
                                                    <input type="hidden" name="target" value="CLEAR">
                                                    <button type="submit" class="btn btn-red" style="font-size:0.7em; padding:2px 6px;">X</button>
                                                </form>
                                            </li>
                                        `).join('') || '<li>Nenhuma rota.</li>'}
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="card">
                        <h2>Sessões Ativas</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>Usuário</th>
                                    <th>IP</th>
                                    <th>Destino</th>
                                    <th>Tempo</th>
                                    <th>Ação</th>
                                </tr>
                            </thead>
                            <tbody>
            `;

    if (globalSessions.size === 0) {
        html += `<tr><td colspan="5" style="text-align:center">Nenhuma conexão ativa.</td></tr>`;
    } else {
        for (const [id, session] of globalSessions.entries()) {
            const alias = manualAliases.get(session.user) || session.user;
            const displayName = (alias !== session.user) ? `<b>${escapeHtml(alias)}</b> <small>(${escapeHtml(session.user)})</small>` : `<b>${escapeHtml(session.user)}</b>`;

            html += `
                        <tr>
                            <td>${displayName}</td>
                            <td>${escapeHtml(session.clientIp)}</td>
                            <td>${escapeHtml(session.targetHost)}:${escapeHtml(session.targetPort)}</td>
                            <td>${Math.floor((Date.now() - session.startTime) / 1000)}s</td>
                            <td>
                                <form action="/api/kill" method="POST" style="display:inline"><input type="hidden" name="key" value="${escapeHtml(API_SECRET || '')}">
                                    <input type="hidden" name="connectionId" value="${id}">
                                    <input type="hidden" name="workerId" value="${session.workerId}">
                                    <button type="submit" class="btn btn-red">KILL</button>
                                </form>
                            </td>
                        </tr>
                    `;
        }
    }

    html += `</tbody></table></div></div></body></html>`;
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
}
    }).listen(DASHBOARD_PORT);

} else {
    // === WORKER ===
    const socketMap = new Map();
    let workerManualRoutes = new Map();
    let workerServerWeights = new Map();
    let workerServerHealth = new Map();
    let workerBalancingStrategy = 'NAME';
    let workerBlacklistIPs = new Set();
    let workerBlacklistUsers = new Set();
    let workerIsLearningMode = false;

    // === CONSTANTES DE PRODUÇÃO ===
    const BACKEND_CONNECT_TIMEOUT = 5000;  // 5s timeout para conectar ao backend
    const INITIAL_DATA_TIMEOUT = 10000;    // 10s para cliente enviar dados iniciais
    const MAX_CONNECTIONS_PER_WORKER = 500; // Limite de conexões por worker
    let activeConnections = 0;

    // Erros de rede que devem ser ignorados (não são bugs)
    const IGNORED_ERRORS = ['ECONNRESET', 'EPIPE', 'ETIMEDOUT', 'ECONNREFUSED', 'EHOSTUNREACH'];
    const shouldIgnoreError = (err) => IGNORED_ERRORS.includes(err?.code);

    // Antispam Memory
    const ipHistory = new Map(); // IP -> { count, windowStart }
    const userHistory = new Map(); // User -> { count, windowStart }

    // Limpeza periódica de memória anti-spam (a cada 60s)
    setInterval(() => {
        const now = Date.now();
        for (const [key, record] of ipHistory.entries()) {
            if (now - record.windowStart > 60000) ipHistory.delete(key);
        }
        for (const [key, record] of userHistory.entries()) {
            if (now - record.windowStart > 60000) userHistory.delete(key);
        }
    }, 60000);

    targets.forEach(t => workerServerWeights.set(`${t.host}:${t.port}`, 1));

    let isShuttingDown = false;

    process.on('message', (msg) => {
        if (msg.type === 'CMD_KILL') {
            const socket = socketMap.get(msg.connectionId);
            if (socket) {
                socket.destroy();
                socketMap.delete(msg.connectionId);
            }
        }
        else if (msg.type === 'CMD_UPDATE_CONFIG') {
            workerManualRoutes = new Map(msg.manualRoutes);
            workerServerWeights = new Map(msg.serverWeights);
            if (msg.serverHealth) workerServerHealth = new Map(msg.serverHealth);
            if (msg.balancingStrategy) workerBalancingStrategy = msg.balancingStrategy;
            if (msg.blacklistedIPs) workerBlacklistIPs = new Set(msg.blacklistedIPs);
            if (msg.blacklistedUsers) workerBlacklistUsers = new Set(msg.blacklistedUsers);
            if (msg.isLearningMode !== undefined) workerIsLearningMode = msg.isLearningMode;
        }
        else if (msg.type === 'CMD_SHUTDOWN') {
            isShuttingDown = true;
            console.log(`[WORKER ${cluster.worker.id}] Encerrando conexões...`);
            for (const [id, socket] of socketMap.entries()) {
                socket.destroy();
            }
            socketMap.clear();
            process.exit(0);
        }
    });

    // Filtra servidores disponíveis (online e peso > 0)
    const getAvailableTargets = () => {
        return targets.filter(t => {
            const key = `${t.host}:${t.port}`;
            const weight = workerServerWeights.get(key) || 1;
            const health = workerServerHealth.get(key);
            const isOnline = !health || health.status === 'ONLINE' || health.status === 'PENDING';
            return weight > 0 && isOnline;
        });
    };

    const normalizeIp = (ip) => {
        if (!ip) return ip;
        return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
    };

    // Função de hash para sticky sessions
    const hashString = (str) => {
        let hash = 5381;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) + hash) + str.charCodeAt(i);
        }
        return Math.abs(hash);
    };

    const getWeightedTarget = () => {
        const available = getAvailableTargets();
        if (available.length === 0) {
            // Fallback: tenta qualquer servidor, mesmo offline
            console.log('[WORKER] AVISO: Nenhum servidor disponível, usando fallback.');
            return targets[0] || null;
        }

        const expandedTargets = [];
        available.forEach(t => {
            const w = workerServerWeights.get(`${t.host}:${t.port}`) || 1;
            for (let k = 0; k < w; k++) expandedTargets.push(t);
        });

        if (expandedTargets.length === 0) return available[0];
        return expandedTargets[Math.floor(Math.random() * expandedTargets.length)];
    };

    // Seleciona servidor por hash, respeitando health e peso
    const getHashedTarget = (hashKey) => {
        const available = getAvailableTargets();
        if (available.length === 0) {
            console.log('[WORKER] AVISO: Nenhum servidor disponível para hash, usando fallback.');
            return targets[0] || null;
        }
        const hash = hashString(hashKey);
        const index = hash % available.length;
        return available[index];
    };

    // Seleciona servidor com MENOR uso de RAM
    const getSmartTarget = () => {
        const available = getAvailableTargets();
        if (available.length === 0) {
            console.log('[WORKER] AVISO: Nenhum servidor disponível para Smart Ram, usando fallback.');
            return targets[0] || null;
        }

        // Filtra apenas servidores com dados de RAM
        const withRam = available.filter(t => {
            const key = `${t.host}:${t.port}`;
            const h = workerServerHealth.get(key);
            return h && h.ram !== undefined;
        });

        if (withRam.length === 0) {
            // Se ninguém reportou RAM ainda, usa Weighted
            return getWeightedTarget();
        }

        // Ordena por RAM crescente (menor uso primeiro)
        withRam.sort((a, b) => {
            const hA = workerServerHealth.get(`${a.host}:${a.port}`);
            const hB = workerServerHealth.get(`${b.host}:${b.port}`);
            return hA.ram - hB.ram;
        });

        return withRam[0];
    };

    const createServer = (port) => {
        const server = net.createServer((clientSocket) => {
            // Limite de conexões por worker
            if (activeConnections >= MAX_CONNECTIONS_PER_WORKER) {
                clientSocket.destroy();
                return;
            }
            activeConnections++;

            clientSocket.setNoDelay(true);
            clientSocket.setKeepAlive(true, 5000);

            const clientIp = normalizeIp(clientSocket.remoteAddress);

            // Timeout se cliente não enviar dados iniciais
            clientSocket.setTimeout(INITIAL_DATA_TIMEOUT);
            clientSocket.on('timeout', () => {
                clientSocket.destroy();
            });

            // 1. CHECAGEM DE IP BLACKLIST (Imediata)
            if (clientIp && workerBlacklistIPs.has(clientIp)) {
                activeConnections--;
                clientSocket.destroy();
                return;
            }

            // 2. IP RATE LIMITING (Tracking - sem ban automático)
            if (clientIp) {
                const now = Date.now();
                const record = ipHistory.get(clientIp) || { count: 0, windowStart: now };
                if (now - record.windowStart > 5000) { record.count = 0; record.windowStart = now; }
                record.count++;
                ipHistory.set(clientIp, record);

                if (record.count > 5) {
                    // Reporta atividade suspeita (sem banir)
                    process.send({ type: 'CMD_SUSPICIOUS_ACTIVITY', ip: clientIp, reason: 'IP_FLOOD', count: record.count });
                }
            }

            const connectionId = `${cluster.worker.id}_${Date.now()}_${Math.random()}`;
            socketMap.set(connectionId, clientSocket);

            let userInfo = null;

            clientSocket.once('data', (data) => {
                // Busca mstshash no buffer binário (ANSI dentro de X.224)
                const payload = data.toString('latin1');
                const match = payload.match(/mstshash=([^\r\n]+)/i);

                let target;
                let username = null;

                if (match && match[1]) {
                    let raw = match[1].trim();
                    // Remove domínio (DOMINIO\usuario → usuario)
                    if (raw.includes('\\')) {
                        raw = raw.split('\\').pop();
                    }
                    // Remove domínio formato UPN (usuario@dominio → usuario)
                    if (raw.includes('@')) {
                        raw = raw.split('@')[0];
                    }
                    if (raw.length > 0) {
                        username = raw;
                    }
                }

                // 3. USERNAME CHECK
                if (username) {
                    // Bloqueia user banido (Case Insensitive)
                    const isBanned = Array.from(workerBlacklistUsers).some(u => u.toLowerCase() === username.toLowerCase());

                    if (isBanned) {
                        process.send({ type: 'CMD_SUSPICIOUS_ACTIVITY', ip: clientIp, user: username, reason: 'BANNED_USER' });
                        clientSocket.destroy();
                        return;
                    }
                    // Tracking de frequência
                    const now = Date.now();
                    const record = userHistory.get(username) || { count: 0, windowStart: now };
                    if (now - record.windowStart > 5000) { record.count = 0; record.windowStart = now; }
                    record.count++;
                    userHistory.set(username, record);
                    if (record.count > 5) {
                        // Reporta atividade suspeita (sem banir)
                        process.send({ type: 'CMD_SUSPICIOUS_ACTIVITY', ip: clientIp, user: username, reason: 'USER_FLOOD', count: record.count });
                    }
                }

                // 4. LEARNING MODE & ROUTING
                let isFixed = false;

                if (username && workerManualRoutes.has(username)) {
                    // Rota Fixa (JÁ PRESA)
                    const hostPort = workerManualRoutes.get(username);
                    const [h, p] = hostPort.split(':');
                    target = { host: h, port: parseInt(p) };
                    isFixed = true;
                }
                else if (workerBalancingStrategy === 'IP') {
                    target = getHashedTarget(clientIp || 'unknown');
                }
                else if (workerBalancingStrategy === 'HYBRID') {
                    const uniqueKey = (username || 'unknown') + (clientIp || '');
                    target = getHashedTarget(uniqueKey);
                }
                else if (workerBalancingStrategy === 'RAM') {
                    // Estratégia SMART: Menor uso de RAM (com fallback para Weighted se sem dados)
                    target = getSmartTarget();
                }
                else if (username) {
                    target = getHashedTarget(username);
                }
                else {
                    target = getWeightedTarget();
                }

                // Verifica se há servidor disponível
                if (!target) {
                    console.log('[WORKER] ERRO: Nenhum servidor disponível. Fechando conexão.');
                    clientSocket.destroy();
                    return;
                }

                // AUTO-LEARN
                if (workerIsLearningMode && username && !isFixed) {
                    process.send({
                        type: 'CMD_REGISTER_STICKY',
                        user: username,
                        targetHost: target.host,
                        targetPort: target.port
                    });
                }

                userInfo = {
                    user: normalizeUsername(username) || 'Unknown/New',
                    clientIp: clientIp,
                    targetHost: target.host,
                    targetPort: target.port,
                    workerId: cluster.worker.id,
                    startTime: Date.now()
                };

                if (process.send) {
                    process.send({ type: 'SESSION_CONNECTED', id: connectionId, data: userInfo });
                }

                let serverSocket = null;
                let cleanupDone = false;

                const cleanup = () => {
                    if (cleanupDone) return;
                    cleanupDone = true;
                    activeConnections--;
                    socketMap.delete(connectionId);
                    if (serverSocket) {
                        serverSocket.unpipe();
                        serverSocket.destroy();
                        serverSocket = null;
                    }
                    clientSocket.unpipe();
                    clientSocket.destroy();
                    if (userInfo && process.send) {
                        process.send({ type: 'SESSION_DISCONNECTED', id: connectionId });
                        userInfo = null;
                    }
                };

                serverSocket = net.connect(target.port, target.host, () => {
                    clientSocket.setTimeout(0); // Remove timeout inicial após receber dados
                    serverSocket.setTimeout(0); // Remove timeout de conexão
                    serverSocket.setNoDelay(true);
                    serverSocket.setKeepAlive(true, 10000); // Keep-alive mais agressivo no backend
                    serverSocket.write(data);

                    // Proxy bidirecional com tratamento de erros
                    clientSocket.pipe(serverSocket);
                    serverSocket.pipe(clientSocket);
                });

                // Timeout para conexão ao backend (5s)
                serverSocket.setTimeout(BACKEND_CONNECT_TIMEOUT);
                serverSocket.on('timeout', () => {
                    cleanup();
                });

                serverSocket.on('error', (err) => {
                    if (!shouldIgnoreError(err)) {
                        console.error(`[WORKER] Erro backend ${target.host}:${target.port}:`, err.code || err.message);
                    }
                    cleanup();
                });

                serverSocket.on('close', () => {
                    cleanup();
                });

                clientSocket.on('error', (err) => {
                    if (!shouldIgnoreError(err)) {
                        console.error(`[WORKER] Erro cliente ${clientIp}:`, err.code || err.message);
                    }
                    cleanup();
                });

                clientSocket.on('close', () => {
                    cleanup();
                });
            });
        });

        server.on('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                console.error(`[WORKER] ERRO CRÍTICO: A porta ${port} já está em uso! Verifique se não há outro serviço rodando.`);
                process.exit(1);
            } else {
                console.error(`[WORKER] Erro no servidor:`, err);
            }
        });

        server.listen(port);
    };

    ports.forEach(port => createServer(port));
}
