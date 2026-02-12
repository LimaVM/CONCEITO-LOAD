require('dotenv').config();
const { execSync } = require('child_process');
const http = require('http');
const os = require('os');

// === CONFIGURAÇÃO ===
const LOAD_BALANCER_URL = process.env.LOAD_BALANCER_URL || 'http://10.0.0.1:3000';
const REPORT_INTERVAL = parseInt(process.env.REPORT_INTERVAL) || 5000;
const DASHBOARD_PORT = parseInt(process.env.DASHBOARD_PORT) || 62873;
const SERVER_ID = process.env.SERVER_ID || os.hostname();
const API_SECRET = process.env.API_SECRET; // AUTH TOKEN

if (!API_SECRET) {
    console.warn('⚠️ AVISO: API_SECRET não definido! O Agente pode ser recusado pelo Master.');
}

// Keep-Alive Agent para reutilizar conexões TCP (Performance)
const keepAliveAgent = new http.Agent({
    keepAlive: true,
    maxSockets: 1,
    keepAliveMsecs: 3000
});

// === ESTADO ===
let lastSessions = [];
let sessionStartTimes = new Map(); // sessionId -> timestamp
let lastReportStatus = 'Aguardando...';
let lastReportTime = null;
let reportCount = 0;
let errorCount = 0;
let bannedUsers = []; // Lista recebida do Load Balancer
let blockedIPs = new Set(); // IPs bloqueados no firewall local
let cpuUsage = 0; // % de uso de CPU
const logs = [];
const MAX_LOGS = 100;

const addLog = (msg) => {
    const timestamp = new Date().toLocaleTimeString('pt-BR');
    const entry = `[${timestamp}] ${msg}`;
    logs.unshift(entry);
    if (logs.length > MAX_LOGS) logs.pop();
    console.log(entry);
};

const normalizeUsername = (value) => {
    if (!value) return '';
    let normalized = String(value).trim();
    if (normalized.includes('\\')) normalized = normalized.split('\\').pop();
    if (normalized.includes('@')) normalized = normalized.split('@')[0];
    return normalized.trim();
};

// IP local deste servidor
const getLocalIPs = () => {
    const interfaces = os.networkInterfaces();
    const ips = [];
    for (const name in interfaces) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                ips.push(iface.address);
            }
        }
    }
    return ips;
};

const LOCAL_IPS = getLocalIPs();

// === SYNC FIREWALL (Bloqueio de IPs) ===
const syncFirewall = (targetIPs) => {
    const targets = new Set(targetIPs);

    // 1. Bloquear novos IPs
    for (const ip of targets) {
        if (!blockedIPs.has(ip)) {
            try {
                // Nome da regra: CONCEITO-BLOCK-{IP}
                const ruleName = `CONCEITO-BLOCK-${ip}`;
                // Remove regra antiga se existir (pra garantir)
                try { execSync(`netsh advfirewall firewall delete rule name="${ruleName}"`, { stdio: 'ignore' }); } catch (e) { }

                // Adiciona nova regra
                execSync(`netsh advfirewall firewall add rule name="${ruleName}" dir=in action=block remoteip=${ip}`, { stdio: 'ignore' });

                blockedIPs.add(ip);
                addLog(`🛡️ FIREWALL: IP ${ip} bloqueado localmente.`);
            } catch (err) {
                addLog(`❌ Falha ao bloquear IP ${ip}: ${err.message}`);
            }
        }
    }

    // 2. Desbloquear IPs removidos
    for (const ip of blockedIPs) {
        if (!targets.has(ip)) {
            try {
                const ruleName = `CONCEITO-BLOCK-${ip}`;
                execSync(`netsh advfirewall firewall delete rule name="${ruleName}"`, { stdio: 'ignore' });
                blockedIPs.delete(ip);
                addLog(`🔓 FIREWALL: IP ${ip} desbloqueado.`);
            } catch (err) {
                addLog(`❌ Falha ao desbloquear IP ${ip}: ${err.message}`);
            }
        }
    }
};

// === PARSER DO QWINSTA ===
const getActiveSessions = () => {
    try {
        const output = execSync('qwinsta', {
            encoding: 'utf8',
            timeout: 10000,
            windowsHide: true
        });

        const lines = output.split('\n').slice(1);
        const sessions = [];

        const currentSessionIds = new Set();
        const activeSessions = [];

        for (const line of lines) {
            if (!line.trim()) continue;

            const sessionName = line.substring(1, 19).trim();
            const username = normalizeUsername(line.substring(19, 41).trim());
            const idStr = line.substring(41, 46).trim();
            const state = line.substring(46, 54).trim();
            const sessionId = parseInt(idStr) || 0;

            if (state === 'Ativo' || state === 'Active' || state === 'Disc' || state === 'Disconnected') {
                if (username && username.length > 0) {
                    // Ignora sistema/serviços se não for RDP
                    // Mas queremos pegar usuários desconectados também

                    // Rastreia firstSeen
                    if (!sessionStartTimes.has(sessionId)) {
                        sessionStartTimes.set(sessionId, Date.now());
                    }
                    currentSessionIds.add(sessionId);

                    activeSessions.push({
                        sessionName,
                        username,
                        sessionId,
                        state: (state === 'Ativo' || state === 'Active') ? 'Active' : 'Disc',
                        loginTime: sessionStartTimes.get(sessionId)
                    });
                }
            }
        }

        // Limpa sessões antigas
        for (const id of sessionStartTimes.keys()) {
            if (!currentSessionIds.has(id)) {
                sessionStartTimes.delete(id);
            }
        }

        return activeSessions;
    } catch (err) {
        addLog(`❌ Erro qwinsta: ${err.message}`);
        errorCount++;
        return [];
    }
};

// === MONITORAMENTO DE CPU (Tick Diff) ===
let previousCpus = os.cpus();

const measureCPU = () => {
    const currentCpus = os.cpus();
    let totalIdle = 0;
    let totalTick = 0;

    for (let i = 0; i < currentCpus.length; i++) {
        const prev = previousCpus[i];
        const curr = currentCpus[i];

        let idle = curr.times.idle - prev.times.idle;
        let tick = 0;

        for (const type in curr.times) {
            tick += curr.times[type] - prev.times[type];
        }

        totalIdle += idle;
        totalTick += tick;
    }

    previousCpus = currentCpus;

    // Evita divisão por zero
    if (totalTick === 0) return 0;

    const idlePercent = totalIdle / totalTick;
    return Math.round((1 - idlePercent) * 100);
};



// === REPORT PARA O LOAD BALANCER ===
const reportSessions = (sessions) => {
    // Calcula uso de RAM
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const ramUsage = Math.round((usedMem / totalMem) * 100);

    const data = JSON.stringify({
        serverId: SERVER_ID,
        serverIPs: LOCAL_IPS,
        sessions: sessions,
        ramUsage: ramUsage,
        cpuUsage: cpuUsage, // Adiciona CPU
        uptime: os.uptime(), // Adiciona Uptime (segundos)
        timestamp: Date.now()
    });

    try {
        const url = new URL(LOAD_BALANCER_URL + '/api/agent-report');

        const options = {
            hostname: url.hostname,
            port: url.port || 80,
            path: url.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data),
                'x-api-key': API_SECRET || '' // Envia token de auth
            },
            agent: keepAliveAgent, // Usa conexão persistente
            timeout: 5000
        };

        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', chunk => { body += chunk; });
            res.on('end', () => {
                lastReportStatus = `✅ OK (HTTP ${res.statusCode})`;
                lastReportTime = Date.now();
                reportCount++;

                // Processa resposta com lista de bans
                try {
                    const response = JSON.parse(body);
                    if (response.bannedUsers && Array.isArray(response.bannedUsers)) {
                        bannedUsers = response.bannedUsers;
                    }
                    if (response.bannedIPs && Array.isArray(response.bannedIPs)) {
                        syncFirewall(response.bannedIPs);
                    }
                } catch (e) {
                    // Resposta não é JSON válido
                }
            });
        });

        req.on('error', (err) => {
            lastReportStatus = `❌ Erro: ${err.code || err.message}`;
            errorCount++;
            addLog(`❌ Report falhou: ${err.code || err.message}`);
        });

        req.on('timeout', () => {
            lastReportStatus = '❌ Timeout';
            errorCount++;
            req.destroy();
        });

        req.write(data);
        req.end();
    } catch (err) {
        lastReportStatus = `❌ Erro: ${err.message}`;
        errorCount++;
        addLog(`❌ Erro HTTP: ${err.message}`);
    }
};

// === ESCAPE HTML ===
const esc = (str) => {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
};

// === DASHBOARD WEB ===
const dashboardServer = http.createServer((req, res) => {
    if (req.url === '/api/status') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            serverId: SERVER_ID,
            localIPs: LOCAL_IPS,
            loadBalancer: LOAD_BALANCER_URL,
            sessions: lastSessions,
            bannedUsers,
            kickedSessions: [], // Removido
            lastReportStatus,
            lastReportTime,
            reportCount,
            errorCount,
            uptime: process.uptime()
        }));
        return;
    }

    // Dashboard HTML
    const uptimeMin = Math.floor(process.uptime() / 60);
    const lastReportAgo = lastReportTime ? Math.floor((Date.now() - lastReportTime) / 1000) + 's atrás' : 'Nunca';

    let html = `<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ConceitoLoad Agent - ${esc(SERVER_ID)}</title>
    <meta http-equiv="refresh" content="5">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #16213e, #0f3460); padding: 20px 30px; border-bottom: 3px solid #e94560; }
        .header h1 { font-size: 1.4em; color: #e94560; }
        .header p { color: #8899aa; font-size: 0.9em; margin-top: 4px; }
        .container { max-width: 1100px; margin: 20px auto; padding: 0 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat { background: #16213e; padding: 18px; border-radius: 10px; text-align: center; border: 1px solid #0f3460; }
        .stat h3 { font-size: 2em; color: #e94560; }
        .stat p { color: #8899aa; font-size: 0.85em; margin-top: 4px; }
        .card { background: #16213e; border-radius: 10px; padding: 20px; margin-bottom: 20px; border: 1px solid #0f3460; }
        .card h2 { color: #e94560; margin-bottom: 15px; font-size: 1.2em; border-bottom: 1px solid #0f3460; padding-bottom: 8px; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #0f3460; color: #e94560; padding: 10px; text-align: left; font-size: 0.85em; }
        td { padding: 10px; border-bottom: 1px solid #0f3460; font-size: 0.9em; }
        tr:hover { background: rgba(233, 69, 96, 0.05); }
        .tag { padding: 3px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; display: inline-block; }
        .tag-ok { background: #27ae60; color: white; }
        .tag-err { background: #e74c3c; color: white; }
        .tag-warn { background: #f39c12; color: white; }
        .tag-wait { background: #7f8c8d; color: white; }
        .logs { max-height: 250px; overflow-y: auto; background: #0d1117; border-radius: 6px; padding: 12px; font-family: 'Consolas', monospace; font-size: 0.8em; color: #8b949e; }
        .logs p { padding: 2px 0; border-bottom: 1px solid #1a1a2e; }
        .config-info { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .config-item { background: #0f3460; padding: 10px; border-radius: 6px; }
        .config-item label { color: #e94560; font-size: 0.8em; display: block; }
        .config-item span { font-size: 0.95em; word-break: break-all; }
        .ban-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
        .ban-tag { background: #e74c3c; color: white; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 ConceitoLoad Agent Reporter</h1>
        <p>${esc(SERVER_ID)} — Porta ${DASHBOARD_PORT}</p>
    </div>
    <div class="container">
        <div class="stats">
            <div class="stat"><h3>${lastSessions.length}</h3><p>Sessões RDP</p></div>
            <div class="stat"><h3>${bannedUsers.length}</h3><p>Users Banidos</p></div>
            <div class="stat"><h3>${blockedIPs.size}</h3><p>IPs Bloqueados</p></div>
            <div class="stat"><h3>${reportCount}</h3><p>Reports</p></div>
            <div class="stat"><h3>${errorCount}</h3><p>Erros</p></div>
            <div class="stat"><h3>${uptimeMin}m</h3><p>Uptime</p></div>
        </div>

        <div class="card">
            <h2>⚙️ Configuração</h2>
            <div class="config-info">
                <div class="config-item"><label>Load Balancer</label><span>${esc(LOAD_BALANCER_URL)}</span></div>
                <div class="config-item"><label>IPs Locais</label><span>${LOCAL_IPS.join(', ')}</span></div>
                <div class="config-item"><label>Último Report</label><span>${lastReportAgo}</span></div>
                <div class="config-item"><label>Status</label><span>${lastReportStatus.includes('✅') ? '<span class="tag tag-ok">Conectado</span>' : lastReportStatus.includes('❌') ? '<span class="tag tag-err">Erro</span>' : '<span class="tag tag-wait">Aguardando</span>'}</span></div>
            </div>
        </div>

        <div class="card">
            <h2>👥 Sessões RDP Ativas</h2>
            <table>
                <thead><tr><th>Sessão</th><th>Usuário</th><th>ID</th><th>Status</th></tr></thead>
                <tbody>`;

    if (lastSessions.length === 0) {
        html += '<tr><td colspan="4" style="text-align:center; color:#666;">Nenhuma sessão RDP ativa.</td></tr>';
    } else {
        lastSessions.forEach(s => {
            const isBanned = bannedUsers.some(b => {
                const lower = s.username.toLowerCase();
                const bannedLower = b.toLowerCase();
                return lower === bannedLower || lower.startsWith(bannedLower) || bannedLower.startsWith(lower);
            });
            html += `<tr>
                <td>${esc(s.sessionName)}</td>
                <td><b>${esc(s.username)}</b></td>
                <td>${s.sessionId}</td>
                <td>${isBanned ? '<span class="tag tag-err">⛔ BANIDO</span>' : '<span class="tag tag-ok">OK</span>'}</td>
            </tr>`;
        });
    }

    html += `</tbody></table></div>

        <div class="card" style="border-color: #e74c3c;">
            <h2>🚫 Usuários Banidos (via Load Balancer)</h2>
            <div class="ban-list">
                ${bannedUsers.length === 0 ? '<span style="color:#666;">Nenhum usuário banido.</span>' :
            bannedUsers.map(u => `<span class="ban-tag">⛔ ${esc(u)}</span>`).join('')}
            </div>
        </div>`;

    html += `<div class="card">
            <h2>📋 Logs</h2>
            <div class="logs">`;

    if (logs.length === 0) {
        html += '<p>Nenhum log ainda.</p>';
    } else {
        logs.forEach(log => {
            html += `<p>${esc(log)}</p>`;
        });
    }

    html += `</div></div>
    </div>
</body></html>`;

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
});

dashboardServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        addLog(`❌ ERRO: Porta ${DASHBOARD_PORT} já em uso!`);
        process.exit(1);
    }
    addLog(`❌ Erro servidor dashboard: ${err.message}`);
});

// === LOOP PRINCIPAL ===
const tick = () => {
    // 1. Coleta Sessões
    const sessions = getActiveSessions();

    // 2. Mede CPU (Intervalo entre reports)
    cpuUsage = measureCPU();

    lastSessions = sessions;
    reportSessions(sessions);
    if (sessions.length > 0) {
        addLog(`📡 ${sessions.length} sessão(ões): ${sessions.map(s => s.username).join(', ')}`);
    }
};

// === INÍCIO ===
dashboardServer.listen(DASHBOARD_PORT, '0.0.0.0', () => {
    addLog('=== ConceitoLoad Agent Reporter ===');
    addLog(`Servidor: ${SERVER_ID}`);
    addLog(`IPs: ${LOCAL_IPS.join(', ')}`);
    addLog(`Load Balancer: ${LOAD_BALANCER_URL}`);
    addLog(`Dashboard: http://localhost:${DASHBOARD_PORT}`);
    addLog(`Intervalo: ${REPORT_INTERVAL}ms`);
    addLog('Aguardando sessões...');

    setTimeout(tick, 2000);
    setInterval(tick, REPORT_INTERVAL);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    addLog('Encerrando...');
    dashboardServer.close();
    process.exit(0);
});
process.on('SIGINT', () => {
    addLog('Encerrando...');
    dashboardServer.close();
    process.exit(0);
});
