require('dotenv').config();

const express = require('express');
const cron = require('node-cron');
const fetch = require('node-fetch');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Config (set as environment variables in DigitalOcean) ──────────────────
const KAFKA_UI_URL    = process.env.KAFKA_UI_URL    || 'https://kafka-ui.prod.zwing.in';
const CLUSTER_NAME    = process.env.CLUSTER_NAME    || 'central-zwing';
const UI_PASSWORD     = process.env.UI_PASSWORD;      // optional: if set, UI requires login
const SESSION_SECRET  = process.env.SESSION_SECRET || 'kafka-monitor-default-change-in-prod';
const SLACK_WEBHOOK   = process.env.SLACK_WEBHOOK;
const CHECK_INTERVAL  = process.env.CHECK_INTERVAL  || '*/15 * * * *'; // every 15 min
const KAFKA_UI_USER   = process.env.KAFKA_UI_USER   || 'admin';
const KAFKA_UI_PASS   = process.env.KAFKA_UI_PASS   || 'prodkafka@admin@123';
const LAG_THRESHOLD   = parseInt(process.env.LAG_THRESHOLD || '10000', 10); // alert if lag > this
const CHECK_BALANCE   = process.env.CHECK_PARTITION_BALANCE !== 'false'; // verify partition distribution across members

// ── UI Auth (password protection) ───────────────────────────────────────────
const AUTH_COOKIE = 'kafka_monitor_auth';

function signCookie(val) {
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(val).digest('base64url');
  return `${val}.${sig}`;
}

function verifyCookie(val) {
  if (!val || typeof val !== 'string') return false;
  const idx = val.lastIndexOf('.');
  if (idx < 0) return false;
  const payload = val.slice(0, idx);
  const sig = val.slice(idx + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'base64url'), Buffer.from(expected, 'base64url')) ? payload : false;
  } catch {
    return false;
  }
}

function requireAuth(req, res, next) {
  if (!UI_PASSWORD) return next(); // auth disabled
  const cookie = req.headers.cookie?.split(';').find(c => c.trim().startsWith(AUTH_COOKIE + '='));
  const value = cookie?.split('=')[1]?.trim();
  if (value && verifyCookie(decodeURIComponent(value)) === 'ok') return next();
  if (req.path === '/login' || req.path.startsWith('/login')) return next();
  if (req.xhr || req.headers['accept']?.includes('application/json')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  return res.redirect('/login');
}

function getLoginPage(invalid) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Kafka Monitor — Sign in</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0c0e14; color: #e4e7ed;
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
      padding: 24px;
    }
    [data-theme="light"] body { background: #f5f6f9; color: #1a1d26; }
    .box {
      background: #161922; border: 1px solid #272a36; border-radius: 12px;
      padding: 32px; width: 100%; max-width: 360px; box-shadow: 0 4px 24px rgba(0,0,0,0.3);
    }
    [data-theme="light"] .box { background: #fff; border-color: #e2e6ed; box-shadow: 0 2px 16px rgba(0,0,0,0.06); }
    h1 { font-size: 1.25rem; margin-bottom: 8px; }
    .sub { font-size: 0.85rem; color: #8b92a8; margin-bottom: 24px; }
    [data-theme="light"] .sub { color: #5c6378; }
    label { display: block; font-size: 0.8rem; font-weight: 500; margin-bottom: 6px; color: #8b92a8; }
    input {
      width: 100%; padding: 10px 14px; border: 1px solid #272a36; border-radius: 8px;
      background: #0c0e14; color: #e4e7ed; font-size: 0.95rem; margin-bottom: 16px;
    }
    input:focus { outline: none; border-color: #6b9fff; box-shadow: 0 0 0 3px rgba(107,159,255,0.2); }
    [data-theme="light"] input { background: #fff; border-color: #e2e6ed; color: #1a1d26; }
    .err { color: #ef4444; font-size: 0.8rem; margin-bottom: 12px; }
    button {
      width: 100%; padding: 12px; background: #6b9fff; color: #fff; border: none; border-radius: 8px;
      font-size: 0.95rem; font-weight: 600; cursor: pointer;
    }
    button:hover { background: #5a8eef; }
  </style>
</head>
<body>
  <div class="box">
    <h1>Kafka Monitor</h1>
    <p class="sub">Enter password to continue</p>
    ${invalid ? '<p class="err">Invalid password. Please try again.</p>' : ''}
    <form method="post" action="/login">
      <label for="pw">Password</label>
      <input type="password" id="pw" name="password" placeholder="••••••••" required autofocus />
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>`;
}

// ── Session cookie cache ────────────────────────────────────────────────────
let sessionCookie = null;

async function login() {
  const res = await fetch(`${KAFKA_UI_URL}/auth`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `username=${encodeURIComponent(KAFKA_UI_USER)}&password=${encodeURIComponent(KAFKA_UI_PASS)}`,
    redirect: 'manual',
    timeout: 15000
  });
  const setCookie = res.headers.raw()['set-cookie'];
  if (!setCookie) throw new Error('Login failed: no session cookie returned');
  sessionCookie = setCookie.map(c => c.split(';')[0]).join('; ');
  console.log('[AUTH] Logged in, session cookie obtained.');
}

async function apiFetch(url) {
  if (!sessionCookie && KAFKA_UI_USER) await login();

  let res = await fetch(url, {
    headers: sessionCookie ? { Cookie: sessionCookie } : {},
    redirect: 'manual',
    timeout: 15000
  });

  // Session expired — re-login and retry once
  if ((res.status === 401 || res.status === 302) && KAFKA_UI_USER) {
    await login();
    res = await fetch(url, {
      headers: { Cookie: sessionCookie },
      redirect: 'manual',
      timeout: 15000
    });
  }

  if (!res.ok) throw new Error(`Kafka UI returned ${res.status} for ${url}`);
  return res.json();
}

// ── In-memory state ────────────────────────────────────────────────────────
let state = {
  lastChecked: null,
  connectors: [],
  consumerGroups: [],
  alerts: [],          // last 20 alert events
  checkCount: 0,
  status: 'pending'    // pending | ok | alert | error
};

// ── Core: fetch connectors ─────────────────────────────────────────────────
async function fetchConnectors() {
  return apiFetch(`${KAFKA_UI_URL}/api/clusters/${CLUSTER_NAME}/connectors`);
}

// ── Core: fetch all consumer groups (all pages) ────────────────────────────
async function fetchAllConsumerGroups() {
  const perPage = 100;
  const first = await apiFetch(
    `${KAFKA_UI_URL}/api/clusters/${CLUSTER_NAME}/consumer-groups/paged?page=0&perPage=${perPage}&sortOrder=ASC`
  );
  const groups = [...first.consumerGroups];
  const totalPages = first.pageCount || 1;

  for (let page = 1; page < totalPages; page++) {
    const data = await apiFetch(
      `${KAFKA_UI_URL}/api/clusters/${CLUSTER_NAME}/consumer-groups/paged?page=${page}&perPage=${perPage}&sortOrder=ASC`
    );
    groups.push(...data.consumerGroups);
  }
  return groups;
}

// ── Core: fetch consumer group details (partitions per member) ───────────────
async function fetchConsumerGroupDetails(groupId) {
  try {
    return await apiFetch(
      `${KAFKA_UI_URL}/api/clusters/${CLUSTER_NAME}/consumer-groups/${encodeURIComponent(groupId)}`
    );
  } catch (err) {
    console.warn(`[WARN] Could not fetch details for group ${groupId}: ${err.message}`);
    return null;
  }
}

// Build member list with topic-partition assignments from consumer group details
function buildMemberAssignments(details) {
  const partitions = details?.partitions || [];
  const byMember = {};
  for (const p of partitions) {
    const cid = p.consumerId ?? '(unknown)';
    if (!byMember[cid]) {
      byMember[cid] = { consumerId: cid, host: p.host ?? '-', topics: [] };
    }
    byMember[cid].topics.push({ topic: p.topic, partition: p.partition });
  }
  return Object.values(byMember);
}

// Check if partition distribution is balanced across members (each has roughly equal topic-partitions)
function checkPartitionBalance(details) {
  const partitions = details?.partitions || [];
  const members = details?.members ?? 0;
  if (members <= 1 || partitions.length === 0) return { balanced: true };

  const byConsumer = {};
  for (const p of partitions) {
    const cid = p.consumerId ?? '(unknown)';
    byConsumer[cid] = (byConsumer[cid] || 0) + 1;
  }
  const counts = Object.values(byConsumer);
  const min = Math.min(...counts);
  const max = Math.max(...counts);
  const balanced = max - min <= 1; // allow 7/3 = 2,2,3
  const distribution = Object.entries(byConsumer).map(([id, n]) => `${id.slice(-8)}:${n}`).join(', ');
  return { balanced, min, max, distribution, byConsumer };
}

// ── Core: send Slack alert ─────────────────────────────────────────────────
function pad(str, len) {
  return String(str).padEnd(len).slice(0, len);
}

async function sendSlackAlert(failedConnectors, totalConnectors, unhealthyGroups) {
  if (!SLACK_WEBHOOK) return;
  const now = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const lines = [];

  if (failedConnectors.length > 0) {
    lines.push(`🚨 *Kafka Connector Alert* — ${failedConnectors.length} of ${totalConnectors} failing on \`${CLUSTER_NAME}\``);
    lines.push(`_Checked at ${now}_`);
    lines.push('');
    const cols = { name: 28, status: 14, failed: 8, connect: 40 };
    const sep = `|${'-'.repeat(cols.name + 2)}|${'-'.repeat(cols.status + 2)}|${'-'.repeat(cols.failed + 2)}|${'-'.repeat(cols.connect + 2)}|`;
    lines.push('```');
    lines.push(`| ${pad('Connector', cols.name)} | ${pad('Status', cols.status)} | ${pad('Failed', cols.failed)} | ${pad('Connect', cols.connect)} |`);
    lines.push(sep);
    for (const c of failedConnectors) {
      const name = c.name.length > cols.name ? c.name.slice(0, cols.name - 2) + '..' : c.name;
      const status = (c.status?.state || 'UNKNOWN').slice(0, cols.status);
      const connect = (c.connect || '-').length > cols.connect ? (c.connect || '-').slice(0, cols.connect - 2) + '..' : (c.connect || '-');
      lines.push(`| ${pad(name, cols.name)} | ${pad(status, cols.status)} | ${pad(String(c.failed_tasks_count ?? 0), cols.failed)} | ${pad(connect, cols.connect)} |`);
    }
    lines.push('```');
    lines.push(`🔗 <${KAFKA_UI_URL}/ui/clusters/${CLUSTER_NAME}/connectors|View Connectors>`);
  }

  if (unhealthyGroups.length > 0) {
    if (lines.length > 0) lines.push('');
    lines.push(`⚠️ *Kafka Consumer Alert* — ${unhealthyGroups.length} unhealthy group(s) on \`${CLUSTER_NAME}\``);
    lines.push(`_Checked at ${now}_`);
    lines.push('');
    const cols = { groupId: 38, state: 10, members: 8, lag: 12, balance: 12 };
    const sep = `|${'-'.repeat(cols.groupId + 2)}|${'-'.repeat(cols.state + 2)}|${'-'.repeat(cols.members + 2)}|${'-'.repeat(cols.lag + 2)}|${'-'.repeat(cols.balance + 2)}|`;
    lines.push('```');
    lines.push(`| ${pad('Consumer Group', cols.groupId)} | ${pad('State', cols.state)} | ${pad('Members', cols.members)} | ${pad('Lag', cols.lag)} | ${pad('Balance', cols.balance)} |`);
    lines.push(sep);
    for (const g of unhealthyGroups) {
      const groupId = g.groupId.length > cols.groupId ? g.groupId.slice(0, cols.groupId - 2) + '..' : g.groupId;
      const state = (g.state || '-').slice(0, cols.state);
      const members = String(g.members ?? 0);
      const lag = g.consumerLag > LAG_THRESHOLD ? g.consumerLag.toLocaleString() : '-';
      const balance = g.partitionUnbalanced
        ? (g.partitionBalance ? `${g.partitionBalance.min}-${g.partitionBalance.max}` : 'unbal')
        : 'ok';
      lines.push(`| ${pad(groupId, cols.groupId)} | ${pad(state, cols.state)} | ${pad(members, cols.members)} | ${pad(lag, cols.lag)} | ${pad(balance, cols.balance)} |`);
    }
    lines.push('```');
    lines.push(`🔗 <${KAFKA_UI_URL}/ui/clusters/${CLUSTER_NAME}/consumer-groups|View Consumer Groups>`);
  }

  await fetch(SLACK_WEBHOOK, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: lines.join('\n') })
  });
}

// ── Core: run a health check ───────────────────────────────────────────────
async function runCheck() {
  console.log(`[${new Date().toISOString()}] Running health check...`);
  state.checkCount++;

  try {
    const [connectors, consumerGroups] = await Promise.all([
      fetchConnectors(),
      fetchAllConsumerGroups()
    ]);

    const failedConnectors = connectors.filter(
      c => c.status?.state !== 'RUNNING' || c.failed_tasks_count > 0
    );

    // Unhealthy: not STABLE, no members (but skip EMPTY groups with 0 topics as they may be unused),
    // lag above threshold, or uneven partition distribution across members
    let unhealthyGroups = consumerGroups.filter(g => {
      const badState  = g.state !== 'STABLE' && !(g.state === 'EMPTY' && g.members === 0 && g.topics === 0);
      const noMembers = g.state === 'STABLE' && g.members === 0;
      const highLag   = g.consumerLag > LAG_THRESHOLD;
      return badState || noMembers || highLag;
    });

    // Fetch details for STABLE groups with members (balance check + member/topic list)
    const stableWithMembers = consumerGroups.filter(g => g.state === 'STABLE' && g.members >= 1);
    for (const g of stableWithMembers) {
      const details = await fetchConsumerGroupDetails(g.groupId);
      if (details) {
        g.memberAssignments = buildMemberAssignments(details);
        if (CHECK_BALANCE && g.members > 1) {
          const balance = checkPartitionBalance(details);
          g.partitionBalance = balance;
          if (!balance.balanced) {
            const existing = unhealthyGroups.find(u => u.groupId === g.groupId);
            if (existing) existing.partitionUnbalanced = true;
            else unhealthyGroups = [...unhealthyGroups, { ...g, partitionUnbalanced: true }];
          }
        }
      }
    }

    state.lastChecked   = new Date().toISOString();
    state.connectors    = connectors;
    state.consumerGroups = consumerGroups;
    state.status        = (failedConnectors.length > 0 || unhealthyGroups.length > 0) ? 'alert' : 'ok';

    if (failedConnectors.length > 0 || unhealthyGroups.length > 0) {
      await sendSlackAlert(failedConnectors, connectors.length, unhealthyGroups);
      const event = {
        time: state.lastChecked,
        connectorCount: failedConnectors.length,
        consumerCount: unhealthyGroups.length,
        names: [
          ...failedConnectors.map(c => `connector:${c.name}`),
          ...unhealthyGroups.map(g => `consumer:${g.groupId}`)
        ]
      };
      state.alerts.unshift(event);
      if (state.alerts.length > 20) state.alerts.pop();
      console.log(`[ALERT] Connectors: ${failedConnectors.length} failed | Consumers: ${unhealthyGroups.length} unhealthy`);
    } else {
      console.log(`[OK] ${connectors.length} connectors, ${consumerGroups.length} consumer groups — all healthy.`);
    }
  } catch (err) {
    state.status = 'error';
    state.lastChecked = new Date().toISOString();
    console.error(`[ERROR] Check failed: ${err.message}`);
  }
}

// ── Routes ─────────────────────────────────────────────────────────────────
app.set('trust proxy', 1); // for secure cookies behind DigitalOcean load balancer
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Login page and auth handlers (no auth required)
app.get('/login', (req, res) => {
  if (!UI_PASSWORD) return res.redirect('/');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(getLoginPage());
});

app.post('/login', (req, res) => {
  if (!UI_PASSWORD) return res.redirect('/');
  const pwd = req.body?.password;
  if (pwd === UI_PASSWORD) {
    const token = signCookie('ok');
    const isProd = process.env.NODE_ENV === 'production';
    res.cookie(AUTH_COOKIE, token, {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/'
    });
    return res.redirect('/');
  }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(401).send(getLoginPage(true));
});

app.get('/logout', (req, res) => {
  res.clearCookie(AUTH_COOKIE, { path: '/' });
  res.redirect('/login');
});

// Protected routes
app.use((req, res, next) => {
  if (req.path === '/health') return next();
  requireAuth(req, res, next);
});

app.use(express.static(path.join(__dirname, 'public')));

// JSON API — used by the dashboard
app.get('/api/status', (req, res) => {
  res.json({
    lastChecked:    state.lastChecked,
    checkCount:     state.checkCount,
    status:         state.status,
    cluster:        CLUSTER_NAME,
    kafkaUiUrl:     KAFKA_UI_URL,
    lagThreshold:   LAG_THRESHOLD,
    connectors: state.connectors.map(c => ({
      name:        c.name,
      connect:     c.connect,
      type:        c.type,
      state:       c.status?.state,
      tasksCount:  c.tasks_count,
      failedTasks: c.failed_tasks_count,
      workerId:    c.status?.worker_id
    })),
    consumerGroups: state.consumerGroups.map(g => ({
      groupId:         g.groupId,
      state:           g.state,
      members:         g.members,
      topics:          g.topics,
      consumerLag:     g.consumerLag,
      partitionBalance: g.partitionBalance,
      partitionUnbalanced: g.partitionUnbalanced,
      memberAssignments: g.memberAssignments
    })),
    alerts: state.alerts
  });
});

// On-demand: fetch consumer group details (member list + topic assignments)
app.get('/api/consumer-groups/:groupId/details', async (req, res) => {
  try {
    const details = await fetchConsumerGroupDetails(req.params.groupId);
    if (!details) return res.status(404).json({ error: 'Group not found or details unavailable' });
    const memberAssignments = buildMemberAssignments(details);
    res.json({ groupId: req.params.groupId, memberAssignments });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Manual trigger endpoint
app.post('/api/check', async (req, res) => {
  await runCheck();
  res.json({ ok: true, status: state.status, lastChecked: state.lastChecked });
});

// Health probe (used by DigitalOcean)
app.get('/health', (req, res) => res.json({ ok: true }));

// ── Cron ───────────────────────────────────────────────────────────────────
cron.schedule(CHECK_INTERVAL, runCheck);
console.log(`Cron scheduled: "${CHECK_INTERVAL}"`);
if (UI_PASSWORD) console.log('[AUTH] UI password protection enabled.');
else console.log('[AUTH] UI password protection disabled (set UI_PASSWORD to enable).');

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Kafka Monitor running on port ${PORT}`);
  runCheck();
});
