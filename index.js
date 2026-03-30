require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const path = require('path');
const cron = require('node-cron');
const fetch = require('node-fetch');

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
const CHECK_DEBEZIUM_TOPICS = process.env.CHECK_DEBEZIUM_TOPICS !== 'false'; // verify Debezium expected topics exist in Kafka
const APP_URL         = process.env.APP_URL || ''; // public URL for ack links in Slack (e.g. https://your-app.ondigitalocean.app)

// ── Acknowledgement store (pause alerts for 1, 2, 4 or 12 hours) ─────────────
const ACKS_FILE = path.join(__dirname, 'data', 'acks.json');

function ensureDataDir() {
  const dir = path.dirname(ACKS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function loadAcks() {
  try {
    ensureDataDir();
    const raw = fs.readFileSync(ACKS_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return { connectors: {}, consumers: {} };
  }
}

function saveAcks(acks) {
  try {
    ensureDataDir();
    fs.writeFileSync(ACKS_FILE, JSON.stringify(acks, null, 2), 'utf8');
  } catch (err) {
    console.warn('[ACK] Could not persist acks:', err.message);
  }
}

function addAck(type, id, hours) {
  const acks = loadAcks();
  const until = Date.now() + hours * 60 * 60 * 1000;
  if (type === 'connector') acks.connectors[id] = { until };
  else acks.consumers[id] = { until };
  saveAcks(acks);
}

function isAcknowledged(type, id) {
  const acks = loadAcks();
  const map = type === 'connector' ? acks.connectors : acks.consumers;
  const entry = map[id];
  if (!entry) return false;
  if (Date.now() > entry.until) {
    delete map[id];
    saveAcks(acks);
    return false;
  }
  return true;
}

function getAcks() {
  const acks = loadAcks();
  const now = Date.now();
  const active = { connectors: [], consumers: [] };
  for (const [id, e] of Object.entries(acks.connectors)) {
    if (now < e.until) active.connectors.push({ id, until: e.until });
    else delete acks.connectors[id];
  }
  for (const [id, e] of Object.entries(acks.consumers)) {
    if (now < e.until) active.consumers.push({ id, until: e.until });
    else delete acks.consumers[id];
  }
  if (Object.keys(acks.connectors).length !== active.connectors.length || Object.keys(acks.consumers).length !== active.consumers.length) saveAcks(acks);
  return active;
}

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
  const redirect = encodeURIComponent(req.originalUrl || req.url);
  return res.redirect(`/login?redirect=${redirect}`);
}

function getLoginPage(invalid, redirect) {
  const redirectInput = redirect ? `<input type="hidden" name="redirect" value="${redirect.replace(/"/g, '&quot;')}" />` : '';
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
      ${redirectInput}
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
  brokers: null,       // [{ id, host, port, partitions, ... }] or null if unreachable
  brokerStatus: 'pending',  // ok | unreachable
  brokerError: null,
  alerts: [],          // last 20 alert events
  checkCount: 0,
  status: 'pending'    // pending | ok | alert | error
};

// ── Core: fetch brokers (detect if cluster/brokers are down) ───────────────
async function fetchBrokers() {
  return apiFetch(`${KAFKA_UI_URL}/api/clusters/${CLUSTER_NAME}/brokers`);
}

// ── Core: fetch connectors ─────────────────────────────────────────────────
async function fetchConnectors() {
  return apiFetch(`${KAFKA_UI_URL}/api/clusters/${CLUSTER_NAME}/connectors`);
}

// ── Debezium: cluster topics + connector config (expected capture topics) ─
async function fetchAllTopicNames() {
  const perPage = 100;
  const base = `${KAFKA_UI_URL}/api/clusters/${CLUSTER_NAME}/topics`;
  const first = await apiFetch(`${base}?page=0&perPage=${perPage}&showInternal=true`);
  const names = (first.topics || []).map(t => t.name);
  const totalPages = first.pageCount || 1;
  for (let page = 1; page < totalPages; page++) {
    const data = await apiFetch(`${base}?page=${page}&perPage=${perPage}&showInternal=true`);
    names.push(...(data.topics || []).map(t => t.name));
  }
  return names;
}

async function fetchConnectorConfig(connectName, connectorName) {
  const cn = encodeURIComponent(connectName);
  const n = encodeURIComponent(connectorName);
  return apiFetch(`${KAFKA_UI_URL}/api/clusters/${CLUSTER_NAME}/connects/${cn}/connectors/${n}/config`);
}

function normalizeConnectorConfig(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    if (v != null && typeof v === 'object' && !Array.isArray(v)) {
      if ('value' in v) out[k] = String(v.value);
      else if ('defaultValue' in v) out[k] = String(v.defaultValue);
      else out[k] = JSON.stringify(v);
    } else out[k] = String(v);
  }
  return out;
}

function isDebeziumConnector(c) {
  const cls = (c.connector_class || '').toLowerCase();
  return cls.includes('debezium');
}

function parseIncludeList(s) {
  if (s == null || !String(s).trim()) return [];
  return String(s)
    .split(',')
    .map(x => x.trim())
    .filter(Boolean);
}

function looksLikeRegexInclude(entry) {
  return /[\*\?\[\]\(\)\|\\]/.test(entry);
}

/** Build expected data + metadata topic names from Debezium connector config (best-effort). */
function deriveExpectedTopicsFromDebeziumConfig(configMap) {
  const connectorClass = String(configMap['connector.class'] || '').toLowerCase();
  const prefix = (configMap['topic.prefix'] || configMap['database.server.name'] || '').trim();
  const notes = [];
  const expected = [];
  let indeterminate = false;

  const hist = configMap['schema.history.internal.kafka.topic'];
  if (hist) expected.push(hist);

  const tableSpecs = parseIncludeList(configMap['table.include.list']);
  const collSpecs = parseIncludeList(configMap['collection.include.list']);
  const dataSpecs = tableSpecs.length ? tableSpecs : collSpecs;

  const hi = parseInt(configMap['heartbeat.interval.ms'] || '0', 10);
  if (prefix && hi > 0) expected.push(`${prefix}.heartbeat`);

  if (prefix && String(configMap['provide.transaction.metadata'] || '').toLowerCase() === 'true') {
    expected.push(`${prefix}.transaction`);
  }

  const signalTopic = configMap['signal.kafka.topic'] || configMap['topic.signal'];
  if (signalTopic) expected.push(signalTopic);

  if (!dataSpecs.length) {
    if (!prefix && (hist || expected.length)) {
      notes.push('No table.include.list / collection.include.list — data topics not derived (connector may capture all tables).');
      indeterminate = true;
    } else if (prefix) {
      notes.push('No table.include.list / collection.include.list — data topics not listed (snapshot/all tables may still apply).');
      indeterminate = true;
    }
    return { expected: [...new Set(expected)], indeterminate, notes, missingPrefix: false };
  }

  if (!prefix) {
    notes.push('Missing topic.prefix — cannot derive names from table/collection list.');
    return { expected: [...new Set(expected)], indeterminate: true, notes, missingPrefix: true };
  }

  for (const spec of dataSpecs) {
    if (looksLikeRegexInclude(spec)) {
      indeterminate = true;
      notes.push(`Skipped regex-like include: ${spec.slice(0, 80)}${spec.length > 80 ? '…' : ''}`);
      continue;
    }
    const parts = spec.split('.').filter(Boolean);
    let topicName = null;
    if (connectorClass.includes('mysql') || connectorClass.includes('mariadb')) {
      if (parts.length >= 2) topicName = `${prefix}.${parts[0]}.${parts[1]}`;
    } else if (connectorClass.includes('postgresql') || connectorClass.includes('sqlserver') || connectorClass.includes('db2')) {
      if (parts.length >= 2) topicName = `${prefix}.${parts[0]}.${parts[1]}`;
    } else if (connectorClass.includes('oracle')) {
      if (parts.length === 2) topicName = `${prefix}.${parts[0]}.${parts[1]}`;
      else if (parts.length === 3) topicName = `${prefix}.${parts[1]}.${parts[2]}`;
    } else if (connectorClass.includes('mongodb')) {
      if (parts.length >= 2) topicName = `${prefix}.${parts[0]}.${parts.slice(1).join('.')}`;
    } else {
      if (parts.length >= 2) {
        topicName = `${prefix}.${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
      } else indeterminate = true;
    }
    if (topicName) expected.push(topicName);
  }

  return { expected: [...new Set(expected)], indeterminate, notes, missingPrefix: false };
}

/**
 * Compare Debezium-expected topics to cluster. Prefers Kafka Connect–declared `topics` on the
 * connector when Kafka UI provides them; otherwise derives from config.
 */
function verifyDebeziumTopicsAgainstCluster(connector, topicSet, configMap) {
  const fromConnect = Array.isArray(connector.topics) ? connector.topics.filter(Boolean) : [];
  const derived = deriveExpectedTopicsFromDebeziumConfig(configMap);

  let expected = [];
  let source = 'derived-config';
  let indeterminate = derived.indeterminate;
  let notes = [...derived.notes];

  if (fromConnect.length > 0) {
    expected = [...fromConnect];
    source = 'kafka-connect';
    indeterminate = false;
  } else {
    expected = [...derived.expected];
  }

  const hist = configMap['schema.history.internal.kafka.topic'];
  if (hist && !expected.includes(hist)) expected.push(hist);

  expected = [...new Set(expected)];

  if (derived.missingPrefix && fromConnect.length === 0 && parseIncludeList(configMap['table.include.list']).length > 0) {
    return {
      ok: false,
      source,
      expected,
      missing: [],
      present: [],
      indeterminate: true,
      notes: [...notes, 'Need topic.prefix or database.server.name to map table.include.list to topic names.'],
      error: 'Missing topic.prefix for derived table topics'
    };
  }

  const missing = expected.filter(t => !topicSet.has(t));
  const present = expected.filter(t => topicSet.has(t));
  return {
    ok: missing.length === 0,
    source,
    expected,
    missing,
    present,
    indeterminate,
    notes
  };
}

async function enrichDebeziumTopicState(connectors, brokerOk) {
  if (!CHECK_DEBEZIUM_TOPICS) return;
  if (!brokerOk) {
    for (const c of connectors.filter(isDebeziumConnector)) {
      c.debeziumTopicVerification = { ok: null, skipped: true, reason: 'Broker/cluster unreachable' };
    }
    return;
  }

  let topicSet = null;
  try {
    const names = await fetchAllTopicNames();
    topicSet = new Set(names);
  } catch (err) {
    console.warn(`[DEBEZIUM] Could not load topics: ${err.message}`);
  }

  const targets = connectors.filter(isDebeziumConnector);
  await Promise.all(
    targets.map(async c => {
      try {
        if (!topicSet) {
          c.debeziumTopicVerification = { ok: null, error: 'Cluster topics unavailable', expected: [], missing: [], present: [] };
          return;
        }
        const rawCfg = await fetchConnectorConfig(c.connect, c.name);
        const configMap = normalizeConnectorConfig(rawCfg);
        c.debeziumTopicVerification = verifyDebeziumTopicsAgainstCluster(c, topicSet, configMap);
      } catch (err) {
        c.debeziumTopicVerification = { ok: null, error: err.message, expected: [], missing: [], present: [] };
      }
    })
  );
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

// Build member list with topic-partition assignments and lag from consumer group details
function buildMemberAssignments(details) {
  const partitions = details?.partitions || [];
  const byMember = {};
  for (const p of partitions) {
    const cid = p.consumerId ?? '(unknown)';
    const lag = p.consumerLag != null ? p.consumerLag : 0;
    if (!byMember[cid]) {
      byMember[cid] = { consumerId: cid, host: p.host ?? '-', topics: [], memberLag: 0 };
    }
    byMember[cid].topics.push({ topic: p.topic, partition: p.partition, lag });
    byMember[cid].memberLag += lag;
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

function ackUrl(type, id, hours) {
  if (!APP_URL) return null;
  return `${APP_URL.replace(/\/$/, '')}/ack?type=${type}&id=${encodeURIComponent(id)}&hours=${hours}`;
}

async function sendSlackAlert(brokerDown, failedConnectors, totalConnectors, unhealthyGroups) {
  if (!SLACK_WEBHOOK) return;
  const now = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const lines = [];

  if (brokerDown) {
    lines.push(`🔴 *Kafka Cluster Unreachable* — Could not reach brokers on \`${CLUSTER_NAME}\``);
    lines.push(`_Checked at ${now}_`);
    lines.push(`_Error: ${state.brokerError || 'Unknown'}_`);
    lines.push(`🔗 <${KAFKA_UI_URL}/ui/clusters/${CLUSTER_NAME}|View in Kafka UI>`);
    lines.push('');
  }

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
    const connAckParts = failedConnectors.map(c => {
      const u1 = ackUrl('connector', c.name, 1), u2 = ackUrl('connector', c.name, 2), u4 = ackUrl('connector', c.name, 4), u12 = ackUrl('connector', c.name, 12);
      return u1 && u2 ? `<${u1}|1h> <${u2}|2h> <${u4}|4h> <${u12}|12h>` : '';
    }).filter(Boolean);
    if (connAckParts.length) lines.push(`_Pause alerts:_ ${connAckParts.join(' | ')}`);
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
    const ackParts = unhealthyGroups.map(g => {
      const u1 = ackUrl('consumer', g.groupId, 1), u2 = ackUrl('consumer', g.groupId, 2), u4 = ackUrl('consumer', g.groupId, 4), u12 = ackUrl('consumer', g.groupId, 12);
      return u1 && u2 ? `<${u1}|1h> <${u2}|2h> <${u4}|4h> <${u12}|12h>` : '';
    }).filter(Boolean);
    if (ackParts.length) lines.push(`_Pause alerts:_ ${ackParts.join(' | ')}`);
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
  state.brokerStatus = 'pending';
  state.brokerError = null;
  state.brokers = null;

  try {
    const [brokersResult, connectorsResult, consumerGroupsResult] = await Promise.allSettled([
      fetchBrokers(),
      fetchConnectors(),
      fetchAllConsumerGroups()
    ]);

    if (brokersResult.status === 'fulfilled') {
      state.brokers = brokersResult.value;
      state.brokerStatus = 'ok';
    } else {
      state.brokerStatus = 'unreachable';
      state.brokerError = brokersResult.reason?.message || 'Could not reach Kafka cluster';
      console.error(`[BROKER] Unreachable: ${state.brokerError}`);
    }

    const connectors = connectorsResult.status === 'fulfilled' ? connectorsResult.value : [];
    const consumerGroups = consumerGroupsResult.status === 'fulfilled' ? consumerGroupsResult.value : [];
    if (connectorsResult.status === 'rejected') {
      console.error('[CONNECTOR] Fetch failed:', connectorsResult.reason?.message);
    }
    if (consumerGroupsResult.status === 'rejected') {
      console.error('[CONSUMER] Fetch failed:', consumerGroupsResult.reason?.message);
    }

    await enrichDebeziumTopicState(connectors, state.brokerStatus === 'ok');

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
    const brokerDown = state.brokerStatus === 'unreachable';
    state.status        = (brokerDown || failedConnectors.length > 0 || unhealthyGroups.length > 0) ? 'alert' : 'ok';

    const toAlertConns = failedConnectors.filter(c => !isAcknowledged('connector', c.name));
    const toAlertCons  = unhealthyGroups.filter(g => !isAcknowledged('consumer', g.groupId));

    if (brokerDown || toAlertConns.length > 0 || toAlertCons.length > 0) {
      await sendSlackAlert(brokerDown, toAlertConns, connectors.length, toAlertCons);
      const event = {
        time: state.lastChecked,
        brokerDown: brokerDown ? 1 : 0,
        connectorCount: failedConnectors.length,
        consumerCount: unhealthyGroups.length,
        names: [
          ...(brokerDown ? ['broker:cluster-unreachable'] : []),
          ...failedConnectors.map(c => `connector:${c.name}`),
          ...unhealthyGroups.map(g => `consumer:${g.groupId}`)
        ]
      };
      state.alerts.unshift(event);
      if (state.alerts.length > 20) state.alerts.pop();
      console.log(`[ALERT] ${brokerDown ? 'Broker unreachable | ' : ''}Connectors: ${failedConnectors.length} failed | Consumers: ${unhealthyGroups.length} unhealthy`);
    } else {
      console.log(`[OK] Brokers: ${state.brokers?.length ?? 0} | ${connectors.length} connectors | ${consumerGroups.length} consumer groups — all healthy.`);
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
  res.send(getLoginPage(false, req.query.redirect));
});

app.post('/login', (req, res) => {
  if (!UI_PASSWORD) return res.redirect('/');
  const pwd = req.body?.password;
  const r = req.body?.redirect;
  const redirectTo = (r && r.startsWith('/') && !r.includes('//')) ? r : '/';
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
    return res.redirect(redirectTo);
  }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(401).send(getLoginPage(true, req.body?.redirect));
});

app.get('/logout', (req, res) => {
  res.clearCookie(AUTH_COOKIE, { path: '/' });
  res.redirect('/login');
});

// Acknowledgement from Slack link (GET) or UI (POST)
app.get('/ack', (req, res, next) => {
  if (req.path === '/health') return next();
  requireAuth(req, res, () => {
    const type = req.query.type, id = req.query.id, hours = parseInt(req.query.hours, 10);
    const validHours = [1, 2, 4, 12];
    if (type && id && validHours.includes(hours)) {
      addAck(type, id, hours);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Acknowledged</title></head><body style="font-family:sans-serif;padding:40px;text-align:center"><h1>✓ Acknowledged</h1><p>Alerts for ${type === 'connector' ? 'connector' : 'consumer group'} <strong>${id}</strong> paused for ${hours} hour(s).</p><p><a href="/">Back to dashboard</a></p></body></html>`);
    } else {
      res.status(400).send('Invalid ack params. Need type, id, and hours (1, 2, 4 or 12).');
    }
  });
});

// Protected routes (skip /health and /ack which has its own auth)
app.use((req, res, next) => {
  if (req.path === '/health') return next();
  requireAuth(req, res, next);
});

app.use(express.static(path.join(__dirname, 'public')));

// JSON API — used by the dashboard
app.get('/api/status', (req, res) => {
  const acks = getAcks();
  res.json({
    lastChecked:    state.lastChecked,
    checkCount:     state.checkCount,
    status:         state.status,
    cluster:        CLUSTER_NAME,
    kafkaUiUrl:     KAFKA_UI_URL,
    lagThreshold:   LAG_THRESHOLD,
    checkDebeziumTopics: CHECK_DEBEZIUM_TOPICS,
    checkPartitionBalance: CHECK_BALANCE,
    acks,
    brokers:        state.brokers,
    brokerStatus:   state.brokerStatus,
    brokerError:    state.brokerError,
    connectors: state.connectors.map(c => ({
      name:        c.name,
      connect:     c.connect,
      type:        c.type,
      connectorClass: c.connector_class,
      state:       c.status?.state,
      tasksCount:  c.tasks_count,
      failedTasks: c.failed_tasks_count,
      workerId:    c.status?.worker_id,
      acknowledged: isAcknowledged('connector', c.name),
      debeziumTopics: c.debeziumTopicVerification || null
    })),
    consumerGroups: state.consumerGroups.map(g => ({
      groupId:         g.groupId,
      state:           g.state,
      members:         g.members,
      topics:          g.topics,
      consumerLag:     g.consumerLag,
      partitionBalance: g.partitionBalance,
      partitionUnbalanced: g.partitionUnbalanced,
      memberAssignments: g.memberAssignments,
      acknowledged: isAcknowledged('consumer', g.groupId)
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

// Acknowledge alert (pause for 1, 2, 4 or 12 hours)
app.post('/api/ack', (req, res) => {
  const { type, id, hours } = req.body || {};
  const validHours = [1, 2, 4, 12];
  if (!type || !id || !validHours.includes(Number(hours))) {
    return res.status(400).json({ error: 'Need type (connector|consumer), id, and hours (1|2|4|12)' });
  }
  if (type !== 'connector' && type !== 'consumer') {
    return res.status(400).json({ error: 'type must be connector or consumer' });
  }
  addAck(type, id, Number(hours));
  res.json({ ok: true, until: Date.now() + Number(hours) * 60 * 60 * 1000 });
});

// List active acknowledgements
app.get('/api/acks', (req, res) => {
  res.json(getAcks());
});

// Clear recent alerts
app.delete('/api/alerts', (req, res) => {
  state.alerts = [];
  res.json({ ok: true });
});

app.delete('/api/alerts/:index', (req, res) => {
  const idx = parseInt(req.params.index, 10);
  if (isNaN(idx) || idx < 0 || idx >= state.alerts.length) {
    return res.status(400).json({ error: 'Invalid alert index' });
  }
  state.alerts.splice(idx, 1);
  res.json({ ok: true });
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
