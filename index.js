require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const path = require('path');
const cron = require('node-cron');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Kafbat UI (formerly Kafka UI) ───────────────────────────────────────────
const KAFKA_UI_URL    = (process.env.KAFKA_UI_URL || 'https://jio-kafka-ui.prod.zwing.in').replace(/\/$/, '');
const CLUSTER_NAME_REQUESTED = (process.env.CLUSTER_NAME || '').trim();
let clusterName = CLUSTER_NAME_REQUESTED || 'kafka-prod';
const UI_PASSWORD     = process.env.UI_PASSWORD;      // optional: if set, dashboard requires login
const SESSION_SECRET  = process.env.SESSION_SECRET || 'kafka-monitor-default-change-in-prod';
const SLACK_WEBHOOK   = process.env.SLACK_WEBHOOK;
const CHECK_INTERVAL  = process.env.CHECK_INTERVAL  || '*/15 * * * *'; // every 15 min
const KAFKA_UI_USER   = process.env.KAFKA_UI_USER   || '';
const KAFKA_UI_PASS   = process.env.KAFKA_UI_PASS   || '';
// GitHub OAuth (Kafbat): copy session cookie from browser DevTools after signing in
const KAFKA_UI_SESSION_COOKIE = process.env.KAFKA_UI_SESSION_COOKIE || '';
// Optional: bearer JWT if Kafbat resource-server auth is configured
const KAFKA_UI_BEARER_TOKEN   = process.env.KAFKA_UI_BEARER_TOKEN   || '';
const LAG_THRESHOLD   = parseInt(process.env.LAG_THRESHOLD || '10000', 10); // default lag SLO
const LAG_VELOCITY_THRESHOLD = parseInt(process.env.LAG_VELOCITY_THRESHOLD || '5000', 10); // lag increase per check → alert
const STUCK_OFFSET_MIN_LAG = parseInt(
  process.env.STUCK_OFFSET_MIN_LAG || String(Math.max(500, Math.floor(parseInt(process.env.LAG_THRESHOLD || '10000', 10) / 10))),
  10
);
const STUCK_OFFSET_CHECKS = parseInt(process.env.STUCK_OFFSET_CHECKS || '2', 10);
const CHECK_BALANCE   = process.env.CHECK_PARTITION_BALANCE !== 'false';
const CHECK_DEBEZIUM_TOPICS = process.env.CHECK_DEBEZIUM_TOPICS !== 'false';
const CHECK_ORPHAN_TOPICS = process.env.CHECK_ORPHAN_TOPICS !== 'false';
const ORPHAN_ZOMBIE_SCAN = process.env.ORPHAN_ZOMBIE_SCAN === 'true';
const ORPHAN_TOPIC_SCAN_LIMIT = parseInt(process.env.ORPHAN_TOPIC_SCAN_LIMIT || '50', 10);
const APP_URL         = process.env.APP_URL || '';

function parseLagSloOverrides(raw) {
  const map = {};
  if (!raw?.trim()) return map;
  for (const part of raw.split(',')) {
    const idx = part.indexOf(':');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const val = parseInt(part.slice(idx + 1).trim(), 10);
    if (key && !Number.isNaN(val)) map[key] = val;
  }
  return map;
}

const LAG_SLO_OVERRIDES = parseLagSloOverrides(process.env.LAG_SLO_OVERRIDES || '');

function sloForGroup(groupId) {
  if (LAG_SLO_OVERRIDES[groupId] != null) return LAG_SLO_OVERRIDES[groupId];
  for (const [pattern, val] of Object.entries(LAG_SLO_OVERRIDES)) {
    if (!pattern.includes('*')) continue;
    const re = new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`);
    if (re.test(groupId)) return val;
  }
  return LAG_THRESHOLD;
}

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

// ── Kafbat UI session (OAuth cookie or form login) ──────────────────────────
let sessionCookie = KAFKA_UI_SESSION_COOKIE.trim() || null;
let kafbatAuthType = null; // OAUTH2 | LOGIN_FORM | DISABLED

async function fetchKafbatAuthSettings() {
  try {
    const res = await fetch(`${KAFKA_UI_URL}/api/config/authentication`, { timeout: 15000 });
    if (!res.ok) return null;
    return res.json();
  } catch (err) {
    console.warn('[AUTH] Could not read Kafbat auth settings:', err.message);
    return null;
  }
}

function kafbatAuthHeaders() {
  const headers = {};
  if (KAFKA_UI_BEARER_TOKEN) {
    headers.Authorization = `Bearer ${KAFKA_UI_BEARER_TOKEN}`;
  } else if (sessionCookie) {
    headers.Cookie = sessionCookie;
  }
  return headers;
}

function oauthSessionHelp() {
  return [
    'Kafbat UI uses GitHub OAuth — username/password login is not available.',
    'Sign in at ' + KAFKA_UI_URL + ' via GitHub, then copy your session cookie',
    '(DevTools → Application → Cookies → copy the SESSION value, or the full Cookie header)',
    'and set KAFKA_UI_SESSION_COOKIE in your environment.',
    'Alternatively, configure Kafbat JWT resource-server auth and set KAFKA_UI_BEARER_TOKEN.'
  ].join(' ');
}

async function loginForm() {
  if (!KAFKA_UI_USER || !KAFKA_UI_PASS) {
    throw new Error('KAFKA_UI_USER and KAFKA_UI_PASS are required for form-based Kafbat login.');
  }

  for (const path of ['/login', '/auth']) {
    const res = await fetch(`${KAFKA_UI_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `username=${encodeURIComponent(KAFKA_UI_USER)}&password=${encodeURIComponent(KAFKA_UI_PASS)}`,
      redirect: 'manual',
      timeout: 15000
    });
    const setCookie = res.headers.raw()['set-cookie'];
    if (setCookie?.length) {
      sessionCookie = setCookie.map(c => c.split(';')[0]).join('; ');
      console.log(`[AUTH] Logged in to Kafbat via ${path}.`);
      return;
    }
  }
  throw new Error('Kafbat form login failed: no session cookie returned.');
}

async function ensureKafbatAuthenticated() {
  if (kafbatAuthType === 'DISABLED') return;
  if (KAFKA_UI_BEARER_TOKEN || sessionCookie) return;
  if (kafbatAuthType === 'OAUTH2') throw new Error(oauthSessionHelp());
  if (KAFKA_UI_USER && KAFKA_UI_PASS) {
    await loginForm();
    return;
  }
  throw new Error('Kafbat UI credentials not configured.');
}

function isOAuthRedirect(res) {
  if (res.status !== 302 && res.status !== 303) return false;
  const loc = res.headers.get('location') || '';
  return loc.includes('oauth2/authorization') || loc.includes('/login');
}

async function initKafbatAuth() {
  const settings = await fetchKafbatAuthSettings();
  kafbatAuthType = settings?.authType || null;

  if (kafbatAuthType === 'OAUTH2') {
    const provider = settings?.oAuthProviders?.[0]?.clientName || 'OAuth';
    if (KAFKA_UI_BEARER_TOKEN) {
      console.log(`[AUTH] Kafbat ${provider} — using KAFKA_UI_BEARER_TOKEN.`);
    } else if (sessionCookie) {
      console.log(`[AUTH] Kafbat ${provider} — using KAFKA_UI_SESSION_COOKIE.`);
    } else {
      console.warn('[AUTH] Kafbat uses ' + provider + '. ' + oauthSessionHelp());
    }
    return;
  }

  if (kafbatAuthType === 'LOGIN_FORM' && KAFKA_UI_USER && KAFKA_UI_PASS) {
    await loginForm();
    return;
  }

  if (kafbatAuthType === 'DISABLED') {
    console.log('[AUTH] Kafbat authentication disabled.');
    return;
  }

  if (sessionCookie) {
    console.log('[AUTH] Using KAFKA_UI_SESSION_COOKIE.');
  } else if (KAFKA_UI_USER && KAFKA_UI_PASS) {
    await loginForm();
  }
}

async function apiFetch(url) {
  await ensureKafbatAuthenticated();

  let res = await fetch(url, {
    headers: kafbatAuthHeaders(),
    redirect: 'manual',
    timeout: 15000
  });

  if (isOAuthRedirect(res)) {
    if (kafbatAuthType === 'OAUTH2') {
      throw new Error('Kafbat session expired or invalid. Refresh KAFKA_UI_SESSION_COOKIE after signing in via GitHub.');
    }
    if (KAFKA_UI_USER && KAFKA_UI_PASS) {
      await loginForm();
      res = await fetch(url, { headers: kafbatAuthHeaders(), redirect: 'manual', timeout: 15000 });
    } else {
      throw new Error(`Kafbat UI authentication required for ${url}`);
    }
  }

  // Form login session expired — re-login and retry once
  if ((res.status === 401 || res.status === 403) && KAFKA_UI_USER && KAFKA_UI_PASS && !KAFKA_UI_BEARER_TOKEN) {
    await loginForm();
    res = await fetch(url, { headers: kafbatAuthHeaders(), redirect: 'manual', timeout: 15000 });
  }

  if (!res.ok) throw new Error(`Kafbat UI returned ${res.status} for ${url}`);
  return res.json();
}

async function fetchKafbatClusters() {
  await ensureKafbatAuthenticated();
  const res = await fetch(`${KAFKA_UI_URL}/api/clusters`, {
    headers: kafbatAuthHeaders(),
    redirect: 'manual',
    timeout: 15000
  });
  if (isOAuthRedirect(res)) {
    throw new Error('Kafbat session expired or invalid. Refresh KAFKA_UI_SESSION_COOKIE after signing in via GitHub.');
  }
  if (!res.ok) throw new Error(`Kafbat UI returned ${res.status} when listing clusters`);
  return res.json();
}

function pickClusterName(clusters, requested) {
  const names = clusters.map(c => c.name).filter(Boolean);
  if (!names.length) throw new Error('No Kafka clusters configured in Kafbat UI.');

  if (requested) {
    const match = clusters.find(c => c.name === requested);
    if (match) return { name: match.name, auto: false };
    console.warn(`[CLUSTER] CLUSTER_NAME="${requested}" not found. Available: ${names.join(', ')}`);
  }

  const defaultCluster = clusters.find(c => c.defaultCluster);
  if (defaultCluster) return { name: defaultCluster.name, auto: true, reason: 'default cluster' };

  const online = clusters.filter(c => c.status === 'ONLINE');
  if (online.length === 1) return { name: online[0].name, auto: true, reason: 'single online cluster' };
  if (clusters.length === 1) return { name: clusters[0].name, auto: true, reason: 'only cluster' };

  if (online.length > 1) {
    console.warn(`[CLUSTER] Multiple online clusters (${online.map(c => c.name).join(', ')}). Using "${online[0].name}". Set CLUSTER_NAME to pick one.`);
    return { name: online[0].name, auto: true, reason: 'first online cluster' };
  }

  throw new Error(`Could not resolve cluster. Set CLUSTER_NAME to one of: ${names.join(', ')}`);
}

async function initKafbatCluster() {
  const clusters = await fetchKafbatClusters();
  const picked = pickClusterName(clusters, CLUSTER_NAME_REQUESTED);
  clusterName = picked.name;
  if (picked.auto) {
    const available = clusters.map(c => `${c.name}${c.status === 'ONLINE' ? '' : ` (${c.status})`}`).join(', ');
    console.log(`[CLUSTER] Using "${clusterName}" (${picked.reason}). Available: ${available}`);
  } else {
    console.log(`[CLUSTER] Using "${clusterName}" from CLUSTER_NAME.`);
  }
}

// ── In-memory state ────────────────────────────────────────────────────────
let state = {
  lastChecked: null,
  connectors: [],
  consumerGroups: [],
  brokers: null,       // [{ id, host, port, partitions, ... }] or null if unreachable
  brokerStatus: 'pending',  // ok | unreachable
  brokerError: null,
  alerts: [],          // last 40 events (failure + recovery)
  healthSnapshot: { brokerDown: false, connectors: [], pausedConnectors: [], stoppedConnectors: [], consumers: [], pipelineIssues: [] },
  pipelineIssues: [],
  checkCount: 0,
  status: 'pending'    // pending | ok | alert | error
};

// Previous check snapshot for lag velocity + stuck offset detection
let lagHistory = { lastCheckedAt: null, consumerGroups: {} };

// ── Core: fetch brokers (detect if cluster/brokers are down) ───────────────
async function fetchBrokers() {
  return apiFetch(`${KAFKA_UI_URL}/api/clusters/${clusterName}/brokers`);
}

// ── Core: fetch connectors ─────────────────────────────────────────────────
async function fetchConnectors() {
  const raw = await apiFetch(`${KAFKA_UI_URL}/api/clusters/${clusterName}/connectors`);
  return normalizeConnectors(raw);
}

function connectorClassName(c) {
  return c.connectorClass || c.connector_class || '';
}

function connectorState(c) {
  if (typeof c.status === 'string') return c.status;
  return c.status?.state || 'UNKNOWN';
}

function connectorFailedTasks(c) {
  return c.failedTasksCount ?? c.failed_tasks_count ?? 0;
}

function connectorTasksCount(c) {
  return c.tasksCount ?? c.tasks_count ?? 0;
}

function connectorWorkerId(c) {
  return c.status?.workerId ?? c.status?.worker_id ?? null;
}

function normalizeConnector(c) {
  const state = connectorState(c);
  const workerId = connectorWorkerId(c);
  return {
    ...c,
    connector_class: connectorClassName(c),
    connectorClass: connectorClassName(c),
    tasks_count: connectorTasksCount(c),
    tasksCount: connectorTasksCount(c),
    failed_tasks_count: connectorFailedTasks(c),
    failedTasksCount: connectorFailedTasks(c),
    status: {
      ...(typeof c.status === 'object' && c.status ? c.status : {}),
      state,
      worker_id: workerId,
      workerId
    }
  };
}

function normalizeConnectors(list) {
  return (Array.isArray(list) ? list : []).map(normalizeConnector);
}

// ── Debezium: cluster topics + connector config (expected capture topics) ─
async function fetchAllTopicNames() {
  const perPage = 100;
  const base = `${KAFKA_UI_URL}/api/clusters/${clusterName}/topics`;
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
  return apiFetch(`${KAFKA_UI_URL}/api/clusters/${clusterName}/connects/${cn}/connectors/${n}/config`);
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
  const cls = connectorClassName(c).toLowerCase();
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
    `${KAFKA_UI_URL}/api/clusters/${clusterName}/consumer-groups/paged?page=0&perPage=${perPage}&sortOrder=ASC`
  );
  const groups = [...first.consumerGroups];
  const totalPages = first.pageCount || 1;

  for (let page = 1; page < totalPages; page++) {
    const data = await apiFetch(
      `${KAFKA_UI_URL}/api/clusters/${clusterName}/consumer-groups/paged?page=${page}&perPage=${perPage}&sortOrder=ASC`
    );
    groups.push(...data.consumerGroups);
  }
  return groups;
}

// ── Core: fetch consumer group details (partitions per member) ───────────────
async function fetchConsumerGroupDetails(groupId) {
  try {
    return await apiFetch(
      `${KAFKA_UI_URL}/api/clusters/${clusterName}/consumer-groups/${encodeURIComponent(groupId)}`
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

function connectorHealthCategory(c) {
  const state = connectorState(c).toUpperCase();
  if (connectorFailedTasks(c) > 0 || state === 'FAILED') return 'failed';
  if (state === 'PAUSED') return 'paused';
  if (state === 'STOPPED' || state === 'UNASSIGNED') return 'stopped';
  if (state === 'RUNNING') return 'running';
  return 'other';
}

function partitionKey(topic, partition) {
  return `${topic}|${partition}`;
}

function analyzeConsumerLagSignals(g, details, checkedAt) {
  const slo = sloForGroup(g.groupId);
  g.lagSlo = slo;
  g.sloBreached = g.consumerLag != null && g.consumerLag > slo;

  const prev = lagHistory.consumerGroups[g.groupId];
  g.lagDelta = null;
  g.lagVelocity = null;
  g.lagVelocityAlert = false;

  if (prev && lagHistory.lastCheckedAt && g.consumerLag != null && prev.consumerLag != null) {
    g.lagDelta = g.consumerLag - prev.consumerLag;
    const mins = Math.max(1, (checkedAt.getTime() - new Date(lagHistory.lastCheckedAt).getTime()) / 60000);
    g.lagVelocity = Math.round(g.lagDelta / mins);
    g.lagVelocityAlert = g.lagDelta >= LAG_VELOCITY_THRESHOLD;
  }

  const stuckPartitions = [];
  for (const p of details?.partitions || []) {
    const lag = p.consumerLag ?? 0;
    if (lag < STUCK_OFFSET_MIN_LAG || p.currentOffset == null) continue;
    const key = partitionKey(p.topic, p.partition);
    const prevPart = prev?.partitions?.[key];
    let stuckChecks = 0;
    if (prevPart && prevPart.currentOffset === p.currentOffset && prevPart.consumerLag >= STUCK_OFFSET_MIN_LAG) {
      stuckChecks = (prevPart.stuckChecks || 1) + 1;
    }
    if (stuckChecks >= STUCK_OFFSET_CHECKS) {
      stuckPartitions.push({
        topic: p.topic,
        partition: p.partition,
        lag,
        currentOffset: p.currentOffset,
        stuckChecks
      });
    }
  }
  g.stuckPartitions = stuckPartitions;
  g.stuckOffset = stuckPartitions.length > 0;
}

function updateLagHistory(consumerGroups, checkedAt) {
  const next = { lastCheckedAt: checkedAt.toISOString(), consumerGroups: {} };
  for (const g of consumerGroups) {
    const partitions = {};
    for (const p of g._detailPartitions || []) {
      if (p.currentOffset == null) continue;
      const key = partitionKey(p.topic, p.partition);
      const prevPart = lagHistory.consumerGroups[g.groupId]?.partitions?.[key];
      let stuckChecks = 0;
      const lag = p.consumerLag ?? 0;
      if (prevPart && prevPart.currentOffset === p.currentOffset && lag >= STUCK_OFFSET_MIN_LAG && prevPart.consumerLag >= STUCK_OFFSET_MIN_LAG) {
        stuckChecks = (prevPart.stuckChecks || 1) + 1;
      }
      partitions[key] = { currentOffset: p.currentOffset, consumerLag: lag, stuckChecks };
    }
    next.consumerGroups[g.groupId] = {
      consumerLag: g.consumerLag ?? 0,
      partitions
    };
  }
  lagHistory = next;
}

async function fetchTopicActiveProducers(topicName) {
  try {
    const data = await apiFetch(
      `${KAFKA_UI_URL}/api/clusters/${clusterName}/topics/${encodeURIComponent(topicName)}/activeproducers`
    );
    return Array.isArray(data) ? data : [];
  } catch {
    return null;
  }
}

async function fetchTopicConsumerGroups(topicName) {
  try {
    const data = await apiFetch(
      `${KAFKA_UI_URL}/api/clusters/${clusterName}/topics/${encodeURIComponent(topicName)}/consumer-groups`
    );
    return Array.isArray(data) ? data : [];
  } catch {
    return null;
  }
}

function isInternalTopic(name) {
  return name.startsWith('__') || name.startsWith('_');
}

async function analyzePipelineTopics({ connectors, groupDetailsMap, clusterTopicSet }) {
  const issues = [];
  const consumedTopics = new Set();
  const connectorTopics = new Set();

  for (const details of Object.values(groupDetailsMap)) {
    for (const p of details?.partitions || []) {
      consumedTopics.add(p.topic);
      if (clusterTopicSet && !clusterTopicSet.has(p.topic)) {
        issues.push({
          kind: 'missing_topic',
          topic: p.topic,
          groupId: details.groupId,
          detail: 'Consumer group subscribed to a topic that does not exist in the cluster'
        });
      }
    }
  }

  for (const c of connectors) {
    for (const topic of c.topics || []) {
      connectorTopics.add(topic);
      if (clusterTopicSet && !clusterTopicSet.has(topic)) {
        issues.push({
          kind: 'missing_topic',
          topic,
          connector: c.name,
          detail: 'Connector lists a topic that does not exist in the cluster'
        });
      } else if (!consumedTopics.has(topic)) {
        issues.push({
          kind: 'no_consumer',
          topic,
          connector: c.name,
          detail: 'Connector output topic has no consuming consumer group'
        });
      }
    }
  }

  if (ORPHAN_ZOMBIE_SCAN && clusterTopicSet) {
    const candidates = [...clusterTopicSet]
      .filter(t => !isInternalTopic(t))
      .filter(t => !consumedTopics.has(t) && !connectorTopics.has(t))
      .slice(0, ORPHAN_TOPIC_SCAN_LIMIT);

    await Promise.all(candidates.map(async topic => {
      const [producers, groups] = await Promise.all([
        fetchTopicActiveProducers(topic),
        fetchTopicConsumerGroups(topic)
      ]);
      if (producers === null && groups === null) return;
      const hasProducers = (producers?.length ?? 0) > 0;
      const hasConsumers = (groups?.length ?? 0) > 0;
      if (!hasProducers && !hasConsumers) {
        issues.push({
          kind: 'zombie',
          topic,
          detail: 'Topic exists but has no active producers or consumer groups'
        });
      }
    }));
  }

  const deduped = [];
  const seen = new Set();
  for (const issue of issues) {
    const key = `${issue.kind}|${issue.topic}|${issue.groupId || ''}|${issue.connector || ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(issue);
  }

  return {
    issues: deduped,
    scannedAt: new Date().toISOString(),
    zombieScanEnabled: ORPHAN_ZOMBIE_SCAN
  };
}

function pipelineIssueKey(issue) {
  return `${issue.kind}|${issue.topic}|${issue.groupId || ''}|${issue.connector || ''}`;
}

function csvEscape(val) {
  const s = String(val ?? '');
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function pipelineIssuesToCsv(issues, cluster, exportedAt) {
  const headers = ['kind', 'topic', 'detail', 'consumer_group', 'connector', 'cluster', 'exported_at'];
  const at = exportedAt || new Date().toISOString();
  const rows = (issues || []).map(i => [
    csvEscape(i.kind),
    csvEscape(i.topic),
    csvEscape(i.detail),
    csvEscape(i.groupId || ''),
    csvEscape(i.connector || ''),
    csvEscape(cluster),
    csvEscape(at)
  ].join(','));
  return [headers.join(','), ...rows].join('\r\n');
}

// ── Core: send Slack alert ─────────────────────────────────────────────────
function pad(str, len) {
  return String(str).padEnd(len).slice(0, len);
}

function ackUrl(type, id, hours) {
  if (!APP_URL) return null;
  return `${APP_URL.replace(/\/$/, '')}/ack?type=${type}&id=${encodeURIComponent(id)}&hours=${hours}`;
}

function ackLinksMarkdown(type, id) {
  const u1 = ackUrl(type, id, 1);
  const u2 = ackUrl(type, id, 2);
  const u4 = ackUrl(type, id, 4);
  const u12 = ackUrl(type, id, 12);
  if (!u1) return '—';
  return `<${u1}|1h> <${u2}|2h> <${u4}|4h> <${u12}|12h>`;
}

function pauseColLabel() {
  return APP_URL ? '1h·2h·4h·12h' : '—';
}

function appendPerRowPauseLines(lines, type, items, idKey) {
  if (!APP_URL || !items.length) return;
  lines.push('');
  lines.push('*Pause alerts (per row):*');
  for (const item of items) {
    const id = item[idKey];
    lines.push(`• \`${id}\`: ${ackLinksMarkdown(type, id)}`);
  }
}

function pushAlertEvent(event) {
  state.alerts.unshift(event);
  if (state.alerts.length > 40) state.alerts.pop();
}

function connectorAlertRow(c, cols, withPause = true) {
  const name = c.name.length > cols.name ? c.name.slice(0, cols.name - 2) + '..' : c.name;
  const status = (connectorState(c) || 'UNKNOWN').slice(0, cols.status);
  const connect = (c.connect || '-').length > cols.connect ? (c.connect || '-').slice(0, cols.connect - 2) + '..' : (c.connect || '-');
  const pause = withPause && cols.pause ? ` | ${pad(pauseColLabel(), cols.pause)}` : '';
  return `| ${pad(name, cols.name)} | ${pad(status, cols.status)} | ${pad(String(connectorFailedTasks(c)), cols.failed)} | ${pad(connect, cols.connect)}${pause} |`;
}

function consumerAlertRow(g, cols, withPause = true) {
  const groupId = g.groupId.length > cols.groupId ? g.groupId.slice(0, cols.groupId - 2) + '..' : g.groupId;
  const st = (g.state || '-').slice(0, cols.state);
  const members = String(g.members ?? 0);
  const lag = (g.consumerLag != null && g.consumerLag > (g.lagSlo ?? LAG_THRESHOLD))
    ? g.consumerLag.toLocaleString()
    : (g.consumerLag != null ? String(g.consumerLag) : '-');
  const flags = [
    g.sloBreached ? 'SLO' : '',
    g.stuckOffset ? 'stuck' : '',
    g.lagVelocityAlert ? `+${g.lagDelta}` : ''
  ].filter(Boolean).join(',') || 'ok';
  const balance = g.partitionUnbalanced
    ? (g.partitionBalance ? `${g.partitionBalance.min}-${g.partitionBalance.max}` : 'unbal')
    : flags.slice(0, 10);
  const pause = withPause && cols.pause ? ` | ${pad(pauseColLabel(), cols.pause)}` : '';
  return `| ${pad(groupId, cols.groupId)} | ${pad(st, cols.state)} | ${pad(members, cols.members)} | ${pad(lag, cols.lag)} | ${pad(balance, cols.balance)}${pause} |`;
}

function toConnectorAlertItem(c) {
  return {
    name: c.name,
    state: connectorState(c),
    healthCategory: connectorHealthCategory(c),
    connect: c.connect,
    failedTasks: connectorFailedTasks(c)
  };
}

function toConsumerAlertItem(g) {
  return {
    groupId: g.groupId,
    state: g.state,
    members: g.members,
    consumerLag: g.consumerLag,
    lagSlo: g.lagSlo,
    sloBreached: g.sloBreached,
    stuckOffset: g.stuckOffset,
    lagVelocityAlert: g.lagVelocityAlert,
    lagDelta: g.lagDelta,
    balance: g.partitionUnbalanced
      ? (g.partitionBalance ? `${g.partitionBalance.min}-${g.partitionBalance.max}` : 'unbal')
      : 'ok'
  };
}

function toPipelineIssueItem(issue) {
  return {
    kind: issue.kind,
    topic: issue.topic,
    detail: issue.detail,
    groupId: issue.groupId || null,
    connector: issue.connector || null
  };
}

async function postSlack(text) {
  if (!SLACK_WEBHOOK) return;
  await fetch(SLACK_WEBHOOK, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text })
  });
}

async function sendSlackFailureAlert({
  brokerDown,
  failedConnectors,
  pausedConnectors,
  stoppedConnectors,
  totalConnectors,
  unhealthyGroups,
  pipelineIssues
}) {
  const now = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const lines = [];

  if (brokerDown) {
    lines.push(`🔴 *Kafka Cluster Unreachable* — Could not reach brokers on \`${clusterName}\``);
    lines.push(`_Checked at ${now}_`);
    lines.push(`_Error: ${state.brokerError || 'Unknown'}_`);
    lines.push(`🔗 <${KAFKA_UI_URL}/ui/clusters/${clusterName}|View in Kafbat UI>`);
    lines.push('');
  }

  if (failedConnectors.length > 0) {
    lines.push(`🚨 *Connector Failed* — ${failedConnectors.length} of ${totalConnectors} on \`${clusterName}\``);
    lines.push(`_Checked at ${now}_`);
    lines.push('');
    const cols = { name: 28, status: 14, failed: 8, connect: 36, pause: 14 };
    const sep = `|${'-'.repeat(cols.name + 2)}|${'-'.repeat(cols.status + 2)}|${'-'.repeat(cols.failed + 2)}|${'-'.repeat(cols.connect + 2)}|${'-'.repeat(cols.pause + 2)}|`;
    lines.push('```');
    lines.push(`| ${pad('Connector', cols.name)} | ${pad('Status', cols.status)} | ${pad('Failed', cols.failed)} | ${pad('Connect', cols.connect)} | ${pad('Pause', cols.pause)} |`);
    lines.push(sep);
    for (const c of failedConnectors) lines.push(connectorAlertRow(c, cols));
    lines.push('```');
    appendPerRowPauseLines(lines, 'connector', failedConnectors, 'name');
    lines.push(`🔗 <${KAFKA_UI_URL}/ui/clusters/${clusterName}/connectors|View Connectors>`);
  }

  if (pausedConnectors.length > 0) {
    if (lines.length > 0) lines.push('');
    lines.push(`⏸ *Connector Paused* — ${pausedConnectors.length} connector(s) on \`${clusterName}\``);
    for (const c of pausedConnectors) lines.push(`• \`${c.name}\` (${c.connect || '—'})`);
    appendPerRowPauseLines(lines, 'connector', pausedConnectors, 'name');
  }

  if (stoppedConnectors.length > 0) {
    if (lines.length > 0) lines.push('');
    lines.push(`⏹ *Connector Stopped* — ${stoppedConnectors.length} connector(s) on \`${clusterName}\``);
    for (const c of stoppedConnectors) lines.push(`• \`${c.name}\` (${c.connect || '—'})`);
    appendPerRowPauseLines(lines, 'connector', stoppedConnectors, 'name');
  }

  if (unhealthyGroups.length > 0) {
    if (lines.length > 0) lines.push('');
    lines.push(`⚠️ *Consumer Group Alert* — ${unhealthyGroups.length} unhealthy group(s) on \`${clusterName}\``);
    lines.push(`_SLO / stuck offset / lag velocity flags in Balance column_`);
    lines.push('');
    const cols = { groupId: 34, state: 10, members: 8, lag: 12, balance: 10, pause: 14 };
    const sep = `|${'-'.repeat(cols.groupId + 2)}|${'-'.repeat(cols.state + 2)}|${'-'.repeat(cols.members + 2)}|${'-'.repeat(cols.lag + 2)}|${'-'.repeat(cols.balance + 2)}|${'-'.repeat(cols.pause + 2)}|`;
    lines.push('```');
    lines.push(`| ${pad('Consumer Group', cols.groupId)} | ${pad('State', cols.state)} | ${pad('Members', cols.members)} | ${pad('Lag', cols.lag)} | ${pad('Flags', cols.balance)} | ${pad('Pause', cols.pause)} |`);
    lines.push(sep);
    for (const g of unhealthyGroups) lines.push(consumerAlertRow(g, cols));
    lines.push('```');
    appendPerRowPauseLines(lines, 'consumer', unhealthyGroups, 'groupId');
    lines.push(`🔗 <${KAFKA_UI_URL}/ui/clusters/${clusterName}/consumer-groups|View Consumer Groups>`);
  }

  if (pipelineIssues?.length > 0) {
    if (lines.length > 0) lines.push('');
    lines.push(`🧟 *Pipeline / Topic Issues* — ${pipelineIssues.length} on \`${clusterName}\``);
    for (const issue of pipelineIssues.slice(0, 15)) {
      const src = issue.groupId ? `cg: ${issue.groupId}` : issue.connector ? `connector: ${issue.connector}` : 'cluster';
      lines.push(`• \`${issue.topic}\` _(${issue.kind})_ — ${issue.detail} [${src}]`);
    }
    if (pipelineIssues.length > 15) lines.push(`_…and ${pipelineIssues.length - 15} more_`);
  }

  if (lines.length) await postSlack(lines.join('\n'));
}

async function sendSlackRecoveryAlert({ brokerRecovered, recoveredConnectors, recoveredConsumers }) {
  const now = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const lines = [];
  const total = (brokerRecovered ? 1 : 0) + recoveredConnectors.length + recoveredConsumers.length;
  lines.push(`✅ *Kafka Recovery* — ${total} item(s) healthy again on \`${clusterName}\``);
  lines.push(`_Checked at ${now}_`);
  lines.push('');

  if (brokerRecovered) {
    lines.push('• *Cluster brokers* — reachable again');
    lines.push(`🔗 <${KAFKA_UI_URL}/ui/clusters/${clusterName}|View in Kafbat UI>`);
    lines.push('');
  }

  if (recoveredConnectors.length > 0) {
    const cols = { name: 28, status: 14, failed: 8, connect: 36 };
    const sep = `|${'-'.repeat(cols.name + 2)}|${'-'.repeat(cols.status + 2)}|${'-'.repeat(cols.failed + 2)}|${'-'.repeat(cols.connect + 2)}|`;
    lines.push(`*Connectors recovered (${recoveredConnectors.length}):*`);
    lines.push('```');
    lines.push(`| ${pad('Connector', cols.name)} | ${pad('Status', cols.status)} | ${pad('Failed', cols.failed)} | ${pad('Connect', cols.connect)} |`);
    lines.push(sep);
    for (const c of recoveredConnectors) lines.push(connectorAlertRow(c, cols, false));
    lines.push('```');
  }

  if (recoveredConsumers.length > 0) {
    const cols = { groupId: 34, state: 10, members: 8, lag: 12, balance: 10 };
    const sep = `|${'-'.repeat(cols.groupId + 2)}|${'-'.repeat(cols.state + 2)}|${'-'.repeat(cols.members + 2)}|${'-'.repeat(cols.lag + 2)}|${'-'.repeat(cols.balance + 2)}|`;
    lines.push(`*Consumer groups recovered (${recoveredConsumers.length}):*`);
    lines.push('```');
    lines.push(`| ${pad('Consumer Group', cols.groupId)} | ${pad('State', cols.state)} | ${pad('Members', cols.members)} | ${pad('Lag', cols.lag)} | ${pad('Balance', cols.balance)} |`);
    lines.push(sep);
    for (const g of recoveredConsumers) lines.push(consumerAlertRow(g, cols, false));
    lines.push('```');
    lines.push(`🔗 <${KAFKA_UI_URL}/ui/clusters/${clusterName}/consumer-groups|View Consumer Groups>`);
  }

  await postSlack(lines.join('\n'));
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

    // Publish fetched data immediately so the dashboard is not blocked by Debezium / per-group detail calls
    state.connectors = connectors;
    state.consumerGroups = consumerGroups;
    state.lastChecked = new Date().toISOString();

    try {
      await enrichDebeziumTopicState(connectors, state.brokerStatus === 'ok');
    } catch (err) {
      console.warn('[DEBEZIUM] Enrichment failed:', err.message);
    }

    const failedConnectors = connectors.filter(c => connectorHealthCategory(c) === 'failed');
    const pausedConnectors = connectors.filter(c => connectorHealthCategory(c) === 'paused');
    const stoppedConnectors = connectors.filter(c => connectorHealthCategory(c) === 'stopped');

    let unhealthyGroups = consumerGroups.filter(g => {
      const badState  = g.state !== 'STABLE' && !(g.state === 'EMPTY' && g.members === 0 && g.topics === 0);
      const noMembers = g.state === 'STABLE' && g.members === 0;
      const highLag   = g.consumerLag > LAG_THRESHOLD;
      return badState || noMembers || highLag;
    });

    const checkedAt = new Date();
    const groupDetailsMap = {};
    const groupsNeedingDetails = consumerGroups.filter(
      g => g.state === 'STABLE' && g.members >= 1
    );

    await Promise.all(groupsNeedingDetails.map(async g => {
      const details = await fetchConsumerGroupDetails(g.groupId);
      if (!details) return;
      groupDetailsMap[g.groupId] = details;
      g._detailPartitions = details.partitions || [];
      g.memberAssignments = buildMemberAssignments(details);
      analyzeConsumerLagSignals(g, details, checkedAt);

      if (g.sloBreached || g.stuckOffset || g.lagVelocityAlert) {
        const existing = unhealthyGroups.find(u => u.groupId === g.groupId);
        if (!existing) unhealthyGroups = [...unhealthyGroups, g];
      }

      if (CHECK_BALANCE && g.members > 1) {
        const balance = checkPartitionBalance(details);
        g.partitionBalance = balance;
        if (!balance.balanced) {
          const existing = unhealthyGroups.find(u => u.groupId === g.groupId);
          if (existing) existing.partitionUnbalanced = true;
          else unhealthyGroups = [...unhealthyGroups, { ...g, partitionUnbalanced: true }];
        }
      }
    }));

    let pipelineResult = { issues: [], scannedAt: null, zombieScanEnabled: ORPHAN_ZOMBIE_SCAN };
    if (CHECK_ORPHAN_TOPICS && state.brokerStatus === 'ok') {
      try {
        let clusterTopicSet = null;
        try {
          const names = await fetchAllTopicNames();
          clusterTopicSet = new Set(names);
        } catch (err) {
          console.warn('[ORPHAN] Could not load cluster topics:', err.message);
        }
        pipelineResult = await analyzePipelineTopics({ connectors, groupDetailsMap, clusterTopicSet });
      } catch (err) {
        console.warn('[ORPHAN] Pipeline analysis failed:', err.message);
      }
    }

    updateLagHistory(consumerGroups, checkedAt);

    state.lastChecked   = checkedAt.toISOString();
    state.connectors    = connectors;
    state.consumerGroups = consumerGroups;
    state.pipelineIssues = pipelineResult.issues;

    const brokerDown = state.brokerStatus === 'unreachable';
    const hasPipelineIssues = pipelineResult.issues.length > 0;
    state.status = (
      brokerDown ||
      failedConnectors.length > 0 ||
      pausedConnectors.length > 0 ||
      stoppedConnectors.length > 0 ||
      unhealthyGroups.length > 0 ||
      hasPipelineIssues
    ) ? 'alert' : 'ok';

    const toAlertConns = failedConnectors.filter(c => !isAcknowledged('connector', c.name));
    const toAlertPaused = pausedConnectors.filter(c => !isAcknowledged('connector', c.name));
    const toAlertStopped = stoppedConnectors.filter(c => !isAcknowledged('connector', c.name));
    const toAlertCons  = unhealthyGroups.filter(g => !isAcknowledged('consumer', g.groupId));
    const toAlertPipeline = pipelineResult.issues;

    const prev = state.healthSnapshot || {
      brokerDown: false,
      connectors: [],
      pausedConnectors: [],
      stoppedConnectors: [],
      consumers: [],
      pipelineIssues: []
    };
    const curConnNames = failedConnectors.map(c => c.name);
    const curPausedNames = pausedConnectors.map(c => c.name);
    const curStoppedNames = stoppedConnectors.map(c => c.name);
    const curConsIds = unhealthyGroups.map(g => g.groupId);
    const curPipelineKeys = pipelineResult.issues.map(pipelineIssueKey);

    const recoveredConnectorNames = prev.connectors.filter(n => !curConnNames.includes(n));
    const recoveredPausedNames = prev.pausedConnectors.filter(n => !curPausedNames.includes(n));
    const recoveredStoppedNames = prev.stoppedConnectors.filter(n => !curStoppedNames.includes(n));
    const recoveredConsumerIds = prev.consumers.filter(id => !curConsIds.includes(id));
    const recoveredPipelineKeys = (prev.pipelineIssues || []).filter(k => !curPipelineKeys.includes(k));
    const brokerRecovered = prev.brokerDown && !brokerDown;

    const recoveredConnectors = recoveredConnectorNames.map(name => {
      const c = connectors.find(x => x.name === name);
      return c || { name, status: { state: 'RUNNING' }, connect: '—', failed_tasks_count: 0 };
    });
    const recoveredConsumers = recoveredConsumerIds.map(id => {
      const g = consumerGroups.find(x => x.groupId === id);
      return g || { groupId: id, state: 'STABLE', members: 0, consumerLag: 0 };
    });

    const hasFailureAlert = brokerDown ||
      toAlertConns.length > 0 ||
      toAlertPaused.length > 0 ||
      toAlertStopped.length > 0 ||
      toAlertCons.length > 0 ||
      toAlertPipeline.length > 0;
    const hasRecovery = brokerRecovered ||
      recoveredConnectors.length > 0 ||
      recoveredPausedNames.length > 0 ||
      recoveredStoppedNames.length > 0 ||
      recoveredConsumers.length > 0 ||
      recoveredPipelineKeys.length > 0;

    if (hasFailureAlert) {
      await sendSlackFailureAlert({
        brokerDown,
        failedConnectors: toAlertConns,
        pausedConnectors: toAlertPaused,
        stoppedConnectors: toAlertStopped,
        totalConnectors: connectors.length,
        unhealthyGroups: toAlertCons,
        pipelineIssues: toAlertPipeline
      });
      pushAlertEvent({
        kind: 'failure',
        time: state.lastChecked,
        brokerDown: brokerDown ? 1 : 0,
        connectors: [...toAlertConns, ...toAlertPaused, ...toAlertStopped].map(toConnectorAlertItem),
        consumers: toAlertCons.map(toConsumerAlertItem),
        pipelineIssues: toAlertPipeline.map(toPipelineIssueItem)
      });
      console.log(
        `[ALERT] ${brokerDown ? 'Broker unreachable | ' : ''}` +
        `Failed: ${toAlertConns.length} | Paused: ${toAlertPaused.length} | Stopped: ${toAlertStopped.length} | ` +
        `Consumers: ${toAlertCons.length} | Pipeline: ${toAlertPipeline.length}`
      );
    }

    if (hasRecovery) {
      await sendSlackRecoveryAlert({ brokerRecovered, recoveredConnectors, recoveredConsumers });
      pushAlertEvent({
        kind: 'recovery',
        time: state.lastChecked,
        brokerRecovered: brokerRecovered ? 1 : 0,
        connectors: recoveredConnectors.map(toConnectorAlertItem),
        consumers: recoveredConsumers.map(toConsumerAlertItem)
      });
      console.log(`[RECOVERY] Broker: ${brokerRecovered ? 'yes' : 'no'} | Connectors: ${recoveredConnectors.length} | Consumers: ${recoveredConsumers.length}`);
    }

    state.healthSnapshot = {
      brokerDown,
      connectors: curConnNames,
      pausedConnectors: curPausedNames,
      stoppedConnectors: curStoppedNames,
      consumers: curConsIds,
      pipelineIssues: curPipelineKeys
    };

    if (!hasFailureAlert && !hasRecovery) {
      console.log(
        `[OK] Brokers: ${state.brokers?.length ?? 0} | ${connectors.length} connectors | ` +
        `${consumerGroups.length} consumer groups | Pipeline issues: ${pipelineResult.issues.length}`
      );
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
    cluster:        clusterName,
    kafkaUiUrl:     KAFKA_UI_URL,
    kafbatAuthType: kafbatAuthType,
    lagThreshold:   LAG_THRESHOLD,
    lagVelocityThreshold: LAG_VELOCITY_THRESHOLD,
    checkDebeziumTopics: CHECK_DEBEZIUM_TOPICS,
    checkPartitionBalance: CHECK_BALANCE,
    checkOrphanTopics: CHECK_ORPHAN_TOPICS,
    orphanZombieScan: ORPHAN_ZOMBIE_SCAN,
    acks,
    brokers:        state.brokers,
    brokerStatus:   state.brokerStatus,
    brokerError:    state.brokerError,
    pipelineIssues: state.pipelineIssues,
    connectors: state.connectors.map(c => ({
      name:        c.name,
      connect:     c.connect,
      type:        c.type,
      connectorClass: connectorClassName(c),
      state:       connectorState(c),
      healthCategory: connectorHealthCategory(c),
      tasksCount:  connectorTasksCount(c),
      failedTasks: connectorFailedTasks(c),
      workerId:    connectorWorkerId(c),
      acknowledged: isAcknowledged('connector', c.name),
      debeziumTopics: c.debeziumTopicVerification || null
    })),
    consumerGroups: state.consumerGroups.map(g => ({
      groupId:         g.groupId,
      state:           g.state,
      members:         g.members,
      topics:          g.topics,
      consumerLag:     g.consumerLag,
      lagSlo:          g.lagSlo,
      sloBreached:     g.sloBreached,
      lagDelta:        g.lagDelta,
      lagVelocity:     g.lagVelocity,
      lagVelocityAlert: g.lagVelocityAlert,
      stuckOffset:     g.stuckOffset,
      stuckPartitions: g.stuckPartitions,
      partitionBalance: g.partitionBalance,
      partitionUnbalanced: g.partitionUnbalanced,
      memberAssignments: g.memberAssignments,
      acknowledged: isAcknowledged('consumer', g.groupId)
    })),
    alerts: state.alerts
  });
});

app.get('/api/pipeline-issues/export.csv', (req, res) => {
  const exportedAt = new Date().toISOString();
  const csv = pipelineIssuesToCsv(state.pipelineIssues, clusterName, exportedAt);
  const safeCluster = clusterName.replace(/[^\w.-]+/g, '_');
  const filename = `pipeline-issues-${safeCluster}-${exportedAt.slice(0, 10)}.csv`;
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send('\uFEFF' + csv);
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
app.listen(PORT, async () => {
  console.log(`Kafka Monitor running on port ${PORT}`);
  console.log(`Kafbat UI: ${KAFKA_UI_URL} (cluster: ${clusterName})`);
  try {
    await initKafbatAuth();
    await initKafbatCluster();
    await runCheck();
  } catch (err) {
    console.error('[STARTUP]', err.message);
    state.status = 'error';
    state.brokerError = err.message;
    state.lastChecked = new Date().toISOString();
  }
});
