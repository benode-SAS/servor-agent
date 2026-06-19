import { createHmac } from 'node:crypto';
import { type CheckDef, type CheckResult, runCheck } from './checks';
import { loadConfig, saveConfig } from './config';
import { collect } from './metrics';
import { setExecPolicy, startTunnel } from './tunnel';
import { stageUpdate } from './updater';
import { BUILD_VERSION } from './version';

const UPDATE_INTERVAL_MS = 60 * 60 * 1000;
const CHECK_TICK_MS = 10 * 1000;
const INTERVAL_MIN = 15;
const INTERVAL_MAX = 300;

const cfg = loadConfig();

const clampInterval = (s: number) => Math.min(INTERVAL_MAX, Math.max(INTERVAL_MIN, Math.round(s)));

// HMAC the agent's per-server secret over `${ts}.${payload}` (same scheme as ingest).
const sign = (payload: string) => {
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = createHmac('sha256', cfg.secret).update(`${ts}.${payload}`).digest('hex');
  return { ts, sig };
};

// ── Graceful self-update (drain) ─────────────────────────────────────────────
// Stage the verified binary, then restart ONLY when the agent is idle so an
// in-progress command or interactive terminal is never killed mid-task. A
// long-running task simply defers the restart until it finishes.
let updateStaged = false;
let tunnelBusy: () => boolean = () => false;

const maybeApplyUpdate = async () => {
  if (!updateStaged) updateStaged = await stageUpdate(cfg, BUILD_VERSION);
  if (updateStaged && !tunnelBusy()) {
    console.log('agent idle — applying staged update, restarting');
    process.exit(0); // service manager relaunches the swapped binary
  }
};

// ── Metrics push (read-only) ─────────────────────────────────────────────────
const pushMetrics = async () => {
  try {
    const payload = await collect(BUILD_VERSION);
    const body = JSON.stringify(payload);
    const { ts, sig } = sign(body);
    await fetch(`${cfg.apiUrl}/agent/ingest/${cfg.serverId}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-servor-timestamp': ts,
        'x-servor-signature': sig,
      },
      body,
    });
  } catch (e) {
    console.error('metrics push failed', (e as Error).message);
  }
};

const metricsLoop = async () => {
  await pushMetrics();
  setTimeout(metricsLoop, cfg.intervalSeconds * 1000);
};

// ── Config sync + agent-driven checks ────────────────────────────────────────
let checks: CheckDef[] = [];
let configIntervalMs = 30 * 1000;
const lastRun = new Map<string, number>();

const fetchConfig = async () => {
  try {
    const { ts, sig } = sign(`config:${cfg.serverId}`);
    const res = await fetch(`${cfg.apiUrl}/agent/config/${cfg.serverId}`, {
      headers: { 'x-servor-timestamp': ts, 'x-servor-signature': sig },
    });
    if (!res.ok) return;
    const data = (await res.json()) as {
      checks?: CheckDef[];
      configIntervalSeconds?: number;
      metricsIntervalSeconds?: number;
      version?: string;
      requireSignedExec?: boolean;
      authorizedExecKeys?: Array<{ userId: string; pubkey: string }>;
    };

    setExecPolicy(
      data.requireSignedExec === true,
      (data.authorizedExecKeys ?? []).map((k) => k.pubkey),
    );

    if (Array.isArray(data.checks)) {
      checks = data.checks;
      const ids = new Set(checks.map((c) => c.id));
      for (const id of lastRun.keys()) if (!ids.has(id)) lastRun.delete(id);
    }
    if (typeof data.configIntervalSeconds === 'number') {
      configIntervalMs = Math.max(10, data.configIntervalSeconds) * 1000;
    }
    if (typeof data.metricsIntervalSeconds === 'number') {
      const next = clampInterval(data.metricsIntervalSeconds);
      if (next !== cfg.intervalSeconds) {
        cfg.intervalSeconds = next;
        saveConfig({ intervalSeconds: next });
      }
    }
    if (updateStaged || (data.version && data.version !== BUILD_VERSION)) void maybeApplyUpdate();
  } catch (e) {
    console.error('config fetch failed', (e as Error).message);
  }
};

const pushResults = async (results: CheckResult[]) => {
  try {
    const body = JSON.stringify({ results });
    const { ts, sig } = sign(body);
    await fetch(`${cfg.apiUrl}/agent/checks/${cfg.serverId}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-servor-timestamp': ts,
        'x-servor-signature': sig,
      },
      body,
    });
  } catch (e) {
    console.error('checks push failed', (e as Error).message);
  }
};

const runDueChecks = async () => {
  const now = Date.now();
  const due = checks.filter((c) => now - (lastRun.get(c.id) ?? 0) >= c.intervalSeconds * 1000);
  if (due.length === 0) return;
  const results: CheckResult[] = [];
  for (const c of due) {
    lastRun.set(c.id, now);
    results.push(await runCheck(c, cfg.user));
  }
  if (results.length > 0) await pushResults(results);
};

const configLoop = async () => {
  await fetchConfig();
  setTimeout(configLoop, configIntervalMs);
};

const checkLoop = async () => {
  await runDueChecks();
  setTimeout(checkLoop, CHECK_TICK_MS);
};

const main = () => {
  console.log(
    `servor-agent ${BUILD_VERSION} starting (mode=${cfg.mode}, interval=${cfg.intervalSeconds}s)`,
  );

  void metricsLoop();
  void configLoop();
  void checkLoop();

  if (cfg.mode === 'tunnel') {
    const tunnel = startTunnel(cfg);
    tunnelBusy = tunnel.isBusy;
  }

  void maybeApplyUpdate();
  setInterval(() => void maybeApplyUpdate(), UPDATE_INTERVAL_MS);

  process.on('SIGTERM', () => process.exit(0));
  process.on('SIGINT', () => process.exit(0));
};

main();
