import { createHmac } from 'node:crypto';
import { type CheckDef, type CheckResult, runCheck } from './checks';
import { loadConfig, saveConfig } from './config';
import { collect } from './metrics';
import { setExecPolicy, startTunnel } from './tunnel';
import { stageUpdate } from './updater';
import { BUILD_VERSION } from './version';

/** How often to look for a newer release, independently of the config channel. */
const UPDATE_INTERVAL_MS = 60 * 60 * 1000;
/** Scheduler resolution: how often due checks are looked for, not how often they run. */
const CHECK_TICK_MS = 10 * 1000;
const INTERVAL_MIN = 15;
const INTERVAL_MAX = 300;

const cfg = loadConfig();

/**
 * Keep a control-plane-supplied push interval inside what the agent will honour.
 *
 * @remarks
 * A floor as much as a ceiling: without it a config response could pin the
 * agent to a one-second interval and turn the fleet's own telemetry into a load
 * generator against the host and the API.
 */
const clampInterval = (s: number) => Math.min(INTERVAL_MAX, Math.max(INTERVAL_MIN, Math.round(s)));

/**
 * Authenticate one outbound request by HMAC-ing the per-server secret.
 *
 * @param payload - Exact bytes being authenticated: the JSON body for a push, or
 * a short descriptor such as `config:<serverId>` for a GET.
 * @returns The timestamp and hex signature to send as `x-servor-timestamp` and
 * `x-servor-signature`.
 *
 * @remarks
 * The timestamp is inside the signed string, so the control plane can reject a
 * captured request replayed later. This proves the request came from this
 * agent; it authorises nothing in the other direction — a command still needs a
 * grant signed by an operator key, which this secret cannot produce.
 */
const sign = (payload: string) => {
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = createHmac('sha256', cfg.secret).update(`${ts}.${payload}`).digest('hex');
  return { ts, sig };
};

let updateStaged = false;
/** Replaced by the tunnel's own predicate once it starts; `push` mode is never busy. */
let tunnelBusy: () => boolean = () => false;

/**
 * Stage a verified update if one exists, and restart only once the agent is idle.
 *
 * @remarks
 * The two halves are deliberately separate. Staging swaps the binary on disk,
 * which is safe while running because the live process keeps its code in
 * memory. Restarting is what would kill an in-flight command or an interactive
 * terminal, so it waits for the tunnel to report idle; a long task simply
 * defers the restart until it finishes. Exiting is the whole restart mechanism:
 * the service manager relaunches the swapped binary.
 */
const maybeApplyUpdate = async () => {
  if (!updateStaged) updateStaged = await stageUpdate(cfg, BUILD_VERSION);
  if (updateStaged && !tunnelBusy()) {
    console.log('agent idle — applying staged update, restarting');
    process.exit(0); // service manager relaunches the swapped binary
  }
};

/**
 * Collect one host sample and POST it to the ingest endpoint.
 *
 * @remarks
 * Failures are logged and dropped rather than retried: the next round is
 * seconds away, and a queue of stale samples is worth less than a fresh one.
 */
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

/**
 * Push metrics forever, re-reading the interval each round.
 *
 * @remarks
 * Chained timeouts rather than `setInterval`: the delay starts when the
 * previous push finished, so a slow API cannot pile overlapping pushes on top
 * of each other, and a retune applied by {@link fetchConfig} takes effect on
 * the next round.
 */
const metricsLoop = async () => {
  await pushMetrics();
  setTimeout(metricsLoop, cfg.intervalSeconds * 1000);
};

/** Check definitions currently in force, replaced wholesale on each config sync. */
let checks: CheckDef[] = [];
let configIntervalMs = 30 * 1000;
/** Last run time per check id, so each check keeps its own cadence. */
const lastRun = new Map<string, number>();

/**
 * Pull this agent's configuration and apply it: exec policy, checks, intervals.
 *
 * @remarks
 * This is the channel that carries the execution policy — the set of operator
 * public keys authorised to sign commands, and whether a signature is required
 * — and {@link setExecPolicy} applies it as given. The agent starts fail-closed
 * (signature required, no keys, so nothing runs) and only ever relaxes that on
 * a response it has authenticated with its own HMAC secret. A fully compromised
 * control plane could still add a key of its own to the authorised set; that
 * limitation is stated in the README and closing it needs the key set pinned at
 * enrollment, which is not implemented.
 *
 * A failed or non-OK fetch changes nothing: the previous policy, checks and
 * intervals stay in force rather than degrading to a permissive default.
 */
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

    // `requireSignedExec` is deliberately ignored: signing is pinned on in the
    // agent. Only the key set is taken from the response.
    setExecPolicy((data.authorizedExecKeys ?? []).map((k) => k.pubkey));

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

/** POST a batch of check results; a failed push is logged and the batch dropped. */
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

/**
 * Run every check whose interval has elapsed and push their results together.
 *
 * @remarks
 * `lastRun` is stamped before the check runs, not after, so a probe that takes
 * longer than its own interval cannot queue a second copy of itself. Due checks
 * run one after another rather than in parallel: they are monitoring, and a
 * burst of concurrent probes would distort the very host they measure.
 */
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

/** Re-sync configuration forever, at the cadence the last sync asked for. */
const configLoop = async () => {
  await fetchConfig();
  setTimeout(configLoop, configIntervalMs);
};

/** Tick the check scheduler forever; each tick runs only what is actually due. */
const checkLoop = async () => {
  await runDueChecks();
  setTimeout(checkLoop, CHECK_TICK_MS);
};

/**
 * Start every loop and, in tunnel mode, the command channel.
 *
 * @remarks
 * The loops are fire-and-forget by design: each one reschedules itself and
 * swallows its own errors, so no single failing endpoint can stop the others.
 * SIGTERM and SIGINT exit cleanly, which under a service manager is also how a
 * staged update gets applied.
 */
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
