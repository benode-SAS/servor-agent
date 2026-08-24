import { createHmac } from 'node:crypto';
import { type CheckDef, type CheckResult, runCheck as defaultRunCheck } from './checks';
import { type AgentConfig, saveConfig as defaultSaveConfig } from './config';
import { collect as defaultCollect } from './metrics';
import { type AgentMessageKind, canonicalAgentMessage } from './protocol/agent-hmac';
import { setExecPolicy as defaultSetExecPolicy, startTunnel as defaultStartTunnel } from './tunnel';
import { stageUpdate as defaultStageUpdate } from './updater';
import { BUILD_VERSION } from './version';

/** How often to look for a newer release, independently of the config channel. */
const UPDATE_INTERVAL_MS = 60 * 60 * 1000;
/** Scheduler resolution: how often due checks are looked for, not how often they run. */
const CHECK_TICK_MS = 10 * 1000;
const INTERVAL_MIN = 15;
const INTERVAL_MAX = 300;

/**
 * Keep a control-plane-supplied push interval inside what the agent will honour.
 *
 * @remarks
 * A floor as much as a ceiling: without it a config response could pin the
 * agent to a one-second interval and turn the fleet's own telemetry into a load
 * generator against the host and the API.
 */
export const clampInterval = (s: number) =>
  Math.min(INTERVAL_MAX, Math.max(INTERVAL_MIN, Math.round(s)));

/**
 * Collaborators the agent reaches the outside world through.
 *
 * @remarks
 * Every field defaults to the production implementation, so omitting `deps` —
 * which is what the entrypoint does — leaves behaviour unchanged. They exist so
 * the loops can be exercised without a network, a clock, a real host or a real
 * process.
 */
export type AgentDeps = {
  fetch: (url: string, init?: RequestInit) => Promise<Response>;
  now: () => number;
  collect: typeof defaultCollect;
  runCheck: typeof defaultRunCheck;
  stageUpdate: typeof defaultStageUpdate;
  startTunnel: (cfg: AgentConfig) => { isBusy: () => boolean };
  setExecPolicy: typeof defaultSetExecPolicy;
  saveConfig: typeof defaultSaveConfig;
  /** How the process ends; exiting is the whole of the restart mechanism. */
  exit: (code: number) => void;
};

/** One configured agent: its loops, and the operations those loops perform. */
export type Agent = {
  start: () => void;
  stop: () => void;
  sign: (kind: AgentMessageKind, payload: string) => { ts: string; sig: string };
  clampInterval: (s: number) => number;
  fetchConfig: () => Promise<void>;
  pushMetrics: () => Promise<void>;
  pushResults: (results: CheckResult[]) => Promise<void>;
  runDueChecks: () => Promise<void>;
  maybeApplyUpdate: () => Promise<void>;
};

/**
 * Build the agent for one loaded configuration.
 *
 * @param cfg - Config read from disk. `intervalSeconds` is mutated in place when
 * the control plane retunes it, so the running loops pick up the new cadence.
 * @param deps - Collaborators to substitute; each one defaults to the real
 * implementation.
 */
export const createAgent = (cfg: AgentConfig, deps: Partial<AgentDeps> = {}): Agent => {
  const {
    fetch: fetchImpl = fetch,
    now = Date.now,
    collect = defaultCollect,
    runCheck = defaultRunCheck,
    stageUpdate = defaultStageUpdate,
    startTunnel = defaultStartTunnel,
    setExecPolicy = defaultSetExecPolicy,
    saveConfig = defaultSaveConfig,
    exit = (code: number) => process.exit(code),
  } = deps;

  let stopped = false;
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const intervals = new Set<ReturnType<typeof setInterval>>();

  /** Reschedule a self-perpetuating loop, unless the agent has been stopped. */
  const later = (fn: () => void, ms: number) => {
    if (stopped) return;
    const t = setTimeout(() => {
      timers.delete(t);
      fn();
    }, ms);
    timers.add(t);
  };

  /**
   * Authenticate one outbound request by HMAC-ing the per-server secret.
   *
   * @param kind - What the signature is allowed to authenticate. One secret
   * signs several kinds of request, so it is inside the signed bytes: without
   * it, a signature lifted from one exchange authenticates another whose body
   * happens to match.
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
  const sign = (kind: AgentMessageKind, payload: string) => {
    const ts = String(Math.floor(now() / 1000));
    const sig = createHmac('sha256', cfg.secret)
      .update(canonicalAgentMessage({ kind, serverId: cfg.serverId, timestamp: ts, body: payload }))
      .digest('hex');
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
      exit(0); // service manager relaunches the swapped binary
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
      const { ts, sig } = sign('ingest', body);
      await fetchImpl(`${cfg.apiUrl}/agent/ingest/${cfg.serverId}`, {
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
    later(() => void metricsLoop(), cfg.intervalSeconds * 1000);
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
      const { ts, sig } = sign('config', `config:${cfg.serverId}`);
      const res = await fetchImpl(`${cfg.apiUrl}/agent/config/${cfg.serverId}`, {
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
      const { ts, sig } = sign('result', body);
      await fetchImpl(`${cfg.apiUrl}/agent/checks/${cfg.serverId}`, {
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
    const stamp = now();
    const due = checks.filter((c) => stamp - (lastRun.get(c.id) ?? 0) >= c.intervalSeconds * 1000);
    if (due.length === 0) return;
    const results: CheckResult[] = [];
    for (const c of due) {
      lastRun.set(c.id, stamp);
      results.push(await runCheck(c, cfg.user));
    }
    if (results.length > 0) await pushResults(results);
  };

  /** Re-sync configuration forever, at the cadence the last sync asked for. */
  const configLoop = async () => {
    await fetchConfig();
    later(() => void configLoop(), configIntervalMs);
  };

  /** Tick the check scheduler forever; each tick runs only what is actually due. */
  const checkLoop = async () => {
    await runDueChecks();
    later(() => void checkLoop(), CHECK_TICK_MS);
  };

  const onSignal = () => exit(0);

  /**
   * Start every loop and, in tunnel mode, the command channel.
   *
   * @remarks
   * The loops are fire-and-forget by design: each one reschedules itself and
   * swallows its own errors, so no single failing endpoint can stop the others.
   * SIGTERM and SIGINT exit cleanly, which under a service manager is also how a
   * staged update gets applied.
   */
  const start = () => {
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
    const updateTimer = setInterval(() => void maybeApplyUpdate(), UPDATE_INTERVAL_MS);
    intervals.add(updateTimer);

    process.on('SIGTERM', onSignal);
    process.on('SIGINT', onSignal);
  };

  /** Cancel every pending loop and drop the signal handlers. */
  const stop = () => {
    stopped = true;
    for (const t of timers) clearTimeout(t);
    timers.clear();
    for (const i of intervals) clearInterval(i);
    intervals.clear();
    process.off('SIGTERM', onSignal);
    process.off('SIGINT', onSignal);
  };

  return {
    start,
    stop,
    sign,
    clampInterval,
    fetchConfig,
    pushMetrics,
    pushResults,
    runDueChecks,
    maybeApplyUpdate,
  };
};
