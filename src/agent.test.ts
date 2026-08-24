import { beforeEach, describe, expect, test } from 'bun:test';
import { createHmac } from 'node:crypto';
import { x25519 } from '@noble/curves/ed25519';
import { clampInterval, createAgent } from './agent';
import type { CheckDef, CheckResult } from './checks';
import type { AgentConfig } from './config';
import { createGrantVerifier } from './grant';
import type { Payload } from './metrics';
import { type AgentMessageKind, canonicalAgentMessage } from './protocol/agent-hmac';
import { execPublicKeyFromVault } from './protocol/exec-sign';
import { BUILD_VERSION } from './version';

const SERVER_ID = '019ecd37-5979-72ce-8960-fc9454880973';
const SECRET = 'per-server-enrollment-secret';
const API = 'https://api.servor.test';

let clock = Date.UTC(2026, 0, 1, 12, 0, 0);

const config = (over: Partial<AgentConfig> = {}): AgentConfig => ({
  serverId: SERVER_ID,
  secret: SECRET,
  apiUrl: API,
  intervalSeconds: 60,
  mode: 'push',
  version: '1',
  ...over,
});

const check = (id: string, over: Partial<CheckDef> = {}): CheckDef => ({
  id,
  type: 'http',
  intervalSeconds: 60,
  timeoutSeconds: 5,
  config: { url: `${API}/ping` },
  ...over,
});

const sample = (agentVersion: string): Payload => ({
  v: 1,
  agentVersion,
  os: 'linux',
  specs: {},
  metrics: {},
});

const outcome = (monitorId: string): CheckResult => ({
  monitorId,
  status: 'up',
  latencyMs: 1,
  errorMessage: null,
});

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/** Let every already-scheduled promise chain settle before asserting. */
const flush = () => Bun.sleep(1);

const hmac = (secret: string, ts: string, kind: AgentMessageKind, payload: string) =>
  createHmac('sha256', secret)
    .update(canonicalAgentMessage({ kind, serverId: SERVER_ID, timestamp: ts, body: payload }))
    .digest('hex');

const pubkeyB64 = () =>
  Buffer.from(execPublicKeyFromVault(x25519.utils.randomPrivateKey())).toString('base64');

type Sent = { url: string; init?: RequestInit };

type HarnessOptions = {
  cfg?: AgentConfig;
  respond?: (url: string) => Response | Promise<Response>;
  stageUpdate?: () => Promise<boolean>;
  runCheck?: (def: CheckDef, user?: string) => Promise<CheckResult>;
  busy?: () => boolean;
};

/** One agent with every collaborator replaced by a recorder. */
const harness = (opts: HarnessOptions = {}) => {
  const cfg = opts.cfg ?? config();
  const sent: Sent[] = [];
  const policies: string[][] = [];
  const saved: Partial<AgentConfig>[] = [];
  const exits: number[] = [];
  const tunnels: AgentConfig[] = [];
  let staged = 0;

  const agent = createAgent(cfg, {
    fetch: async (url, init) => {
      sent.push({ url, init });
      return opts.respond ? await opts.respond(url) : json({});
    },
    now: () => clock,
    collect: async (version) => sample(version),
    runCheck: opts.runCheck ?? (async (def) => outcome(def.id)),
    stageUpdate: async () => {
      staged++;
      return opts.stageUpdate ? await opts.stageUpdate() : false;
    },
    startTunnel: (c) => {
      tunnels.push(c);
      return { isBusy: opts.busy ?? (() => false) };
    },
    setExecPolicy: (keys) => policies.push(keys),
    saveConfig: (patch) => saved.push(patch),
    exit: (code) => exits.push(code),
  });

  return {
    agent,
    cfg,
    sent,
    policies,
    saved,
    exits,
    tunnels,
    stagedCount: () => staged,
    lastPolicy: () => policies[policies.length - 1] ?? [],
    bodyOf: (n: number) => String(sent[n]?.init?.body ?? ''),
    headersOf: (n: number) => (sent[n]?.init?.headers ?? {}) as Record<string, string>,
  };
};

beforeEach(() => {
  clock = Date.UTC(2026, 0, 1, 12, 0, 0);
});

describe('interval clamping', () => {
  test('an interval inside the accepted range is kept as it is', () => {
    expect(clampInterval(60)).toBe(60);
  });

  test('an interval below the floor is raised to 15 seconds', () => {
    expect(clampInterval(1)).toBe(15);
    expect(clampInterval(0)).toBe(15);
    expect(clampInterval(-3600)).toBe(15);
  });

  test('an interval above the ceiling is capped at 300 seconds', () => {
    expect(clampInterval(301)).toBe(300);
    expect(clampInterval(86_400)).toBe(300);
  });

  test('the bounds themselves are accepted', () => {
    expect(clampInterval(15)).toBe(15);
    expect(clampInterval(300)).toBe(300);
  });

  test('a fractional interval is rounded to the nearest second', () => {
    expect(clampInterval(42.4)).toBe(42);
    expect(clampInterval(42.5)).toBe(43);
    expect(clampInterval(14.6)).toBe(15);
  });

  test('the agent exposes the same clamp its config channel applies', () => {
    expect(harness().agent.clampInterval(9999)).toBe(300);
  });
});

describe('request signing', () => {
  test('the signature covers the timestamp as well as the payload', () => {
    const { agent } = harness();
    const { ts, sig } = agent.sign('ingest', 'body');
    expect(ts).toBe(String(Math.floor(clock / 1000)));
    expect(sig).toBe(hmac(SECRET, ts, 'ingest', 'body'));
  });

  test('the same payload signed at another moment gives another signature', () => {
    const { agent } = harness();
    const first = agent.sign('ingest', 'body');
    clock += 60_000;
    const second = agent.sign('ingest', 'body');
    expect(second.ts).not.toBe(first.ts);
    expect(second.sig).not.toBe(first.sig);
  });

  test('the same payload signed for another purpose gives another signature', () => {
    // One secret signs metrics pushes, config fetches, result batches and the
    // tunnel handshake. Without the kind inside the signed bytes, a signature
    // lifted from one authenticates another whose body happens to match.
    const { agent } = harness();
    const ingest = agent.sign('ingest', 'body');
    const result = agent.sign('result', 'body');
    expect(ingest.ts).toBe(result.ts);
    expect(ingest.sig).not.toBe(result.sig);
  });

  test('a different payload gives a different signature', () => {
    const { agent } = harness();
    expect(agent.sign('ingest', 'one').sig).not.toBe(agent.sign('ingest', 'two').sig);
  });

  test('a different secret gives a different signature', () => {
    const mine = harness().agent.sign('ingest', 'body');
    const theirs = harness({ cfg: config({ secret: 'someone-elses-secret' }) }).agent.sign(
      'ingest',
      'body',
    );
    expect(theirs.sig).not.toBe(mine.sig);
  });

  test('the shape is the seconds timestamp and hex digest the API verifies', () => {
    const { ts, sig } = harness().agent.sign('ingest', 'body');
    expect(ts).toMatch(/^\d{10}$/);
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('config sync', () => {
  test('the authorized exec keys from the response become the policy', async () => {
    const a = pubkeyB64();
    const b = pubkeyB64();
    const h = harness({
      respond: () =>
        json({
          authorizedExecKeys: [
            { userId: 'user-a', pubkey: a },
            { userId: 'user-b', pubkey: b },
          ],
        }),
    });
    await h.agent.fetchConfig();
    expect(h.policies).toEqual([[a, b]]);
  });

  test('the request is signed with the config descriptor, not the body', async () => {
    const h = harness();
    await h.agent.fetchConfig();
    expect(h.sent[0]?.url).toBe(`${API}/agent/config/${SERVER_ID}`);
    const headers = h.headersOf(0);
    const ts = headers['x-servor-timestamp'] ?? '';
    expect(headers['x-servor-signature']).toBe(hmac(SECRET, ts, 'config', `config:${SERVER_ID}`));
  });

  test('a response dropping an operator revokes that key', async () => {
    const kept = pubkeyB64();
    const revoked = pubkeyB64();
    let keys = [kept, revoked];
    const h = harness({
      respond: () => json({ authorizedExecKeys: keys.map((pubkey) => ({ userId: 'u', pubkey })) }),
    });
    await h.agent.fetchConfig();
    keys = [kept];
    await h.agent.fetchConfig();
    expect(h.lastPolicy()).toEqual([kept]);
  });

  test('a response carrying no keys leaves the agent unable to run anything', async () => {
    const h = harness({ respond: () => json({}) });
    await h.agent.fetchConfig();
    expect(h.policies).toEqual([[]]);
  });

  test('a response saying signatures are not required does not disable signing', async () => {
    const pubkey = pubkeyB64();
    const h = harness({
      respond: () =>
        json({ requireSignedExec: false, authorizedExecKeys: [{ userId: 'u', pubkey }] }),
    });
    await h.agent.fetchConfig();
    expect(h.lastPolicy()).toEqual([pubkey]);

    const verifier = createGrantVerifier({ serverId: SERVER_ID, now: () => clock });
    verifier.setKeys(h.lastPolicy());
    expect(verifier.verify('exec', 'whoami', { command: 'whoami' })).toBe(false);
  });

  test('the check list is replaced wholesale rather than merged', async () => {
    const ran: string[] = [];
    let checks = [check('a'), check('b')];
    const h = harness({
      respond: () => json({ checks }),
      runCheck: async (def) => {
        ran.push(def.id);
        return outcome(def.id);
      },
    });
    await h.agent.fetchConfig();
    await h.agent.runDueChecks();
    expect(ran).toEqual(['a', 'b']);

    checks = [check('c')];
    await h.agent.fetchConfig();
    ran.length = 0;
    await h.agent.runDueChecks();
    expect(ran).toEqual(['c']);
  });

  test('a check that disappears and comes back forgets when it last ran', async () => {
    const ran: string[] = [];
    let checks = [check('a', { intervalSeconds: 3600 })];
    const h = harness({
      respond: () => json({ checks }),
      runCheck: async (def) => {
        ran.push(def.id);
        return outcome(def.id);
      },
    });
    await h.agent.fetchConfig();
    await h.agent.runDueChecks();
    expect(ran).toEqual(['a']);

    checks = [];
    await h.agent.fetchConfig();
    checks = [check('a', { intervalSeconds: 3600 })];
    await h.agent.fetchConfig();
    await h.agent.runDueChecks();
    expect(ran).toEqual(['a', 'a']);
  });

  test('a retuned metrics interval is clamped and written back to disk', async () => {
    const h = harness({ respond: () => json({ metricsIntervalSeconds: 1 }) });
    await h.agent.fetchConfig();
    expect(h.cfg.intervalSeconds).toBe(15);
    expect(h.saved).toEqual([{ intervalSeconds: 15 }]);
  });

  test('an interval identical to the running one is not written back', async () => {
    const h = harness({ respond: () => json({ metricsIntervalSeconds: 60 }) });
    await h.agent.fetchConfig();
    expect(h.cfg.intervalSeconds).toBe(60);
    expect(h.saved).toEqual([]);
  });

  test('a non-OK response leaves the previous policy, checks and interval in force', async () => {
    const pubkey = pubkeyB64();
    const ran: string[] = [];
    let respond = () =>
      json({
        authorizedExecKeys: [{ userId: 'u', pubkey }],
        checks: [check('a')],
        metricsIntervalSeconds: 120,
      });
    const h = harness({
      respond: () => respond(),
      runCheck: async (def) => {
        ran.push(def.id);
        return outcome(def.id);
      },
    });
    await h.agent.fetchConfig();
    await h.agent.runDueChecks();
    expect(h.policies).toHaveLength(1);
    expect(ran).toEqual(['a']);

    respond = () => json({ authorizedExecKeys: [], checks: [] }, 500);
    await h.agent.fetchConfig();

    expect(h.policies).toEqual([[pubkey]]);
    expect(h.cfg.intervalSeconds).toBe(120);
    expect(h.saved).toEqual([{ intervalSeconds: 120 }]);
    clock += 120_000;
    await h.agent.runDueChecks();
    expect(ran).toEqual(['a', 'a']);
  });

  test('a fetch that throws leaves the previous policy in force', async () => {
    const pubkey = pubkeyB64();
    let respond = () => json({ authorizedExecKeys: [{ userId: 'u', pubkey }] });
    const h = harness({ respond: () => respond() });
    await h.agent.fetchConfig();

    respond = () => {
      throw new Error('ECONNREFUSED');
    };
    await h.agent.fetchConfig();
    expect(h.policies).toEqual([[pubkey]]);
  });

  test('a body that is not JSON leaves the previous policy in force', async () => {
    const pubkey = pubkeyB64();
    let respond = () => json({ authorizedExecKeys: [{ userId: 'u', pubkey }] });
    const h = harness({ respond: () => respond() });
    await h.agent.fetchConfig();

    respond = () => new Response('<html>gateway error</html>', { status: 200 });
    await h.agent.fetchConfig();
    expect(h.policies).toEqual([[pubkey]]);
  });
});

describe('metrics push', () => {
  test('the sample is posted to the ingest endpoint under a signature over its body', async () => {
    const h = harness();
    await h.agent.pushMetrics();
    expect(h.sent).toHaveLength(1);
    expect(h.sent[0]?.url).toBe(`${API}/agent/ingest/${SERVER_ID}`);
    expect(h.sent[0]?.init?.method).toBe('POST');

    const headers = h.headersOf(0);
    expect(headers['content-type']).toBe('application/json');
    const ts = headers['x-servor-timestamp'] ?? '';
    expect(headers['x-servor-signature']).toBe(hmac(SECRET, ts, 'ingest', h.bodyOf(0)));
    expect(JSON.parse(h.bodyOf(0)).agentVersion).toBe(BUILD_VERSION);
  });

  test('a push that fails is dropped rather than retried', async () => {
    const h = harness({
      respond: () => {
        throw new Error('network unreachable');
      },
    });
    await h.agent.pushMetrics();
    expect(h.sent).toHaveLength(1);
  });
});

describe('check results push', () => {
  test('the batch is posted to the checks endpoint under a signature over its body', async () => {
    const h = harness();
    await h.agent.pushResults([outcome('a'), outcome('b')]);
    expect(h.sent[0]?.url).toBe(`${API}/agent/checks/${SERVER_ID}`);
    expect(h.sent[0]?.init?.method).toBe('POST');

    const headers = h.headersOf(0);
    const ts = headers['x-servor-timestamp'] ?? '';
    expect(headers['x-servor-signature']).toBe(hmac(SECRET, ts, 'result', h.bodyOf(0)));
    expect(JSON.parse(h.bodyOf(0)).results).toHaveLength(2);
  });

  test('a push that fails is dropped rather than retried', async () => {
    const h = harness({
      respond: () => {
        throw new Error('network unreachable');
      },
    });
    await h.agent.pushResults([outcome('a')]);
    expect(h.sent).toHaveLength(1);
  });
});

describe('check scheduling', () => {
  const scheduled = async (checks: CheckDef[], opts: Partial<HarnessOptions> = {}) => {
    const ran: string[] = [];
    const h = harness({
      respond: () => json({ checks }),
      runCheck:
        opts.runCheck ??
        (async (def) => {
          ran.push(def.id);
          return outcome(def.id);
        }),
    });
    await h.agent.fetchConfig();
    h.sent.length = 0;
    return { ...h, ran };
  };

  test('only the checks whose interval has elapsed run', async () => {
    const h = await scheduled([
      check('fast', { intervalSeconds: 60 }),
      check('slow', { intervalSeconds: 3600 }),
    ]);
    await h.agent.runDueChecks();
    expect(h.ran).toEqual(['fast', 'slow']);

    h.ran.length = 0;
    clock += 120_000;
    await h.agent.runDueChecks();
    expect(h.ran).toEqual(['fast']);
  });

  test('nothing is pushed when nothing is due', async () => {
    const h = await scheduled([check('a', { intervalSeconds: 3600 })]);
    await h.agent.runDueChecks();
    h.sent.length = 0;
    h.ran.length = 0;

    await h.agent.runDueChecks();
    expect(h.ran).toEqual([]);
    expect(h.sent).toEqual([]);
  });

  test('a slow probe cannot queue a second copy of itself', async () => {
    const ran: string[] = [];
    let release = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const h = await scheduled([check('slow')], {
      runCheck: async (def) => {
        ran.push(def.id);
        await gate;
        return outcome(def.id);
      },
    });

    const first = h.agent.runDueChecks();
    const second = h.agent.runDueChecks();
    release();
    await Promise.all([first, second]);
    expect(ran).toEqual(['slow']);
  });

  test('due checks run one after another, never in parallel', async () => {
    const ran: string[] = [];
    let inFlight = 0;
    let peak = 0;
    const h = await scheduled([check('a'), check('b'), check('c')], {
      runCheck: async (def) => {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await Promise.resolve();
        ran.push(def.id);
        inFlight--;
        return outcome(def.id);
      },
    });

    await h.agent.runDueChecks();
    expect(peak).toBe(1);
    expect(ran).toEqual(['a', 'b', 'c']);
  });

  test('every due result travels in one batch', async () => {
    const h = await scheduled([check('a'), check('b')]);
    await h.agent.runDueChecks();
    expect(h.sent).toHaveLength(1);
    expect(JSON.parse(h.bodyOf(0)).results).toHaveLength(2);
  });
});

describe('self-update', () => {
  test('an idle agent exits so the service manager relaunches the swapped binary', async () => {
    const h = harness({ stageUpdate: async () => true });
    await h.agent.maybeApplyUpdate();
    expect(h.exits).toEqual([0]);
  });

  test('nothing is staged and nothing exits when no newer build exists', async () => {
    const h = harness({ stageUpdate: async () => false });
    await h.agent.maybeApplyUpdate();
    await h.agent.maybeApplyUpdate();
    expect(h.exits).toEqual([]);
    expect(h.stagedCount()).toBe(2);
  });

  test('a busy tunnel defers the restart, and the binary is staged only once', async () => {
    let busy = true;
    const h = harness({
      cfg: config({ mode: 'tunnel' }),
      stageUpdate: async () => true,
      busy: () => busy,
    });
    h.agent.start();
    await flush();
    await h.agent.maybeApplyUpdate();
    expect(h.exits).toEqual([]);
    expect(h.stagedCount()).toBe(1);

    busy = false;
    await h.agent.maybeApplyUpdate();
    expect(h.exits).toEqual([0]);
    expect(h.stagedCount()).toBe(1);
    h.agent.stop();
  });

  test('a config response advertising another version triggers an update check', async () => {
    const h = harness({
      respond: () => json({ version: `${BUILD_VERSION}-next` }),
      stageUpdate: async () => false,
    });
    await h.agent.fetchConfig();
    await flush();
    expect(h.stagedCount()).toBe(1);
  });

  test('a config response advertising the running version triggers nothing', async () => {
    const h = harness({ respond: () => json({ version: BUILD_VERSION }) });
    await h.agent.fetchConfig();
    await flush();
    expect(h.stagedCount()).toBe(0);
  });
});

describe('startup', () => {
  test('push mode never opens the command channel', async () => {
    const h = harness();
    h.agent.start();
    await flush();
    expect(h.tunnels).toEqual([]);
    h.agent.stop();
  });

  test('tunnel mode opens the command channel for this server', async () => {
    const h = harness({ cfg: config({ mode: 'tunnel' }) });
    h.agent.start();
    await Promise.resolve();
    expect(h.tunnels.map((c) => c.serverId)).toEqual([SERVER_ID]);
    h.agent.stop();
  });

  test('starting pushes a first sample and syncs the config immediately', async () => {
    const h = harness();
    h.agent.start();
    await flush();
    const urls = h.sent.map((s) => s.url);
    expect(urls).toContain(`${API}/agent/ingest/${SERVER_ID}`);
    expect(urls).toContain(`${API}/agent/config/${SERVER_ID}`);
    h.agent.stop();
  });

  test('a termination signal exits cleanly, and stopping gives the handler back', () => {
    const h = harness();
    const before = process.listenerCount('SIGTERM');
    h.agent.start();
    expect(process.listenerCount('SIGTERM')).toBe(before + 1);

    const handler = process.listeners('SIGTERM').at(-1);
    handler?.('SIGTERM');
    expect(h.exits).toEqual([0]);

    h.agent.stop();
    expect(process.listenerCount('SIGTERM')).toBe(before);
  });

  test('a stopped agent schedules nothing further', async () => {
    const h = harness();
    h.agent.start();
    h.agent.stop();
    await flush();
    const settled = h.sent.length;
    await h.agent.runDueChecks();
    expect(h.sent).toHaveLength(settled);
  });
});
