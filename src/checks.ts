import { createConnection } from 'node:net';
import { connect, type PeerCertificate } from 'node:tls';
import { validateCommand } from '@servor/shared/utils';

// Checks run locally on the server, against localhost only. No remote host is
// ever contacted — the control plane never sends a command to run them.

export type CheckType = 'http' | 'tcp' | 'ssl' | 'ssh' | 'disk' | 'process' | 'custom_script';

export type CheckDef = {
  id: string;
  type: CheckType;
  intervalSeconds: number;
  timeoutSeconds: number;
  config: Record<string, unknown>;
};

export type CheckResult = {
  monitorId: string;
  status: 'up' | 'down' | 'degraded';
  latencyMs: number | null;
  errorMessage: string | null;
  metadata?: Record<string, unknown>;
};

type Outcome = Omit<CheckResult, 'monitorId'>;

const DEGRADED_LATENCY_MS = 3_000;
const DAY_MS = 86_400_000;

const ok = (latencyMs: number, metadata?: Record<string, unknown>): Outcome => ({
  status: 'up',
  latencyMs,
  errorMessage: null,
  metadata,
});
const down = (
  errorMessage: string,
  latencyMs: number | null = null,
  metadata?: Record<string, unknown>,
): Outcome => ({ status: 'down', latencyMs, errorMessage, metadata });
const degraded = (
  errorMessage: string,
  latencyMs: number,
  metadata?: Record<string, unknown>,
): Outcome => ({ status: 'degraded', latencyMs, errorMessage, metadata });

const isRoot = () => typeof process.getuid === 'function' && process.getuid() === 0;

// Arbitrary commands (custom_script / ssh) run as the configured SSH user.
const wrapAsUser = (user: string | undefined, command: string): string[] => {
  if (process.platform === 'win32') return ['powershell', '-NoProfile', '-Command', command];
  if (process.platform === 'linux' && user && isRoot()) {
    return ['runuser', '-u', user, '--', 'bash', '-lc', command];
  }
  return ['bash', '-lc', command];
};

const sh = async (
  argv: string[],
  timeoutMs: number,
): Promise<{ code: number; stdout: string; stderr: string }> => {
  const proc = Bun.spawn(argv, { stdout: 'pipe', stderr: 'pipe' });
  const timer = setTimeout(() => proc.kill(), timeoutMs);
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const code = await proc.exited;
  clearTimeout(timer);
  return { code, stdout, stderr };
};

const runHttp = async (cfg: Record<string, unknown>, timeoutMs: number): Promise<Outcome> => {
  const url = String(cfg.url ?? '');
  const expected = Array.isArray(cfg.expectedStatus)
    ? (cfg.expectedStatus as unknown[]).map(Number)
    : [200];
  const start = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const init: Record<string, unknown> = {
      method: String(cfg.method ?? 'GET'),
      redirect: cfg.followRedirects === false ? 'manual' : 'follow',
      signal: ctrl.signal,
    };
    // Bun extension: skip TLS verification for self-signed local certs.
    if (cfg.verifyTls === false) init.tls = { rejectUnauthorized: false };
    const res = await fetch(url, init as RequestInit);
    const latencyMs = Date.now() - start;
    if (!expected.includes(res.status))
      return down(`unexpected status ${res.status}`, latencyMs, { status: res.status });
    if (cfg.bodyMatch) {
      const text = await res.text();
      if (!text.includes(String(cfg.bodyMatch)))
        return down('body match not found', latencyMs, { status: res.status });
    }
    if (latencyMs > DEGRADED_LATENCY_MS)
      return degraded(`slow response (${latencyMs}ms)`, latencyMs, { status: res.status });
    return ok(latencyMs, { status: res.status });
  } catch (e) {
    return down((e as Error).message, Date.now() - start);
  } finally {
    clearTimeout(timer);
  }
};

const runTcp = (cfg: Record<string, unknown>, timeoutMs: number): Promise<Outcome> =>
  new Promise((resolve) => {
    const port = Number(cfg.port);
    const match = cfg.bannerMatch ? String(cfg.bannerMatch) : '';
    const start = Date.now();
    const socket = createConnection({ host: '127.0.0.1', port });
    socket.setTimeout(timeoutMs);
    let banner = '';
    const done = (o: Outcome) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(o);
    };
    socket.on('connect', () => {
      if (!match) done(ok(Date.now() - start));
    });
    socket.on('data', (c) => {
      banner += c.toString('utf8');
      if (match && banner.includes(match))
        done(ok(Date.now() - start, { banner: banner.slice(0, 200) }));
    });
    socket.on('timeout', () => done(down('tcp connect timeout', Date.now() - start)));
    socket.on('error', (e) => done(down(e.message, Date.now() - start)));
    socket.on('end', () => {
      if (match && !banner.includes(match))
        done(down('banner match not found', Date.now() - start));
    });
  });

const runSsl = (cfg: Record<string, unknown>, timeoutMs: number): Promise<Outcome> =>
  new Promise((resolve) => {
    const port = Number(cfg.port ?? 443);
    const warnDays = Number(cfg.warnDaysBeforeExpiry ?? 14);
    const start = Date.now();
    const socket = connect({
      host: '127.0.0.1',
      port,
      servername: 'localhost',
      rejectUnauthorized: false,
      timeout: timeoutMs,
    });
    const done = (o: Outcome) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(o);
    };
    socket.on('secureConnect', () => {
      const latencyMs = Date.now() - start;
      const cert = socket.getPeerCertificate(false) as PeerCertificate;
      if (!cert?.valid_to) return done(down('no peer certificate', latencyMs));
      const daysLeft = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / DAY_MS);
      const meta = {
        issuer: cert.issuer?.CN ?? null,
        subject: cert.subject?.CN ?? null,
        validTo: cert.valid_to,
        daysLeft,
      };
      if (daysLeft <= 0) return done(down('certificate expired', latencyMs, meta));
      if (daysLeft <= warnDays)
        return done(degraded(`certificate expires in ${daysLeft}d`, latencyMs, meta));
      done(ok(latencyMs, meta));
    });
    socket.on('timeout', () => done(down('tls handshake timeout', Date.now() - start)));
    socket.on('error', (e) => done(down(e.message, Date.now() - start)));
  });

const runDisk = async (cfg: Record<string, unknown>, timeoutMs: number): Promise<Outcome> => {
  const mount = String(cfg.mountPoint ?? '/');
  const warn = Number(cfg.warnPercent ?? 80);
  const crit = Number(cfg.critPercent ?? 95);
  const start = Date.now();
  const res = await sh(['df', '-Pk', mount], timeoutMs);
  const latencyMs = Date.now() - start;
  if (res.code !== 0) return down(`df exit ${res.code}`, latencyMs);
  const line = res.stdout.trim().split('\n').pop() ?? '';
  const percent = Number((line.trim().split(/\s+/)[4] ?? '').replace('%', ''));
  if (!Number.isFinite(percent)) return down(`mount '${mount}' not found`, latencyMs);
  const meta = { percent, mount };
  if (percent >= crit) return down(`disk ${percent}% used`, latencyMs, meta);
  if (percent >= warn) return degraded(`disk ${percent}% used`, latencyMs, meta);
  return ok(latencyMs, meta);
};

const runProcess = async (cfg: Record<string, unknown>, timeoutMs: number): Promise<Outcome> => {
  const name = String(cfg.processName ?? '');
  const start = Date.now();
  const res = await sh(['pgrep', '-af', '--', name], timeoutMs);
  const latencyMs = Date.now() - start;
  const lines = res.stdout.trim().split('\n').filter(Boolean);
  if (res.code !== 0 || lines.length === 0) return down(`process '${name}' not running`, latencyMs);
  return ok(latencyMs, { count: lines.length });
};

const runShellCommand = async (
  command: string,
  timeoutMs: number,
  user: string | undefined,
): Promise<Outcome> => {
  // The blocklist is applied here too, not only on the control plane. A check
  // definition arrives over the config channel and is not covered by an exec
  // grant, so this is the only guard left if that channel is ever wrong.
  const guard = validateCommand(command);
  if (!guard.ok) return down(`command rejected: ${guard.reason}`, 0);
  const start = Date.now();
  const res = await sh(wrapAsUser(user, command), timeoutMs);
  const latencyMs = Date.now() - start;
  if (res.code === 0) return ok(latencyMs, { stdout: res.stdout.slice(0, 200).trim() });
  return down(`exit ${res.code}: ${res.stderr.slice(0, 200)}`, latencyMs);
};

export const runCheck = async (def: CheckDef, user?: string): Promise<CheckResult> => {
  const timeoutMs = Math.max(1, def.timeoutSeconds) * 1_000;
  let outcome: Outcome;
  try {
    switch (def.type) {
      case 'http':
        outcome = await runHttp(def.config, timeoutMs);
        break;
      case 'tcp':
        outcome = await runTcp(def.config, timeoutMs);
        break;
      case 'ssl':
        outcome = await runSsl(def.config, timeoutMs);
        break;
      case 'disk':
        outcome = await runDisk(def.config, timeoutMs);
        break;
      case 'process':
        outcome = await runProcess(def.config, timeoutMs);
        break;
      case 'custom_script':
        outcome = await runShellCommand(String(def.config.command ?? ''), timeoutMs, user);
        break;
      case 'ssh':
        outcome = await runShellCommand(String(def.config.command ?? 'echo ok'), timeoutMs, user);
        break;
      default:
        outcome = down('unknown check type');
    }
  } catch (e) {
    outcome = down((e as Error).message);
  }
  return { monitorId: def.id, ...outcome };
};
