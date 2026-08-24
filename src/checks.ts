import { createConnection } from 'node:net';
import { connect, type PeerCertificate } from 'node:tls';
import { validateCommand } from './protocol/command-guards';

// Checks run from this host, on the schedule the control plane sends. The tcp
// and ssl probes are pinned to 127.0.0.1; an http check dials whatever URL its
// definition names, which is the point of it — reaching a service the outside
// world cannot.
//
// Check definitions arrive over the config channel and carry no execution
// grant, so the ones that run a command (custom_script, ssh) go through the
// local blocklist in runShellCommand. See the README's limitations section.

/** Probe kinds a check definition can ask for. */
export type CheckType = 'http' | 'tcp' | 'ssl' | 'ssh' | 'disk' | 'process' | 'custom_script';

/** A scheduled probe as configured by the control plane. */
export type CheckDef = {
  /** Monitor this check reports as; also the key of its schedule. */
  id: string;
  type: CheckType;
  /** Minimum delay between two runs of this check. */
  intervalSeconds: number;
  /** Per-run deadline; exceeding it is a `down`, never a hang. */
  timeoutSeconds: number;
  /** Type-specific settings (url, port, mountPoint, command…), validated per probe. */
  config: Record<string, unknown>;
};

/** Outcome of one check run, as pushed back to the control plane. */
export type CheckResult = {
  monitorId: string;
  /** `degraded` means the probe succeeded but crossed a warning threshold. */
  status: 'up' | 'down' | 'degraded';
  /** Measured duration, or `null` when the probe failed before it could time anything. */
  latencyMs: number | null;
  /** Human-readable failure cause; `null` when `up`. */
  errorMessage: string | null;
  /** Probe-specific detail (HTTP status, certificate expiry, disk percentage…). */
  metadata?: Record<string, unknown>;
};

/** A {@link CheckResult} before it is attributed to a monitor. */
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

/**
 * Build the argv that runs `command` as the configured user rather than root.
 *
 * @remarks
 * Only meaningful when the agent itself runs as root: `runuser` drops to the
 * enrolled account so a check command has that account's rights, not root's. If
 * no user is configured, or the agent is not root, the command runs as whatever
 * the agent is — the README says this plainly: it runs as the user you
 * configure, and if you configure root, it is root.
 */
const wrapAsUser = (user: string | undefined, command: string): string[] => {
  if (process.platform === 'win32') return ['powershell', '-NoProfile', '-Command', command];
  if (process.platform === 'linux' && user && isRoot()) {
    return ['runuser', '-u', user, '--', 'bash', '-lc', command];
  }
  return ['bash', '-lc', command];
};

/** Grace between the polite kill and the one that cannot be refused. */
const SIGKILL_GRACE_MS = 2_000;

/**
 * Spawn a command, capture both streams, and kill it once the deadline passes.
 *
 * @returns The exit code and captured output. A killed process reports the
 * signal's exit code, so a timeout surfaces as a non-zero result rather than a
 * thrown error.
 *
 * @remarks
 * SIGTERM first, then SIGKILL. A script that traps TERM — or one whose child
 * survives it — would otherwise never exit, and since checks run one after
 * another that single process stalls the whole loop rather than one monitor.
 */
const sh = async (
  argv: string[],
  timeoutMs: number,
): Promise<{ code: number; stdout: string; stderr: string }> => {
  const proc = Bun.spawn(argv, { stdout: 'pipe', stderr: 'pipe' });
  const term = setTimeout(() => proc.kill(), timeoutMs);
  const hard = setTimeout(() => proc.kill('SIGKILL'), timeoutMs + SIGKILL_GRACE_MS);
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const code = await proc.exited;
  clearTimeout(term);
  clearTimeout(hard);
  return { code, stdout, stderr };
};

/**
 * Request a URL and grade the response against the expected status and body.
 *
 * @returns `down` on an unexpected status, a missing body match or a transport
 * error; `degraded` when the response arrived but took longer than
 * {@link DEGRADED_LATENCY_MS}.
 */
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

/**
 * Open a TCP connection to a local port, optionally waiting for a banner.
 *
 * @returns `up` as soon as the connection is established when no banner is
 * expected; otherwise once the banner contains the expected substring.
 *
 * @remarks
 * Pinned to 127.0.0.1: this exists to prove a service is listening on this
 * machine, and refusing to dial elsewhere keeps the check from being usable as
 * a port scanner driven from the control plane.
 *
 * `setTimeout` on a socket is an *idle* timeout: every byte received resets it.
 * A peer that dribbles one non-matching byte per second would therefore keep a
 * banner check alive indefinitely, and with it the whole sequential check loop.
 * The absolute deadline below is what actually bounds the probe.
 */
const runTcp = (cfg: Record<string, unknown>, timeoutMs: number): Promise<Outcome> =>
  new Promise((resolve) => {
    const port = Number(cfg.port);
    const match = cfg.bannerMatch ? String(cfg.bannerMatch) : '';
    const start = Date.now();
    const socket = createConnection({ host: '127.0.0.1', port });
    socket.setTimeout(timeoutMs);
    let banner = '';
    let deadline: ReturnType<typeof setTimeout>;
    const done = (o: Outcome) => {
      clearTimeout(deadline);
      socket.removeAllListeners();
      socket.destroy();
      resolve(o);
    };
    deadline = setTimeout(
      () => done(down('tcp check deadline exceeded', Date.now() - start)),
      timeoutMs,
    );
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

/**
 * Grade a peer certificate by how long it has left.
 *
 * @param cert - What the handshake produced; a peer that sent none is `down`.
 * @param warnDays - Days of remaining life below which the check degrades.
 * @param now - Reference instant, injectable so the boundaries are testable.
 *
 * @returns `down` past expiry, `degraded` inside the warning window, `up`
 * otherwise; the remaining days travel in the metadata either way.
 *
 * @remarks
 * Separate from the socket work because this is the part that decides whether
 * someone is woken up. `daysLeft` floors, so a certificate with eleven hours
 * left reads as 0 and is treated as expired rather than as nearly fine.
 */
export const gradeCertificate = (
  cert: Pick<PeerCertificate, 'valid_to' | 'issuer' | 'subject'> | null | undefined,
  warnDays: number,
  latencyMs: number,
  now: number = Date.now(),
): Outcome => {
  if (!cert?.valid_to) return down('no peer certificate', latencyMs);
  const expiry = new Date(cert.valid_to).getTime();
  if (Number.isNaN(expiry)) return down('unreadable certificate expiry', latencyMs);
  const daysLeft = Math.floor((expiry - now) / DAY_MS);
  const meta = {
    issuer: cert.issuer?.CN ?? null,
    subject: cert.subject?.CN ?? null,
    validTo: cert.valid_to,
    daysLeft,
  };
  if (daysLeft <= 0) return down('certificate expired', latencyMs, meta);
  if (daysLeft <= warnDays) return degraded(`certificate expires in ${daysLeft}d`, latencyMs, meta);
  return ok(latencyMs, meta);
};

/**
 * Handshake with a local TLS port and report how long the certificate has left.
 *
 * @remarks
 * `rejectUnauthorized` is off on purpose: the goal is to read the certificate's
 * expiry, and connecting to 127.0.0.1 by a name the certificate was not issued
 * for would otherwise fail the handshake before it could be read. Nothing is
 * sent over this connection, so accepting an untrusted peer exposes nothing.
 *
 * @returns `down` past expiry, `degraded` inside the warning window, `up`
 * otherwise; the remaining days travel in the metadata either way.
 */
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
    // Same idle-timeout caveat as runTcp: a handshake that never completes but
    // keeps bytes moving would never trip `timeout`.
    let deadline: ReturnType<typeof setTimeout>;
    const done = (o: Outcome) => {
      clearTimeout(deadline);
      socket.removeAllListeners();
      socket.destroy();
      resolve(o);
    };
    deadline = setTimeout(
      () => done(down('tls handshake deadline exceeded', Date.now() - start)),
      timeoutMs,
    );
    socket.on('secureConnect', () => {
      const cert = socket.getPeerCertificate(false) as PeerCertificate;
      done(gradeCertificate(cert, warnDays, Date.now() - start));
    });
    socket.on('timeout', () => done(down('tls handshake timeout', Date.now() - start)));
    socket.on('error', (e) => done(down(e.message, Date.now() - start)));
  });

/**
 * Read `df` for one mount point and grade its usage against two thresholds.
 *
 * @returns `down` at or above the critical percentage, `degraded` at or above
 * the warning one. A mount point `df` does not know is `down` with a distinct
 * message, since a monitor pointed at a vanished filesystem is itself a fault.
 */
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

/**
 * Report whether at least one process matches a name, via `pgrep -af`.
 *
 * @remarks
 * The name is passed after `--` so a value starting with a dash is treated as a
 * pattern and not as a pgrep option.
 *
 * @returns `up` with the number of matches, or `down` when none match.
 */
const runProcess = async (cfg: Record<string, unknown>, timeoutMs: number): Promise<Outcome> => {
  const name = String(cfg.processName ?? '');
  const start = Date.now();
  const res = await sh(['pgrep', '-af', '--', name], timeoutMs);
  const latencyMs = Date.now() - start;
  const lines = res.stdout.trim().split('\n').filter(Boolean);
  if (res.code !== 0 || lines.length === 0) return down(`process '${name}' not running`, latencyMs);
  return ok(latencyMs, { count: lines.length });
};

/**
 * Run a check's own shell command and grade it by exit code.
 *
 * @returns `up` when the command exits 0, carrying the first 200 characters of
 * stdout as evidence; `down` otherwise, or immediately if the blocklist refuses
 * the command.
 *
 * @remarks
 * The blocklist is applied here, not only on the control plane. A check
 * definition arrives over the config channel and carries no execution grant, so
 * this call is the last guard between a wrong or malicious config response and
 * a command running on the host. Removing it would turn the config channel —
 * which is authenticated by the shared HMAC secret, not by an operator's
 * signature — into an unsigned execution path. It refuses destructive and
 * lockout commands; it is not a sandbox, and a command that only reads what
 * this user can read will pass.
 */
const runShellCommand = async (
  command: string,
  timeoutMs: number,
  user: string | undefined,
): Promise<Outcome> => {
  const guard = validateCommand(command);
  if (!guard.ok) return down(`command rejected: ${guard.reason}`, 0);
  const start = Date.now();
  const res = await sh(wrapAsUser(user, command), timeoutMs);
  const latencyMs = Date.now() - start;
  if (res.code === 0) return ok(latencyMs, { stdout: res.stdout.slice(0, 200).trim() });
  return down(`exit ${res.code}: ${res.stderr.slice(0, 200)}`, latencyMs);
};

/** Slack over a probe's own deadline before the backstop below takes over. */
const BACKSTOP_GRACE_MS = 5_000;

/**
 * Run one check definition and attribute the outcome to its monitor.
 *
 * @param user - OS account command-running checks are dropped to when the agent
 * has root.
 * @returns Always a result, never a rejection: a probe that throws, times out
 * or names an unknown type becomes a `down` with the reason attached, because a
 * check that silently produces nothing is indistinguishable from a healthy one.
 *
 * @remarks
 * The outer deadline is a backstop, not the mechanism: each probe bounds
 * itself, and this only fires if one fails to. It exists because checks are
 * awaited one after another and the loop schedules its next tick only once the
 * batch resolves — so a single probe that never settles does not degrade one
 * monitor, it silently stops every check on the host. Failing loudly as a
 * `down` is the lesser outcome.
 *
 * A probe caught here may still be holding a socket or a child process; that is
 * why each one has its own deadline, and why this one landing is worth treating
 * as a bug rather than as normal operation.
 */
export const runCheck = async (def: CheckDef, user?: string): Promise<CheckResult> => {
  const timeoutMs = Math.max(1, def.timeoutSeconds) * 1_000;
  let backstopTimer: ReturnType<typeof setTimeout> | undefined;
  const backstop = new Promise<Outcome>((resolve) => {
    backstopTimer = setTimeout(
      () => resolve(down(`check exceeded its deadline (${timeoutMs}ms)`)),
      timeoutMs + BACKSTOP_GRACE_MS,
    );
    backstopTimer.unref?.();
  });
  const probe = async (): Promise<Outcome> => {
    switch (def.type) {
      case 'http':
        return runHttp(def.config, timeoutMs);
      case 'tcp':
        return runTcp(def.config, timeoutMs);
      case 'ssl':
        return runSsl(def.config, timeoutMs);
      case 'disk':
        return runDisk(def.config, timeoutMs);
      case 'process':
        return runProcess(def.config, timeoutMs);
      case 'custom_script':
        return runShellCommand(String(def.config.command ?? ''), timeoutMs, user);
      case 'ssh':
        return runShellCommand(String(def.config.command ?? 'echo ok'), timeoutMs, user);
      default:
        return down('unknown check type');
    }
  };

  let outcome: Outcome;
  try {
    outcome = await Promise.race([probe(), backstop]);
  } catch (e) {
    outcome = down((e as Error).message);
  } finally {
    clearTimeout(backstopTimer);
  }
  return { monitorId: def.id, ...outcome };
};
