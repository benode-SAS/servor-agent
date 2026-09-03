import { createHmac } from 'node:crypto';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import type { AgentConfig } from './config';
import { type FsRequest, fsDescriptorFor, runFsOp } from './fs';
import { createGrantVerifier, type GrantVerifier } from './grant';
import { type NetRequest, netBodyBytes, netDescriptorFor, runNetRequest } from './net';
import { canonicalAgentMessage } from './protocol/agent-hmac';
import type { LocalHeader, LocalMethod, LocalScheme } from './protocol/net-grant';
import { isPowerAction, POWER_COMMANDS } from './protocol/power-action';

// The execution policy arrives from the control plane (fetchConfig) before the
// tunnel is necessarily up, so the key set is held here and handed to the
// verifier as soon as one exists. See grant.ts for what verification means.
let execKeysB64: string[] = [];
let verifier: GrantVerifier | null = null;

/**
 * Install the execution policy received from the control plane.
 *
 * @param keysB64 - Base64 Ed25519 public keys allowed to sign grants; replaces
 * the previous set, so revoking an operator is a matter of dropping their key
 * from the next config response.
 *
 * @remarks
 * Only public keys ever reach this agent. It can verify a grant and can do
 * nothing else with these bytes — it cannot mint one, and neither can anything
 * that reads them off this machine.
 */
export const setExecPolicy = (keysB64: string[]) => {
  execKeysB64 = keysB64;
  verifier?.setKeys(keysB64);
};

const isRoot = () => typeof process.getuid === 'function' && process.getuid() === 0;

// Directories a login shell would normally provide but a systemd-launched agent
// often lacks — sbin dirs in particular vanish for non-root, and snap is common.
const STD_PATH_DIRS = [
  '/usr/local/sbin',
  '/usr/local/bin',
  '/usr/sbin',
  '/usr/bin',
  '/sbin',
  '/bin',
  '/snap/bin',
];

const homeFor = (cfg: AgentConfig): string => {
  if (process.platform === 'win32') return process.env.USERPROFILE ?? '';
  if (cfg.user && cfg.user !== 'root') return `/home/${cfg.user}`;
  if (cfg.user === 'root') return '/root';
  return process.env.HOME ?? (isRoot() ? '/root' : '');
};

const compareNodeVersionsDesc = (a: string, b: string): number => {
  const parse = (s: string) =>
    s
      .replace(/^v/, '')
      .split('.')
      .map((n) => Number.parseInt(n, 10) || 0);
  const [a1 = 0, a2 = 0, a3 = 0] = parse(a);
  const [b1 = 0, b2 = 0, b3 = 0] = parse(b);
  return b1 - a1 || b2 - a2 || b3 - a3;
};

// nvm installs node under ~/.nvm/versions/node/<v>/bin and only exports it from
// ~/.bashrc — which a non-interactive login shell never sources. Resolve the
// default (or newest) version's bin directly so `node`/`npm` are found.
const nvmNodeBin = (home: string): string[] => {
  try {
    const base = `${home}/.nvm/versions/node`;
    if (!existsSync(base)) return [];
    let chosen: string | null = null;
    try {
      const def = readFileSync(`${home}/.nvm/alias/default`, 'utf8').trim();
      if (def && existsSync(`${base}/${def}/bin`)) chosen = def;
    } catch {
      // no default alias — fall through to newest installed
    }
    if (!chosen) {
      const versions = readdirSync(base)
        .filter((v) => existsSync(`${base}/${v}/bin`))
        .sort(compareNodeVersionsDesc);
      chosen = versions[0] ?? null;
    }
    return chosen ? [`${base}/${chosen}/bin`] : [];
  } catch {
    return [];
  }
};

/**
 * Compute a usable PATH for one-shot commands.
 *
 * @remarks
 * A one-shot `bash -lc` is a login but NON-interactive shell: it sources
 * `/etc/profile` (which overwrites PATH) but never `~/.bashrc`, so nvm and most
 * per-user tool shims are invisible, and `/etc/profile` itself strips sbin for
 * non-root. We therefore run the command under a plain `bash -c` (no login, so
 * nothing resets PATH) and hand it a PATH we build here: the agent's inherited
 * PATH, the standard system dirs, the user's common bin dirs, and their nvm
 * node. This is env, not the signed command, so the signature still holds.
 */
const buildExecPath = (cfg: AgentConfig): string => {
  if (process.platform === 'win32') return process.env.PATH ?? '';
  const home = homeFor(cfg);
  const userDirs = home
    ? [
        `${home}/.local/bin`,
        `${home}/bin`,
        `${home}/.bun/bin`,
        `${home}/.deno/bin`,
        `${home}/.cargo/bin`,
        `${home}/go/bin`,
        ...nvmNodeBin(home),
      ]
    : [];
  const inherited = (process.env.PATH ?? '').split(':');
  return [...new Set([...userDirs, ...STD_PATH_DIRS, ...inherited].filter(Boolean))].join(':');
};

/**
 * Build the argv for a one-shot command, dropping root when a user is configured.
 *
 * @remarks
 * Wrapping is limited to choosing the interpreter, the account and the PATH.
 * Nothing is prepended to the command itself — no `cd`, no `sudo`, no exported
 * variable — because the operator signed exactly this string and the signature
 * must keep covering what actually executes. PATH is forced via a leading `env`
 * so `runuser`/`/etc/profile` cannot strip it back to a stripped default.
 */
const wrapExec = (cfg: AgentConfig, command: string, execPath: string): string[] => {
  if (process.platform === 'win32') return ['powershell', '-NoProfile', '-Command', command];
  const inner = ['env', `PATH=${execPath}`, 'bash', '-c', command];
  if (process.platform === 'linux' && cfg.user && isRoot()) {
    return ['runuser', '-u', cfg.user, '--', ...inner];
  }
  return inner;
};

/**
 * Build the argv for an interactive session, backed by a PTY.
 *
 * @remarks
 * `script` (util-linux) is used purely to obtain a pseudo-terminal without a
 * native dependency: without one, programs that check for a TTY behave
 * differently — no colours, no prompts, no line editing — and interactive tools
 * refuse to run at all. The flags differ on macOS because its `script` takes
 * the output file first.
 *
 * The PATH is forced here for the same reason it is in `wrapExec`, and it was
 * missing: `script -c` runs its argument through `/bin/sh`, which inherits
 * whatever bare environment the agent has and sources no profile. A command
 * naming a per-user tool — `pm2`, an nvm-installed binary — therefore died on
 * `sh: 1: pm2: not found` even though the same command succeeded as a one-shot
 * exec. macOS escapes it only because its branch runs a *login* bash, which
 * sources the profile itself.
 *
 * This is env, not the signed command: the string still executes verbatim.
 */
const wrapShell = (cfg: AgentConfig, command: string, execPath: string): string[] => {
  if (process.platform === 'win32') return ['powershell', '-NoProfile', '-Command', command];
  if (process.platform === 'darwin') return ['script', '-q', '/dev/null', 'bash', '-lc', command];
  const base = ['env', `PATH=${execPath}`, 'script', '-qfc', command, '/dev/null'];
  if (cfg.user && isRoot()) return ['runuser', '-u', cfg.user, '--', ...base];
  return base;
};

/** A live session: the process, its buffered output, and how it survives an outage. */
type Shell = {
  proc: ReturnType<typeof Bun.spawn>;
  /** Output produced while the tunnel was down, replayed on resume. */
  offline: string[];
  offlineBytes: number;
  /**
   * Form-launched command: runs to completion and is never reaped by the outage
   * grace timer, unlike an interactive terminal nobody is watching any more.
   */
  persistent: boolean;
};

// proc.stdin is typed as number | FileSink; with stdin:'pipe' it's a FileSink.
const writeStdin = (proc: ReturnType<typeof Bun.spawn>, data: string) => {
  const sink = proc.stdin as import('bun').FileSink;
  sink.write(data);
  sink.flush();
};

/**
 * The two ways the tunnel touches the outside world, injectable for tests.
 *
 * @remarks
 * Both default to the runtime globals, so omitting `deps` leaves behaviour
 * unchanged. `spawn` is the seam that lets a test assert nothing was launched:
 * a refused grant must not reach it at all.
 */
export type TunnelDeps = {
  WebSocket: typeof WebSocket;
  spawn: typeof Bun.spawn;
};

/**
 * Open the outbound command channel and keep it alive for the agent's lifetime.
 *
 * @returns `{ isBusy }`, true while any session is open or a command is
 * running; the updater uses it to defer a restart until the agent is idle.
 *
 * @remarks
 * The connection is outbound only. The agent listens on no port and accepts no
 * inbound connection, which is what lets it work behind NAT or a firewall — and
 * means there is no listening surface to attack here. Reconnection backs off
 * exponentially to a minute, so an API outage does not turn the fleet into a
 * retry storm.
 *
 * Every message that can start a process passes {@link GrantVerifier.verify}
 * first.
 */
export const startTunnel = (cfg: AgentConfig, deps: Partial<TunnelDeps> = {}) => {
  const { WebSocket: WebSocketImpl = WebSocket, spawn = Bun.spawn } = deps;
  const wsUrl = `${cfg.apiUrl.replace(/^http/, 'ws')}/agent/tunnel/${cfg.serverId}`;
  const grants = createGrantVerifier({ serverId: cfg.serverId });
  grants.setKeys(execKeysB64);
  verifier = grants;
  // Resolved once: the fs lookups are cheap and the answer does not change over
  // the agent's lifetime (a new nvm install is picked up on the next restart).
  const execPath = buildExecPath(cfg);
  let ws: WebSocket | null = null;
  let backoff = 1000;
  // Flap breaker. Two agents sharing one serverId evict each other on the control
  // plane (a fresh tunnel closes the previous one), so each reconnects, re-auths,
  // and evicts the other — a storm that authenticates every couple of seconds
  // until it trips the server's rate limit, then resumes. We detect it agent-side:
  // a connection that authenticates but dies before it has been up STABLE_MS is a
  // flap. A run of flaps first stretches the reconnect to a long cooldown, then
  // stops reconnecting entirely — the process stays alive (so systemd does not
  // restart it) but goes silent, ending the storm. A connection that stays up
  // past STABLE_MS is healthy and resets the counter.
  let sawInitOk = false;
  let flapCount = 0;
  let stableTimer: ReturnType<typeof setTimeout> | null = null;
  const STABLE_MS = 60_000;
  const FLAP_SOFT_LIMIT = 5;
  const FLAP_HARD_LIMIT = 20;
  const FLAP_COOLDOWN_MS = 5 * 60_000;
  const clearStableTimer = () => {
    if (stableTimer) {
      clearTimeout(stableTimer);
      stableTimer = null;
    }
  };
  /**
   * The last refusal the API gave, so a loop prints one line and not one a
   * second.
   *
   * @remarks
   * A tunnel that cannot authenticate retries for ever. Logging every attempt
   * would fill the journal with the same sentence — which is both useless and,
   * on a small server, expensive.
   */
  let lastRefusal: string | null = null;
  const shells = new Map<string, Shell>();
  let inflightExec = 0;
  let online = false;
  let graceTimer: ReturnType<typeof setTimeout> | null = null;
  // Heartbeat. The tunnel is idle between commands, and an idle WebSocket is
  // exactly what a proxy or the server's own idle timeout reaps — after which a
  // half-open socket can sit here looking alive until TCP keepalive notices,
  // which on Linux defaults to two hours. A ping every 25s keeps the connection
  // busy so nothing reaps it, and a missing pong past 60s proves the peer is
  // gone long before the kernel would.
  let heartbeat: ReturnType<typeof setTimeout> | null = null;
  let lastPong = 0;
  // Round-trip of the last keepalive. Measured here rather than server-side
  // because only this end knows when the ping actually left: the API sees the
  // frame arrive, which already includes the network time it is trying to
  // measure. Reported on the NEXT ping, so it costs no extra frame.
  let lastPingSentAt = 0;
  let lastRttMs: number | null = null;
  let connectedAt = 0;
  const PING_INTERVAL_MS = 25_000;
  const PONG_DEADLINE_MS = 60_000;
  const stopHeartbeat = () => {
    if (heartbeat) {
      clearTimeout(heartbeat);
      heartbeat = null;
    }
  };
  // Chained timeout rather than setInterval, like the reconnect below: one
  // pending timer, cleared cleanly on close, and no tick pile-up if a send ever
  // blocks.
  const scheduleHeartbeat = () => {
    heartbeat = setTimeout(() => {
      if (!online) return;
      if (Date.now() - lastPong > PONG_DEADLINE_MS) {
        console.error('tunnel heartbeat timed out — reconnecting');
        ws?.close();
        return;
      }
      lastPingSentAt = Date.now();
      send(lastRttMs === null ? { type: 'ping' } : { type: 'ping', rttMs: lastRttMs });
      scheduleHeartbeat();
    }, PING_INTERVAL_MS);
  };
  const OFFLINE_GRACE_MS = 10 * 60 * 1000; // keep shells alive this long across a tunnel outage (API restart)
  const OFFLINE_BUF_MAX = 256_000;

  const send = (data: unknown) => {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
  };

  /**
   * Forward session output live, or buffer it while the tunnel is down.
   *
   * @remarks
   * A command that keeps printing during an API restart would otherwise lose
   * exactly the output someone was waiting for. The buffer is bounded and drops
   * from the front, so a chatty process cannot grow the agent's memory without
   * limit — the oldest output is sacrificed, never the newest.
   */
  const sendShellData = (id: string, data: string) => {
    if (online) {
      send({ type: 'shell.data', id, data });
      return;
    }
    const sh = shells.get(id);
    if (!sh) return;
    sh.offline.push(data);
    sh.offlineBytes += Buffer.byteLength(data, 'utf8');
    while (sh.offlineBytes > OFFLINE_BUF_MAX && sh.offline.length > 1) {
      const d = sh.offline.shift();
      if (d) sh.offlineBytes -= Buffer.byteLength(d, 'utf8');
    }
  };

  /**
   * Run one already-authorized command and report its outcome.
   *
   * @param timeoutMs - Requested deadline; clamped to ten minutes, and defaulted
   * to five when zero, so no request can leave a process running forever.
   *
   * @remarks
   * Called only after the grant verified. Both streams are captured whole and
   * sent back with the exit code, so failures reach the operator instead of
   * vanishing; a spawn that throws is reported as exit 1 with the error message
   * rather than leaving the request unanswered.
   */
  const runExec = async (id: string, command: string, timeoutMs: number) => {
    const start = Date.now();
    inflightExec++;
    try {
      const proc = spawn(wrapExec(cfg, command, execPath), { stdout: 'pipe', stderr: 'pipe' });
      const timer = setTimeout(() => proc.kill(), Math.min(timeoutMs || 300000, 600000));
      const [stdout, stderr] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
      ]);
      const exitCode = await proc.exited;
      clearTimeout(timer);
      send({ type: 'exec.result', id, exitCode, stdout, stderr, durationMs: Date.now() - start });
    } catch (e) {
      send({
        type: 'exec.result',
        id,
        exitCode: 1,
        stdout: '',
        stderr: (e as Error).message,
        durationMs: Date.now() - start,
      });
    } finally {
      inflightExec--;
    }
  };

  /**
   * Start an already-authorized interactive session and stream its output.
   *
   * @param persistent - Keep the process alive through a long tunnel outage
   * (a form-launched command that must finish) instead of reaping it.
   *
   * @remarks
   * The grant covers opening this session, not the keystrokes that follow —
   * an inherent property of an interactive terminal, and stated as such in the
   * README. `TERM`, `COLUMNS` and `LINES` are set so the remote terminal renders
   * at the size the operator actually sees.
   */
  const openShell = (
    id: string,
    command: string,
    cols: number,
    rows: number,
    persistent: boolean,
  ) => {
    try {
      const proc = spawn(wrapShell(cfg, command || 'bash -l', execPath), {
        stdin: 'pipe',
        stdout: 'pipe',
        stderr: 'pipe',
        env: {
          ...process.env,
          TERM: 'xterm-256color',
          COLUMNS: String(cols || 80),
          LINES: String(rows || 24),
        },
      });
      shells.set(id, { proc, offline: [], offlineBytes: 0, persistent });
      const pump = async (stream: ReadableStream<Uint8Array>) => {
        const dec = new TextDecoder();
        for await (const chunk of stream) sendShellData(id, dec.decode(chunk));
      };
      void pump(proc.stdout as ReadableStream<Uint8Array>);
      void pump(proc.stderr as ReadableStream<Uint8Array>);
      void proc.exited.then((code) => {
        send({ type: 'shell.exit', id, code });
        shells.delete(id);
      });
    } catch {
      send({ type: 'shell.exit', id, code: 1 });
    }
  };

  /**
   * Dispatch one tunnel message.
   *
   * @remarks
   * The two cases that can start a process — `exec` and `shell.open` — verify a
   * grant first and answer with a refusal (exit code 126, "command not
   * executable") when it does not hold. Unknown message types are ignored
   * rather than treated as anything.
   *
   * The remaining cases act on an already-open session identified by `id`, and
   * carry no grant of their own: writing to a session's stdin is a continuation
   * of the session that was authorized at open.
   */
  const handle = (msg: Record<string, unknown>) => {
    const id = String(msg.id ?? '');
    switch (msg.type) {
      case 'exec': {
        const command = String(msg.command ?? '');
        if (!grants.verify('exec', command, msg)) {
          send({
            type: 'exec.result',
            id,
            exitCode: 126,
            stdout: '',
            stderr: 'unauthorized: valid exec signature required',
            durationMs: 0,
          });
          return;
        }
        void runExec(id, command, Number(msg.timeoutMs ?? 0));
        return;
      }
      case 'power': {
        // The signed field is an ACTION, not a command. An unknown word is
        // refused outright, and the command itself is looked up here — so
        // nothing the control plane sends ever reaches a shell on this path.
        const action = String(msg.action ?? '');
        if (!isPowerAction(action)) {
          send({ type: 'power.result', id, ok: false, error: 'unknown power action' });
          return;
        }
        if (!grants.verify('power', action, msg)) {
          send({
            type: 'power.result',
            id,
            ok: false,
            error: 'unauthorized: valid power signature required',
          });
          return;
        }
        // Answer before acting: `systemctl reboot` never returns, so a reply
        // sent afterwards would never be sent at all and the operator would
        // see a timeout on a reboot that worked.
        send({ type: 'power.result', id, ok: true, error: null });
        console.log(`power ${action} requested`);
        const argv = POWER_COMMANDS[action];
        setTimeout(() => {
          try {
            Bun.spawn([...argv], { stdout: 'ignore', stderr: 'ignore' });
          } catch (e) {
            console.error(`power ${action} failed: ${(e as Error).message}`);
          }
        }, 500);
        return;
      }
      case 'shell.open': {
        const shellCommand = String(msg.command ?? 'bash -l');
        // Bind the grant to the exact shell command (live-exec runs a real command
        // via a PTY; a generic terminal opens 'bash -l').
        if (!grants.verify('shell', shellCommand, msg)) {
          // Say why, in the terminal itself. A bare exit shows only "session
          // ended" — the silent refusal that makes a signing or key-mismatch
          // problem impossible to tell from a dead tunnel.
          send({
            type: 'shell.data',
            id,
            data: '\r\n\x1b[31mExec refused: no valid vault signature for this server.\x1b[0m\r\n\x1b[2mUnlock the vault in your browser; if it stays refused, the authorized key no longer matches this vault.\x1b[0m\r\n',
          });
          send({ type: 'shell.exit', id, code: 126 });
          return;
        }
        openShell(
          id,
          shellCommand,
          Number(msg.cols ?? 80),
          Number(msg.rows ?? 24),
          Boolean(msg.persistent),
        );
        return;
      }
      case 'fs': {
        // The descriptor is rebuilt from the decoded bytes, never from a hash
        // the caller supplied: that is what stops a relay from keeping a valid
        // signature while swapping the content that reaches the disk.
        const req: FsRequest = {
          op: String(msg.op ?? '') as FsRequest['op'],
          path: String(msg.path ?? ''),
          to: typeof msg.to === 'string' ? msg.to : undefined,
          mode: typeof msg.mode === 'string' ? msg.mode : undefined,
          content: typeof msg.content === 'string' ? msg.content : undefined,
          recursive: msg.recursive === true,
        };
        const bytes = req.op === 'write' ? Buffer.from(req.content ?? '', 'base64') : null;
        if (!grants.verify('fs', fsDescriptorFor(req, bytes), msg)) {
          send({
            type: 'fs.result',
            id,
            ok: false,
            code: 'denied',
            error: 'unauthorized: valid fs signature required',
          });
          return;
        }
        void runFsOp(cfg, req).then((result) => send({ type: 'fs.result', id, ...result }));
        return;
      }
      case 'net': {
        // Same rule as `fs`: the descriptor is rebuilt from the decoded bytes,
        // so the request that goes out is the one that was signed — down to the
        // headers and the body — and not whatever the relay claims it hashed.
        const req: NetRequest = {
          scheme: String(msg.scheme ?? 'http') as LocalScheme,
          host: String(msg.host ?? ''),
          port: Number(msg.port ?? 0),
          method: String(msg.method ?? 'GET') as LocalMethod,
          path: String(msg.path ?? ''),
          headers: Array.isArray(msg.headers)
            ? (msg.headers as LocalHeader[]).map((h) => ({
                name: String(h?.name ?? ''),
                value: String(h?.value ?? ''),
              }))
            : [],
          body: typeof msg.body === 'string' ? msg.body : undefined,
          insecureTls: msg.insecureTls === true,
        };
        if (!grants.verify('net', netDescriptorFor(req, netBodyBytes(req)), msg)) {
          send({
            type: 'net.result',
            id,
            ok: false,
            code: 'denied',
            error: 'unauthorized: valid net signature required',
          });
          return;
        }
        // The URL is logged, the headers and both bodies never are: an
        // Authorization header on a local admin API is a credential.
        console.log(`net ${req.method} ${req.scheme}://${req.host}:${req.port}${req.path}`);
        void runNetRequest(req).then((result) => send({ type: 'net.result', id, ...result }));
        return;
      }
      case 'shell.input': {
        const sh = shells.get(id);
        if (sh && typeof msg.data === 'string') writeStdin(sh.proc, msg.data);
        return;
      }
      case 'shell.signal': {
        const sh = shells.get(id);
        if (sh) writeStdin(sh.proc, '\x03');
        return;
      }
      case 'shell.close': {
        const sh = shells.get(id);
        if (sh) {
          try {
            sh.proc.kill();
          } catch {
            // ignore
          }
          shells.delete(id);
        }
        return;
      }
      default:
        return;
    }
  };

  /**
   * Dial the control plane and wire up the socket, reconnecting on close.
   *
   * @remarks
   * The first message is an HMAC over `tunnel:<serverId>` with the enrollment
   * secret, proving to the control plane which agent this is. It says nothing
   * about what may be executed — that is settled per command, by signature.
   */
  const connect = () => {
    ws = new WebSocketImpl(wsUrl);
    ws.onopen = () => {
      const ts = String(Math.floor(Date.now() / 1000));
      const sig = createHmac('sha256', cfg.secret)
        .update(
          canonicalAgentMessage({
            kind: 'tunnel',
            serverId: cfg.serverId,
            timestamp: ts,
            body: `tunnel:${cfg.serverId}`,
          }),
        )
        .digest('hex');
      send({ type: 'init', ts, sig });
    };
    ws.onmessage = (e) => {
      let msg: Record<string, unknown> | null = null;
      try {
        msg = JSON.parse(typeof e.data === 'string' ? e.data : '');
      } catch {
        return;
      }
      if (!msg) return;
      if (msg.type === 'init.ok') {
        backoff = 1000;
        lastRefusal = null;
        online = true;
        if (graceTimer) {
          clearTimeout(graceTimer);
          graceTimer = null;
        }
        // Re-advertise still-running shells so the relay (fresh after an API
        // restart) rebuilds them as re-attachable, then flush buffered output.
        if (shells.size > 0) {
          send({
            type: 'resume',
            shells: [...shells].map(([id, sh]) => ({ id, persistent: sh.persistent })),
          });
          for (const [id, sh] of shells) {
            for (const d of sh.offline) send({ type: 'shell.data', id, data: d });
            sh.offline = [];
            sh.offlineBytes = 0;
          }
        }
        console.log('tunnel authenticated');
        lastPong = Date.now();
        connectedAt = Date.now();
        sawInitOk = true;
        clearStableTimer();
        stableTimer = setTimeout(() => {
          if (flapCount > 0) console.log('tunnel stable — flap counter reset');
          flapCount = 0;
        }, STABLE_MS);
        stopHeartbeat();
        scheduleHeartbeat();
        return;
      }
      if (msg.type === 'pong') {
        lastPong = Date.now();
        if (lastPingSentAt > 0) lastRttMs = lastPong - lastPingSentAt;
        return;
      }
      if (msg.type === 'init.error') {
        const reason = typeof msg.reason === 'string' ? msg.reason : 'unknown';
        if (reason !== lastRefusal) {
          lastRefusal = reason;
          console.error(
            `tunnel auth rejected: ${reason}`,
            reason === 'clock_skew'
              ? '(the clock on this host is more than 5 minutes off — check NTP)'
              : '',
          );
        }
        return;
      }
      handle(msg);
    };
    ws.onclose = () => {
      online = false;
      ws = null;
      stopHeartbeat();
      clearStableTimer();
      // A connection that authenticated but died young is a flap; one that never
      // authenticated is an ordinary connection failure (server down, refused),
      // already handled by the exponential backoff below.
      if (sawInitOk && Date.now() - connectedAt < STABLE_MS) flapCount++;
      sawInitOk = false;
      // Do NOT kill shells: a Servor API restart / network blip must not stop
      // running commands. Keep them alive (buffering output) and reclaim only if
      // the tunnel stays down past the grace window.
      if (!graceTimer && shells.size > 0) {
        graceTimer = setTimeout(() => {
          // Reap only non-persistent (interactive) shells after a long outage.
          // Form-launched persistent commands keep running until they finish.
          for (const [id, sh] of shells) {
            if (sh.persistent) continue;
            try {
              sh.proc.kill();
            } catch {
              // ignore
            }
            shells.delete(id);
          }
          graceTimer = null;
        }, OFFLINE_GRACE_MS);
      }
      if (flapCount >= FLAP_HARD_LIMIT) {
        // Giving up on reconnecting, not exiting: the process stays alive so
        // systemd (Restart=always) does not immediately relaunch it into the
        // same storm. It will retry only on a manual restart or reboot.
        console.error(
          `tunnel flapped ${flapCount} times — stopping reconnects. Another agent is almost certainly using this server id; reinstall the agent on a single host.`,
        );
        return;
      }
      if (flapCount >= FLAP_SOFT_LIMIT) {
        if (flapCount === FLAP_SOFT_LIMIT) {
          console.error(
            `tunnel flapping — backing off for ${FLAP_COOLDOWN_MS / 1000}s (a duplicate agent may share this server id)`,
          );
        }
        setTimeout(connect, FLAP_COOLDOWN_MS);
        return;
      }
      setTimeout(connect, backoff);
      // Ten seconds, not sixty. This is the channel every command travels down,
      // and the minute-long gap it used to reach meant a freshly installed
      // agent stayed unreachable long after whatever refused it had cleared —
      // usually a clock that had since synced. A retry costs a WebSocket
      // handshake; being unreachable costs the product.
      backoff = Math.min(backoff * 2, 10000);
    };
    ws.onerror = () => ws?.close();
  };

  connect();

  // Force a reconnect when the control plane reports, over the HTTP config
  // poll, that it holds no tunnel for us while we still believe we are online —
  // the half-open case the config loop can see even when the socket cannot. The
  // 30s floor since the last connect avoids flapping on a response that was
  // computed before a fresh reconnect had registered.
  const reconnectNow = () => {
    if (!online || !ws) return;
    if (Date.now() - connectedAt < 30_000) return;
    console.error('control plane reports no tunnel — reconnecting');
    try {
      ws.close();
    } catch {
      // onclose will schedule the reconnect regardless
    }
  };

  return { isBusy: () => shells.size > 0 || inflightExec > 0, reconnectNow };
};
