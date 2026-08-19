import { createHmac } from 'node:crypto';
import type { AgentConfig } from './config';
import { verifyExecGrant } from './protocol/exec-sign';

// End-to-end execution policy, synced from the control plane by fetchConfig.
// Every exec and shell.open must carry a grant signed by one of the authorized
// vault-derived operator keys, and that signature is verified HERE, on this
// host. The control plane never holds the private half, so it relays a grant it
// cannot forge; it decides what reaches the agent, not what the agent accepts.
//
// The initial value is deliberately the restrictive one: a command that arrives
// before the first config sync finds signing required and no key to satisfy it,
// so it is refused rather than run.
// Not a variable, and not settable from the network. The control plane used to
// send a `requireSignedExec` flag that this agent honoured; a response that
// merely *omitted* it turned verification off entirely, which made the one
// property the agent exists to provide remotely disableable — by silence.
const EXEC_REQUIRE = true;
let execKeys: Uint8Array[] = [];

/** Nonces of accepted grants, mapped to when they were accepted. */
const seenNonces = new Map<string, number>();

/** How far in the past a grant's timestamp may sit and still be accepted. */
const GRANT_PAST_SKEW_S = 300;
/** How far ahead a grant's timestamp may sit — tolerance for clock drift, no more. */
const GRANT_FUTURE_SKEW_S = 60;
/**
 * How long an accepted nonce is remembered.
 *
 * @remarks
 * A grant is accepted anywhere in a window spanning both skews, so one
 * signature can remain cryptographically valid for their sum. The nonce has to
 * outlive that window, with margin — forget a nonce while its signature is
 * still inside the acceptance window and the same captured grant becomes
 * replayable. That is the entire reason this TTL exceeds the window rather than
 * matching it.
 */
const NONCE_TTL_MS = (GRANT_PAST_SKEW_S + GRANT_FUTURE_SKEW_S + 60) * 1000;

const fromB64 = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, 'base64'));

/**
 * Install the execution policy received from the control plane.
 *
 * @param require - Whether a valid signature is demanded before anything runs.
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
  execKeys = keysB64.map(fromB64);
};

const isRoot = () => typeof process.getuid === 'function' && process.getuid() === 0;

/**
 * Build the argv for a one-shot command, dropping root when a user is configured.
 *
 * @remarks
 * Wrapping is limited to choosing the interpreter and the account. Nothing is
 * prepended to the command itself — no `cd`, no `sudo`, no exported variable —
 * because the operator signed exactly this string and the signature must keep
 * covering what actually executes.
 */
const wrapExec = (cfg: AgentConfig, command: string): string[] => {
  if (process.platform === 'win32') return ['powershell', '-NoProfile', '-Command', command];
  if (process.platform === 'linux' && cfg.user && isRoot()) {
    return ['runuser', '-u', cfg.user, '--', 'bash', '-lc', command];
  }
  return ['bash', '-lc', command];
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
 */
const wrapShell = (cfg: AgentConfig, command: string): string[] => {
  if (process.platform === 'win32') return ['powershell', '-NoProfile', '-Command', command];
  if (process.platform === 'darwin') return ['script', '-q', '/dev/null', 'bash', '-lc', command];
  const base = ['script', '-qfc', command, '/dev/null'];
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
 * Every message that can start a process passes {@link verifyGrant} first.
 */
export const startTunnel = (cfg: AgentConfig) => {
  const wsUrl = `${cfg.apiUrl.replace(/^http/, 'ws')}/agent/tunnel/${cfg.serverId}`;
  let ws: WebSocket | null = null;
  let backoff = 1000;
  const shells = new Map<string, Shell>();
  let inflightExec = 0;
  let online = false;
  let graceTimer: ReturnType<typeof setTimeout> | null = null;
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
   * Decide whether a request to run something carries a valid operator grant.
   *
   * @param kind - `exec` or `shell`; part of the signed message, so a grant for
   * a one-shot command cannot be re-used to open an interactive session.
   * @param command - The exact command about to run, also signed. Verifying the
   * string that executes, and not a description of it, is what stops the relay
   * from substituting a different command behind a valid signature.
   * @param msg - Raw tunnel message; `nonce`, `ts` and `sig` are read from it
   * and everything else ignored.
   * @returns `true` only when a signature over the whole grant verifies against
   * one of the authorized keys. Every other outcome is `false`, and the caller
   * refuses to run anything.
   *
   * @remarks
   * This function is the trust boundary. Nothing upstream of it is trusted: the
   * control plane relays a grant, it does not vouch for one.
   *
   * Four independent conditions must hold, and each closes a distinct attack.
   *
   * - **A key must exist.** With no authorized key, no signature can verify and
   *   the answer is `false`. Verification fails closed on purpose: an agent that
   *   ran commands while it had nothing to check them against would be at the
   *   mercy of whoever spoke to it first.
   * - **The grant is bound to this server.** `serverId` is the agent's own, taken
   *   from local config and never from the message, so a grant captured on one
   *   host cannot be replayed against another.
   * - **The timestamp must fall inside the acceptance window.** The window is
   *   asymmetric by design: several minutes of lateness are tolerated because
   *   networks and queues are slow, but a grant minted far in the future is
   *   refused — accepting one would stretch its validity past the lifetime of
   *   the nonce that is supposed to make it single-use.
   * - **The nonce must be unseen.** Signatures are replayable by anyone who
   *   observes one; the nonce table is what makes a grant good exactly once.
   *   It is only recorded on success, so a rejected grant cannot be used to
   *   consume a nonce someone else would legitimately have presented.
   *
   * The table is pruned on every acceptance rather than past some size
   * threshold: an earlier version pruned only after a thousand entries, which
   * let expired nonces sit in memory while fresh ones were still being refused.
   * The map stays small, so the sweep costs nothing.
   *
   * What this does not establish is who was at the keyboard. It proves a
   * request was signed by a key the operator authorized — not that the person
   * holding it meant to send this command, or that their browser was not
   * compromised.
   */
  const verifyGrant = (
    kind: 'exec' | 'shell',
    command: string,
    msg: Record<string, unknown>,
  ): boolean => {
    if (!EXEC_REQUIRE) return true;
    const nonce = String(msg.nonce ?? '');
    const ts = String(msg.ts ?? '');
    const sig = String(msg.sig ?? '');
    if (!nonce || !ts || !sig || execKeys.length === 0) return false;
    const tsn = Number.parseInt(ts, 10);
    const ageS = Math.floor(Date.now() / 1000) - tsn;
    if (!Number.isFinite(tsn) || ageS > GRANT_PAST_SKEW_S || ageS < -GRANT_FUTURE_SKEW_S) {
      return false;
    }
    if (seenNonces.has(nonce)) return false;
    let sigBytes: Uint8Array;
    try {
      sigBytes = fromB64(sig);
    } catch {
      return false;
    }
    const grant = { serverId: cfg.serverId, kind, command, nonce, ts };
    const ok = execKeys.some((k) => verifyExecGrant(k, grant, sigBytes));
    if (ok) {
      seenNonces.set(nonce, Date.now());
      const cutoff = Date.now() - NONCE_TTL_MS;
      for (const [n, ti] of seenNonces) if (ti < cutoff) seenNonces.delete(n);
    }
    return ok;
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
      const proc = Bun.spawn(wrapExec(cfg, command), { stdout: 'pipe', stderr: 'pipe' });
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
      const proc = Bun.spawn(wrapShell(cfg, command || 'bash -l'), {
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
        if (!verifyGrant('exec', command, msg)) {
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
      case 'shell.open': {
        const shellCommand = String(msg.command ?? 'bash -l');
        // Bind the grant to the exact shell command (live-exec runs a real command
        // via a PTY; a generic terminal opens 'bash -l').
        if (!verifyGrant('shell', shellCommand, msg)) {
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
    ws = new WebSocket(wsUrl);
    ws.onopen = () => {
      const ts = String(Math.floor(Date.now() / 1000));
      const sig = createHmac('sha256', cfg.secret)
        .update(`${ts}.tunnel:${cfg.serverId}`)
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
        return;
      }
      if (msg.type === 'init.error') {
        console.error('tunnel auth rejected');
        return;
      }
      handle(msg);
    };
    ws.onclose = () => {
      online = false;
      ws = null;
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
      setTimeout(connect, backoff);
      backoff = Math.min(backoff * 2, 60000);
    };
    ws.onerror = () => ws?.close();
  };

  connect();

  return { isBusy: () => shells.size > 0 || inflightExec > 0 };
};
