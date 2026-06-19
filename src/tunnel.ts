import { createHmac } from 'node:crypto';
import { verifyExecGrant } from '@servor/shared/crypto';
import type { AgentConfig } from './config';

// End-to-end exec policy, synced from the control plane config. When required,
// every exec/shell.open must carry a grant signed by one of the authorized
// vault-derived keys — verified LOCALLY, so a compromised control plane cannot
// forge an execution.
// Fail-closed: require a signed grant by default (until config says otherwise,
// which it never does — signing is mandatory). With no keys yet, exec is refused.
let execRequire = true;
let execKeys: Uint8Array[] = [];
const seenNonces = new Map<string, number>();
const NONCE_TTL_MS = 6 * 60 * 1000;

const fromB64 = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, 'base64'));

export const setExecPolicy = (require: boolean, keysB64: string[]) => {
  execRequire = require;
  execKeys = keysB64.map(fromB64);
};

const isRoot = () => typeof process.getuid === 'function' && process.getuid() === 0;

// Wrap a command so it runs as the configured user (drop root via runuser).
const wrapExec = (cfg: AgentConfig, command: string): string[] => {
  if (process.platform === 'win32') return ['powershell', '-NoProfile', '-Command', command];
  if (process.platform === 'linux' && cfg.user && isRoot()) {
    return ['runuser', '-u', cfg.user, '--', 'bash', '-lc', command];
  }
  return ['bash', '-lc', command];
};

// PTY-backed interactive shell via `script` (util-linux). Runs as configured user.
const wrapShell = (cfg: AgentConfig, command: string): string[] => {
  if (process.platform === 'win32') return ['powershell', '-NoProfile', '-Command', command];
  if (process.platform === 'darwin') return ['script', '-q', '/dev/null', 'bash', '-lc', command];
  const base = ['script', '-qfc', command, '/dev/null'];
  if (cfg.user && isRoot()) return ['runuser', '-u', cfg.user, '--', ...base];
  return base;
};

type Shell = {
  proc: ReturnType<typeof Bun.spawn>;
  offline: string[]; // output buffered while the tunnel is down (flushed on resume)
  offlineBytes: number;
  persistent: boolean; // form-launched command → never reaped by outage grace, runs to completion
};

// proc.stdin is typed as number | FileSink; with stdin:'pipe' it's a FileSink.
const writeStdin = (proc: ReturnType<typeof Bun.spawn>, data: string) => {
  const sink = proc.stdin as import('bun').FileSink;
  sink.write(data);
  sink.flush();
};

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

  // Shell output: send live when connected, else buffer (bounded) so an API
  // restart / blip doesn't lose output — flushed on resume.
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

  // Verify a signed exec/shell grant against the authorized keys. serverId is the
  // agent's own (anti-replay across servers); ts window + single-use nonce.
  const verifyGrant = (
    kind: 'exec' | 'shell',
    command: string,
    msg: Record<string, unknown>,
  ): boolean => {
    if (!execRequire) return true;
    const nonce = String(msg.nonce ?? '');
    const ts = String(msg.ts ?? '');
    const sig = String(msg.sig ?? '');
    if (!nonce || !ts || !sig || execKeys.length === 0) return false;
    const tsn = Number.parseInt(ts, 10);
    if (!Number.isFinite(tsn) || Math.abs(Math.floor(Date.now() / 1000) - tsn) > 300) return false;
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
      if (seenNonces.size > 1000) {
        const cutoff = Date.now() - NONCE_TTL_MS;
        for (const [n, ti] of seenNonces) if (ti < cutoff) seenNonces.delete(n);
      }
    }
    return ok;
  };

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
    } catch (e) {
      send({ type: 'shell.exit', id, code: 1 });
    }
  };

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

  // Exposed so the updater can drain: true while any interactive shell is open
  // or a one-shot exec is running. Used to defer a staged self-update until idle.
  return { isBusy: () => shells.size > 0 || inflightExec > 0 };
};
