import { createHmac } from 'node:crypto';
import type { AgentConfig } from './config';

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

type Shell = { proc: ReturnType<typeof Bun.spawn> };

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

  const send = (data: unknown) => {
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
  };

  const runExec = async (id: string, command: string, timeoutMs: number) => {
    const start = Date.now();
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
    }
  };

  const openShell = (id: string, command: string, cols: number, rows: number) => {
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
      shells.set(id, { proc });
      const pump = async (stream: ReadableStream<Uint8Array>) => {
        const dec = new TextDecoder();
        for await (const chunk of stream) send({ type: 'shell.data', id, data: dec.decode(chunk) });
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
      case 'exec':
        void runExec(id, String(msg.command ?? ''), Number(msg.timeoutMs ?? 0));
        return;
      case 'shell.open':
        openShell(
          id,
          String(msg.command ?? 'bash -l'),
          Number(msg.cols ?? 80),
          Number(msg.rows ?? 24),
        );
        return;
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
      for (const sh of shells.values()) {
        try {
          sh.proc.kill();
        } catch {
          // ignore
        }
      }
      shells.clear();
      ws = null;
      setTimeout(connect, backoff);
      backoff = Math.min(backoff * 2, 60000);
    };
    ws.onerror = () => ws?.close();
  };

  connect();
};
