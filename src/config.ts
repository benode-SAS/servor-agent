import { readFileSync, renameSync, writeFileSync } from 'node:fs';

/**
 * Everything the agent needs to reach its control plane and behave on this host.
 *
 * @remarks
 * Written at enrollment and read from disk at startup. `secret` is the
 * per-server HMAC key shared with the control plane; it authenticates the
 * agent's own outbound calls (metrics, checks, tunnel handshake). It grants no
 * authority to execute anything — that requires a signed grant, see
 * `tunnel.ts`.
 */
export type AgentConfig = {
  /** Server this agent is enrolled as, in the control plane's namespace. */
  serverId: string;
  /** Per-server HMAC key proving outbound requests come from this agent. */
  secret: string;
  /** HTTPS base of the control plane, e.g. https://api.servor.benode.fr. */
  apiUrl: string;
  /** Delay between two metrics pushes; the control plane may retune it. */
  intervalSeconds: number;
  /** `tunnel` also opens the WebSocket that carries commands; `push` is metrics only. */
  mode: 'push' | 'tunnel';
  /** OS user commands are dropped to (the configured SSH user) when running as root. */
  user?: string;
  /** Config file format version, not the agent version. */
  version: string;
};

const defaultPath = () =>
  process.platform === 'win32'
    ? `${process.env.ProgramData ?? 'C:\\ProgramData'}\\ServorAgent\\config.json`
    : '/etc/servor-agent/config.json';

/**
 * Location of the config file: `SERVOR_CONFIG` if set, else the OS default.
 *
 * @returns `%ProgramData%\ServorAgent\config.json` on Windows,
 * `/etc/servor-agent/config.json` elsewhere.
 */
export const configPath = (): string => process.env.SERVOR_CONFIG ?? defaultPath();

/**
 * Merge a few fields into the config file so a live retune survives a restart.
 *
 * @param patch - Fields to overwrite; everything else on disk is preserved.
 *
 * @remarks
 * Writes to a temporary file and renames over the original, so a crash mid-write
 * cannot leave a truncated config that would stop the agent from starting. The
 * temporary file is created 0600 because the config holds the HMAC secret.
 * Failures are logged and swallowed: losing a retuned interval is not worth
 * killing a running agent over.
 */
export const saveConfig = (patch: Partial<AgentConfig>): void => {
  const path = configPath();
  try {
    const cur = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    const tmp = `${path}.tmp`;
    writeFileSync(tmp, JSON.stringify({ ...cur, ...patch }), { mode: 0o600 });
    renameSync(tmp, path);
  } catch (e) {
    console.error('config save failed', (e as Error).message);
  }
};

/**
 * Read and normalise the config file, refusing to start on anything unusable.
 *
 * @returns A config with the trailing slash stripped from `apiUrl`, the push
 * interval clamped to 15–300 s, and an unrecognised `mode` degraded to `push`
 * (metrics only, no command channel).
 * @throws If the file is missing, is not JSON, or lacks `serverId`, `secret` or
 * `apiUrl` — the agent cannot meaningfully run without them, so it exits rather
 * than half-work.
 */
export const loadConfig = (): AgentConfig => {
  const path = configPath();
  const raw = readFileSync(path, 'utf8');
  const cfg = JSON.parse(raw) as Partial<AgentConfig>;
  if (!cfg.serverId || !cfg.secret || !cfg.apiUrl) {
    throw new Error(`invalid config at ${path}`);
  }
  return {
    serverId: cfg.serverId,
    secret: cfg.secret,
    apiUrl: cfg.apiUrl.replace(/\/$/, ''),
    intervalSeconds: Math.min(300, Math.max(15, cfg.intervalSeconds ?? 60)),
    mode: cfg.mode === 'tunnel' ? 'tunnel' : 'push',
    user: cfg.user,
    version: cfg.version ?? '1',
  };
};
