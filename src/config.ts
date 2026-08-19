import { readFileSync, renameSync, writeFileSync } from 'node:fs';

export type AgentConfig = {
  serverId: string;
  secret: string;
  apiUrl: string; // https base, e.g. https://api.servor.benode.fr
  intervalSeconds: number;
  mode: 'push' | 'tunnel';
  user?: string; // OS user to run tunnel commands as (the configured SSH user)
  version: string;
};

const defaultPath = () =>
  process.platform === 'win32'
    ? `${process.env.ProgramData ?? 'C:\\ProgramData'}\\ServorAgent\\config.json`
    : '/etc/servor-agent/config.json';

export const configPath = (): string => process.env.SERVOR_CONFIG ?? defaultPath();

// Atomic merge-write so live config changes (e.g. interval) survive restarts.
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
