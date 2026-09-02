import { redactSecrets } from '@servor/shared/utils';

// Host facts: what is running on the box + its health. Two cadences keep the
// agent light: live parts (containers, pm2, failed units) are recomputed on every
// call; heavy parts (service versions, TLS, k8s, domains, firewall…) are cached
// and only refreshed every FACTS_TTL_MS. Everything is best-effort — a failing
// probe yields an absent field, never an error.

const sh = (cmd: string[], timeoutMs = 5000): string => {
  try {
    const p = Bun.spawnSync(cmd, { stdout: 'pipe', stderr: 'ignore', timeout: timeoutMs });
    return p.success ? new TextDecoder().decode(p.stdout).trim() : '';
  } catch {
    return '';
  }
};
const bash = (script: string, timeoutMs = 5000): string => sh(['bash', '-lc', script], timeoutMs);
const has = (bin: string): boolean => bash(`command -v ${bin} >/dev/null 2>&1 && echo 1`) === '1';
const isActive = (svc: string): boolean => sh(['systemctl', 'is-active', svc]) === 'active';

/**
 * Is a process by that exact name running, whoever started it?
 *
 * @remarks
 * `systemctl is-active` only answers for units systemd owns. A service run
 * under pm2, supervisor, a container or plain `&` is invisible to it, and was
 * reported as inactive while serving traffic. `--` keeps a name that starts
 * with a dash from being read as an option, as in checks.ts.
 */
const isRunning = (proc: string): boolean => sh(['pgrep', '-x', '--', proc]).length > 0;

type Container = {
  name: string;
  image?: string;
  state?: string;
  status?: string;
  health?: 'healthy' | 'unhealthy' | 'starting' | 'none';
  ports?: string[];
  runtime?: 'docker' | 'podman';
};
type ProcessInfo = {
  name: string;
  status?: string;
  restarts?: number;
  cpu?: number;
  memMb?: number;
  uptimeSec?: number;
  outLogPath?: string;
  errLogPath?: string;
};
type Service = {
  name: string;
  kind?: 'web' | 'proxy' | 'database' | 'cache' | 'queue' | 'runtime' | 'other';
  active?: boolean;
  version?: string;
  detail?: string;
};
type TlsCert = { domain: string; notAfter?: string; daysLeft?: number };
export type HostFacts = {
  collectedAt?: string;
  docker?: { version?: string; running?: number; total?: number };
  containers?: Container[];
  pm2?: { version?: string };
  supervisor?: { version?: string; programs?: string[] };
  processes?: ProcessInfo[];
  services?: Service[];
  selfHosted?: string[];
  systemd?: { failedCount?: number; failed?: string[] };
  cron?: CronEntry[];
  kubernetes?: { flavor?: string; nodes?: number; pods?: number };
  tls?: TlsCert[];
  domains?: string[];
  health?: {
    rebootRequired?: boolean;
    firewall?: string;
    firewallActive?: boolean;
    timeSync?: boolean;
  };
};

const parseHealth = (status: string): Container['health'] => {
  const s = status.toLowerCase();
  if (s.includes('unhealthy')) return 'unhealthy';
  if (s.includes('health: starting')) return 'starting';
  if (s.includes('healthy')) return 'healthy';
  return 'none';
};

const collectContainers = (): Container[] => {
  const out: Container[] = [];
  if (has('docker')) {
    for (const line of sh(['docker', 'ps', '-a', '--format', '{{json .}}']).split('\n')) {
      if (!line.trim()) continue;
      try {
        const c = JSON.parse(line) as Record<string, string>;
        const status = c.Status ?? '';
        out.push({
          name: c.Names ?? '?',
          image: c.Image,
          state: c.State,
          status,
          health: parseHealth(status),
          ports: c.Ports
            ? c.Ports.split(',')
                .map((p) => p.trim())
                .filter(Boolean)
                .slice(0, 30)
            : undefined,
          runtime: 'docker',
        });
      } catch {}
    }
  }
  if (has('podman')) {
    try {
      const arr = JSON.parse(sh(['podman', 'ps', '-a', '--format', 'json']) || '[]') as Array<
        Record<string, unknown>
      >;
      for (const c of arr) {
        const names = c.Names as string[] | undefined;
        out.push({
          name: names?.[0] ?? '?',
          image: c.Image as string | undefined,
          state: c.State as string | undefined,
          status: c.Status as string | undefined,
          runtime: 'podman',
        });
      }
    } catch {}
  }
  return out.slice(0, 300);
};

const collectPm2 = (): { pm2?: { version?: string }; processes?: ProcessInfo[] } => {
  if (!has('pm2')) return {};
  const version = sh(['pm2', '-v']) || undefined;
  const processes: ProcessInfo[] = [];
  try {
    const arr = JSON.parse(sh(['pm2', 'jlist']) || '[]') as Array<Record<string, unknown>>;
    for (const p of arr) {
      const env = (p.pm2_env ?? {}) as Record<string, unknown>;
      const monit = (p.monit ?? {}) as Record<string, unknown>;
      const upMs = env.pm_uptime as number | undefined;
      processes.push({
        name: (p.name as string) ?? '?',
        status: env.status as string | undefined,
        restarts: env.restart_time as number | undefined,
        cpu: monit.cpu as number | undefined,
        memMb:
          typeof monit.memory === 'number'
            ? Math.round((monit.memory as number) / 1048576)
            : undefined,
        uptimeSec:
          env.status === 'online' && upMs ? Math.round((Date.now() - upMs) / 1000) : undefined,
        outLogPath: env.pm_out_log_path as string | undefined,
        errLogPath: env.pm_err_log_path as string | undefined,
      });
    }
  } catch {}
  return { pm2: { version }, processes: processes.slice(0, 300) };
};

/**
 * One scheduled job already present on the machine, discovered — never written.
 *
 * @remarks
 * Servor's own scheduled commands never reach the system crontab: the agent
 * evaluates their expressions in-process and runs them itself. Everything found
 * here is therefore the operator's own, and the two lists cannot overlap.
 */
type CronEntry = {
  schedule: string;
  command: string;
  /** Present for /etc/crontab and /etc/cron.d, which carry a user column. */
  user?: string;
  /** Where it was read from, so the UI can say `/etc/cron.d/backup`. */
  source: string;
};

const CRON_SPECIALS = new Set([
  '@reboot',
  '@yearly',
  '@annually',
  '@monthly',
  '@weekly',
  '@daily',
  '@midnight',
  '@hourly',
]);

/**
 * Parse a crontab, tolerating everything a real one contains.
 *
 * @param withUser - true for `/etc/crontab` and `/etc/cron.d/*`, whose lines
 * carry a user column between the schedule and the command. A per-user spool
 * has no such column, and reading one as the other would silently turn the
 * first word of every command into a username.
 *
 * @remarks
 * Comments and `KEY=value` assignments are skipped rather than parsed: `MAILTO`
 * and `PATH` are not jobs. Commands are redacted, because a cron line is one of
 * the likelier places on a box to find a token sitting in plain sight.
 */
export const parseCrontab = (content: string, withUser: boolean, source: string): CronEntry[] => {
  const out: CronEntry[] = [];
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    // MAILTO="x", PATH=/usr/bin, SHELL=/bin/sh — settings, not schedules.
    if (/^[A-Za-z_][A-Za-z0-9_]*\s*=/.test(line)) continue;

    const parts = line.split(/\s+/);
    let schedule: string;
    let rest: string[];
    const head = parts[0];
    if (head && CRON_SPECIALS.has(head)) {
      schedule = head;
      rest = parts.slice(1);
    } else if (parts.length >= (withUser ? 7 : 6)) {
      schedule = parts.slice(0, 5).join(' ');
      rest = parts.slice(5);
    } else {
      continue;
    }

    const user = withUser ? rest[0] : undefined;
    const command = (withUser ? rest.slice(1) : rest).join(' ');
    if (!command) continue;
    out.push({ schedule, command: redactSecrets(command).text, user, source });
  }
  return out;
};

/**
 * Everything the machine schedules on its own: the system crontab, its
 * drop-ins, and the per-user spools when the agent can read them.
 */
const collectCron = (): CronEntry[] => {
  const entries: CronEntry[] = [];
  const read = (path: string): string => bash(`cat ${JSON.stringify(path)} 2>/dev/null`);

  entries.push(...parseCrontab(read('/etc/crontab'), true, '/etc/crontab'));

  for (const name of bash('ls -1 /etc/cron.d 2>/dev/null').split('\n')) {
    const file = name.trim();
    // cron itself ignores drop-ins whose name contains a dot.
    if (!file || file.includes('.')) continue;
    entries.push(...parseCrontab(read(`/etc/cron.d/${file}`), true, `/etc/cron.d/${file}`));
  }

  // Both layouts exist: Debian spools under crontabs/, RHEL directly.
  for (const dir of ['/var/spool/cron/crontabs', '/var/spool/cron']) {
    for (const name of bash(`ls -1 ${dir} 2>/dev/null`).split('\n')) {
      const user = name.trim();
      if (!user) continue;
      entries.push(
        ...parseCrontab(read(`${dir}/${user}`), false, `crontab:${user}`).map((e) => ({
          ...e,
          user,
        })),
      );
    }
  }

  // Last resort when the spools are unreadable: the agent's own crontab.
  if (entries.length === 0 && has('crontab')) {
    entries.push(...parseCrontab(sh(['crontab', '-l']), false, 'crontab'));
  }

  return entries.slice(0, 200);
};

const collectFailedUnits = (): { failedCount?: number; failed?: string[] } => {
  const raw = sh(['systemctl', '--failed', '--no-legend', '--plain']);
  if (!raw) return { failedCount: 0, failed: [] };
  const failed = raw
    .split('\n')
    .map((l) => l.trim().split(/\s+/)[0])
    .filter(
      (n): n is string => (!!n && n.endsWith('.service') === true) || (!!n && n.includes('.')),
    )
    .slice(0, 60);
  return { failedCount: failed.length, failed };
};

// ── heavy (cached) ────────────────────────────────────────────────────────────

// `bin` is what proves the software is installed; `proc` is what proves it is
// running. They differ more often than not — postgresql is detected through its
// client `psql` but runs as `postgres`.
const SERVICE_PROBES: {
  name: string;
  kind: Service['kind'];
  bin: string;
  proc: string;
  version: string[];
}[] = [
  { name: 'nginx', kind: 'web', bin: 'nginx', proc: 'nginx', version: ['nginx', '-v'] },
  { name: 'caddy', kind: 'web', bin: 'caddy', proc: 'caddy', version: ['caddy', 'version'] },
  { name: 'apache2', kind: 'web', bin: 'apache2', proc: 'apache2', version: ['apache2', '-v'] },
  { name: 'httpd', kind: 'web', bin: 'httpd', proc: 'httpd', version: ['httpd', '-v'] },
  { name: 'haproxy', kind: 'proxy', bin: 'haproxy', proc: 'haproxy', version: ['haproxy', '-v'] },
  {
    name: 'traefik',
    kind: 'proxy',
    bin: 'traefik',
    proc: 'traefik',
    version: ['traefik', 'version'],
  },
  {
    name: 'postgresql',
    kind: 'database',
    bin: 'psql',
    proc: 'postgres',
    version: ['psql', '--version'],
  },
  {
    name: 'mysql',
    kind: 'database',
    bin: 'mysqld',
    proc: 'mysqld',
    version: ['mysqld', '--version'],
  },
  {
    name: 'mariadb',
    kind: 'database',
    bin: 'mariadbd',
    proc: 'mariadbd',
    version: ['mariadbd', '--version'],
  },
  {
    name: 'mongod',
    kind: 'database',
    bin: 'mongod',
    proc: 'mongod',
    version: ['mongod', '--version'],
  },
  {
    name: 'redis',
    kind: 'cache',
    bin: 'redis-server',
    proc: 'redis-server',
    version: ['redis-server', '--version'],
  },
  {
    name: 'memcached',
    kind: 'cache',
    bin: 'memcached',
    proc: 'memcached',
    version: ['memcached', '-h'],
  },
];

/**
 * supervisord, pm2's closest peer: a userland process manager that owns its own
 * programs and its own log files, and that systemd knows nothing about.
 *
 * @remarks
 * `supervisorctl status` exits non-zero when any program is not RUNNING, so its
 * output is parsed regardless of the exit code — an all-stopped supervisor is
 * still a supervisor worth reporting.
 */
const collectSupervisor = (): { supervisor?: { version?: string; programs?: string[] } } => {
  if (!has('supervisorctl')) return {};
  const version = sh(['supervisorctl', 'version']) || undefined;
  const programs: string[] = [];
  for (const line of sh(['supervisorctl', 'status']).split('\n')) {
    const name = line.trim().split(/\s+/)[0];
    if (name) programs.push(name);
  }
  return { supervisor: { version, programs: programs.slice(0, 300) } };
};

const collectServices = (): Service[] => {
  const services: Service[] = [];
  for (const p of SERVICE_PROBES) {
    if (!has(p.bin)) continue;
    const raw = sh(p.version).split('\n')[0] ?? '';
    const version = raw.match(/\d+\.\d+(\.\d+)?/)?.[0];
    // Running counts, whatever supervises it — systemd, pm2, supervisor, a
    // container, or nothing at all.
    const active = isActive(p.name) || isActive(`${p.name}.service`) || isRunning(p.proc);
    let detail: string | undefined;
    if (p.name === 'nginx')
      detail = sh(['nginx', '-t']).includes('successful') ? 'config valid' : undefined;
    services.push({ name: p.name, kind: p.kind, active, version, detail });
  }
  return services.slice(0, 80);
};

const collectSelfHosted = (): string[] => {
  const found: string[] = [];
  if (bash('test -d /data/coolify && echo 1') === '1') found.push('coolify');
  if (has('docker') && sh(['docker', 'ps', '--format', '{{.Names}}']).includes('portainer'))
    found.push('portainer');
  if (has('dokku')) found.push('dokku');
  return found;
};

const collectKubernetes = (): HostFacts['kubernetes'] => {
  const kube = has('k3s') ? ['k3s', 'kubectl'] : has('kubectl') ? ['kubectl'] : null;
  if (!kube) return undefined;
  const nodes = Number.parseInt(
    sh([...kube, 'get', 'nodes', '--no-headers'])
      .split('\n')
      .filter(Boolean)
      .length.toString(),
    10,
  );
  const pods = sh([...kube, 'get', 'pods', '-A', '--no-headers'])
    .split('\n')
    .filter(Boolean).length;
  return { flavor: has('k3s') ? 'k3s' : 'k8s', nodes: nodes || undefined, pods: pods || undefined };
};

const collectDomains = (): string[] => {
  const set = new Set<string>();
  const fqdn = sh(['hostname', '-f']);
  if (fqdn && fqdn.includes('.') && !/^\d/.test(fqdn)) set.add(fqdn);
  // nginx server_name directives
  const ng = bash(
    `grep -rhoE 'server_name[[:space:]]+[^;]+' /etc/nginx 2>/dev/null | sed 's/server_name//'`,
  );
  for (const tok of ng.split(/\s+/)) {
    const d = tok.replace(/;$/, '').trim();
    if (d && d !== '_' && d.includes('.') && !d.startsWith('*') && !/^\d+\.\d+\.\d+\.\d+$/.test(d))
      set.add(d);
  }
  return [...set].slice(0, 120);
};

const collectTls = (): TlsCert[] => {
  const certs: TlsCert[] = [];
  // Let's Encrypt live certs (local, cheap) — the common case.
  const live = bash('ls -d /etc/letsencrypt/live/*/ 2>/dev/null').split('\n').filter(Boolean);
  for (const dir of live.slice(0, 60)) {
    const domain = dir.replace(/\/$/, '').split('/').pop() ?? '';
    const end = bash(
      `openssl x509 -enddate -noout -in ${dir}fullchain.pem 2>/dev/null | cut -d= -f2`,
    );
    if (!end) continue;
    const notAfter = new Date(end);
    if (Number.isNaN(notAfter.getTime())) continue;
    certs.push({
      domain,
      notAfter: notAfter.toISOString(),
      daysLeft: Math.round((notAfter.getTime() - Date.now()) / 86400000),
    });
  }
  return certs;
};

const collectHealth = (): HostFacts['health'] => {
  const rebootRequired =
    bash('test -f /var/run/reboot-required && echo 1') === '1' ||
    (has('needs-restarting') && sh(['needs-restarting', '-r']).includes('Reboot is required'));
  let firewall = 'none';
  let firewallActive = false;
  if (has('ufw')) {
    firewall = 'ufw';
    firewallActive = sh(['ufw', 'status']).includes('Status: active');
  } else if (isActive('firewalld')) {
    firewall = 'firewalld';
    firewallActive = true;
  } else if (has('nft') && bash('nft list ruleset 2>/dev/null | head -1').length > 0) {
    firewall = 'nftables';
    firewallActive = true;
  }
  const timeSync = sh(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value']) === 'yes';
  return { rebootRequired, firewall, firewallActive, timeSync };
};

let heavyCache: Partial<HostFacts> | null = null;
let heavyCacheAt = 0;
const FACTS_TTL_MS = 15 * 60 * 1000;

const collectHeavy = (): Partial<HostFacts> => {
  const services = collectServices();
  const dockerVersion = has('docker')
    ? sh(['docker', 'version', '-f', '{{.Server.Version}}']) || undefined
    : undefined;
  const domains = collectDomains();
  return {
    docker: has('docker') ? { version: dockerVersion } : undefined,
    services,
    selfHosted: collectSelfHosted(),
    kubernetes: collectKubernetes(),
    domains,
    tls: collectTls(),
    health: collectHealth(),
  };
};

// Merge live facts (every call) with the cached heavy facts (refreshed slowly).
// Linux only for now; other platforms simply report no facts.
export const getFacts = (): HostFacts => {
  if (process.platform !== 'linux') return {};
  const now = Date.now();
  if (!heavyCache || now - heavyCacheAt > FACTS_TTL_MS) {
    heavyCache = collectHeavy();
    heavyCacheAt = now;
  }
  const containers = collectContainers();
  const { pm2, processes } = collectPm2();
  // Live, like pm2: a program can be added or stopped between two heavy passes.
  const { supervisor } = collectSupervisor();
  const cron = collectCron();
  const systemd = collectFailedUnits();
  const running = containers.filter((c) => c.state === 'running').length;
  return {
    collectedAt: new Date().toISOString(),
    ...heavyCache,
    docker:
      containers.some((c) => c.runtime === 'docker') || heavyCache.docker
        ? { ...heavyCache.docker, running, total: containers.length }
        : undefined,
    containers: containers.length ? containers : undefined,
    pm2,
    supervisor,
    processes: processes?.length ? processes : undefined,
    systemd,
    cron: cron.length ? cron : undefined,
  };
};
