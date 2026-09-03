import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
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
  /** Who supervises it — only `systemd` makes a `systemctl` action meaningful. */
  supervisor?: 'systemd' | 'other';
  /** The unit that answered `is-active`, which is what an action must target. */
  unit?: string;
};
type MountInfo = {
  mount: string;
  device: string;
  fstype?: string;
  usedKb: number;
  availKb: number;
  /** Inodes run out independently of space — the failure df -h cannot show. */
  inodesUsedPct?: number;
};
type SmartInfo = { device: string; healthy?: boolean };
type StorageInfo = { mounts: MountInfo[]; smart: SmartInfo[] };
type PackageUpdates = {
  manager: 'apt' | 'dnf';
  total: number;
  security: number;
  packages: string[];
};
type SshKey = { type: string; comment?: string; fingerprint: string };
type UserAccount = {
  name: string;
  uid: number;
  shell?: string;
  sudo: boolean;
  keys: SshKey[];
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
  users?: UserAccount[];
  updates?: PackageUpdates;
  storage?: StorageInfo;
  systemd?: { failedCount?: number; failed?: string[] };
  cron?: CronEntry[];
  kubernetes?: { flavor?: string; nodes?: number; pods?: number };
  tls?: TlsCert[];
  domains?: string[];
  health?: {
    rebootRequired?: boolean;
    firewall?: string;
    firewallActive?: boolean;
    firewallRules?: string[];
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
    const unit = isActive(p.name)
      ? p.name
      : isActive(`${p.name}.service`)
        ? `${p.name}.service`
        : null;
    const active = unit !== null || isRunning(p.proc);
    // Which unit answered, so the dashboard knows whether `systemctl` speaks for
    // this service at all. Offering a restart button for a pm2-managed process
    // would build a command that fails every single time.
    const supervisor = unit ? 'systemd' : active ? 'other' : undefined;
    let detail: string | undefined;
    if (p.name === 'nginx')
      detail = sh(['nginx', '-t']).includes('successful') ? 'config valid' : undefined;
    services.push({
      name: p.name,
      kind: p.kind,
      active,
      version,
      detail,
      supervisor,
      unit: unit ?? undefined,
    });
  }
  return services.slice(0, 80);
};

/**
 * Login accounts on the machine, and how many keys can open each.
 *
 * @remarks
 * **No key material leaves the host.** Only the type, the comment and the
 * SHA-256 fingerprint travel — which is what an operator reads to recognise a
 * key anyway. A public key is not a secret, but shipping thousands of them in
 * every facts push would be both wasteful and an invitation to start treating
 * this array as a key store.
 *
 * `uid >= 1000` plus root is the conventional line between people and system
 * accounts. It is a heuristic, and a deliberately conservative one: a service
 * account that happens to sit above 1000 shows up, which is far better than
 * hiding a real account that sits below it.
 */
const collectUsers = (): UserAccount[] => {
  const passwd = (() => {
    try {
      return readFileSync('/etc/passwd', 'utf8');
    } catch {
      return '';
    }
  })();
  if (!passwd) return [];

  // Members of the groups that grant root. Read once rather than per user.
  const sudoers = new Set<string>();
  for (const group of ['sudo', 'wheel', 'admin']) {
    const line = sh(['getent', 'group', group]);
    for (const name of (line.split(':')[3] ?? '').split(',')) {
      if (name.trim()) sudoers.add(name.trim());
    }
  }

  const out: UserAccount[] = [];
  for (const raw of passwd.split('\n')) {
    const [name, , uidStr, , , home, shell] = raw.split(':');
    if (!name || !uidStr) continue;
    const uid = Number.parseInt(uidStr, 10);
    if (!Number.isFinite(uid)) continue;
    if (uid !== 0 && uid < 1000) continue;
    // A user whose shell cannot log in is not an access path worth listing.
    if (shell && /(nologin|false)$/.test(shell)) continue;

    out.push({
      name,
      uid,
      shell: shell || undefined,
      sudo: uid === 0 || sudoers.has(name),
      keys: home ? readAuthorizedKeys(home) : [],
    });
    if (out.length >= 60) break;
  }
  return out;
};

/**
 * Pending package updates, and how many of them are security fixes.
 *
 * @remarks
 * Read-only, and it must stay that way: `apt-get update` writes to the package
 * cache and takes a lock, which would fight with the operator's own session.
 * The lists here are whatever the last refresh left behind, which is exactly
 * what `apt list --upgradable` reports and what the machine itself acts on.
 *
 * The security count is what matters. "142 updates pending" is background
 * noise on any Debian box; "3 security updates pending" is a decision.
 */
/**
 * Storage beyond the percentage: mounts, inodes, and disk health.
 *
 * @remarks
 * The disk-usage percentage already reported misses the two failures that
 * actually take a machine down. **Inodes** run out independently of space — a
 * directory full of tiny session files fills the table while `df -h` still
 * reads 40%, and every write then fails with ENOSPC on a disk that looks
 * half-empty. And a **failing drive** announces itself in SMART hours or days
 * before it stops answering, which is the only warning anyone gets.
 *
 * SMART needs root and `smartctl`; where either is missing the field is simply
 * absent, like every other probe here.
 */
const collectStorage = (): StorageInfo | undefined => {
  const mounts: MountInfo[] = [];
  // `-PT` gives POSIX single-line output plus the filesystem type; without -P a
  // long device name wraps onto its own line and every column shifts by one.
  for (const line of sh(['df', '-PT', '-x', 'tmpfs', '-x', 'devtmpfs']).split('\n').slice(1)) {
    const p = line.trim().split(/\s+/);
    if (p.length < 7) continue;
    const [device, fstype, , used, avail, , mount] = p as string[];
    if (!mount || !device) continue;
    mounts.push({
      mount,
      device,
      fstype,
      usedKb: Number.parseInt(used ?? '0', 10) || 0,
      availKb: Number.parseInt(avail ?? '0', 10) || 0,
    });
    if (mounts.length >= 40) break;
  }

  // Inodes come from a second call rather than being parsed out of the first:
  // `df` cannot report blocks and inodes in one invocation.
  for (const line of sh(['df', '-PiT', '-x', 'tmpfs', '-x', 'devtmpfs']).split('\n').slice(1)) {
    const p = line.trim().split(/\s+/);
    if (p.length < 7) continue;
    const mount = p[6];
    const pct = Number.parseInt((p[5] ?? '').replace('%', ''), 10);
    const target = mounts.find((m) => m.mount === mount);
    if (target && Number.isFinite(pct)) target.inodesUsedPct = pct;
  }

  const smart: SmartInfo[] = [];
  if (has('smartctl')) {
    for (const dev of sh(['lsblk', '-dno', 'PATH,TYPE'])
      .split('\n')
      .filter((l) => l.trim().endsWith('disk'))
      .map((l) => (l.trim().split(/\s+/)[0] ?? '').trim())
      .filter(Boolean)
      .slice(0, 12)) {
      const out = sh(['smartctl', '-H', dev], 8000);
      if (!out) continue;
      // "PASSED" (ATA) or "OK" (NVMe). Anything else, including an unreadable
      // answer, is reported as unknown rather than quietly as healthy.
      const healthy = /PASSED|result:\s*OK/i.test(out)
        ? true
        : /FAILED|FAILING/i.test(out)
          ? false
          : undefined;
      smart.push({ device: dev, healthy });
    }
  }

  if (mounts.length === 0 && smart.length === 0) return undefined;
  return { mounts, smart };
};

const collectUpdates = (): PackageUpdates | undefined => {
  if (has('apt')) {
    const raw = bash('apt list --upgradable 2>/dev/null');
    const lines = raw
      .split('\n')
      .filter((l) => l.includes('/') && !l.startsWith('Listing'))
      .map((l) => l.trim());
    const security = lines.filter((l) => /-security/i.test(l)).length;
    return {
      manager: 'apt',
      total: lines.length,
      security,
      // Package names only — a full apt line carries versions and origins that
      // add length without telling the operator anything they act on.
      packages: lines.map((l) => (l.split('/')[0] ?? '').trim()).filter(Boolean).slice(0, 60),
    };
  }
  if (has('dnf')) {
    // `check-update` exits 100 when updates exist, which is not a failure.
    const raw = bash('dnf -q check-update 2>/dev/null || true');
    const lines = raw.split('\n').filter((l) => /^\S+\.\S+\s+\S+\s+\S+$/.test(l.trim()));
    const security = Number.parseInt(
      bash('dnf -q updateinfo list security 2>/dev/null | wc -l') || '0',
      10,
    );
    return {
      manager: 'dnf',
      total: lines.length,
      security: Number.isFinite(security) ? security : 0,
      packages: lines.map((l) => (l.trim().split(/\s+/)[0] ?? '').trim()).filter(Boolean).slice(0, 60),
    };
  }
  return undefined;
};

/** Fingerprints of the keys that can open an account. Never the keys. */
const readAuthorizedKeys = (home: string): SshKey[] => {
  const path = `${home}/.ssh/authorized_keys`;
  let content = '';
  try {
    content = readFileSync(path, 'utf8');
  } catch {
    return [];
  }
  const keys: SshKey[] = [];
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(/\s+/);
    // `type base64 comment`, possibly preceded by options. Find the type.
    const i = parts.findIndex((p) => p.startsWith('ssh-') || p.startsWith('ecdsa-'));
    if (i === -1) continue;
    const type = parts[i] as string;
    const blob = parts[i + 1];
    if (!blob) continue;
    const comment = parts.slice(i + 2).join(' ') || undefined;
    keys.push({
      type,
      comment: comment?.slice(0, 120),
      // The same fingerprint `ssh-keygen -lf` prints, so an operator can match
      // it against what they hold without us shipping the key itself.
      fingerprint: `SHA256:${createHash('sha256').update(Buffer.from(blob, 'base64')).digest('base64').replace(/=+$/, '')}`,
    });
    if (keys.length >= 30) break;
  }
  return keys;
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
  return {
    rebootRequired,
    firewall,
    firewallActive,
    firewallRules: collectFirewallRules(firewall),
    timeSync,
  };
};

/**
 * The rules the firewall is actually enforcing, as lines to display.
 *
 * @remarks
 * Kept as opaque text rather than parsed into a structure. ufw, firewalld and
 * nftables describe rules in three unrelated grammars, and a parser that got
 * one of them subtly wrong would show an operator a permissive rule as
 * restrictive — worse than showing them the tool's own output, which they
 * already know how to read.
 *
 * Capped hard: a busy nftables ruleset runs to thousands of lines, and this
 * travels in every facts push.
 */
const collectFirewallRules = (kind: string): string[] => {
  const raw =
    kind === 'ufw'
      ? sh(['ufw', 'status', 'numbered'])
      : kind === 'firewalld'
        ? sh(['firewall-cmd', '--list-all'])
        : kind === 'nftables'
          ? bash('nft list ruleset 2>/dev/null')
          : '';
  if (!raw) return [];
  return raw
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .slice(0, 80)
    .map((l) => l.slice(0, 200));
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
    // Heavy side: reading every home's authorized_keys is filesystem work that
    // has no business running on the fast metrics cadence.
    users: collectUsers(),
    updates: collectUpdates(),
    storage: collectStorage(),
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
