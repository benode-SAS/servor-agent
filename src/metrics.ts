import { readFileSync } from 'node:fs';
import { getFacts } from './facts';

/**
 * One metrics sample as sent to the control plane.
 *
 * @remarks
 * Read-only host telemetry: nothing here is derived from a command the control
 * plane sent. `specs` holds what rarely changes (distro, kernel, CPU model,
 * total RAM), `metrics` what is sampled each round. Both are loose maps because
 * the set of keys differs per platform and the server validates them; a missing
 * key means "not collectable here", never zero.
 *
 * `os` only admits the two families the wire format knows. macOS reports
 * `linux` here and carries its real identity in `specs.osFamily`.
 */
export type Payload = {
  /** Payload format version, bumped when the shape changes. */
  v: 1;
  agentVersion: string;
  os: 'linux' | 'windows';
  hostname?: string;
  collectedAt?: string;
  specs: Record<string, unknown>;
  metrics: Record<string, unknown>;
  facts?: Record<string, unknown>;
};

/** Run a command and return its trimmed stdout, or `''` if it fails at all. */
const sh = (cmd: string[]): string => {
  try {
    const p = Bun.spawnSync(cmd, { stdout: 'pipe', stderr: 'ignore' });
    return new TextDecoder().decode(p.stdout).trim();
  } catch {
    return '';
  }
};
/** Read a file (typically under /proc), returning `''` rather than throwing. */
const readProc = (p: string): string => {
  try {
    return readFileSync(p, 'utf8');
  } catch {
    return '';
  }
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** Parse a float, mapping anything unparseable to `undefined` so it is omitted. */
const num = (s: string | undefined) => {
  const n = Number.parseFloat(s ?? '');
  return Number.isFinite(n) ? n : undefined;
};

/** Cumulative jiffies since boot, for one CPU line of /proc/stat. */
export type CpuSnap = { busy: number; total: number };

/**
 * Turn /proc/stat into cumulative busy/total counters, keyed `cpu`, `cpu0`, …
 *
 * @remarks
 * The kernel exposes counters, not a rate, so a percentage only exists between
 * two snapshots (see {@link collectLinux}). Idle is `idle + iowait`; busy is
 * user, nice, system, irq, softirq and steal. The trailing guest counters are
 * left out because the kernel already counts them inside user time — adding
 * them would inflate busy above total.
 */
export const parseCpuLines = (raw: string): Map<string, CpuSnap> => {
  const map = new Map<string, CpuSnap>();
  for (const line of raw.split('\n')) {
    if (!line.startsWith('cpu')) continue;
    const f = line.trim().split(/\s+/);
    const key = f[0];
    if (!key) continue;
    const v = f.slice(1).map((x) => Number.parseInt(x, 10) || 0);
    const idle = (v[3] ?? 0) + (v[4] ?? 0);
    const busy = (v[0] ?? 0) + (v[1] ?? 0) + (v[2] ?? 0) + (v[5] ?? 0) + (v[6] ?? 0) + (v[7] ?? 0);
    map.set(key, { busy, total: busy + idle });
  }
  return map;
};

/** Overall and per-core usage between two /proc/stat snapshots. */
export type CpuUsage = {
  /** Percentage across all cores, or `null` when the `cpu` line is missing from either snapshot. */
  cpuPercent: number | null;
  cpus: Array<{ core: number; percent: number }>;
};

/**
 * Turn two /proc/stat snapshots into a usage percentage per CPU line.
 *
 * @remarks
 * A zero delta — the counters did not move, or the same snapshot was passed
 * twice — is reported as 0 rather than dividing by it. A core present in the
 * second snapshot but not the first is left out entirely: there is no interval
 * to measure it over, and reporting it as idle would be a lie.
 */
export const computeCpuUsage = (s1: Map<string, CpuSnap>, s2: Map<string, CpuSnap>): CpuUsage => {
  const pct = (k: string) => {
    const a = s1.get(k);
    const b = s2.get(k);
    if (!a || !b) return null;
    const dt = b.total - a.total;
    return dt > 0 ? Math.round(((b.busy - a.busy) / dt) * 1000) / 10 : 0;
  };
  const cpus: Array<{ core: number; percent: number }> = [];
  for (const k of s2.keys()) {
    if (k === 'cpu') continue;
    const p = pct(k);
    if (p != null) cpus.push({ core: Number.parseInt(k.slice(3), 10), percent: p });
  }
  cpus.sort((a, b) => a.core - b.core);
  return { cpuPercent: pct('cpu'), cpus };
};

/**
 * Read /proc/meminfo into its kB values.
 *
 * @returns Only the keys actually present. A key the kernel did not report is
 * absent from the map rather than zero, so a caller can tell "no swap
 * configured" from "swap is empty".
 */
export const parseMeminfo = (raw: string): Map<string, number> => {
  const map = new Map<string, number>();
  for (const line of raw.split('\n')) {
    const m = line.match(/^([^\s:]+):\s+(\d+)/);
    if (m?.[1] && m[2]) map.set(m[1], Number.parseInt(m[2], 10));
  }
  return map;
};

/**
 * Total the receive and transmit byte counters across real interfaces.
 *
 * @remarks
 * Loopback is excluded: traffic a host sends to itself is not network usage,
 * and on a busy box it dwarfs the counters anyone actually wants to see.
 */
export const parseNetDev = (raw: string): { rx: number; tx: number } => {
  let rx = 0;
  let tx = 0;
  for (const line of raw.split('\n').slice(2)) {
    const [iface, rest] = line.split(':');
    if (!rest || iface?.trim() === 'lo') continue;
    const f = rest.trim().split(/\s+/);
    rx += Number.parseInt(f[0] ?? '0', 10) || 0;
    tx += Number.parseInt(f[8] ?? '0', 10) || 0;
  }
  return { rx, tx };
};

/** One filesystem as reported by `df -Pk`, converted to gigabytes. */
export type DiskEntry = { mount: string; totalGb: number; usedGb: number; usedPct: number };

/** Every filesystem `df` listed, plus their totals. */
export type DfSummary = { disks: DiskEntry[]; totalGb: number; usedGb: number };

/**
 * Parse `df -Pk` output into per-filesystem sizes and their totals.
 *
 * @param mountIndex - Column the mount point starts at: 5 on Linux, 8 on macOS,
 * whose `df` inserts the inode columns before it.
 *
 * @remarks
 * The mount point is everything from that column to the end of the line, not
 * just the next field: `df` does not escape spaces, so a mount point that
 * contains one would otherwise be truncated at the first space and reported
 * under a name no operator would recognise. A line that is too short, or whose
 * mount point is not an absolute path, is skipped rather than parsed into
 * nonsense.
 */
export const parseDf = (raw: string, mountIndex: number): DfSummary => {
  const disks: DiskEntry[] = [];
  let totalGb = 0;
  let usedGb = 0;
  for (const line of raw.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length <= mountIndex) continue;
    const mount = f.slice(mountIndex).join(' ');
    if (!mount.startsWith('/')) continue;
    const tg = (Number.parseInt(f[1] ?? '', 10) || 0) / 1048576;
    const ug = (Number.parseInt(f[2] ?? '', 10) || 0) / 1048576;
    disks.push({
      mount,
      totalGb: Math.round(tg * 100) / 100,
      usedGb: Math.round(ug * 100) / 100,
      usedPct: tg > 0 ? Math.round((ug / tg) * 1000) / 10 : 0,
    });
    totalGb += tg;
    usedGb += ug;
  }
  return { disks, totalGb, usedGb };
};

/** One process from `ps -eo pid=,pcpu=,pmem=,comm=`. */
export type ProcessEntry = {
  pid: number;
  cpuPct: number | undefined;
  memPct: number | undefined;
  name: string;
};

/**
 * Take the busiest processes off `ps` output.
 *
 * @remarks
 * The command name is rejoined from the remaining fields, so a name containing
 * a space survives. A line without a usable pid is dropped, which also disposes
 * of the empty string an empty `ps` output splits into.
 */
export const parsePs = (raw: string, limit = 5): ProcessEntry[] =>
  raw
    .split('\n')
    .slice(0, limit)
    .map((l) => {
      const f = l.trim().split(/\s+/);
      return {
        pid: Number.parseInt(f[0] ?? '0', 10) || 0,
        cpuPct: num(f[1]),
        memPct: num(f[2]),
        name: f.slice(3).join(' ').slice(0, 60),
      };
    })
    .filter((p) => p.pid > 0);

/**
 * Read /etc/os-release into its key/value pairs, with quotes stripped.
 *
 * @returns Only the keys the file actually declares; a distro that omits
 * `VERSION_ID` yields no entry for it rather than an empty one.
 */
export const parseOsRelease = (raw: string): Map<string, string> => {
  const map = new Map<string, string>();
  for (const line of raw.split('\n')) {
    const eq = line.indexOf('=');
    if (eq <= 0 || line.trimStart().startsWith('#')) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    map.set(key, value.replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1'));
  }
  return map;
};

/**
 * Sample a Linux host, mostly from /proc plus a few coreutils.
 *
 * @remarks
 * Blocks for one second between the two /proc/stat reads: CPU usage is a
 * difference between counters, so there is no instantaneous value to read. The
 * loopback interface is excluded from network totals, and pseudo-filesystems
 * (tmpfs, devtmpfs, overlay, squashfs) from disk totals, so the numbers
 * describe real hardware rather than the kernel's bookkeeping.
 */
type ListeningPort = { port: number; proto?: 'tcp' | 'udp'; process?: string; address?: string };

// Parse `ss -tulnpH` (tcp+udp, listening, numeric, no header, with process).
// Columns: Netid State Recv-Q Send-Q Local:Port Peer:Port [users:(("proc",…))].
const parseListeningPorts = (raw: string): ListeningPort[] => {
  const byKey = new Map<string, ListeningPort>();
  for (const line of raw.split('\n')) {
    const f = line.trim().split(/\s+/);
    if (f.length < 5) continue;
    const proto = f[0] === 'tcp' ? 'tcp' : f[0] === 'udp' ? 'udp' : undefined;
    const local = f[4] ?? '';
    const m = local.match(/:(\d+)$/);
    if (!m?.[1]) continue;
    const port = Number.parseInt(m[1], 10);
    if (!Number.isFinite(port)) continue;
    const address = local.slice(0, local.length - m[0].length) || undefined;
    const proc = line.match(/users:\(\("([^"]+)"/)?.[1];
    const key = `${proto ?? ''}:${port}`;
    if (!byKey.has(key)) byKey.set(key, { port, proto, address, process: proc });
  }
  return [...byKey.values()].sort((a, b) => a.port - b.port).slice(0, 200);
};

const collectLinux = async (version: string): Promise<Payload> => {
  const s1 = parseCpuLines(readProc('/proc/stat'));
  await sleep(1000);
  const s2 = parseCpuLines(readProc('/proc/stat'));
  const { cpuPercent, cpus } = computeCpuUsage(s1, s2);

  const mem = parseMeminfo(readProc('/proc/meminfo'));
  const memVal = (key: string) => mem.get(key) ?? 0;
  const memTotal = memVal('MemTotal');
  const memAvail = memVal('MemAvailable');
  const cached = memVal('Cached') + memVal('Buffers');
  const swapTotal = memVal('SwapTotal');
  const swapFree = memVal('SwapFree');

  const [load1, load5, load15] = readProc('/proc/loadavg').split(/\s+/).map(num);
  const uptime = num(readProc('/proc/uptime').split(/\s+/)[0]);

  const { rx, tx } = parseNetDev(readProc('/proc/net/dev'));

  const df = sh(['df', '-Pk', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'overlay', '-x', 'squashfs']);
  const { disks, totalGb: diskTotalGb, usedGb: diskUsedGb } = parseDf(df, 5);

  const topProcesses = parsePs(sh(['ps', '-eo', 'pid=,pcpu=,pmem=,comm=', '--sort=-pcpu']));

  const osRelease = parseOsRelease(readProc('/etc/os-release'));
  const procCount = sh(['bash', '-c', 'ls -d /proc/[0-9]* 2>/dev/null | wc -l']);

  return {
    v: 1,
    agentVersion: version,
    os: 'linux',
    hostname: sh(['hostname']),
    collectedAt: new Date().toISOString(),
    specs: {
      osFamily: 'linux',
      osDistro: osRelease.get('NAME'),
      osVersion: osRelease.get('VERSION_ID'),
      kernelVersion: sh(['uname', '-r']),
      architecture: sh(['uname', '-m']),
      cpuCount: Number.parseInt(sh(['nproc']), 10) || cpus.length || undefined,
      cpuModel: readProc('/proc/cpuinfo')
        .match(/model name\s*:\s*(.+)/)?.[1]
        ?.trim(),
      ramTotalMb: Math.round(memTotal / 1024),
      diskTotalGb: Math.round(diskTotalGb * 100) / 100,
      listeningPorts: parseListeningPorts(sh(['ss', '-tulnpH'])),
    },
    metrics: {
      cpuPercent,
      load1,
      load5,
      load15,
      ramUsedMb: Math.round((memTotal - memAvail) / 1024),
      ramFreeMb: Math.round(memAvail / 1024),
      ramCachedMb: Math.round(cached / 1024),
      swapTotalMb: Math.round(swapTotal / 1024),
      swapUsedMb: Math.round((swapTotal - swapFree) / 1024),
      diskTotalGb: Math.round(diskTotalGb * 100) / 100,
      diskUsedGb: Math.round(diskUsedGb * 100) / 100,
      netRxBytes: rx,
      netTxBytes: tx,
      uptimeSeconds: uptime ? Math.round(uptime) : undefined,
      procCount: Number.parseInt(procCount, 10) || undefined,
      cpus,
      disks,
      topProcesses,
    },
    facts: getFacts(),
  };
};

/**
 * Sample a macOS host, best-effort.
 *
 * @remarks
 * macOS is a development convenience, not a supported production target: there
 * is no per-core breakdown, no memory or network detail and no uptime, because
 * getting them reliably would mean shelling out to far more tooling than this
 * is worth. CPU usage comes from a single `top` sample rather than a delta.
 */
const collectDarwin = (version: string): Payload => {
  const cores = Number.parseInt(sh(['sysctl', '-n', 'hw.ncpu']), 10) || undefined;
  const memTotalB = Number.parseInt(sh(['sysctl', '-n', 'hw.memsize']), 10) || 0;
  const cpuLine = sh(['bash', '-c', "top -l 1 -n 0 | grep 'CPU usage'"]);
  const cpuUser = num(cpuLine.match(/([\d.]+)% user/)?.[1]) ?? 0;
  const cpuSys = num(cpuLine.match(/([\d.]+)% sys/)?.[1]) ?? 0;
  const [load1, load5, load15] = sh(['sysctl', '-n', 'vm.loadavg'])
    .replace(/[{}]/g, '')
    .trim()
    .split(/\s+/)
    .map(num);

  const { disks, totalGb: diskTotalGb, usedGb: diskUsedGb } = parseDf(sh(['df', '-Pk']), 8);

  return {
    v: 1,
    agentVersion: version,
    os: 'linux',
    hostname: sh(['hostname']),
    collectedAt: new Date().toISOString(),
    specs: {
      osFamily: 'darwin',
      osDistro: 'macOS',
      osVersion: sh(['sw_vers', '-productVersion']),
      kernelVersion: sh(['uname', '-r']),
      architecture: sh(['uname', '-m']),
      cpuCount: cores,
      ramTotalMb: Math.round(memTotalB / 1048576),
      diskTotalGb: Math.round(diskTotalGb * 100) / 100,
    },
    metrics: {
      cpuPercent: Math.round((cpuUser + cpuSys) * 10) / 10,
      load1,
      load5,
      load15,
      diskTotalGb: Math.round(diskTotalGb * 100) / 100,
      diskUsedGb: Math.round(diskUsedGb * 100) / 100,
      uptimeSeconds: undefined,
      disks,
    },
  };
};

/**
 * PowerShell script that collects the whole Windows payload in one process.
 *
 * @remarks
 * A single script rather than one spawn per metric: process creation is
 * expensive on Windows and CIM queries are slow enough that a dozen of them
 * would dominate the sampling interval. `__V__` is substituted with the agent
 * version before execution; it is the only interpolation, and its value is a
 * compile-time constant, never anything received over the network.
 */
const PS_SCRIPT = `
$o=Get-CimInstance Win32_OperatingSystem
$cpu=(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$cores=(Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
$disks=@(); $dt=0.0; $du=0.0
foreach($d in Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"){ $tg=[math]::Round($d.Size/1GB,2); $ug=[math]::Round(($d.Size-$d.FreeSpace)/1GB,2); $pct=if($d.Size-gt0){[math]::Round((($d.Size-$d.FreeSpace)/$d.Size)*100,1)}else{0}; $disks+=@{mount=$d.DeviceID;totalGb=$tg;usedGb=$ug;usedPct=$pct}; $dt+=$tg; $du+=$ug }
$cpus=@(); try { Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor | Where-Object {$_.Name -ne '_Total'} | ForEach-Object { $cpus+=@{core=[int]$_.Name;percent=[double]$_.PercentProcessorTime} } } catch {}
$ports=@(); try { Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Group-Object LocalPort | Select-Object -First 200 | ForEach-Object { $c=$_.Group[0]; $pn=''; try{$pn=(Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName}catch{}; $ports+=@{port=[int]$c.LocalPort;proto='tcp';address=[string]$c.LocalAddress;process=$pn} } } catch {}
@{ v=1; agentVersion="__V__"; os="windows"; hostname=$env:COMPUTERNAME; collectedAt=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
  specs=@{ osFamily="windows"; osDistro=$o.Caption; osVersion=$o.Version; kernelVersion=$o.BuildNumber; architecture=$env:PROCESSOR_ARCHITECTURE; cpuCount=[int]$cores; ramTotalMb=[int][math]::Round($o.TotalVisibleMemorySize/1024); diskTotalGb=$dt; listeningPorts=$ports };
  metrics=@{ cpuPercent=[double]$cpu; ramUsedMb=[int][math]::Round(($o.TotalVisibleMemorySize-$o.FreePhysicalMemory)/1024); ramFreeMb=[int][math]::Round($o.FreePhysicalMemory/1024); swapTotalMb=[int][math]::Round($o.TotalVirtualMemorySize/1024); swapUsedMb=[int][math]::Round(($o.TotalVirtualMemorySize-$o.FreeVirtualMemory)/1024); diskTotalGb=$dt; diskUsedGb=$du; uptimeSeconds=[int]((Get-Date)-$o.LastBootUpTime).TotalSeconds; procCount=(Get-Process).Count; cpus=$cpus; disks=$disks }
} | ConvertTo-Json -Depth 6 -Compress
`;

/**
 * Sample a Windows host by running {@link PS_SCRIPT} and parsing its JSON.
 *
 * @returns An empty-but-valid payload if PowerShell fails or prints something
 * unparseable, so a broken sample skips a round instead of stopping the loop.
 */
const collectWindows = (version: string): Payload => {
  const out = sh(['powershell', '-NoProfile', '-Command', PS_SCRIPT.replace('__V__', version)]);
  try {
    return JSON.parse(out) as Payload;
  } catch {
    return { v: 1, agentVersion: version, os: 'windows', specs: {}, metrics: {} };
  }
};

/**
 * Collect one host sample using the collector for the current platform.
 *
 * @param version - Agent build version, stamped into the payload so the control
 * plane knows which code produced these numbers.
 * @remarks
 * Takes roughly a second on Linux, where CPU usage is measured across two
 * snapshots. Everything read here is local host state; the control plane cannot
 * influence what is collected.
 */
export const collect = async (version: string): Promise<Payload> => {
  if (process.platform === 'win32') return collectWindows(version);
  if (process.platform === 'darwin') return collectDarwin(version);
  return collectLinux(version);
};
