import { readFileSync } from 'node:fs';

export type Payload = {
  v: 1;
  agentVersion: string;
  os: 'linux' | 'windows';
  hostname?: string;
  collectedAt?: string;
  specs: Record<string, unknown>;
  metrics: Record<string, unknown>;
};

const sh = (cmd: string[]): string => {
  try {
    const p = Bun.spawnSync(cmd, { stdout: 'pipe', stderr: 'ignore' });
    return new TextDecoder().decode(p.stdout).trim();
  } catch {
    return '';
  }
};
const readProc = (p: string): string => {
  try {
    return readFileSync(p, 'utf8');
  } catch {
    return '';
  }
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const num = (s: string | undefined) => {
  const n = Number.parseFloat(s ?? '');
  return Number.isFinite(n) ? n : undefined;
};

// ── Linux ───────────────────────────────────────────────────────────────────
type CpuSnap = { busy: number; total: number };
const parseCpuLines = (raw: string): Map<string, CpuSnap> => {
  const map = new Map<string, CpuSnap>();
  for (const line of raw.split('\n')) {
    if (!line.startsWith('cpu')) continue;
    const f = line.trim().split(/\s+/);
    const key = f[0]!;
    const v = f.slice(1).map((x) => Number.parseInt(x, 10) || 0);
    const idle = (v[3] ?? 0) + (v[4] ?? 0);
    const busy = (v[0] ?? 0) + (v[1] ?? 0) + (v[2] ?? 0) + (v[5] ?? 0) + (v[6] ?? 0) + (v[7] ?? 0);
    map.set(key, { busy, total: busy + idle });
  }
  return map;
};

const collectLinux = async (version: string): Promise<Payload> => {
  const s1 = parseCpuLines(readProc('/proc/stat'));
  await sleep(1000);
  const s2 = parseCpuLines(readProc('/proc/stat'));
  const pct = (k: string) => {
    const a = s1.get(k);
    const b = s2.get(k);
    if (!a || !b) return null;
    const dt = b.total - a.total;
    return dt > 0 ? Math.round(((b.busy - a.busy) / dt) * 1000) / 10 : 0;
  };
  const cpuPercent = pct('cpu');
  const cpus: Array<{ core: number; percent: number }> = [];
  for (const k of s2.keys()) {
    if (k === 'cpu') continue;
    const p = pct(k);
    if (p != null) cpus.push({ core: Number.parseInt(k.slice(3), 10), percent: p });
  }
  cpus.sort((a, b) => a.core - b.core);

  const mem = readProc('/proc/meminfo');
  const memVal = (key: string) => num(mem.match(new RegExp(`^${key}:\\s+(\\d+)`, 'm'))?.[1]) ?? 0;
  const memTotal = memVal('MemTotal');
  const memAvail = memVal('MemAvailable');
  const cached = memVal('Cached') + memVal('Buffers');
  const swapTotal = memVal('SwapTotal');
  const swapFree = memVal('SwapFree');

  const [load1, load5, load15] = readProc('/proc/loadavg').split(/\s+/).map(num);
  const uptime = num(readProc('/proc/uptime').split(/\s+/)[0]);

  let rx = 0;
  let tx = 0;
  for (const line of readProc('/proc/net/dev').split('\n').slice(2)) {
    const [iface, rest] = line.split(':');
    if (!rest || iface?.trim() === 'lo') continue;
    const f = rest.trim().split(/\s+/);
    rx += Number.parseInt(f[0] ?? '0', 10) || 0;
    tx += Number.parseInt(f[8] ?? '0', 10) || 0;
  }

  const df = sh(['df', '-Pk', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'overlay', '-x', 'squashfs']);
  const disks: Array<{ mount: string; totalGb: number; usedGb: number; usedPct: number }> = [];
  let diskTotalGb = 0;
  let diskUsedGb = 0;
  for (const line of df.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 6) continue;
    const tg = (Number.parseInt(f[1]!, 10) || 0) / 1048576;
    const ug = (Number.parseInt(f[2]!, 10) || 0) / 1048576;
    disks.push({
      mount: f[5]!,
      totalGb: Math.round(tg * 100) / 100,
      usedGb: Math.round(ug * 100) / 100,
      usedPct: tg > 0 ? Math.round((ug / tg) * 1000) / 10 : 0,
    });
    diskTotalGb += tg;
    diskUsedGb += ug;
  }

  const psOut = sh(['ps', '-eo', 'pid=,pcpu=,pmem=,comm=', '--sort=-pcpu']);
  const topProcesses = psOut
    .split('\n')
    .slice(0, 5)
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

  const osRelease = readProc('/etc/os-release');
  const orVal = (k: string) => osRelease.match(new RegExp(`^${k}="?([^"\\n]*)"?`, 'm'))?.[1];
  const procCount = sh(['bash', '-c', 'ls -d /proc/[0-9]* 2>/dev/null | wc -l']);

  return {
    v: 1,
    agentVersion: version,
    os: 'linux',
    hostname: sh(['hostname']),
    collectedAt: new Date().toISOString(),
    specs: {
      osFamily: 'linux',
      osDistro: orVal('NAME'),
      osVersion: orVal('VERSION_ID'),
      kernelVersion: sh(['uname', '-r']),
      architecture: sh(['uname', '-m']),
      cpuCount: Number.parseInt(sh(['nproc']), 10) || cpus.length || undefined,
      cpuModel: readProc('/proc/cpuinfo')
        .match(/model name\s*:\s*(.+)/)?.[1]
        ?.trim(),
      ramTotalMb: Math.round(memTotal / 1024),
      diskTotalGb: Math.round(diskTotalGb * 100) / 100,
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
  };
};

// ── macOS (best-effort) ───────────────────────────────────────────────────────
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

  const df = sh(['df', '-Pk']);
  const disks: Array<{ mount: string; totalGb: number; usedGb: number; usedPct: number }> = [];
  let diskTotalGb = 0;
  let diskUsedGb = 0;
  for (const line of df.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 9 || !f[8]?.startsWith('/')) continue;
    const tg = (Number.parseInt(f[1]!, 10) || 0) / 1048576;
    const ug = (Number.parseInt(f[2]!, 10) || 0) / 1048576;
    disks.push({
      mount: f[8]!,
      totalGb: Math.round(tg * 100) / 100,
      usedGb: Math.round(ug * 100) / 100,
      usedPct: tg > 0 ? Math.round((ug / tg) * 1000) / 10 : 0,
    });
    diskTotalGb += tg;
    diskUsedGb += ug;
  }

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

// ── Windows (best-effort, PowerShell) ────────────────────────────────────────
const PS_SCRIPT = `
$o=Get-CimInstance Win32_OperatingSystem
$cpu=(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$cores=(Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
$disks=@(); $dt=0.0; $du=0.0
foreach($d in Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"){ $tg=[math]::Round($d.Size/1GB,2); $ug=[math]::Round(($d.Size-$d.FreeSpace)/1GB,2); $pct=if($d.Size-gt0){[math]::Round((($d.Size-$d.FreeSpace)/$d.Size)*100,1)}else{0}; $disks+=@{mount=$d.DeviceID;totalGb=$tg;usedGb=$ug;usedPct=$pct}; $dt+=$tg; $du+=$ug }
$cpus=@(); try { Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor | Where-Object {$_.Name -ne '_Total'} | ForEach-Object { $cpus+=@{core=[int]$_.Name;percent=[double]$_.PercentProcessorTime} } } catch {}
@{ v=1; agentVersion="__V__"; os="windows"; hostname=$env:COMPUTERNAME; collectedAt=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
  specs=@{ osFamily="windows"; osDistro=$o.Caption; osVersion=$o.Version; kernelVersion=$o.BuildNumber; architecture=$env:PROCESSOR_ARCHITECTURE; cpuCount=[int]$cores; ramTotalMb=[int][math]::Round($o.TotalVisibleMemorySize/1024); diskTotalGb=$dt };
  metrics=@{ cpuPercent=[double]$cpu; ramUsedMb=[int][math]::Round(($o.TotalVisibleMemorySize-$o.FreePhysicalMemory)/1024); ramFreeMb=[int][math]::Round($o.FreePhysicalMemory/1024); swapTotalMb=[int][math]::Round($o.TotalVirtualMemorySize/1024); swapUsedMb=[int][math]::Round(($o.TotalVirtualMemorySize-$o.FreeVirtualMemory)/1024); diskTotalGb=$dt; diskUsedGb=$du; uptimeSeconds=[int]((Get-Date)-$o.LastBootUpTime).TotalSeconds; procCount=(Get-Process).Count; cpus=$cpus; disks=$disks }
} | ConvertTo-Json -Depth 6 -Compress
`;

const collectWindows = (version: string): Payload => {
  const out = sh(['powershell', '-NoProfile', '-Command', PS_SCRIPT.replace('__V__', version)]);
  try {
    return JSON.parse(out) as Payload;
  } catch {
    return { v: 1, agentVersion: version, os: 'windows', specs: {}, metrics: {} };
  }
};

export const collect = async (version: string): Promise<Payload> => {
  if (process.platform === 'win32') return collectWindows(version);
  if (process.platform === 'darwin') return collectDarwin(version);
  return collectLinux(version);
};
