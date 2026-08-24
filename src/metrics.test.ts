import { describe, expect, test } from 'bun:test';
import {
  computeCpuUsage,
  parseCpuLines,
  parseDf,
  parseMeminfo,
  parseNetDev,
  parseOsRelease,
  parsePs,
} from './metrics';

const PROC_STAT_1 = `cpu  100 0 50 850 0 0 0 0 0 0
cpu0 50 0 25 425 0 0 0 0 0 0
cpu1 50 0 25 425 0 0 0 0 0 0
intr 123456 0 0
ctxt 987654
`;

const PROC_STAT_2 = `cpu  200 0 100 1700 0 0 0 0 0 0
cpu0 150 0 75 775 0 0 0 0 0 0
cpu1 50 0 25 925 0 0 0 0 0 0
intr 223456 0 0
ctxt 1087654
`;

describe('parseCpuLines', () => {
  test('busy and total are accumulated per cpu line', () => {
    const snap = parseCpuLines(PROC_STAT_1);
    expect(snap.get('cpu')).toEqual({ busy: 150, total: 1000 });
    expect(snap.get('cpu0')).toEqual({ busy: 75, total: 500 });
  });

  test('non-cpu lines are ignored', () => {
    const snap = parseCpuLines(PROC_STAT_1);
    expect([...snap.keys()]).toEqual(['cpu', 'cpu0', 'cpu1']);
  });

  test('iowait counts as idle, not as busy', () => {
    const snap = parseCpuLines('cpu 100 0 0 800 100 0 0 0 0 0');
    expect(snap.get('cpu')).toEqual({ busy: 100, total: 1000 });
  });

  test('guest jiffies are left out, since the kernel already counts them in user', () => {
    const withGuest = parseCpuLines('cpu 100 0 50 850 0 0 0 0 9999 9999');
    expect(withGuest.get('cpu')).toEqual({ busy: 150, total: 1000 });
  });

  test('unparseable fields count as zero rather than poisoning the total', () => {
    const snap = parseCpuLines('cpu  100 - 50 850 0 0 0 0');
    expect(snap.get('cpu')).toEqual({ busy: 150, total: 1000 });
  });

  test('an empty /proc/stat yields no snapshot at all', () => {
    expect(parseCpuLines('').size).toBe(0);
  });
});

describe('computeCpuUsage', () => {
  test('two snapshots give the percentage busy over the interval', () => {
    const usage = computeCpuUsage(parseCpuLines(PROC_STAT_1), parseCpuLines(PROC_STAT_2));
    expect(usage.cpuPercent).toBe(15);
  });

  test('each core is reported separately and sorted by core number', () => {
    const usage = computeCpuUsage(parseCpuLines(PROC_STAT_1), parseCpuLines(PROC_STAT_2));
    expect(usage.cpus).toEqual([
      { core: 0, percent: 30 },
      { core: 1, percent: 0 },
    ]);
  });

  test('a zero delta is 0 percent, never a division by zero', () => {
    const same = parseCpuLines(PROC_STAT_1);
    const usage = computeCpuUsage(same, parseCpuLines(PROC_STAT_1));
    expect(usage.cpuPercent).toBe(0);
    expect(usage.cpus).toEqual([
      { core: 0, percent: 0 },
      { core: 1, percent: 0 },
    ]);
  });

  test('a missing cpu line yields null rather than a made-up number', () => {
    const usage = computeCpuUsage(new Map(), parseCpuLines(PROC_STAT_2));
    expect(usage.cpuPercent).toBeNull();
    expect(usage.cpus).toEqual([]);
  });

  test('a core that appeared only in the second snapshot is left out', () => {
    const first = parseCpuLines('cpu 100 0 50 850 0 0 0 0\ncpu0 50 0 25 425 0 0 0 0');
    const second = parseCpuLines(
      'cpu 200 0 100 1700 0 0 0 0\ncpu0 150 0 75 775 0 0 0 0\ncpu1 10 0 5 85 0 0 0 0',
    );
    expect(computeCpuUsage(first, second).cpus).toEqual([{ core: 0, percent: 30 }]);
  });
});

const MEMINFO = `MemTotal:       16316456 kB
MemFree:          123456 kB
MemAvailable:    8158228 kB
Buffers:          204800 kB
Cached:          4096000 kB
Active(anon):    1000000 kB
`;

describe('parseMeminfo', () => {
  test('every declared key is read in kB', () => {
    const mem = parseMeminfo(MEMINFO);
    expect(mem.get('MemTotal')).toBe(16316456);
    expect(mem.get('MemAvailable')).toBe(8158228);
    expect(mem.get('Cached')).toBe(4096000);
  });

  test('a key with parentheses in its name is still read', () => {
    expect(parseMeminfo(MEMINFO).get('Active(anon)')).toBe(1000000);
  });

  test('a key the kernel did not report is absent, not zero', () => {
    const mem = parseMeminfo(MEMINFO);
    expect(mem.has('SwapTotal')).toBe(false);
    expect(mem.get('SwapTotal')).toBeUndefined();
  });

  test('a malformed line is skipped rather than throwing', () => {
    const mem = parseMeminfo('MemTotal: not a number\nHugePages_Total:       0\n\ngarbage\n');
    expect(mem.has('MemTotal')).toBe(false);
    expect(mem.get('HugePages_Total')).toBe(0);
  });
});

const NET_DEV = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 999999999    1000    0    0    0     0          0         0 999999999    1000    0    0    0     0       0          0
  eth0:      2000      20    0    0    0     0          0         0      3000      30    0    0    0     0       0          0
 wlan0:      1000      10    0    0    0     0          0         0       500       5    0    0    0     0       0          0
`;

describe('parseNetDev', () => {
  test('counters are summed across interfaces', () => {
    expect(parseNetDev(NET_DEV)).toEqual({ rx: 3000, tx: 3500 });
  });

  test('loopback is excluded so a host talking to itself is not counted as traffic', () => {
    const withoutLoopback = NET_DEV.split('\n')
      .filter((l) => !l.includes('lo:'))
      .join('\n');
    expect(parseNetDev(withoutLoopback)).toEqual(parseNetDev(NET_DEV));
  });

  test('the two header lines are not mistaken for interfaces', () => {
    expect(parseNetDev('Inter-|   Receive |  Transmit\n face |bytes\n')).toEqual({ rx: 0, tx: 0 });
  });

  test('a line without a colon is skipped rather than throwing', () => {
    expect(parseNetDev(`${NET_DEV}not an interface line\n`)).toEqual({ rx: 3000, tx: 3500 });
  });
});

const DF_LINUX = `Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/sda1         41943040  20971520  20971520      50% /
/dev/sdb1         10485760   1048576   9437184      10% /mnt/my backup disk
tmpfs                 1024         0      1024       0% not-an-absolute-path
truncated line
`;

describe('parseDf', () => {
  test('sizes are converted from 1K blocks to gigabytes', () => {
    const { disks } = parseDf(DF_LINUX, 5);
    expect(disks[0]).toEqual({ mount: '/', totalGb: 40, usedGb: 20, usedPct: 50 });
  });

  test('a mount point containing spaces keeps its whole name', () => {
    const { disks } = parseDf(DF_LINUX, 5);
    expect(disks[1]?.mount).toBe('/mnt/my backup disk');
  });

  test('totals cover every filesystem that parsed', () => {
    const { totalGb, usedGb } = parseDf(DF_LINUX, 5);
    expect(totalGb).toBe(50);
    expect(usedGb).toBe(21);
  });

  test('a malformed or non-absolute line is skipped rather than throwing', () => {
    expect(parseDf(DF_LINUX, 5).disks).toHaveLength(2);
  });

  test('the header line is never parsed as a filesystem', () => {
    expect(parseDf('Filesystem 1024-blocks Used Available Capacity Mounted on\n', 5).disks).toEqual(
      [],
    );
  });

  test('a filesystem of zero size is 0 percent used, not a division by zero', () => {
    const { disks } = parseDf('header\nnone 0 0 0 - /proc/sys\n', 5);
    expect(disks[0]?.usedPct).toBe(0);
  });

  test('the macOS column layout is read from its own mount index', () => {
    const macos = `Filesystem 1024-blocks Used Available Capacity iused ifree %iused Mounted on
/dev/disk1s1 41943040 20971520 20971520 50% 1000 4294966279 0% /System/Volumes/Data
`;
    expect(parseDf(macos, 8).disks).toEqual([
      { mount: '/System/Volumes/Data', totalGb: 40, usedGb: 20, usedPct: 50 },
    ]);
  });
});

describe('parsePs', () => {
  test('pid, cpu, memory and command name are read off each line', () => {
    const entries = parsePs(' 1234  12.5  3.1 postgres\n 5678   0.0  0.5 sshd\n');
    expect(entries).toEqual([
      { pid: 1234, cpuPct: 12.5, memPct: 3.1, name: 'postgres' },
      { pid: 5678, cpuPct: 0, memPct: 0.5, name: 'sshd' },
    ]);
  });

  test('a command name containing a space survives', () => {
    expect(parsePs('1234 1.0 1.0 Google Chrome Helper\n')[0]?.name).toBe('Google Chrome Helper');
  });

  test('only the first few processes are kept', () => {
    const raw = Array.from({ length: 20 }, (_, i) => `${i + 1} 1.0 1.0 proc${i}`).join('\n');
    expect(parsePs(raw)).toHaveLength(5);
  });

  test('a line with no usable pid is dropped', () => {
    expect(parsePs('\nheader junk here\n4321 1.0 1.0 nginx\n')).toEqual([
      { pid: 4321, cpuPct: 1, memPct: 1, name: 'nginx' },
    ]);
  });

  test('an unparseable percentage is undefined rather than zero', () => {
    const [entry] = parsePs('1234 - - weird\n');
    expect(entry?.cpuPct).toBeUndefined();
    expect(entry?.memPct).toBeUndefined();
  });

  test('an empty ps output yields no processes', () => {
    expect(parsePs('')).toEqual([]);
  });
});

const OS_RELEASE = `PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
`;

describe('parseOsRelease', () => {
  test('quoted and unquoted values are both read', () => {
    const os = parseOsRelease(OS_RELEASE);
    expect(os.get('NAME')).toBe('Ubuntu');
    expect(os.get('VERSION_ID')).toBe('24.04');
    expect(os.get('ID')).toBe('ubuntu');
  });

  test('a value containing spaces and parentheses is kept whole', () => {
    expect(parseOsRelease(OS_RELEASE).get('VERSION')).toBe('24.04.1 LTS (Noble Numbat)');
  });

  test('NAME is not confused with PRETTY_NAME', () => {
    expect(parseOsRelease(OS_RELEASE).get('NAME')).not.toContain('LTS');
  });

  test('a key the distro does not declare is undefined, not empty', () => {
    expect(parseOsRelease(OS_RELEASE).get('BUILD_ID')).toBeUndefined();
  });

  test('comments and blank lines are skipped rather than parsed', () => {
    const os = parseOsRelease('# a comment=with an equals sign\n\nID=alpine\n');
    expect([...os.keys()]).toEqual(['ID']);
  });

  test('a missing /etc/os-release yields nothing rather than throwing', () => {
    expect(parseOsRelease('').size).toBe(0);
  });
});
