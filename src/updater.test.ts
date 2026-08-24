import { afterEach, describe, expect, mock, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { existsSync, statSync } from 'node:fs';
import type { AgentConfig } from './config';
import { platformKey, stageUpdate } from './updater';

const cfg: AgentConfig = {
  serverId: '019ecd37-5979-72ce-8960-fc9454880973',
  secret: 'enrollment-secret',
  apiUrl: 'https://api.servor.benode.fr',
  intervalSeconds: 60,
  mode: 'tunnel',
  version: '1',
};

const RUNNING = '1.0.11';
const BINARY = 'not really a binary, but it hashes just the same';
const DIGEST = createHash('sha256').update(Buffer.from(BINARY)).digest('hex');

const realFetch = globalThis.fetch;

/** Answer the version endpoint with `info` and the binary endpoint with `body`. */
const respondWith = (info: unknown, body: string | null = BINARY, versionOk = true) =>
  mock((input: unknown) => {
    const url = String(input);
    if (url.endsWith('/agent/version')) {
      return Promise.resolve(
        versionOk
          ? new Response(JSON.stringify(info), { status: 200 })
          : new Response('nope', { status: 503 }),
      );
    }
    return Promise.resolve(
      body === null ? new Response('gone', { status: 404 }) : new Response(body, { status: 200 }),
    );
  });

describe('platformKey', () => {
  test.each([
    ['linux', 'x64', 'linux-x64'],
    ['linux', 'arm64', 'linux-arm64'],
    ['darwin', 'x64', 'darwin-x64'],
    ['darwin', 'arm64', 'darwin-arm64'],
    ['win32', 'x64', 'windows-x64'],
    ['win32', 'arm64', 'windows-arm64'],
  ])('%s/%s maps to %s', (platform, arch, expected) => {
    expect(platformKey(platform, arch)).toBe(expected);
  });

  test.each(['freebsd', 'openbsd', 'aix', 'sunos'])('%s is treated as linux', (platform) => {
    expect(platformKey(platform, 'x64')).toBe('linux-x64');
  });

  test.each(['ia32', 'ppc64', 'riscv64', 's390x'])('%s is treated as x64', (arch) => {
    expect(platformKey('linux', arch)).toBe('linux-x64');
  });

  test('the running host always maps to one of the published builds', () => {
    expect(platformKey()).toMatch(/^(linux|darwin|windows)-(x64|arm64)$/);
  });
});

describe('stageUpdate refuses everything it cannot verify', () => {
  const plat = platformKey();
  const binary = statSync(process.execPath);

  /** The refusal paths all return before the swap, so the running binary is untouched. */
  const expectNothingWritten = () => {
    expect(existsSync(`${process.execPath}.new`)).toBe(false);
    const now = statSync(process.execPath);
    expect(now.size).toBe(binary.size);
    expect(now.mtimeMs).toBe(binary.mtimeMs);
  };

  const run = async (fetchMock: ReturnType<typeof mock>) => {
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    return stageUpdate(cfg, RUNNING);
  };

  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  test('a version endpoint that is not ok stages nothing', async () => {
    expect(await run(respondWith({}, BINARY, false))).toBe(false);
    expectNothingWritten();
  });

  test('a manifest advertising no version stages nothing', async () => {
    expect(await run(respondWith({ builds: {} }))).toBe(false);
    expectNothingWritten();
  });

  test('the version already running stages nothing', async () => {
    const info = { version: RUNNING, builds: { [plat]: { sha256: DIGEST, signature: 'x' } } };
    expect(await run(respondWith(info))).toBe(false);
    expectNothingWritten();
  });

  test('a download that fails stages nothing', async () => {
    expect(await run(respondWith({ version: '9.9.9' }, null))).toBe(false);
    expectNothingWritten();
  });

  test('no advertised digest for this platform stages nothing', async () => {
    const info = { version: '9.9.9', builds: { 'some-other-platform': { sha256: DIGEST } } };
    expect(await run(respondWith(info))).toBe(false);
    expectNothingWritten();
  });

  test('a digest that does not match the downloaded bytes stages nothing', async () => {
    const info = { version: '9.9.9', builds: { [plat]: { sha256: 'f'.repeat(64) } } };
    expect(await run(respondWith(info))).toBe(false);
    expectNothingWritten();
  });

  test('a matching digest with no signature stages nothing', async () => {
    const info = { version: '9.9.9', builds: { [plat]: { sha256: DIGEST } } };
    expect(await run(respondWith(info))).toBe(false);
    expectNothingWritten();
  });

  test('a signature that does not verify against the embedded key stages nothing', async () => {
    const info = {
      version: '9.9.9',
      builds: { [plat]: { sha256: DIGEST, signature: Buffer.alloc(64).toString('base64') } },
    };
    expect(await run(respondWith(info))).toBe(false);
    expectNothingWritten();
  });

  test('an unusable signature is an abort, not a thrown error', async () => {
    const info = {
      version: '9.9.9',
      builds: { [plat]: { sha256: DIGEST, signature: 'not-a-signature' } },
    };
    expect(await run(respondWith(info))).toBe(false);
    expectNothingWritten();
  });

  test('a network failure is an abort, not a thrown error', async () => {
    const failing = mock(() => Promise.reject(new Error('ECONNREFUSED')));
    expect(await run(failing)).toBe(false);
    expectNothingWritten();
  });

  test('a manifest that is not JSON is an abort, not a thrown error', async () => {
    const broken = mock(() => Promise.resolve(new Response('<html>502</html>', { status: 200 })));
    expect(await run(broken)).toBe(false);
    expectNothingWritten();
  });
});
