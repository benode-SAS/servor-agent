import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configPath, loadConfig, saveConfig } from './config';

const valid = {
  serverId: '019ecd37-5979-72ce-8960-fc9454880973',
  secret: 'enrollment-secret',
  apiUrl: 'https://api.servor.benode.fr',
};

let dir: string;
let file: string;
const previousEnv = process.env.SERVOR_CONFIG;

const write = (contents: unknown) => {
  writeFileSync(file, typeof contents === 'string' ? contents : JSON.stringify(contents));
};

describe('config', () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'servor-agent-config-'));
    file = join(dir, 'config.json');
    process.env.SERVOR_CONFIG = file;
  });

  afterEach(() => {
    if (previousEnv === undefined) delete process.env.SERVOR_CONFIG;
    else process.env.SERVOR_CONFIG = previousEnv;
    rmSync(dir, { recursive: true, force: true });
  });

  test('configPath honours SERVOR_CONFIG', () => {
    expect(configPath()).toBe(file);
  });

  test('a trailing slash is stripped from apiUrl', () => {
    write({ ...valid, apiUrl: 'https://api.servor.benode.fr/' });
    expect(loadConfig().apiUrl).toBe('https://api.servor.benode.fr');
  });

  test('a missing interval defaults to 60 seconds', () => {
    write(valid);
    expect(loadConfig().intervalSeconds).toBe(60);
  });

  test.each([
    [1, 15],
    [15, 15],
    [16, 16],
    [299, 299],
    [300, 300],
    [3600, 300],
  ])('an interval of %i is clamped to %i', (given, expected) => {
    write({ ...valid, intervalSeconds: given });
    expect(loadConfig().intervalSeconds).toBe(expected);
  });

  test('tunnel mode is preserved', () => {
    write({ ...valid, mode: 'tunnel' });
    expect(loadConfig().mode).toBe('tunnel');
  });

  test.each(['push', 'shell', '', 'TUNNEL'])('an unrecognised mode %p degrades to push', (mode) => {
    write({ ...valid, mode });
    expect(loadConfig().mode).toBe('push');
  });

  test('a missing mode degrades to push', () => {
    write(valid);
    expect(loadConfig().mode).toBe('push');
  });

  test('the optional user is carried through, and absent when unset', () => {
    write({ ...valid, user: 'deploy' });
    expect(loadConfig().user).toBe('deploy');
    write(valid);
    expect(loadConfig().user).toBeUndefined();
  });

  test('a missing format version defaults to 1', () => {
    write(valid);
    expect(loadConfig().version).toBe('1');
  });

  test.each([
    'serverId',
    'secret',
    'apiUrl',
  ] as const)('a config without %s refuses to load', (field) => {
    const partial: Record<string, unknown> = { ...valid };
    delete partial[field];
    write(partial);
    expect(() => loadConfig()).toThrow(/invalid config/);
  });

  test('an empty required field refuses to load', () => {
    write({ ...valid, secret: '' });
    expect(() => loadConfig()).toThrow(/invalid config/);
  });

  test('malformed JSON refuses to load', () => {
    write('{ this is not json');
    expect(() => loadConfig()).toThrow();
  });

  test('a missing file refuses to load', () => {
    expect(() => loadConfig()).toThrow();
  });

  test('saveConfig merges into the file without dropping other fields', () => {
    write({ ...valid, mode: 'tunnel', user: 'deploy', intervalSeconds: 60 });
    saveConfig({ intervalSeconds: 120 });
    const onDisk = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
    expect(onDisk).toEqual({
      ...valid,
      mode: 'tunnel',
      user: 'deploy',
      intervalSeconds: 120,
    });
  });

  test('saveConfig leaves no temporary file behind', () => {
    write(valid);
    saveConfig({ intervalSeconds: 90 });
    expect(existsSync(`${file}.tmp`)).toBe(false);
  });

  test('a failed save is swallowed rather than killing the agent', () => {
    process.env.SERVOR_CONFIG = join(dir, 'no-such-directory', 'config.json');
    expect(() => saveConfig({ intervalSeconds: 120 })).not.toThrow();
  });

  test('a failed save leaves the previous config untouched', () => {
    write({ ...valid, intervalSeconds: 60 });
    const unwritable = join(dir, 'locked');
    mkdirSync(unwritable);
    process.env.SERVOR_CONFIG = unwritable;
    expect(() => saveConfig({ intervalSeconds: 120 })).not.toThrow();
    process.env.SERVOR_CONFIG = file;
    expect(loadConfig().intervalSeconds).toBe(60);
  });
});
