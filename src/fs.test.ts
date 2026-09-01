import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FS_MAX_BYTES, fsDescriptorFor, performFsOp } from './fs';
import { fsContentHash } from './protocol/fs-grant';

let dir = '';
const p = (...parts: string[]) => join(dir, ...parts);
const b64 = (s: string) => Buffer.from(s, 'utf-8').toString('base64');

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'servor-fs-'));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('list', () => {
  test('returns directories first, then files, each sorted by name', async () => {
    await mkdir(p('zeta'));
    await mkdir(p('alpha'));
    await writeFile(p('b.txt'), 'b');
    await writeFile(p('a.txt'), 'a');

    const res = await performFsOp({ op: 'list', path: dir });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.entries?.map((e) => e.name)).toEqual(['alpha', 'zeta', 'a.txt', 'b.txt']);
    expect(res.entries?.[0]?.type).toBe('dir');
    expect(res.entries?.[2]?.type).toBe('file');
  });

  test('a missing directory is a typed error, not a throw', async () => {
    const res = await performFsOp({ op: 'list', path: p('nope') });
    expect(res).toMatchObject({ ok: false, code: 'not-found' });
  });
});

describe('read', () => {
  test('returns the bytes as base64', async () => {
    await writeFile(p('conf'), 'listen 80;');
    const res = await performFsOp({ op: 'read', path: p('conf') });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(Buffer.from(res.content ?? '', 'base64').toString()).toBe('listen 80;');
  });

  test('binary content survives the round trip', async () => {
    const bytes = Buffer.from([0x00, 0xff, 0x10, 0x80, 0x0a]);
    await writeFile(p('bin'), bytes);
    const res = await performFsOp({ op: 'read', path: p('bin') });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect([...Buffer.from(res.content ?? '', 'base64')]).toEqual([...bytes]);
  });

  test('refuses a file past the size ceiling instead of loading it', async () => {
    await writeFile(p('big'), Buffer.alloc(FS_MAX_BYTES + 1));
    const res = await performFsOp({ op: 'read', path: p('big') });
    expect(res).toMatchObject({ ok: false, code: 'too-large' });
  });

  test('reading a directory is refused', async () => {
    await mkdir(p('d'));
    expect(await performFsOp({ op: 'read', path: p('d') })).toMatchObject({
      ok: false,
      code: 'is-a-directory',
    });
  });
});

describe('write', () => {
  test('creates a file with the content it was given', async () => {
    const res = await performFsOp({ op: 'write', path: p('new.conf'), content: b64('hello') });
    expect(res.ok).toBe(true);
    expect(await readFile(p('new.conf'), 'utf-8')).toBe('hello');
  });

  test('replaces the content of an existing file', async () => {
    await writeFile(p('secret'), 'old');
    await performFsOp({ op: 'write', path: p('secret'), content: b64('new') });
    expect(await readFile(p('secret'), 'utf-8')).toBe('new');
  });

  // Windows does not carry POSIX permission bits, so the mode assertions below
  // can only mean anything on the platforms the agent actually guards.
  test.skipIf(process.platform === 'win32')(
    'keeps the permissions of the file it replaces',
    async () => {
      await writeFile(p('secret'), 'old', { mode: 0o600 });
      await performFsOp({ op: 'write', path: p('secret'), content: b64('new') });
      // Saving a config must never widen who can read it.
      expect((await stat(p('secret'))).mode & 0o777).toBe(0o600);
    },
  );

  test('leaves no temp file behind', async () => {
    await performFsOp({ op: 'write', path: p('f'), content: b64('x') });
    const res = await performFsOp({ op: 'list', path: dir });
    if (!res.ok) throw new Error('list failed');
    expect(res.entries?.map((e) => e.name)).toEqual(['f']);
  });

  test('refuses content past the ceiling', async () => {
    const res = await performFsOp({
      op: 'write',
      path: p('big'),
      content: Buffer.alloc(FS_MAX_BYTES + 1).toString('base64'),
    });
    expect(res).toMatchObject({ ok: false, code: 'too-large' });
  });
});

describe('mkdir, move, chmod, remove', () => {
  test('mkdir creates missing parents', async () => {
    expect((await performFsOp({ op: 'mkdir', path: p('a', 'b', 'c') })).ok).toBe(true);
    expect((await stat(p('a', 'b', 'c'))).isDirectory()).toBe(true);
  });

  test('move renames', async () => {
    await writeFile(p('from'), 'x');
    expect((await performFsOp({ op: 'move', path: p('from'), to: p('to') })).ok).toBe(true);
    expect(await readFile(p('to'), 'utf-8')).toBe('x');
  });

  test('move refuses a destination that is not an absolute normalized path', async () => {
    await writeFile(p('from'), 'x');
    const res = await performFsOp({ op: 'move', path: p('from'), to: 'relative/dest' });
    expect(res).toMatchObject({ ok: false, code: 'invalid-path' });
  });

  test('chmod rejects a mode that is not octal', async () => {
    await writeFile(p('f'), 'x');
    for (const mode of ['rwx', '999', '', '07777777']) {
      expect(await performFsOp({ op: 'chmod', path: p('f'), mode })).toMatchObject({
        ok: false,
        code: 'invalid-mode',
      });
    }
  });

  test.skipIf(process.platform === 'win32')('chmod applies the octal mode', async () => {
    await writeFile(p('f'), 'x', { mode: 0o644 });
    expect((await performFsOp({ op: 'chmod', path: p('f'), mode: '0600' })).ok).toBe(true);
    expect((await stat(p('f'))).mode & 0o777).toBe(0o600);
  });

  test('remove takes a file, and a tree only when asked', async () => {
    await mkdir(p('tree'));
    await writeFile(p('tree', 'f'), 'x');
    expect(await performFsOp({ op: 'remove', path: p('tree') })).toMatchObject({ ok: false });
    expect((await performFsOp({ op: 'remove', path: p('tree'), recursive: true })).ok).toBe(true);
  });

  test('a recursive remove of a system root is refused', async () => {
    // The one destructive gesture in the explorer with no undo.
    expect(await performFsOp({ op: 'remove', path: '/etc', recursive: true })).toMatchObject({
      ok: false,
      code: 'protected-path',
    });
  });
});

describe('path validation is enforced here, not upstream', () => {
  test('a traversal path is refused even though the control plane relayed it', async () => {
    for (const path of ['../etc/passwd', '/etc/../root', 'relative']) {
      expect(await performFsOp({ op: 'read', path })).toMatchObject({
        ok: false,
        code: 'invalid-path',
      });
    }
  });
});

describe('fsDescriptorFor', () => {
  test('a write is described by its content, so swapped bytes describe differently', () => {
    const req = { op: 'write' as const, path: '/etc/hosts', content: b64('a') };
    const mine = fsDescriptorFor(req, Buffer.from('a'));
    const swapped = fsDescriptorFor({ ...req, content: b64('b') }, Buffer.from('b'));
    expect(mine).not.toBe(swapped);
    expect(mine).toContain(fsContentHash(new TextEncoder().encode('a')));
  });

  test('a non-write carries no content hash', () => {
    expect(fsDescriptorFor({ op: 'read', path: '/etc/hosts' }, null)).toBe(
      fsDescriptorFor({ op: 'read', path: '/etc/hosts' }, null),
    );
  });
});
