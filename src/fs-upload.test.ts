import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  chunkBytes,
  chunkDescriptorFor,
  type FsChunkRequest,
  resetUploads,
  runFsChunkOp,
} from './fs-upload';
import { FS_CHUNK_MAX_BYTES, FS_UPLOAD_MAX_BYTES } from './protocol/fs-grant';

let dir = '';
const p = (...parts: string[]) => join(dir, ...parts);
const b64 = (s: string) => Buffer.from(s, 'utf-8').toString('base64');

const req = (over: Partial<FsChunkRequest>): FsChunkRequest => ({
  op: 'write-begin',
  uploadId: '',
  path: p('big.bin'),
  offset: 0,
  content: '',
  totalBytes: 0,
  mode: '',
  ...over,
});

const run = (over: Partial<FsChunkRequest>) => {
  const r = req(over);
  return runFsChunkOp(r, chunkBytes(r));
};

/** Begin an upload and hand back the id the agent minted. */
const begin = async (totalBytes: number, over: Partial<FsChunkRequest> = {}) => {
  const res = await run({ op: 'write-begin', totalBytes, ...over });
  expect(res.ok).toBe(true);
  if (!res.ok) throw new Error('begin failed');
  return res.uploadId as string;
};

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'servor-upload-'));
});

afterEach(async () => {
  await resetUploads();
  await rm(dir, { recursive: true, force: true });
});

describe('a whole file, one chunk at a time', () => {
  test('the pieces land in order and the file appears at the end', async () => {
    const id = await begin(6);
    await run({ op: 'write-chunk', uploadId: id, offset: 0, content: b64('abc') });
    await run({ op: 'write-chunk', uploadId: id, offset: 3, content: b64('def') });
    const done = await run({ op: 'write-commit', uploadId: id, totalBytes: 6 });

    expect(done.ok).toBe(true);
    expect(await readFile(p('big.bin'), 'utf-8')).toBe('abcdef');
  });

  // The whole point of the temp file: a transfer that dies leaves the old
  // version intact rather than a truncated one.
  test('nothing appears at the destination before the commit', async () => {
    const id = await begin(6);
    await run({ op: 'write-chunk', uploadId: id, offset: 0, content: b64('abc') });
    await expect(stat(p('big.bin'))).rejects.toThrow();
  });

  test('an existing file is only replaced on commit', async () => {
    await writeFile(p('big.bin'), 'old');
    const id = await begin(3);
    await run({ op: 'write-chunk', uploadId: id, offset: 0, content: b64('new') });
    expect(await readFile(p('big.bin'), 'utf-8')).toBe('old');
    await run({ op: 'write-commit', uploadId: id, totalBytes: 3 });
    expect(await readFile(p('big.bin'), 'utf-8')).toBe('new');
  });

  // Windows carries no POSIX permission bits, so there is nothing to preserve.
  test.skipIf(process.platform === 'win32')(
    'the mode of the file being replaced is carried over',
    async () => {
      await writeFile(p('big.bin'), 'old', { mode: 0o600 });
      const id = await begin(3);
      await run({ op: 'write-chunk', uploadId: id, offset: 0, content: b64('new') });
      await run({ op: 'write-commit', uploadId: id, totalBytes: 3 });
      expect((await stat(p('big.bin'))).mode & 0o777).toBe(0o600);
    },
  );

  test('an abort removes the temp file and leaves nothing behind', async () => {
    const id = await begin(6);
    await run({ op: 'write-chunk', uploadId: id, offset: 0, content: b64('abc') });
    const res = await run({ op: 'write-abort', uploadId: id });
    expect(res.ok).toBe(true);
    expect(await readdir(dir)).toEqual([]);
  });
});

describe('what the agent refuses', () => {
  test('a chunk out of order', async () => {
    const id = await begin(6);
    const res = await run({ op: 'write-chunk', uploadId: id, offset: 3, content: b64('def') });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error).toContain('expected offset 0');
  });

  test('a chunk replayed at an offset already written', async () => {
    const id = await begin(6);
    await run({ op: 'write-chunk', uploadId: id, offset: 0, content: b64('abc') });
    const res = await run({ op: 'write-chunk', uploadId: id, offset: 0, content: b64('XXX') });
    expect(res.ok).toBe(false);
  });

  test('more bytes than were declared', async () => {
    const id = await begin(3);
    const res = await run({ op: 'write-chunk', uploadId: id, offset: 0, content: b64('abcdef') });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe('too-large');
  });

  test('a commit short of the declared size', async () => {
    const id = await begin(6);
    await run({ op: 'write-chunk', uploadId: id, offset: 0, content: b64('abc') });
    const res = await run({ op: 'write-commit', uploadId: id, totalBytes: 6 });
    expect(res.ok).toBe(false);
    await expect(stat(p('big.bin'))).rejects.toThrow();
  });

  test('an unknown upload id', async () => {
    const res = await run({ op: 'write-chunk', uploadId: 'nope', offset: 0, content: b64('a') });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe('not-found');
  });

  // The signed path is what pins the upload; a relay swapping in another id can
  // only ever hit an upload aimed at the same destination.
  test('an upload id whose destination is not the signed path', async () => {
    const id = await begin(3);
    const res = await run({
      op: 'write-chunk',
      uploadId: id,
      path: p('other.bin'),
      offset: 0,
      content: b64('abc'),
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe('denied');
  });

  test('a declared size above the ceiling', async () => {
    const res = await run({ op: 'write-begin', totalBytes: FS_UPLOAD_MAX_BYTES + 1 });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe('too-large');
  });

  test('a relative path, before any syscall', async () => {
    const res = await run({ op: 'write-begin', path: 'relative/file', totalBytes: 1 });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe('invalid-path');
  });

  test('a destination that is a directory', async () => {
    const res = await run({ op: 'write-begin', path: dir, totalBytes: 1 });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe('is-a-directory');
  });

  test('an empty chunk', async () => {
    const id = await begin(3);
    const res = await run({ op: 'write-chunk', uploadId: id, offset: 0, content: '' });
    expect(res.ok).toBe(false);
  });
});

describe('chunkDescriptorFor', () => {
  const base = req({ op: 'write-chunk', uploadId: 'u1', offset: 0, content: b64('abc') });

  test('binds the chunk bytes, not a caller-supplied hash', () => {
    const swapped = { ...base, content: b64('xyz') };
    expect(chunkDescriptorFor(base, chunkBytes(base))).not.toBe(
      chunkDescriptorFor(swapped, chunkBytes(swapped)),
    );
  });

  test('the same bytes at another offset are a different descriptor', () => {
    const moved = { ...base, offset: 3 };
    expect(chunkDescriptorFor(base, chunkBytes(base))).not.toBe(
      chunkDescriptorFor(moved, chunkBytes(moved)),
    );
  });

  test('the destination path is covered on every operation', () => {
    const elsewhere = { ...base, path: p('other.bin') };
    expect(chunkDescriptorFor(base, chunkBytes(base))).not.toBe(
      chunkDescriptorFor(elsewhere, chunkBytes(elsewhere)),
    );
  });

  test('a chunk grant cannot be replayed as a commit', () => {
    const commit = { ...base, op: 'write-commit' as const, content: '' };
    expect(chunkDescriptorFor(base, chunkBytes(base))).not.toBe(
      chunkDescriptorFor(commit, chunkBytes(commit)),
    );
  });
});

describe('limits', () => {
  test('a chunk larger than the ceiling is refused before it is written', async () => {
    const id = await begin(FS_CHUNK_MAX_BYTES + 10);
    const oversized = Buffer.alloc(FS_CHUNK_MAX_BYTES + 1, 0x61).toString('base64');
    const res = await run({ op: 'write-chunk', uploadId: id, offset: 0, content: oversized });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe('too-large');
  });
});
