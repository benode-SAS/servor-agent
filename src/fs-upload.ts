import { randomBytes } from 'node:crypto';
import { open, rename, rm, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { FsErrorCode, FsResponse } from './fs';
import {
  describeFsChunk,
  FS_CHUNK_MAX_BYTES,
  FS_UPLOAD_MAX_BYTES,
  type FsChunkOp,
  fsContentHash,
  validateFsPath,
} from './protocol/fs-grant';

/**
 * Uploads assembled from many signed chunks.
 *
 * @remarks
 * A single `write` carries the file inside one tunnel frame, which is what caps
 * it. This lifts the ceiling without loosening anything: each chunk is its own
 * signed operation covering its own bytes, appended to a temporary file beside
 * the destination, and the finished file only takes the real name on the final
 * rename. A transfer that dies halfway leaves a stray temp file, never a
 * truncated version of the file it was replacing.
 *
 * Chunks must arrive **in order**, each starting exactly where the last one
 * ended. Accepting arbitrary offsets would mean supporting overlap, sparse
 * holes, and re-writes of already-committed ranges — three ways to end up with a
 * file whose bytes nobody signed for, in exchange for a reordering ability no
 * client here needs.
 *
 * @module
 */

type Upload = {
  id: string;
  /** Final destination, fixed at `write-begin` and never re-read from a frame. */
  path: string;
  tmp: string;
  /** Bytes committed so far, and therefore the only offset the next chunk may use. */
  written: number;
  totalBytes: number;
  mode: string;
  lastActivity: number;
};

const uploads = new Map<string, Upload>();

/** An upload nobody has touched for this long is abandoned and its temp file removed. */
const UPLOAD_IDLE_MS = 10 * 60 * 1000;
const MAX_CONCURRENT_UPLOADS = 8;

const fail = (code: FsErrorCode, error: string): FsResponse => ({ ok: false, code, error });

export type FsChunkRequest = {
  op: FsChunkOp;
  uploadId: string;
  path: string;
  offset: number;
  /** base64 of this chunk's bytes; empty except on `write-chunk`. */
  content: string;
  totalBytes: number;
  mode: string;
};

/** Decode a chunk's bytes once; the same buffer is hashed and written. */
export const chunkBytes = (req: FsChunkRequest): Uint8Array =>
  req.op === 'write-chunk' && req.content ? Buffer.from(req.content, 'base64') : new Uint8Array(0);

/**
 * The exact string the grant for this operation must have been signed over.
 *
 * @remarks
 * Built from the decoded bytes, never from a hash the caller supplied — the same
 * rule as `fsDescriptorFor`, and for the same reason: a relay must not be able
 * to keep a valid signature while changing what lands on disk.
 */
export const chunkDescriptorFor = (req: FsChunkRequest, bytes: Uint8Array): string =>
  describeFsChunk({
    op: req.op,
    uploadId: req.uploadId,
    path: req.path,
    offset: req.offset,
    contentHash: bytes.length > 0 ? fsContentHash(bytes) : '',
    totalBytes: req.totalBytes,
    mode: req.mode,
  });

const sweep = async () => {
  const cutoff = Date.now() - UPLOAD_IDLE_MS;
  for (const [id, u] of uploads) {
    if (u.lastActivity >= cutoff) continue;
    uploads.delete(id);
    await rm(u.tmp, { force: true }).catch(() => {});
  }
};

const begin = async (req: FsChunkRequest): Promise<FsResponse> => {
  await sweep();
  if (uploads.size >= MAX_CONCURRENT_UPLOADS) {
    return fail('failed', 'too many uploads in flight');
  }
  if (req.totalBytes <= 0 || req.totalBytes > FS_UPLOAD_MAX_BYTES) {
    return fail('too-large', `size must be between 1 and ${FS_UPLOAD_MAX_BYTES} bytes`);
  }

  // Refuse a destination that is already a directory now rather than at the
  // rename, after the whole file has crossed the wire.
  try {
    const existing = await stat(req.path);
    if (existing.isDirectory()) return fail('is-a-directory', 'is a directory');
  } catch {
    // Absent is the normal case for an upload.
  }

  const id = randomBytes(16).toString('hex');
  const tmp = join(dirname(req.path), `.servor-upload-${id}.tmp`);
  try {
    // Created empty and closed immediately: the handle is reopened per chunk so
    // an upload that stalls holds no file descriptor for ten minutes.
    const handle = await open(tmp, 'w', 0o600);
    await handle.close();
  } catch (e) {
    return fail('denied', (e as Error).message);
  }

  uploads.set(id, {
    id,
    path: req.path,
    tmp,
    written: 0,
    totalBytes: req.totalBytes,
    mode: req.mode,
    lastActivity: Date.now(),
  });
  return { ok: true, uploadId: id };
};

const resolve = (req: FsChunkRequest): Upload | FsResponse => {
  const upload = uploads.get(req.uploadId);
  if (!upload) return fail('not-found', 'unknown or expired upload');
  // The path is signed on every operation, so a relay that swapped in someone
  // else's upload id is caught here: the only id it could substitute is one
  // already writing to this same destination.
  if (upload.path !== req.path) return fail('denied', 'upload does not target this path');
  return upload;
};

const chunk = async (req: FsChunkRequest, bytes: Uint8Array): Promise<FsResponse> => {
  const found = resolve(req);
  if ('ok' in found) return found;
  const upload = found;

  if (bytes.length === 0) return fail('failed', 'empty chunk');
  if (bytes.length > FS_CHUNK_MAX_BYTES) {
    return fail('too-large', `chunk is ${bytes.length} bytes, limit is ${FS_CHUNK_MAX_BYTES}`);
  }
  if (req.offset !== upload.written) {
    return fail('failed', `expected offset ${upload.written}, got ${req.offset}`);
  }
  if (upload.written + bytes.length > upload.totalBytes) {
    return fail('too-large', 'chunk would exceed the declared size');
  }

  try {
    const handle = await open(upload.tmp, 'r+');
    try {
      await handle.write(bytes, 0, bytes.length, upload.written);
    } finally {
      await handle.close();
    }
  } catch (e) {
    return fail('failed', (e as Error).message);
  }

  upload.written += bytes.length;
  upload.lastActivity = Date.now();
  return { ok: true, written: upload.written };
};

const commit = async (req: FsChunkRequest): Promise<FsResponse> => {
  const found = resolve(req);
  if ('ok' in found) return found;
  const upload = found;

  if (upload.written !== upload.totalBytes) {
    return fail('failed', `expected ${upload.totalBytes} bytes, received ${upload.written}`);
  }

  // Carried over from the file being replaced, exactly like a plain `write`, so
  // an upload over an existing config never widens its permissions.
  let mode = upload.mode ? Number.parseInt(upload.mode, 8) : 0o644;
  try {
    const existing = await stat(upload.path);
    if (existing.isDirectory()) return fail('is-a-directory', 'is a directory');
    if (!upload.mode) mode = existing.mode & 0o7777;
  } catch {
    // No previous file: the default stands.
  }

  try {
    const handle = await open(upload.tmp, 'r+');
    try {
      await handle.chmod(mode);
      // The rename is atomic but does not itself flush; without this a crash
      // right after can leave the new name pointing at unwritten blocks.
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(upload.tmp, upload.path);
  } catch (e) {
    await rm(upload.tmp, { force: true }).catch(() => {});
    uploads.delete(upload.id);
    return fail('failed', (e as Error).message);
  }

  uploads.delete(upload.id);
  return { ok: true, written: upload.written };
};

const abort = async (req: FsChunkRequest): Promise<FsResponse> => {
  const found = resolve(req);
  if ('ok' in found) return found;
  uploads.delete(found.id);
  await rm(found.tmp, { force: true }).catch(() => {});
  return { ok: true };
};

/**
 * Run one chunked-upload operation.
 *
 * @remarks
 * Assumes the grant is already verified. The path is re-validated here anyway:
 * this is the last place before a syscall, and the control plane is not trusted
 * to have checked anything.
 */
export const runFsChunkOp = async (req: FsChunkRequest, bytes: Uint8Array): Promise<FsResponse> => {
  const path = validateFsPath(req.path);
  if (!path.ok) return fail('invalid-path', `path ${path.reason}`);

  switch (req.op) {
    case 'write-begin':
      return begin(req);
    case 'write-chunk':
      return chunk(req, bytes);
    case 'write-commit':
      return commit(req);
    case 'write-abort':
      return abort(req);
    default:
      return fail('unsupported', 'unknown upload operation');
  }
};

/** Drop every in-flight upload and its temp file — used on shutdown and in tests. */
export const resetUploads = async () => {
  const all = [...uploads.values()];
  uploads.clear();
  await Promise.all(all.map((u) => rm(u.tmp, { force: true }).catch(() => {})));
};
