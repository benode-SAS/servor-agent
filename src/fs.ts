import type { Stats } from 'node:fs';
import { chmod, lstat, mkdir, readdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { AgentConfig } from './config';
import {
  describeFsOp,
  type FsOp,
  fsContentHash,
  isProtectedFsPath,
  validateFsPath,
} from './protocol/fs-grant';

/**
 * Filesystem operations driven from the browser's file explorer.
 *
 * @remarks
 * Every one of them is authorized exactly like a command: the browser signs a
 * canonical descriptor, the control plane relays it verbatim, and `tunnel.ts`
 * verifies it against a provisioned key **before** anything here is called. The
 * descriptor covers the content of a write, so the bytes that land on disk are
 * the bytes the user signed for.
 *
 * @module
 */

/**
 * Biggest file the explorer will open, save, upload or download.
 *
 * @remarks
 * The whole payload travels base64-encoded inside one tunnel frame, so the
 * ceiling is really the frame budget: 8 MiB becomes ~10.7 MiB encoded, well
 * under the 16 MiB default. Raising it further would mean chunking rather than
 * a bigger number.
 */
export const FS_MAX_BYTES = 8 * 1024 * 1024;
/** Directory listings stop here; a directory with more is not browsable anyway. */
export const FS_MAX_ENTRIES = 2000;

export type FsRequest = {
  op: FsOp;
  path: string;
  /** `move`: destination. */
  to?: string;
  /** `chmod`: octal, e.g. `0644`. */
  mode?: string;
  /** `write`: base64 of the bytes to put on disk. */
  content?: string;
  /** `remove`: take the whole subtree. */
  recursive?: boolean;
};

export type FsEntry = {
  name: string;
  type: 'file' | 'dir' | 'symlink' | 'other';
  size: number;
  /** Octal permission bits, e.g. `0644`. */
  mode: string;
  /** ISO 8601 UTC. */
  mtime: string;
};

export type FsResponse =
  | {
      ok: true;
      entries?: FsEntry[];
      stat?: FsEntry;
      /** base64, `read` only. */
      content?: string;
      /** Minted by `write-begin`; the id every later chunk carries. */
      uploadId?: string;
      /** Bytes an upload holds so far — also the offset the next chunk must use. */
      written?: number;
    }
  | { ok: false; error: string; code: FsErrorCode };

export type FsErrorCode =
  | 'invalid-path'
  | 'invalid-mode'
  | 'too-large'
  | 'protected-path'
  | 'not-found'
  | 'denied'
  | 'exists'
  | 'not-a-directory'
  | 'is-a-directory'
  | 'unsupported'
  | 'failed';

const fail = (code: FsErrorCode, error: string): FsResponse => ({ ok: false, code, error });

/**
 * The exact string the grant for this request must have been signed over.
 *
 * @remarks
 * Built from the decoded content, never from a hash the caller supplied — that
 * is what stops the relay keeping a valid signature while swapping the bytes.
 */
export const fsDescriptorFor = (req: FsRequest, content: Uint8Array | null): string =>
  describeFsOp({
    op: req.op,
    path: req.path,
    to: req.to ?? null,
    mode: req.mode ?? null,
    contentHash: content ? fsContentHash(content) : null,
    recursive: req.recursive ?? null,
  });

const MODE_RE = /^[0-7]{3,4}$/;

const kindOf = (s: { isFile(): boolean; isDirectory(): boolean; isSymbolicLink(): boolean }) =>
  s.isDirectory() ? 'dir' : s.isSymbolicLink() ? 'symlink' : s.isFile() ? 'file' : 'other';

const describe = (name: string, s: Stats): FsEntry => ({
  name,
  type: kindOf(s),
  size: s.size,
  mode: (s.mode & 0o7777).toString(8).padStart(4, '0'),
  mtime: new Date(s.mtimeMs).toISOString(),
});

// errno → a code the UI can phrase, so the browser never shows a raw strerror.
const fromErrno = (e: unknown): FsResponse => {
  const code = (e as { code?: string }).code;
  if (code === 'ENOENT') return fail('not-found', 'no such file or directory');
  if (code === 'EACCES' || code === 'EPERM') return fail('denied', 'permission denied');
  if (code === 'EEXIST') return fail('exists', 'already exists');
  if (code === 'ENOTDIR') return fail('not-a-directory', 'not a directory');
  if (code === 'EISDIR') return fail('is-a-directory', 'is a directory');
  if (code === 'ENOTEMPTY') return fail('failed', 'directory not empty');
  return fail('failed', code ?? 'operation failed');
};

/**
 * Runs one operation in the current process.
 *
 * @remarks
 * Assumes the grant is already verified. Paths are re-validated here anyway:
 * this is the last place before a syscall, and the control plane is not trusted
 * to have checked anything.
 */
export const performFsOp = async (req: FsRequest): Promise<FsResponse> => {
  const path = validateFsPath(req.path);
  if (!path.ok) return fail('invalid-path', `path ${path.reason}`);

  try {
    switch (req.op) {
      case 'list': {
        const dirents = await readdir(req.path, { withFileTypes: true });
        const entries: FsEntry[] = [];
        for (const d of dirents.slice(0, FS_MAX_ENTRIES)) {
          try {
            entries.push(describe(d.name, await lstat(join(req.path, d.name))));
          } catch {
            // A dangling symlink or a file that vanished mid-listing is listed
            // with what we know rather than failing the whole directory.
            entries.push({ name: d.name, type: 'other', size: 0, mode: '0000', mtime: '' });
          }
        }
        entries.sort((a, b) =>
          a.type === b.type
            ? a.name.localeCompare(b.name)
            : a.type === 'dir'
              ? -1
              : b.type === 'dir'
                ? 1
                : 0,
        );
        return { ok: true, entries };
      }

      case 'stat':
        return {
          ok: true,
          stat: describe(req.path.split(/[\\/]/).pop() ?? '', await lstat(req.path)),
        };

      case 'read': {
        const s = await lstat(req.path);
        if (s.isDirectory()) return fail('is-a-directory', 'is a directory');
        if (s.size > FS_MAX_BYTES) {
          return fail('too-large', `file is ${s.size} bytes, limit is ${FS_MAX_BYTES}`);
        }
        const buf = await readFile(req.path);
        return { ok: true, content: buf.toString('base64'), stat: describe('', s) };
      }

      case 'write': {
        const bytes = Buffer.from(req.content ?? '', 'base64');
        if (bytes.byteLength > FS_MAX_BYTES) {
          return fail(
            'too-large',
            `content is ${bytes.byteLength} bytes, limit is ${FS_MAX_BYTES}`,
          );
        }
        // Same-directory temp + rename: a save that dies halfway leaves the old
        // file intact instead of a truncated one. The mode of an existing file
        // is carried over so saving a config never widens its permissions.
        let keepMode: number | null = null;
        try {
          const existing = await lstat(req.path);
          if (existing.isDirectory()) return fail('is-a-directory', 'is a directory');
          keepMode = existing.mode & 0o7777;
        } catch {
          keepMode = null;
        }
        const tmp = join(
          dirname(req.path),
          `.servor-${Date.now()}-${Math.random().toString(36).slice(2)}.tmp`,
        );
        try {
          await writeFile(tmp, bytes, keepMode == null ? { mode: 0o644 } : { mode: keepMode });
          await rename(tmp, req.path);
        } catch (e) {
          await rm(tmp, { force: true }).catch(() => {});
          throw e;
        }
        return { ok: true, stat: describe('', await lstat(req.path)) };
      }

      case 'mkdir':
        await mkdir(req.path, { recursive: true });
        return { ok: true };

      case 'move': {
        const to = validateFsPath(req.to ?? '');
        if (!to.ok) return fail('invalid-path', `destination ${to.reason}`);
        await rename(req.path, req.to as string);
        return { ok: true };
      }

      case 'remove': {
        const recursive = req.recursive === true;
        // A mis-click in a file tree has no undo, so the roots that would take
        // the machine down are refused outright. The terminal is unaffected.
        if (recursive && isProtectedFsPath(req.path)) {
          return fail('protected-path', 'refusing to recursively remove a system directory');
        }
        await rm(req.path, { recursive, force: false });
        return { ok: true };
      }

      case 'chmod': {
        if (!MODE_RE.test(req.mode ?? '')) return fail('invalid-mode', 'mode must be octal');
        await chmod(req.path, Number.parseInt(req.mode as string, 8));
        return { ok: true };
      }

      default:
        return fail('unsupported', `unknown operation ${String(req.op)}`);
    }
  } catch (e) {
    return fromErrno(e);
  }
};

const isRoot = (): boolean => typeof process.getuid === 'function' && process.getuid() === 0;

/** Env flag that turns a spawned copy of this binary into the helper below. */
export const FS_HELPER_ENV = 'SERVOR_FS_HELPER';

/**
 * Helper entrypoint: reads one request as JSON on stdin, writes one response as
 * JSON on stdout. Invoked only by {@link runFsOp} through `runuser`.
 */
export const runFsHelper = async (): Promise<void> => {
  let out: FsResponse;
  try {
    const raw = await new Response(Bun.stdin.stream()).text();
    out = await performFsOp(JSON.parse(raw) as FsRequest);
  } catch (e) {
    out = fail('failed', (e as Error).message);
  }
  process.stdout.write(JSON.stringify(out));
};

/**
 * Runs one operation with the same privileges a command would get.
 *
 * @remarks
 * When the agent runs as root and a `user` is configured, commands are dropped
 * to that user by `runuser`. File operations have to follow: an explorer that
 * wrote as root while the terminal ran unprivileged would be a way around the
 * very restriction the operator asked for. The drop re-invokes this binary as
 * the helper above — argv only, no shell, so no path or content can be read as
 * syntax — and the request travels on stdin.
 */
export const runFsOp = async (cfg: AgentConfig, req: FsRequest): Promise<FsResponse> => {
  const drop = process.platform === 'linux' && cfg.user && cfg.user !== 'root' && isRoot();
  if (!drop) return performFsOp(req);

  try {
    const child = Bun.spawn(
      ['runuser', '-u', cfg.user as string, '--', 'env', `${FS_HELPER_ENV}=1`, process.execPath],
      { stdin: new TextEncoder().encode(JSON.stringify(req)), stdout: 'pipe', stderr: 'pipe' },
    );
    const [body, exitCode] = await Promise.all([new Response(child.stdout).text(), child.exited]);
    if (exitCode !== 0 || !body) {
      const err = await new Response(child.stderr).text();
      return fail('failed', err.trim().slice(0, 300) || `helper exited ${exitCode}`);
    }
    return JSON.parse(body) as FsResponse;
  } catch (e) {
    return fail('failed', `privilege drop failed: ${(e as Error).message}`);
  }
};
