// Vendored from packages/shared/src/crypto/fs-grant.ts — do not edit here.
//
// The agent ships as an independent, auditable artefact: a reader must be
// able to see every line that decides whether a command runs, without
// resolving a private Servor package. `bun run protocol:check` fails if this
// copy drifts from the original, because a guard that disagrees with the one
// on the control plane is worse than no guard.

import { sha256 } from '@noble/hashes/sha256';

// ── Canonical descriptor for a signed filesystem operation ──────────────────
// An exec grant signs one `command` string. A filesystem operation carries
// several parameters — a path, sometimes a destination, a mode, and for a write
// the CONTENT itself — and every one of them has to be covered by the
// signature. The control plane relays a grant verbatim, but a descriptor that
// named only the path would let a compromised relay keep the signature and swap
// the bytes that land on disk. So the descriptor packs them all, and the agent
// rebuilds it from what it is about to do rather than from what it was told.

const enc = new TextEncoder();

export const FS_OPS = [
  'list',
  'stat',
  'read',
  'write',
  'mkdir',
  'move',
  'remove',
  'chmod',
] as const;
export type FsOp = (typeof FS_OPS)[number];

// Length-prefixed, exactly like canonicalExecMessage and for the same reason: a
// path may hold any byte but NUL, so no separator on its own is unambiguous.
const field = (s: string): string => `${enc.encode(s).length}:${s}`;

/** Lowercase hex SHA-256 of the exact bytes a write will put on disk. */
export const fsContentHash = (content: Uint8Array): string => {
  let out = '';
  for (const b of sha256(content)) out += b.toString(16).padStart(2, '0');
  return out;
};

export type FsDescriptorInput = {
  op: FsOp;
  path: string;
  /** `move`: the destination path. */
  to?: string | null;
  /** `chmod`: octal mode, e.g. `0644`. */
  mode?: string | null;
  /** `write`: {@link fsContentHash} of the content. */
  contentHash?: string | null;
  /** `remove`: whether the whole subtree goes. */
  recursive?: boolean | null;
};

/**
 * The string signed as an `fs` grant's `command`.
 *
 * @remarks
 * Every field is emitted, in a fixed order, whether or not the operation uses
 * it. Fixed arity plus length prefixes makes the encoding injective: no two
 * distinct operations can produce the same descriptor, so a signature obtained
 * for one can never be replayed onto another.
 */
export const describeFsOp = (i: FsDescriptorInput): string =>
  [`fs.${i.op}`, i.path, i.to ?? '', i.mode ?? '', i.contentHash ?? '', i.recursive ? '1' : '0']
    .map(field)
    .join('');

export type FsPathProblem = 'empty' | 'not-absolute' | 'nul-byte' | 'not-normalized' | 'too-long';

/** Absolute POSIX path, or a Windows drive-letter path for Windows agents. */
const ABSOLUTE = /^(\/|[A-Za-z]:[\\/])/;
const MAX_PATH_LENGTH = 4096;

/**
 * Rejects anything that is not already an absolute, fully normalized path.
 *
 * @remarks
 * Normalizing instead of rejecting would be a mistake: the signature covers the
 * literal string, so the bytes that get touched must be the bytes that were
 * signed. A path the agent had to rewrite is a path the user never approved.
 * Enforced agent-side — the control plane is not trusted to have done it.
 */
export const validateFsPath = (
  path: string,
): { ok: true } | { ok: false; reason: FsPathProblem } => {
  if (path.length === 0) return { ok: false, reason: 'empty' };
  if (path.length > MAX_PATH_LENGTH) return { ok: false, reason: 'too-long' };
  if (path.includes('\0')) return { ok: false, reason: 'nul-byte' };
  if (!ABSOLUTE.test(path)) return { ok: false, reason: 'not-absolute' };

  // The head is either '' (leading '/') or a drive letter — neither is a segment
  // to validate. Past it, an empty segment means '//' and a '.' or '..' means
  // the caller sent a path that does not denote itself.
  const [, ...segments] = path.split(/[\\/]/);
  for (const [index, segment] of segments.entries()) {
    if (segment === '.' || segment === '..') return { ok: false, reason: 'not-normalized' };
    // A single trailing slash on the root itself is the one empty tail allowed.
    if (segment === '' && !(index === segments.length - 1 && segments.length === 1)) {
      return { ok: false, reason: 'not-normalized' };
    }
  }
  if (segments.length > 1 && segments[segments.length - 1] === '') {
    return { ok: false, reason: 'not-normalized' };
  }
  return { ok: true };
};

// Directories where a recursive delete is never a legitimate UI gesture. The
// terminal can still do anything the user's shell can — this guards the file
// explorer's own destructive action, where one mis-click has no undo.
const PROTECTED = new Set([
  '/',
  '/bin',
  '/boot',
  '/dev',
  '/etc',
  '/home',
  '/lib',
  '/lib32',
  '/lib64',
  '/opt',
  '/proc',
  '/root',
  '/run',
  '/sbin',
  '/srv',
  '/sys',
  '/usr',
  '/var',
]);

/** True when a recursive removal of this path must be refused outright. */
export const isProtectedFsPath = (path: string): boolean => {
  const trimmed = path.length > 1 ? path.replace(/[\\/]+$/, '') : path;
  if (PROTECTED.has(trimmed)) return true;
  return /^[A-Za-z]:[\\/]?$/.test(trimmed) || /^[A-Za-z]:[\\/]Windows$/i.test(trimmed);
};
