// Vendored from packages/shared/src/crypto/net-grant.ts — do not edit here.
//
// The agent ships as an independent, auditable artefact: a reader must be
// able to see every line that decides whether a command runs, without
// resolving a private Servor package. `bun run protocol:check` fails if this
// copy drifts from the original, because a guard that disagrees with the one
// on the control plane is worse than no guard.

import { sha256 } from '@noble/hashes/sha256';

// ── Canonical descriptor for a signed request to a service on the server ────
//
// The browser cannot open a local TCP listener, so `ssh -L` has no equivalent
// here. What an operator actually wants from port forwarding, though, is
// reachable: talk to a service that only listens on the box — a Prometheus on
// 127.0.0.1:9090, an admin API on :8080 — without opening a firewall port for
// it. The agent makes the request from inside the machine and hands back the
// response.
//
// Like `fs`, this carries several parameters and every one of them has to be
// covered by the signature: an approval for `GET /metrics` must not be
// replayable as `DELETE /api/keys`, and a relay must not be able to keep the
// signature while swapping the port, the headers or the body.

const enc = new TextEncoder();

export const LOCAL_SCHEMES = ['http', 'https'] as const;
export type LocalScheme = (typeof LOCAL_SCHEMES)[number];

export const LOCAL_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
export type LocalMethod = (typeof LOCAL_METHODS)[number];

/** A request body is capped well below the tunnel's frame budget. */
export const MAX_LOCAL_BODY_BYTES = 256 * 1024;
/** And so is the response the agent sends back. */
export const MAX_LOCAL_RESPONSE_BYTES = 1024 * 1024;

const MAX_HOST_LENGTH = 255;
const MAX_PATH_LENGTH = 2048;
const MAX_HEADERS = 20;
const MAX_HEADER_VALUE_LENGTH = 4096;

// Length-prefixed, exactly like `canonicalExecMessage` and `describeFsOp`: a
// header value may contain a colon and a path may contain almost anything, so
// no separator on its own is unambiguous.
const field = (s: string): string => `${enc.encode(s).length}:${s}`;

/** Lowercase hex SHA-256 of the exact bytes the request will carry. */
export const localBodyHash = (body: Uint8Array): string => {
  let out = '';
  for (const b of sha256(body)) out += b.toString(16).padStart(2, '0');
  return out;
};

export type LocalHeader = { name: string; value: string };

/**
 * Headers in one fixed order, so the same set always signs the same way.
 *
 * @remarks
 * Sorted by lowercased name, and the name is emitted lowercased: HTTP header
 * names are case-insensitive, so `Authorization` and `authorization` are the
 * same header and must not produce two different descriptors. Values keep
 * their bytes — those are case-sensitive and are what the service reads.
 */
export const canonicalHeaders = (headers: readonly LocalHeader[]): string =>
  [...headers]
    .map((h) => ({ name: h.name.toLowerCase(), value: h.value }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.value < b.value ? -1 : 1))
    .map((h) => field(h.name) + field(h.value))
    .join('');

export type LocalRequestDescriptorInput = {
  scheme: LocalScheme;
  host: string;
  port: number;
  method: LocalMethod;
  /** Path and query, starting with `/`. */
  path: string;
  headers: readonly LocalHeader[];
  /** `localBodyHash` of the body, or `''` when the request carries none. */
  bodyHash: string;
  /** Signed too: skipping certificate verification is the user's decision. */
  insecureTls: boolean;
};

/**
 * The string signed as a `net` grant's `command`.
 *
 * @remarks
 * Fixed arity, every field emitted whether or not it is used, each one length-
 * prefixed. `insecureTls` is in there on purpose: a relay able to flip it would
 * turn an approved HTTPS call into one that accepts any certificate.
 */
export const describeLocalRequest = (i: LocalRequestDescriptorInput): string =>
  [
    `net.${i.scheme}.${i.method}`,
    i.host,
    String(i.port),
    i.path,
    canonicalHeaders(i.headers),
    i.bodyHash,
    i.insecureTls ? '1' : '0',
  ]
    .map(field)
    .join('');

export type LocalTargetProblem =
  | 'host-empty'
  | 'host-too-long'
  | 'host-invalid'
  | 'port-invalid'
  | 'path-not-absolute'
  | 'path-too-long'
  | 'path-control-char'
  | 'header-name-invalid'
  | 'header-value-invalid'
  | 'too-many-headers';

// A bare host: no scheme, no credentials, no port, no path. Covers a hostname,
// an IPv4 literal, and an IPv6 literal in brackets.
const HOST = /^(?:\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?)$/;
// RFC 7230 token — the characters a header name may legally hold.
const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
// A CR, LF or NUL in a request line or header value is header injection,
// whatever the client library happens to do with it today. Scanned by code
// point rather than by regex: a regex holding the characters it forbids is
// itself a control character in the source.
const hasControlChar = (s: string): boolean => {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
};

/**
 * Rejects a target the agent should not have to interpret.
 *
 * @remarks
 * Rejects rather than normalizes, for the same reason `validateFsPath` does:
 * the signature covers the literal strings, so what is reached must be what was
 * signed. A path the agent had to rewrite is a path the user never approved.
 *
 * There is deliberately **no host allowlist**. The agent reaches only what the
 * signing user could already reach from a shell on that machine — they have
 * one — so a blocklist here would buy nothing the `exec` path does not already
 * grant, while making a legitimate private address look forbidden.
 */
export const validateLocalTarget = (i: {
  host: string;
  port: number;
  path: string;
  headers: readonly LocalHeader[];
}): { ok: true } | { ok: false; reason: LocalTargetProblem } => {
  if (i.host.length === 0) return { ok: false, reason: 'host-empty' };
  if (i.host.length > MAX_HOST_LENGTH) return { ok: false, reason: 'host-too-long' };
  if (!HOST.test(i.host)) return { ok: false, reason: 'host-invalid' };

  if (!Number.isInteger(i.port) || i.port < 1 || i.port > 65535) {
    return { ok: false, reason: 'port-invalid' };
  }

  if (!i.path.startsWith('/')) return { ok: false, reason: 'path-not-absolute' };
  if (i.path.length > MAX_PATH_LENGTH) return { ok: false, reason: 'path-too-long' };
  if (hasControlChar(i.path)) return { ok: false, reason: 'path-control-char' };

  if (i.headers.length > MAX_HEADERS) return { ok: false, reason: 'too-many-headers' };
  for (const h of i.headers) {
    if (!HEADER_NAME.test(h.name)) return { ok: false, reason: 'header-name-invalid' };
    if (h.value.length > MAX_HEADER_VALUE_LENGTH) {
      return { ok: false, reason: 'header-value-invalid' };
    }
    if (hasControlChar(h.value)) return { ok: false, reason: 'header-value-invalid' };
  }

  return { ok: true };
};

export const isLocalMethod = (value: string): value is LocalMethod =>
  (LOCAL_METHODS as readonly string[]).includes(value);

export const isLocalScheme = (value: string): value is LocalScheme =>
  (LOCAL_SCHEMES as readonly string[]).includes(value);

/** Methods that carry no body — a body on one of these is a caller mistake. */
export const methodAllowsBody = (method: LocalMethod): boolean =>
  method !== 'GET' && method !== 'HEAD';
