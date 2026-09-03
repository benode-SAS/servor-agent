import {
  describeLocalRequest,
  isLocalMethod,
  isLocalScheme,
  type LocalHeader,
  type LocalMethod,
  type LocalScheme,
  localBodyHash,
  MAX_LOCAL_BODY_BYTES,
  MAX_LOCAL_RESPONSE_BYTES,
  methodAllowsBody,
  validateLocalTarget,
} from './protocol/net-grant';

/**
 * One HTTP request, made from inside the machine.
 *
 * @remarks
 * This is what port forwarding becomes when the client is a browser: it cannot
 * bind a local socket, so instead of tunnelling a TCP stream the agent performs
 * the request where the service is reachable and hands the response back. A
 * Prometheus bound to 127.0.0.1:9090 stays bound to 127.0.0.1 — nothing is
 * exposed, no firewall port is opened, and the response travels the same
 * signed, end-to-end path as every other operation.
 *
 * Authorization is `tunnel.ts`'s job and happens **before** anything here runs.
 * What this module owes the caller is that the request it performs is exactly
 * the one described by `netDescriptorFor` — same method, host, port, path,
 * headers and body bytes — because that descriptor is what was signed.
 *
 * @module
 */

export type NetRequest = {
  scheme: LocalScheme;
  host: string;
  port: number;
  method: LocalMethod;
  path: string;
  headers: LocalHeader[];
  /** base64 of the request body, absent when there is none. */
  body?: string;
  insecureTls: boolean;
};

export type NetErrorCode =
  | 'invalid-request'
  | 'too-large'
  | 'unreachable'
  | 'timed-out'
  | 'tls'
  | 'failed';

export type NetResponse =
  | {
      ok: true;
      status: number;
      statusText: string;
      headers: LocalHeader[];
      /** base64 of the response body, truncated at `MAX_LOCAL_RESPONSE_BYTES`. */
      body: string;
      truncated: boolean;
      durationMs: number;
    }
  | { ok: false; code: NetErrorCode; error: string };

const REQUEST_TIMEOUT_MS = 15_000;

const fail = (code: NetErrorCode, error: string): NetResponse => ({ ok: false, code, error });

/** Decode the body once; the same bytes are hashed and sent. */
export const netBodyBytes = (req: NetRequest): Uint8Array =>
  req.body ? Buffer.from(req.body, 'base64') : new Uint8Array(0);

/**
 * The exact string the grant for this request must have been signed over.
 *
 * @remarks
 * Rebuilt from the decoded bytes, never from a hash the caller supplied — the
 * same rule as `fsDescriptorFor`, and for the same reason: a relay must not be
 * able to keep a valid signature while changing what actually gets sent.
 */
export const netDescriptorFor = (req: NetRequest, body: Uint8Array): string =>
  describeLocalRequest({
    scheme: req.scheme,
    host: req.host,
    port: req.port,
    method: req.method,
    path: req.path,
    headers: req.headers,
    bodyHash: body.length > 0 ? localBodyHash(body) : '',
    insecureTls: req.insecureTls,
  });

/** Everything the descriptor cannot express: shape, size and method coherence. */
export const validateNetRequest = (req: NetRequest, body: Uint8Array): NetResponse | null => {
  if (!isLocalScheme(req.scheme)) return fail('invalid-request', 'unsupported scheme');
  if (!isLocalMethod(req.method)) return fail('invalid-request', 'unsupported method');

  const target = validateLocalTarget({
    host: req.host,
    port: req.port,
    path: req.path,
    headers: req.headers,
  });
  if (!target.ok) return fail('invalid-request', target.reason);

  if (body.length > MAX_LOCAL_BODY_BYTES) return fail('too-large', 'request body too large');
  if (body.length > 0 && !methodAllowsBody(req.method)) {
    return fail('invalid-request', `${req.method} carries no body`);
  }
  return null;
};

const classify = (e: unknown): NetResponse => {
  const message = e instanceof Error ? e.message : String(e);
  if (e instanceof Error && e.name === 'TimeoutError') {
    return fail('timed-out', `no response after ${REQUEST_TIMEOUT_MS}ms`);
  }
  if (/certificate|self-signed|SSL|TLS/i.test(message)) return fail('tls', message);
  if (/ECONNREFUSED|EHOSTUNREACH|ENOTFOUND|ECONNRESET|Unable to connect/i.test(message)) {
    return fail('unreachable', message);
  }
  return fail('failed', message);
};

/**
 * Perform the request and return at most `MAX_LOCAL_RESPONSE_BYTES` of it.
 *
 * @remarks
 * The body is read as a stream and cut at the cap rather than buffered whole:
 * pointing this at a log endpoint that streams forever must not grow the
 * agent's memory until the box runs out.
 */
export const runNetRequest = async (req: NetRequest): Promise<NetResponse> => {
  const body = netBodyBytes(req);
  const invalid = validateNetRequest(req, body);
  if (invalid) return invalid;

  const url = `${req.scheme}://${req.host}:${req.port}${req.path}`;
  const headers = new Headers();
  for (const h of req.headers) headers.set(h.name, h.value);

  const startedAt = Date.now();
  try {
    const res = await fetch(url, {
      method: req.method,
      headers,
      body: body.length > 0 ? body : undefined,
      redirect: 'manual',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      // Bun-only: the user signed for this, and a local service with a
      // self-signed certificate is the common case rather than the exception.
      ...(req.insecureTls ? { tls: { rejectUnauthorized: false } } : {}),
    } as RequestInit);

    const chunks: Uint8Array[] = [];
    let size = 0;
    let truncated = false;
    if (res.body) {
      const reader = res.body.getReader();
      while (size < MAX_LOCAL_RESPONSE_BYTES) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;
        const room = MAX_LOCAL_RESPONSE_BYTES - size;
        if (value.length > room) {
          chunks.push(value.subarray(0, room));
          size += room;
          truncated = true;
          break;
        }
        chunks.push(value);
        size += value.length;
      }
      await reader.cancel().catch(() => {});
    }

    return {
      ok: true,
      status: res.status,
      statusText: res.statusText,
      headers: [...res.headers].map(([name, value]) => ({ name, value })),
      body: Buffer.concat(chunks).toString('base64'),
      truncated,
      durationMs: Date.now() - startedAt,
    };
  } catch (e) {
    return classify(e);
  }
};
