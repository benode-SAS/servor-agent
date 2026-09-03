import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import {
  type NetRequest,
  netBodyBytes,
  netDescriptorFor,
  runNetRequest,
  validateNetRequest,
} from './net';
import { MAX_LOCAL_RESPONSE_BYTES } from './protocol/net-grant';

const base: NetRequest = {
  scheme: 'http',
  host: '127.0.0.1',
  port: 1,
  method: 'GET',
  path: '/',
  headers: [],
  insecureTls: false,
};

const b64 = (s: string) => Buffer.from(s, 'utf-8').toString('base64');

let server: ReturnType<typeof Bun.serve> | null = null;
let port = 0;

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === '/metrics') return new Response('up 1\n');
      if (url.pathname === '/echo-header') {
        return new Response(req.headers.get('x-probe') ?? '');
      }
      if (url.pathname === '/echo-body') return new Response(req.body, { status: 201 });
      if (url.pathname === '/huge') {
        // Twice the cap, streamed: the reader must stop at the ceiling.
        return new Response('x'.repeat(MAX_LOCAL_RESPONSE_BYTES * 2));
      }
      if (url.pathname === '/redirect') {
        return new Response(null, { status: 302, headers: { location: '/metrics' } });
      }
      return new Response('nope', { status: 404 });
    },
  });
  port = server.port;
});

afterAll(() => {
  server?.stop(true);
});

const text = (b: string) => Buffer.from(b, 'base64').toString('utf-8');

describe('netDescriptorFor', () => {
  test('binds the body bytes, not a caller-supplied hash', () => {
    const withBody = { ...base, method: 'POST' as const, body: b64('{"a":1}') };
    const swapped = { ...withBody, body: b64('{"a":2}') };
    expect(netDescriptorFor(withBody, netBodyBytes(withBody))).not.toBe(
      netDescriptorFor(swapped, netBodyBytes(swapped)),
    );
  });

  test('an empty body hashes to the empty marker, not to sha256("")', () => {
    const d = netDescriptorFor(base, netBodyBytes(base));
    expect(d).toContain('0:');
  });
});

describe('validateNetRequest', () => {
  test('accepts a plain loopback GET', () => {
    expect(validateNetRequest(base, netBodyBytes(base))).toBeNull();
  });

  test('refuses a body on GET', () => {
    const req = { ...base, body: b64('x') };
    const res = validateNetRequest(req, netBodyBytes(req));
    expect(res?.ok).toBe(false);
  });

  test('refuses a malformed host', () => {
    const req = { ...base, host: 'http://127.0.0.1' };
    expect(validateNetRequest(req, netBodyBytes(req))?.ok).toBe(false);
  });

  test('refuses an unsupported method', () => {
    const req = { ...base, method: 'TRACE' as NetRequest['method'] };
    expect(validateNetRequest(req, netBodyBytes(req))?.ok).toBe(false);
  });
});

describe('runNetRequest', () => {
  test('returns the body of a local service', async () => {
    const res = await runNetRequest({ ...base, port, path: '/metrics' });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.status).toBe(200);
    expect(text(res.body)).toBe('up 1\n');
    expect(res.truncated).toBe(false);
  });

  test('sends the headers it was given', async () => {
    const res = await runNetRequest({
      ...base,
      port,
      path: '/echo-header',
      headers: [{ name: 'x-probe', value: 'hello' }],
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(text(res.body)).toBe('hello');
  });

  test('sends the body bytes on POST', async () => {
    const res = await runNetRequest({
      ...base,
      port,
      method: 'POST',
      path: '/echo-body',
      body: b64('{"a":1}'),
    });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.status).toBe(201);
    expect(text(res.body)).toBe('{"a":1}');
  });

  test('a non-2xx status is a result, not an error', async () => {
    const res = await runNetRequest({ ...base, port, path: '/missing' });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.status).toBe(404);
  });

  // A redirect followed silently would leave the descriptor describing one URL
  // while another was fetched.
  test('does not follow redirects', async () => {
    const res = await runNetRequest({ ...base, port, path: '/redirect' });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.status).toBe(302);
  });

  test('caps a response that would not fit', async () => {
    const res = await runNetRequest({ ...base, port, path: '/huge' });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.truncated).toBe(true);
    expect(Buffer.from(res.body, 'base64').length).toBe(MAX_LOCAL_RESPONSE_BYTES);
  });

  test('a closed port is reported as unreachable, not as a crash', async () => {
    const res = await runNetRequest({ ...base, port: 1 });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(['unreachable', 'failed', 'timed-out']).toContain(res.code);
  });

  test('an invalid request never leaves the agent', async () => {
    const res = await runNetRequest({ ...base, path: 'relative' });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.code).toBe('invalid-request');
  });
});
