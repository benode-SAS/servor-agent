import { beforeEach, describe, expect, test } from 'bun:test';
import { x25519 } from '@noble/curves/ed25519';
import { createGrantVerifier, GRANT_FUTURE_SKEW_S, GRANT_PAST_SKEW_S, NONCE_TTL_MS } from './grant';
import { type ExecGrant, execPublicKeyFromVault, signExecGrant } from './protocol/exec-sign';

const SERVER_ID = '019ecd37-5979-72ce-8960-fc9454880973';

const vaultKey = () => x25519.utils.randomPrivateKey();
const pubB64 = (vaultPrivkey: Uint8Array) =>
  Buffer.from(execPublicKeyFromVault(vaultPrivkey)).toString('base64');

let clock = Date.UTC(2026, 0, 1, 12, 0, 0);
const now = () => clock;
const nowSeconds = () => Math.floor(clock / 1000);

let nonceCounter = 0;
const freshNonce = () => `nonce-${++nonceCounter}`;

type GrantOver = Partial<ExecGrant>;

const makeGrant = (over: GrantOver = {}): ExecGrant => ({
  serverId: SERVER_ID,
  kind: 'exec',
  command: 'systemctl restart nginx',
  nonce: freshNonce(),
  ts: String(nowSeconds()),
  ...over,
});

/** Sign a grant and shape it as the tunnel message the agent actually receives. */
const message = (vaultPrivkey: Uint8Array, grant: ExecGrant): Record<string, unknown> => ({
  type: 'exec',
  id: 'req-1',
  command: grant.command,
  nonce: grant.nonce,
  ts: grant.ts,
  sig: Buffer.from(signExecGrant(vaultPrivkey, grant)).toString('base64'),
});

describe('grant verification', () => {
  beforeEach(() => {
    clock = Date.UTC(2026, 0, 1, 12, 0, 0);
  });

  test('a grant signed by an authorized key for this server is accepted', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const grant = makeGrant();
    expect(v.verify('exec', grant.command, message(key, grant))).toBe(true);
  });

  test('replaying the same nonce is refused', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const grant = makeGrant();
    const msg = message(key, grant);
    expect(v.verify('exec', grant.command, msg)).toBe(true);
    expect(v.verify('exec', grant.command, msg)).toBe(false);
  });

  test('a grant naming another server is refused', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const grant = makeGrant({ serverId: 'some-other-server' });
    expect(v.verify('exec', grant.command, message(key, grant))).toBe(false);
  });

  test('an exec grant cannot open a shell', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const grant = makeGrant({ kind: 'exec', command: 'bash -l' });
    expect(v.verify('shell', grant.command, message(key, grant))).toBe(false);
  });

  test('a shell grant cannot run a one-shot command', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const grant = makeGrant({ kind: 'shell', command: 'bash -l' });
    expect(v.verify('exec', grant.command, message(key, grant))).toBe(false);
  });

  test('substituting the command behind a valid signature is refused', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const grant = makeGrant({ command: 'systemctl status nginx' });
    const msg = message(key, grant);
    expect(v.verify('exec', 'rm -rf /var/lib/postgresql', msg)).toBe(false);
  });

  test('a timestamp older than the past skew is refused', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const grant = makeGrant({ ts: String(nowSeconds() - GRANT_PAST_SKEW_S - 1) });
    expect(v.verify('exec', grant.command, message(key, grant))).toBe(false);
  });

  test('a timestamp at exactly the past skew is still accepted', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const grant = makeGrant({ ts: String(nowSeconds() - GRANT_PAST_SKEW_S) });
    expect(v.verify('exec', grant.command, message(key, grant))).toBe(true);
  });

  test('a timestamp further ahead than the future skew is refused', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const grant = makeGrant({ ts: String(nowSeconds() + GRANT_FUTURE_SKEW_S + 1) });
    expect(v.verify('exec', grant.command, message(key, grant))).toBe(false);
  });

  test('a timestamp at exactly the future skew is still accepted', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const grant = makeGrant({ ts: String(nowSeconds() + GRANT_FUTURE_SKEW_S) });
    expect(v.verify('exec', grant.command, message(key, grant))).toBe(true);
  });

  test('a non-numeric timestamp is refused', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const grant = makeGrant({ ts: 'not-a-timestamp' });
    expect(v.verify('exec', grant.command, message(key, grant))).toBe(false);
  });

  test.each(['nonce', 'ts', 'sig'] as const)('a grant with no %s is refused', (field) => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const grant = makeGrant();
    const msg = message(key, grant);
    delete msg[field];
    expect(v.verify('exec', grant.command, msg)).toBe(false);
  });

  test('nothing runs while no key is installed', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    const grant = makeGrant();
    expect(v.verify('exec', grant.command, message(key, grant))).toBe(false);
  });

  test('a signature that is not valid base64 is refused', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const grant = makeGrant();
    const msg = { ...message(key, grant), sig: '!!! not base64 !!!' };
    expect(v.verify('exec', grant.command, msg)).toBe(false);
  });

  test('a signature by an unauthorized key is refused', () => {
    const authorized = vaultKey();
    const attacker = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(authorized)]);
    const grant = makeGrant();
    expect(v.verify('exec', grant.command, message(attacker, grant))).toBe(false);
  });

  test('any one of several installed keys is enough', () => {
    const a = vaultKey();
    const b = vaultKey();
    const c = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(a), pubB64(b), pubB64(c)]);
    for (const key of [a, b, c]) {
      const grant = makeGrant();
      expect(v.verify('exec', grant.command, message(key, grant))).toBe(true);
    }
  });

  test('replacing the key set revokes the operator it dropped', () => {
    const revoked = vaultKey();
    const kept = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(revoked), pubB64(kept)]);
    const before = makeGrant();
    expect(v.verify('exec', before.command, message(revoked, before))).toBe(true);

    v.setKeys([pubB64(kept)]);
    const after = makeGrant();
    expect(v.verify('exec', after.command, message(revoked, after))).toBe(false);
    const stillValid = makeGrant();
    expect(v.verify('exec', stillValid.command, message(kept, stillValid))).toBe(true);
  });

  test('a rejected grant does not consume its nonce', () => {
    const authorized = vaultKey();
    const attacker = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(authorized)]);
    const nonce = freshNonce();

    const forged = makeGrant({ nonce });
    expect(v.verify('exec', forged.command, message(attacker, forged))).toBe(false);

    const legitimate = makeGrant({ nonce });
    expect(v.verify('exec', legitimate.command, message(authorized, legitimate))).toBe(true);
  });

  test('a nonce stays remembered while its signature could still be replayed', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const nonce = freshNonce();
    const first = makeGrant({ nonce });
    expect(v.verify('exec', first.command, message(key, first))).toBe(true);

    clock += NONCE_TTL_MS - 60_000;
    const sweeper = makeGrant();
    expect(v.verify('exec', sweeper.command, message(key, sweeper))).toBe(true);

    const replayed = makeGrant({ nonce });
    expect(v.verify('exec', replayed.command, message(key, replayed))).toBe(false);
  });

  test('a nonce older than the TTL is swept out of the table', () => {
    const key = vaultKey();
    const v = createGrantVerifier({ serverId: SERVER_ID, now });
    v.setKeys([pubB64(key)]);
    const nonce = freshNonce();
    const first = makeGrant({ nonce });
    expect(v.verify('exec', first.command, message(key, first))).toBe(true);

    clock += NONCE_TTL_MS + 1_000;
    const sweeper = makeGrant();
    expect(v.verify('exec', sweeper.command, message(key, sweeper))).toBe(true);

    const reused = makeGrant({ nonce });
    expect(v.verify('exec', reused.command, message(key, reused))).toBe(true);
  });

  test('each agent keeps its own nonce table', () => {
    const key = vaultKey();
    const a = createGrantVerifier({ serverId: SERVER_ID, now });
    const b = createGrantVerifier({ serverId: SERVER_ID, now });
    a.setKeys([pubB64(key)]);
    b.setKeys([pubB64(key)]);
    const grant = makeGrant();
    const msg = message(key, grant);
    expect(a.verify('exec', grant.command, msg)).toBe(true);
    expect(b.verify('exec', grant.command, msg)).toBe(true);
  });
});
