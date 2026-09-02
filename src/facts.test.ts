import { describe, expect, test } from 'bun:test';
import { parseCrontab } from './facts';

describe('parseCrontab', () => {
  test('reads a per-user spool, where there is no user column', () => {
    const entries = parseCrontab('30 4 * * * /usr/local/bin/backup.sh', false, 'crontab:deploy');
    expect(entries).toEqual([
      {
        schedule: '30 4 * * *',
        command: '/usr/local/bin/backup.sh',
        user: undefined,
        source: 'crontab:deploy',
      },
    ]);
  });

  test('reads /etc/crontab, where the sixth field is the user', () => {
    // Getting this backwards would silently turn `root` into the command.
    const entries = parseCrontab(
      '17 * * * * root cd / && run-parts /etc/cron.hourly',
      true,
      '/etc/crontab',
    );
    expect(entries[0]?.user).toBe('root');
    expect(entries[0]?.command).toBe('cd / && run-parts /etc/cron.hourly');
  });

  test('keeps the @-shorthands cron actually accepts', () => {
    const entries = parseCrontab('@daily /opt/rotate.sh\n@reboot root /opt/boot.sh', false, 'x');
    expect(entries[0]?.schedule).toBe('@daily');
    expect(entries[1]?.schedule).toBe('@reboot');
  });

  test('skips comments, blanks and settings', () => {
    const content = [
      '# nightly backup',
      '',
      'MAILTO="ops@example.com"',
      'PATH=/usr/bin:/bin',
      'SHELL=/bin/sh',
    ].join('\n');
    expect(parseCrontab(content, false, 'x')).toEqual([]);
  });

  test('skips a line too short to be a schedule', () => {
    expect(parseCrontab('* * * *', false, 'x')).toEqual([]);
    expect(parseCrontab('30 4 * * * root', true, 'x')).toEqual([]);
  });

  test('redacts a secret sitting in a cron line', () => {
    // A cron line is one of the likelier places on a box to find a token.
    const entries = parseCrontab(
      '0 * * * * curl -H "Authorization: Bearer sk_live_abcdef1234567890" https://api.example.com',
      false,
      'x',
    );
    expect(entries[0]?.command).not.toContain('sk_live_abcdef1234567890');
    expect(entries[0]?.command).toContain('redacted');
  });

  test('records where each entry came from', () => {
    const entries = parseCrontab('@daily /opt/x.sh', false, '/etc/cron.d/backup');
    expect(entries[0]?.source).toBe('/etc/cron.d/backup');
  });
});
