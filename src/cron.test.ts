import { describe, expect, test } from 'bun:test';
import { cronMatches } from './cron';

// Local time (the matcher uses the host clock).
const at = (y: number, mo: number, d: number, h: number, mi: number) =>
  new Date(y, mo - 1, d, h, mi, 0);

describe('cronMatches', () => {
  test('* * * * * matches any minute', () => {
    expect(cronMatches('* * * * *', at(2026, 1, 1, 13, 37))).toBe(true);
  });

  test('a fixed time matches only that minute', () => {
    expect(cronMatches('0 3 * * *', at(2026, 1, 1, 3, 0))).toBe(true);
    expect(cronMatches('0 3 * * *', at(2026, 1, 1, 3, 1))).toBe(false);
    expect(cronMatches('0 3 * * *', at(2026, 1, 1, 4, 0))).toBe(false);
  });

  test('step every 15 minutes', () => {
    expect(cronMatches('*/15 * * * *', at(2026, 1, 1, 10, 30))).toBe(true);
    expect(cronMatches('*/15 * * * *', at(2026, 1, 1, 10, 31))).toBe(false);
  });

  test('list and range', () => {
    expect(cronMatches('0,30 9-17 * * *', at(2026, 1, 1, 12, 30))).toBe(true);
    expect(cronMatches('0,30 9-17 * * *', at(2026, 1, 1, 18, 0))).toBe(false);
  });

  test('day-of-week (Sunday as 0 and 7)', () => {
    // 2026-01-04 is a Sunday.
    expect(cronMatches('0 9 * * 0', at(2026, 1, 4, 9, 0))).toBe(true);
    expect(cronMatches('0 9 * * 7', at(2026, 1, 4, 9, 0))).toBe(true);
    expect(cronMatches('0 9 * * 1', at(2026, 1, 4, 9, 0))).toBe(false);
  });

  test('dom + dow both restricted → OR semantics', () => {
    // Runs on the 1st OR on Mondays. 2026-01-01 is a Thursday (not Monday) but
    // is the 1st → matches.
    expect(cronMatches('0 0 1 * 1', at(2026, 1, 1, 0, 0))).toBe(true);
  });

  test('malformed expressions never match', () => {
    expect(cronMatches('0 3 * *', at(2026, 1, 1, 3, 0))).toBe(false); // 4 fields
    expect(cronMatches('x 3 * * *', at(2026, 1, 1, 3, 0))).toBe(false);
    expect(cronMatches('99 3 * * *', at(2026, 1, 1, 3, 0))).toBe(false); // out of range
  });
});
