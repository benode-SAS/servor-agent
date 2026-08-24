import { describe, expect, test } from 'bun:test';
import { BUILD_VERSION } from './version';

describe('build version', () => {
  test('is a bare semver string the control plane can compare against', () => {
    expect(BUILD_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
