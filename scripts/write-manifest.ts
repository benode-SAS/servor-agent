/**
 * Write dist/manifest.json, the version the API advertises to the fleet.
 *
 * @remarks
 * Deliberately the last step of the build, after the binaries exist. The
 * manifest is what tells agents a newer version is available, so writing it
 * from the source constant at any earlier point would let a bumped-but-unbuilt
 * version send every agent chasing a download that is not there.
 *
 * @module
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { BUILD_VERSION } from '../src/version';

const out = join(import.meta.dir, '..', 'dist', 'manifest.json');
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify({ version: BUILD_VERSION, builtAt: new Date().toISOString() }));
process.stdout.write(`manifest written: ${BUILD_VERSION}\n`);
