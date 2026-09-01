import { createAgent } from './agent';
import { loadConfig } from './config';
import { FS_HELPER_ENV, runFsHelper } from './fs';

// A copy of this binary spawned under `runuser` to perform one filesystem
// operation as the configured user, then exit. Checked before anything else so
// the helper never starts a second agent. See `runFsOp` in fs.ts.
if (process.env[FS_HELPER_ENV] === '1') {
  await runFsHelper();
} else {
  createAgent(loadConfig()).start();
}
