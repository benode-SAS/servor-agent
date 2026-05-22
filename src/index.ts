import { createHmac } from 'node:crypto';
import { loadConfig } from './config';
import { collect } from './metrics';
import { startTunnel } from './tunnel';
import { checkUpdate } from './updater';

const BUILD_VERSION = '1.0.0';
const UPDATE_INTERVAL_MS = 60 * 60 * 1000;

const cfg = loadConfig();

const pushMetrics = async () => {
  try {
    const payload = await collect(BUILD_VERSION);
    const body = JSON.stringify(payload);
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = createHmac('sha256', cfg.secret).update(`${ts}.${body}`).digest('hex');
    await fetch(`${cfg.apiUrl}/agent/ingest/${cfg.serverId}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-servor-timestamp': ts,
        'x-servor-signature': sig,
      },
      body,
    });
  } catch (e) {
    console.error('metrics push failed', (e as Error).message);
  }
};

const main = () => {
  console.log(
    `servor-agent ${BUILD_VERSION} starting (mode=${cfg.mode}, interval=${cfg.intervalSeconds}s)`,
  );

  void pushMetrics();
  setInterval(() => void pushMetrics(), cfg.intervalSeconds * 1000);

  if (cfg.mode === 'tunnel') startTunnel(cfg);

  void checkUpdate(cfg, BUILD_VERSION);
  setInterval(() => void checkUpdate(cfg, BUILD_VERSION), UPDATE_INTERVAL_MS);

  process.on('SIGTERM', () => process.exit(0));
  process.on('SIGINT', () => process.exit(0));
};

main();
