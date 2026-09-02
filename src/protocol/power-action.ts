// Power actions — the one execution path that carries no command string.
//
// `reboot`, `shutdown`, `halt` and `poweroff` are refused by the shared
// blocklist, and that refusal is worth keeping: it is what stops the AI copilot
// or a free-form terminal command from taking a machine down. So power is not
// an exception carved into the blocklist — it is a separate, narrower channel.
//
// The browser signs an **action name**, not a command line. The agent holds the
// commands and looks them up by name. There is therefore nothing to quote,
// nothing to inject, and no way for a relay to turn a reboot into anything
// else: an unknown word is simply refused.

export const POWER_ACTIONS = ['reboot', 'poweroff'] as const;
export type PowerAction = (typeof POWER_ACTIONS)[number];

export const isPowerAction = (value: string): value is PowerAction =>
  (POWER_ACTIONS as readonly string[]).includes(value);

/**
 * The command each action maps to, held here and resolved by the agent.
 *
 * @remarks
 * `systemctl` rather than the bare `reboot` binary: it goes through the init
 * system, so services are stopped in dependency order and filesystems are
 * unmounted cleanly, instead of the machine dropping mid-write.
 */
export const POWER_COMMANDS: Record<PowerAction, readonly string[]> = {
  reboot: ['systemctl', 'reboot'],
  poweroff: ['systemctl', 'poweroff'],
};
