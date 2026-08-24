// Vendored from packages/shared/src/constants/command-blacklist.ts — do not edit here.
//
// The agent ships as an independent, auditable artefact: a reader must be
// able to see every line that decides whether a command runs, without
// resolving a private Servor package. `bun run protocol:check` fails if this
// copy drifts from the original, because a guard that disagrees with the one
// on the control plane is worse than no guard.

export const COMMAND_BLACKLIST_PATTERNS: { pattern: RegExp; reason: string }[] = [
  { pattern: /\brm\s+(-[a-z]*r[a-z]*f?|--recursive|--force)\s+\/(\s|$)/i, reason: 'rm -rf /' },
  {
    pattern: /\brm\s+(-[a-z]*[rf][a-z]*\s+){0,}--no-preserve-root\b/i,
    reason: 'rm --no-preserve-root',
  },
  { pattern: /\bdd\s+.*\bof=\/dev\/(sd|nvme|hd|vd|xvd|mmcblk)/i, reason: 'dd to raw block device' },
  {
    pattern: /\bmkfs(\.[a-z0-9]+)?\s+\/dev\/(sd|nvme|hd|vd|xvd|mmcblk)/i,
    reason: 'mkfs on raw device',
  },
  { pattern: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, reason: 'fork bomb' },
  // No \b before the redirect: a word boundary cannot exist between a space and
  // `>`, so `\b>` only ever matched `x>/etc/passwd` — the spaced form everyone
  // actually types walked straight through.
  {
    pattern: />>?\s*\/etc\/(?:passwd|shadow|sudoers|gshadow)\b/i,
    reason: 'overwrite /etc/passwd|shadow|sudoers',
  },
  {
    pattern: /\b(rm|mv|cp|chmod|chown|truncate)\s+.*\/etc\/(passwd|shadow|sudoers|gshadow)\b/i,
    reason: 'modify /etc/passwd|shadow|sudoers',
  },
  { pattern: /\bchmod\s+(-R\s+)?[0-7]*777\s+\//, reason: 'chmod 777 /' },
  { pattern: /\b(shutdown|halt|poweroff|reboot)\b/i, reason: 'shutdown/reboot' },
  {
    pattern: /\b(curl|wget)\s+[^|]*\|\s*(sudo\s+)?(bash|sh|zsh|dash)\b/i,
    reason: 'curl | bash from untrusted',
  },
  { pattern: />\s*\/dev\/(?:sd|nvme|hd|vd|xvd|mmcblk)/i, reason: 'redirect to raw device' },
  { pattern: /\bcryptsetup\s+(luksFormat|erase)\b/i, reason: 'cryptsetup destructive' },
  {
    pattern: /\b(parted|fdisk|gdisk)\s+.*\b(mklabel|mktable|wipe)\b/i,
    reason: 'partition table wipe',
  },
];

export const COMMAND_CHAIN_OPERATORS = [';', '&&', '||', '|', '`', '$('] as const;
