// Vendored from packages/shared/src/utils/command-guards.ts — do not edit here.
//
// The agent ships as an independent, auditable artefact: a reader must be
// able to see every line that decides whether a command runs, without
// resolving a private Servor package. `bun run protocol:check` fails if this
// copy drifts from the original, because a guard that disagrees with the one
// on the control plane is worse than no guard.

import { parse } from 'shell-quote';
import { COMMAND_BLACKLIST_PATTERNS } from './command-blacklist';

export type CommandGuardResult =
  | { ok: true }
  | { ok: false; reason: string; rule: 'blacklist' | 'chain' | 'syntax' };

export type CommandRisk = 'safe' | 'caution' | 'destructive';

// Read-only inspection commands — safe to auto-run without approval.
const SAFE_READ_PATTERNS: RegExp[] = [
  /^(cat|head|tail|less|more|grep|egrep|zgrep|ls|ll|find|stat|file|wc|awk|sed -n|cut|sort|uniq|tr)\b/,
  /^(ps|pgrep|top -bn1|htop -|free|df|du|uptime|vmstat|iostat|lsof|lsblk|mount)\b/,
  /^(whoami|id|hostname|uname|date|env|printenv|pwd|which|type|command -v)\b/,
  /^(systemctl\s+(--failed|--all|-a|status|is-active|is-enabled|is-failed|list-units|list-unit-files|list-timers|list-sockets|list-dependencies|list-jobs|show|show-environment|cat|get-default)|journalctl)\b/,
  /^(ss|netstat|ip|dig|host|nslookup|ping -c|traceroute|getent)\b/,
  /^(docker (ps|logs|inspect|images|stats)|podman (ps|logs|inspect)|kubectl (get|describe|logs))\b/,
  /^(curl (--head|-I|-sS|-fsS)|wget --spider|nginx -t|apache2ctl configtest|sshd -t|git status|git log)\b/,
  /^(cat \/etc\/os-release|lsb_release)\b/,
];

// Irreversible / high-impact mutations — require explicit confirmation even in Auto.
const DESTRUCTIVE_PATTERNS: RegExp[] = [
  /\brm\s+(-[a-zA-Z]*\s+)*(-rf|-fr|-r|-f)\b/,
  /\b(mkfs|fdisk|parted|wipefs|blkdiscard|sgdisk)\b/,
  /\bdd\b[^|]*\bof=\/dev\//,
  /\b(shutdown|reboot|poweroff|halt|init\s+0|init\s+6)\b/,
  /\bsystemctl\s+(stop|disable|mask)\b/,
  /\b(userdel|groupdel|deluser|delgroup)\b/,
  /\b(drop\s+(database|table|schema)|truncate\s+table)\b/i,
  /\b(iptables\s+-F|ufw\s+reset|nft\s+flush)\b/,
  /\b(apt-get|apt|dnf|yum)\s+(remove|purge|autoremove)\b/,
  /\b(docker|podman)\s+(rm|rmi|system\s+prune|volume\s+rm)\b/,
  /\bkill(all)?\s+-9\b/,
  />\s*\/dev\/(sd|nvme|vd)/,
  /\bchmod\s+(-R\s+)?0{3}\b/,
  /\bchown\s+-R\b[^|]*\s\/(\s|$)/,
];

// Classify a command's blast radius for approval policy (Auto auto-runs safe +
// caution, prompts on destructive; Plan auto-runs safe, prompts otherwise).
export const classifyCommandRisk = (command: string): CommandRisk => {
  const trimmed = command.trim();
  if (DESTRUCTIVE_PATTERNS.some((p) => p.test(trimmed))) return 'destructive';
  if (SAFE_READ_PATTERNS.some((p) => p.test(trimmed))) return 'safe';
  return 'caution';
};

const DANGEROUS_CHAIN_OPS = new Set(['||', '&&', ';', '|', '&']);

export const validateCommand = (
  command: string,
  opts: { allowChains?: boolean } = {},
): CommandGuardResult => {
  const trimmed = command.trim();
  if (!trimmed) return { ok: false, reason: 'empty command', rule: 'syntax' };

  for (const { pattern, reason } of COMMAND_BLACKLIST_PATTERNS) {
    if (pattern.test(trimmed)) return { ok: false, reason, rule: 'blacklist' };
  }

  if (!opts.allowChains) {
    // A newline separates commands for `bash -lc` exactly as `;` does, but
    // shell-quote does not model it as an operator, so every chain check below
    // was blind to it: a command with an embedded newline parsed as a plain
    // token list and passed. Refused for the same reason `;` is refused.
    if (/[\n\r]/.test(trimmed)) {
      return { ok: false, reason: 'multi-line command not allowed', rule: 'chain' };
    }

    let tokens: ReturnType<typeof parse>;
    try {
      tokens = parse(trimmed);
    } catch {
      return { ok: false, reason: 'unparseable shell input', rule: 'syntax' };
    }
    for (const t of tokens) {
      if (typeof t === 'object' && t !== null && 'op' in t) {
        if (DANGEROUS_CHAIN_OPS.has(t.op)) {
          return { ok: false, reason: `chain operator '${t.op}' not allowed`, rule: 'chain' };
        }
      }
    }
    if (/\$\(|`/.test(trimmed)) {
      return { ok: false, reason: 'command substitution not allowed', rule: 'chain' };
    }
  }

  return { ok: true };
};
