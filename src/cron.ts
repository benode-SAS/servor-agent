// A tiny, dependency-free 5-field crontab matcher: does `date` fall on the
// minute described by `expr`? Fields, in order: minute (0-59), hour (0-23),
// day-of-month (1-31), month (1-12), day-of-week (0-6, Sunday = 0; 7 also Sunday).
// Each field supports `*`, lists (`a,b`), ranges (`a-b`), and steps (`*/n`,
// `a-b/n`). Evaluated in the host's local time. Unparseable → never matches.

type ScheduledCommand = { id: string; command: string; cron: string };

const parseField = (field: string, min: number, max: number): Set<number> | null => {
  const out = new Set<number>();
  for (const part of field.split(',')) {
    const slash = part.split('/');
    const rangePart = slash[0] ?? '';
    const stepPart = slash[1];
    const step = stepPart ? Number(stepPart) : 1;
    if (!Number.isInteger(step) || step < 1) return null;
    let lo: number;
    let hi: number;
    if (rangePart === '*') {
      lo = min;
      hi = max;
    } else if (rangePart.includes('-')) {
      const [a, b] = rangePart.split('-');
      lo = Number(a);
      hi = Number(b);
    } else {
      lo = Number(rangePart);
      hi = lo;
    }
    if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo < min || hi > max || lo > hi) {
      return null;
    }
    for (let v = lo; v <= hi; v += step) out.add(v);
  }
  return out;
};

export const cronMatches = (expr: string, date: Date): boolean => {
  const fields = expr.trim().split(/\s+/);
  if (fields.length !== 5) return false;
  const minute = parseField(fields[0]!, 0, 59);
  const hour = parseField(fields[1]!, 0, 23);
  const dom = parseField(fields[2]!, 1, 31);
  const month = parseField(fields[3]!, 1, 12);
  const dowRaw = parseField(fields[4]!, 0, 7);
  if (!minute || !hour || !dom || !month || !dowRaw) return false;
  // Normalize Sunday (7 → 0) so both spellings match.
  const dow = new Set([...dowRaw].map((d) => (d === 7 ? 0 : d)));

  if (!minute.has(date.getMinutes())) return false;
  if (!hour.has(date.getHours())) return false;
  if (!month.has(date.getMonth() + 1)) return false;

  // Cron's day-of-month / day-of-week quirk: if BOTH are restricted (not `*`),
  // the command runs when EITHER matches; otherwise both must match.
  const domRestricted = fields[2] !== '*';
  const dowRestricted = fields[4] !== '*';
  const domOk = dom.has(date.getDate());
  const dowOk = dow.has(date.getDay());
  if (domRestricted && dowRestricted) return domOk || dowOk;
  return domOk && dowOk;
};

export const minuteKey = (date: Date): string =>
  `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}-${date.getHours()}-${date.getMinutes()}`;

export type { ScheduledCommand };
