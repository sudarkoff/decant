export type Decision = 'allow' | 'hidden' | 'blocked';

const DAY_MS = 86_400_000;

export function decide(i: {
  publishTime: Date | null;
  conflict: boolean;
  blocked: boolean;
  allowed: boolean;
  cooldownDays: number;
  now: Date;
}): Decision {
  if (i.blocked || i.conflict) return 'blocked';
  if (i.allowed) return 'allow';
  if (i.publishTime === null) return 'hidden';
  return i.now.getTime() - i.publishTime.getTime() >= i.cooldownDays * DAY_MS ? 'allow' : 'hidden';
}
