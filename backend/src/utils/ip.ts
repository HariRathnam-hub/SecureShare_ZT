import net from 'net';

/** Returns the header value only when it is exactly ONE valid IP literal (no lists, ports, or junk). */
export function parseSingleIp(value: string | string[] | undefined): string | undefined {
  if (typeof value !== 'string') return undefined;
  const v = value.trim();
  return v.length > 0 && v.length <= 45 && net.isIP(v) ? v : undefined;
}

/** Expands any valid IPv6 literal to 8 hextets, or undefined when it is not IPv6. */
function expandIPv6(ip: string): string[] | undefined {
  if (net.isIP(ip) !== 6) return undefined;
  let addr = ip.split('%')[0].toLowerCase(); // drop zone id
  // Embedded IPv4 tail (::ffff:1.2.3.4) -> two hextets.
  const v4 = addr.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a, b, c, d] = v4.slice(1).map(Number);
    addr = addr.slice(0, addr.length - v4[0].length) + ((a << 8) | b).toString(16) + ':' + ((c << 8) | d).toString(16);
  }
  const [head, tail] = addr.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const missing = addr.includes('::') ? 8 - h.length - t.length : 0;
  const groups = [...h, ...Array(Math.max(missing, 0)).fill('0'), ...t].map((g) => g.padStart(4, '0'));
  return groups.length === 8 ? groups : undefined;
}

/**
 * Stable bucket for rate limiting.
 *  - IPv4 and IPv4-mapped IPv6 (::ffff:a.b.c.d) map to the same IPv4 key.
 *  - Other IPv6 addresses are grouped by their /64, because a single subscriber normally controls a whole /64 and could
 *    otherwise rotate through addresses to dodge limits.
 */
export function ipRateLimitKey(ip: string | undefined): string {
  if (!ip) return 'ip:unknown';
  if (net.isIP(ip) === 4) return `ip:${ip}`;
  const g = expandIPv6(ip);
  if (!g) return `ip:${ip.slice(0, 64)}`;
  if (g.slice(0, 5).every((x) => x === '0000') && g[5] === 'ffff') {
    const n = (i: number) => parseInt(g[i], 16);
    return `ip:${n(6) >> 8}.${n(6) & 255}.${n(7) >> 8}.${n(7) & 255}`;
  }
  return `ip6:${g.slice(0, 4).join(':')}/64`;
}
