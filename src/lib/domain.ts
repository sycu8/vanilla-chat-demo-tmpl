/**
 * Domain extraction and validation utilities.
 * Extend here for DNS lookups, WHOIS, etc. in production mode.
 */

const URL_PATTERN =
  /^(https?:\/\/)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(\/.*)?$/;

/** Extract bare domain from URL or hostname input */
export function extractDomain(input: string): string {
  let value = input.trim().toLowerCase();
  if (!value) return "";

  if (!value.startsWith("http://") && !value.startsWith("https://")) {
    value = `https://${value}`;
  }

  try {
    const url = new URL(value);
    let host = url.hostname;
    if (host.startsWith("www.")) {
      host = host.slice(4);
    }
    return host;
  } catch {
    const match = input.trim().match(/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return match ? match[1].toLowerCase() : "";
  }
}

/** Validate that input looks like a real domain */
export function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  return URL_PATTERN.test(domain) || URL_PATTERN.test(`https://${domain}`);
}

/** Deterministic numeric seed from domain string */
export function domainSeed(domain: string): number {
  let hash = 0;
  for (let i = 0; i < domain.length; i++) {
    hash = (hash << 5) - hash + domain.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

/** Seeded pseudo-random generator (LCG) for reproducible simulation */
export function createRng(seed: number) {
  let state = seed;
  return {
    next(): number {
      state = (state * 1664525 + 1013904223) >>> 0;
      return state / 0xffffffff;
    },
    pick<T>(arr: T[]): T {
      return arr[Math.floor(this.next() * arr.length)];
    },
    int(min: number, max: number): number {
      return Math.floor(this.next() * (max - min + 1)) + min;
    },
    shuffle<T>(arr: T[]): T[] {
      const copy = [...arr];
      for (let i = copy.length - 1; i > 0; i--) {
        const j = Math.floor(this.next() * (i + 1));
        [copy[i], copy[j]] = [copy[j], copy[i]];
      }
      return copy;
    },
  };
}
