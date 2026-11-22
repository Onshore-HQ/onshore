import dns from "node:dns";
import net from "node:net";
import type { LookupFunction } from "node:net";

const blocked = new net.BlockList();
for (const [addr, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked.addSubnet(addr, prefix, "ipv4");
for (const [addr, prefix] of [
  ["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8],
  // These forms carry an IPv4 address inside, so they could reach a private one.
  ["64:ff9b::", 96], ["2002::", 16], ["::", 96],
] as const) blocked.addSubnet(addr, prefix, "ipv6");

/** BlockList also applies the IPv4 rules to IPv4-mapped IPv6, such as ::ffff:10.0.0.1. */
export function isPublicAddress(ip: string): boolean {
  const family = net.isIP(ip);
  if (family === 0) return false;
  return !blocked.check(ip, family === 6 ? "ipv6" : "ipv4");
}

/** Why a destination URL may not be used, or null if it may. Node's URL parser has
 *  already normalised odd spellings such as 2130706433 and 0x7f.0.0.1. */
export function upstreamUrlProblem(url: string): string | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return "the destination must be a valid URL";
  }
  const allowHttp = process.env.RV_ALLOW_HTTP_UPSTREAM === "true";
  if (u.protocol !== "https:" && !(allowHttp && u.protocol === "http:")) return "the destination must use https";
  if (u.username || u.password) return "credentials do not belong in the destination URL";
  if (process.env.RV_ALLOW_PRIVATE_UPSTREAM === "true") return null;
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host.includes(".") && !host.includes(":")) return "the destination must be a public host name";
  if ((net.isIP(host) && !isPublicAddress(host)) || host.endsWith(".local") || host.endsWith(".internal")) return "the destination must be a public address";
  return null;
}

/**
 * A connect-time DNS check, which also covers rebinding. Node normally asks for every
 * address (`all: true`) and needs an array back, so the answer must follow the caller's
 * form. One private address refuses the whole name, since Node may try any of them.
 */
export function guardedLookup(refusal: string, resolve: LookupFunction = dns.lookup as unknown as LookupFunction): LookupFunction {
  return (host, options, callback) => {
    const cb = callback as unknown as (err: Error | null, address?: unknown, family?: number) => void;
    resolve(host, { ...options, all: true }, (err, result) => {
      if (err) return cb(err);
      const addresses = result as unknown as dns.LookupAddress[];
      const first = addresses[0];
      if (!first) return cb(Object.assign(new Error(`no address for ${host}`), { code: "ENOTFOUND" }));
      if (process.env.RV_ALLOW_PRIVATE_UPSTREAM !== "true" && addresses.some((a) => !isPublicAddress(a.address))) return cb(new Error(refusal));
      if (options.all) return cb(null, addresses);
      cb(null, first.address, first.family);
    });
  };
}
