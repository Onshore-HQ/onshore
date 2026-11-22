import assert from "node:assert/strict";
import { test } from "node:test";
import { guardedLookup, isPublicAddress } from "../src/netguard.js";

const fake = (addresses: { address: string; family: number }[]) => ((_h: string, _o: unknown, cb: (e: Error | null, a: unknown) => void) => cb(null, addresses)) as never;
const run = (lookup: ReturnType<typeof guardedLookup>, all: boolean) =>
  new Promise<{ err: Error | null; address: unknown; family: unknown }>((r) => lookup("idp.example", { all } as never, ((err: Error | null, address: unknown, family: unknown) => r({ err, address, family })) as never));

test("private, reserved and embedded-IPv4 forms are not public", () => {
  for (const ip of ["127.0.0.1", "10.1.1.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "::", "fe80::1", "fd00::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::", "not an ip"]) assert.equal(isPublicAddress(ip), false, ip);
});

test("public addresses pass", () => {
  for (const ip of ["8.8.8.8", "102.89.1.1", "172.32.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"]) assert.equal(isPublicAddress(ip), true, ip);
});

test("all:true gets an array, which is what Node's connect needs", async () => {
  const list = [{ address: "8.8.8.8", family: 4 }, { address: "2606:4700:4700::1111", family: 6 }];
  const { err, address } = await run(guardedLookup("no", fake(list)), true);
  assert.equal(err, null);
  assert.deepEqual(address, list);
});

test("all:false gets a single address and family", async () => {
  const { err, address, family } = await run(guardedLookup("no", fake([{ address: "8.8.8.8", family: 4 }])), false);
  assert.equal(err, null);
  assert.equal(address, "8.8.8.8");
  assert.equal(family, 4);
});

test("one private address among public ones refuses the name", async () => {
  for (const all of [true, false]) {
    const { err } = await run(guardedLookup("refused", fake([{ address: "8.8.8.8", family: 4 }, { address: "10.0.0.5", family: 4 }])), all);
    assert.equal(err?.message, "refused");
  }
});
