import test from "node:test";
import assert from "node:assert/strict";
import {
  BASE_RULES,
  effectiveRules,
  expandLockRules,
  normalizeHost,
  withCanonicalRules,
} from "../scripts/policy-rules.mjs";

const legacyLock = () => ({
  id: "lock-1",
  startsAt: "2026-07-30T00:00:00Z",
  endsAt: "2027-07-30T00:00:00Z",
  domains: BASE_RULES.map((rule) => rule.host),
});

test("legacy locks receive canonical matching semantics", () => {
  const canonical = withCanonicalRules(legacyLock());
  assert.equal(canonical.id, "lock-1");
  assert.deepEqual(canonical.rules, BASE_RULES);
});

test("expansion preserves lock identity and deadline", () => {
  const before = legacyLock();
  const after = expandLockRules(before, "Example.COM.", "subdomains");
  assert.equal(after.id, before.id);
  assert.equal(after.startsAt, before.startsAt);
  assert.equal(after.endsAt, before.endsAt);
  assert.deepEqual(after.rules.at(-1), { host: "example.com", includeSubdomains: true });
  assert.ok(after.domains.includes("example.com"));
});

test("exact rules may expand to subdomains but never narrow", () => {
  const exact = expandLockRules(legacyLock(), "example.com", "exact");
  const expanded = expandLockRules(exact, "example.com", "subdomains");
  assert.equal(effectiveRules(expanded).find((rule) => rule.host === "example.com").includeSubdomains, true);
  assert.throws(() => expandLockRules(expanded, "example.com", "exact"), /cannot narrow/);
});

test("unsafe host input is rejected", () => {
  for (const host of ["https://example.com", "*.example.com", "example.com/path", "localhost", "-bad.example"]) {
    assert.throws(() => normalizeHost(host));
  }
});
