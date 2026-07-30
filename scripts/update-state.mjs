import { createPrivateKey, createPublicKey, randomUUID, sign, verify } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { BASE_RULES, expandLockRules, withCanonicalRules } from "./policy-rules.mjs";

const LOCK_DOMAINS = BASE_RULES.map((rule) => rule.host);

const file = new URL("../state.json", import.meta.url);
const action = process.env.ACTION_TYPE || "refresh";
const deviceId = process.env.DEVICE_ID;
const privateJwk = JSON.parse(process.env.POLICY_PRIVATE_JWK || "null");
if (!deviceId || !privateJwk?.d) throw new Error("DEVICE_ID and POLICY_PRIVATE_JWK are required");

const privateKey = createPrivateKey({ key: privateJwk, format: "jwk" });
const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
const encode = (value) => Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");
const decode = (value) => JSON.parse(Buffer.from(value, "base64url").toString("utf8"));

function readExisting() {
  let document;
  try { document = JSON.parse(readFileSync(file, "utf8")); } catch { return null; }
  if (!document.token) return null;
  const parts = document.token.split(".");
  if (parts.length !== 3) throw new Error("existing state has an invalid JWS");
  const ok = verify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`), { key: createPublicKey(privateKey), dsaEncoding: "ieee-p1363" }, Buffer.from(parts[2], "base64url"));
  if (!ok) throw new Error("existing state signature is invalid");
  return decode(parts[1]);
}

function signPayload(payload) {
  const header = encode({ alg: "ES256", typ: "JWT", kid: "x-lock-github-v1" });
  const body = encode(payload);
  const input = `${header}.${body}`;
  const signature = sign("sha256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return `${input}.${signature}`;
}

const current = readExisting();
const now = new Date();
let lock = current?.lock || null;
let grant = current?.grant || null;
if (lock) lock = withCanonicalRules(lock);

if (action === "initialize") {
  if (lock && new Date(lock.endsAt) > now) throw new Error("cannot initialize over an active lock");
  lock = null;
  grant = null;
} else if (action === "lock") {
  if (lock && new Date(lock.endsAt) > now) throw new Error("an active lock already exists");
  const endsAt = new Date(process.env.ENDS_AT || "");
  if (Number.isNaN(endsAt.getTime()) || endsAt <= now) throw new Error("ENDS_AT must be a future ISO timestamp");
  lock = {
    id: randomUUID(),
    deviceId,
    startsAt: now.toISOString(),
    endsAt: endsAt.toISOString(),
    domains: LOCK_DOMAINS,
    rules: BASE_RULES,
  };
  grant = null;
} else if (action === "expand") {
  if (!lock || new Date(lock.endsAt) <= now) throw new Error("no active lock");
  lock = expandLockRules(lock, process.env.DOMAIN_HOST, process.env.DOMAIN_MODE);
} else if (action === "grant") {
  if (!lock || new Date(lock.endsAt) <= now) throw new Error("no active lock");
  if (grant && new Date(grant.endsAt) > now) throw new Error("an active grant already exists");
  const endsAt = new Date(Math.min(now.getTime() + 600_000, new Date(lock.endsAt).getTime()));
  grant = { id: randomUUID(), lockId: lock.id, deviceId, startsAt: now.toISOString(), endsAt: endsAt.toISOString() };
} else if (action !== "refresh") {
  throw new Error(`unsupported action: ${action}`);
}

const grantActive = Boolean(grant && new Date(grant.endsAt) > now);
const lockActive = Boolean(lock && new Date(lock.endsAt) > now);
const payload = {
  version: 1,
  type: "x-lock-state",
  deviceId,
  serverTime: now.toISOString(),
  lock,
  grant,
  blocked: lockActive && !grantActive,
  iat: Math.floor(now.getTime() / 1000),
  exp: lock ? Math.floor(new Date(lock.endsAt).getTime() / 1000) : Math.floor(now.getTime() / 1000) + 86400,
};

writeFileSync(file, `${JSON.stringify({ token: signPayload(payload), publicKeyJwk: publicJwk, updatedAt: now.toISOString() }, null, 2)}\n`);
