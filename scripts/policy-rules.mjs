const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_RULES = 256;

export const BASE_RULES = Object.freeze([
  { host: "x.com", includeSubdomains: true },
  { host: "twitter.com", includeSubdomains: true },
  { host: "pornhub.com", includeSubdomains: true },
  { host: "xvideos.com", includeSubdomains: true },
  { host: "yandex.com", includeSubdomains: false },
  { host: "www.yandex.com", includeSubdomains: false },
  { host: "ya.ru", includeSubdomains: false },
  { host: "www.ya.ru", includeSubdomains: false },
  { host: "yandex.eu", includeSubdomains: false },
  { host: "www.yandex.eu", includeSubdomains: false },
  { host: "yandex.ru", includeSubdomains: false },
  { host: "www.yandex.ru", includeSubdomains: false },
  { host: "yandex.by", includeSubdomains: false },
  { host: "www.yandex.by", includeSubdomains: false },
  { host: "yandex.kz", includeSubdomains: false },
  { host: "www.yandex.kz", includeSubdomains: false },
  { host: "yandex.com.tr", includeSubdomains: false },
  { host: "www.yandex.com.tr", includeSubdomains: false },
  { host: "yandex.uz", includeSubdomains: false },
  { host: "www.yandex.uz", includeSubdomains: false },
]);

export function normalizeHost(raw) {
  const host = String(raw || "").trim().toLowerCase().replace(/\.+$/, "");
  if (!host || host.length > 253 || !host.includes(".") || /[\s/:*]/.test(host)) {
    throw new Error("DOMAIN_HOST must be a plain DNS hostname");
  }
  if (host.split(".").some((label) => !HOST_LABEL.test(label))) {
    throw new Error("DOMAIN_HOST contains an invalid DNS label");
  }
  return host;
}

export function modeToIncludeSubdomains(raw) {
  if (raw === "exact") return false;
  if (raw === "subdomains") return true;
  throw new Error("DOMAIN_MODE must be exact or subdomains");
}

function normalizeRule(value) {
  if (!value || typeof value !== "object" || typeof value.includeSubdomains !== "boolean") {
    throw new Error("protected-domain rule is malformed");
  }
  return { host: normalizeHost(value.host), includeSubdomains: value.includeSubdomains };
}

function legacyRule(host) {
  const normalized = normalizeHost(host);
  const builtIn = BASE_RULES.find((rule) => rule.host === normalized);
  return builtIn ? { ...builtIn } : { host: normalized, includeSubdomains: false };
}

export function effectiveRules(lock) {
  const source = Array.isArray(lock?.rules) && lock.rules.length
    ? lock.rules.map(normalizeRule)
    : (lock?.domains || []).map(legacyRule);
  const byHost = new Map();
  for (const rule of source) {
    const existing = byHost.get(rule.host);
    byHost.set(rule.host, {
      host: rule.host,
      includeSubdomains: Boolean(existing?.includeSubdomains || rule.includeSubdomains),
    });
  }
  if (byHost.size > MAX_RULES) throw new Error(`a lock may contain at most ${MAX_RULES} rules`);
  return [...byHost.values()];
}

export function withCanonicalRules(lock) {
  const rules = effectiveRules(lock);
  return { ...lock, domains: rules.map((rule) => rule.host), rules };
}

export function expandLockRules(lock, rawHost, rawMode) {
  if (!lock) throw new Error("no active lock");
  const host = normalizeHost(rawHost);
  const includeSubdomains = modeToIncludeSubdomains(rawMode);
  const rules = effectiveRules(lock);
  const index = rules.findIndex((rule) => rule.host === host);
  if (index >= 0) {
    if (rules[index].includeSubdomains && !includeSubdomains) {
      throw new Error("cannot narrow an existing subdomain rule to exact mode");
    }
    rules[index] = { host, includeSubdomains: rules[index].includeSubdomains || includeSubdomains };
  } else {
    if (rules.length >= MAX_RULES) throw new Error(`a lock may contain at most ${MAX_RULES} rules`);
    rules.push({ host, includeSubdomains });
  }
  return { ...lock, domains: rules.map((rule) => rule.host), rules };
}
