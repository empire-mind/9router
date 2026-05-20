#!/usr/bin/env node
/* eslint-disable no-console */

const { spawnSync } = require("node:child_process");
const { createHmac } = require("node:crypto");
const { existsSync, mkdirSync, copyFileSync, writeFileSync } = require("node:fs");
const { dirname, join } = require("node:path");

const home = process.env.HOME || "/Users/halvo";
const dbPath = process.env.NINEROUTER_DB || join(home, ".9router/db/data.sqlite");
const vault = process.env.NINEROUTER_1PASSWORD_VAULT || "Empire";
const opBin = process.env.NINEROUTER_OP_BIN || "op";
const workspace = process.env.NINEROUTER_COMMISSION_WORKSPACE || join(home, "Documents/Codex/2026-05-20/can-you-assess-all-thats-on");
const runId = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "");
const outRoot = join(workspace, `9router-1password-sync-${runId}`);

const topSecretFields = ["apiKey", "accessToken", "refreshToken", "idToken"];
const providerSpecificSecretFields = ["copilotToken", "sessionToken", "ssoToken", "connectionProxyUrl"];
const proxyPoolSecretFields = ["proxyUrl", "relayToken"];
const settingsSecretFields = ["oidcClientSecret", "outboundProxyUrl", "mitmSudoEncrypted"];
const apply = process.argv.includes("--apply");
const auditOnly = process.argv.includes("--audit") || !apply;

function usage() {
  console.log(`Usage:
  node scripts/onepassword-secret-sync.cjs --audit
  node scripts/onepassword-secret-sync.cjs --apply

Moves 9Router secrets out of ~/.9router/db/data.sqlite and into 1Password.
No secret values are written to output reports.
`);
}

if (process.argv.includes("--help") || process.argv.includes("-h")) {
  usage();
  process.exit(0);
}

function run(cmd, args, options = {}) {
  const result = spawnSync(cmd, args, {
    input: options.input,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    env: process.env,
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || `${cmd} failed`).trim();
    throw new Error(detail);
  }
  return result.stdout || "";
}

function tryRun(cmd, args, options = {}) {
  const result = spawnSync(cmd, args, {
    input: options.input,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    env: process.env,
  });
  return result.status === 0 ? (result.stdout || "") : null;
}

function runJson(cmd, args, options = {}) {
  const templateIndex = args.indexOf("-");
  const formattedArgs = templateIndex >= 0
    ? [...args.slice(0, templateIndex), "--format", "json", ...args.slice(templateIndex)]
    : [...args, "--format", "json"];
  return JSON.parse(run(cmd, formattedArgs, options));
}

function sqliteJson(sql) {
  const out = run("sqlite3", ["-json", dbPath, sql]);
  return out.trim() ? JSON.parse(out) : [];
}

function sqlite(sql) {
  return run("sqlite3", [dbPath, sql]);
}

function sqlQuote(value) {
  return `'${String(value ?? "").replace(/'/g, "''")}'`;
}

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isOnePasswordObject(value) {
  return isPlainObject(value) && value.source === "1password" && typeof value.ref === "string";
}

function isOpRef(value) {
  return isOnePasswordObject(value) || (typeof value === "string" && value.startsWith("op://"));
}

function isExternalRef(value) {
  return typeof value === "string" && (value.startsWith("gcp://") || value.startsWith("keychain://"));
}

function isRawSecret(value) {
  if (typeof value !== "string") return false;
  if (!value.trim()) return false;
  if (value === "secretref-managed") return false;
  if (isOpRef(value) || isExternalRef(value)) return false;
  return true;
}

function secretState(value) {
  if (isOpRef(value)) return "op-ref";
  if (isExternalRef(value)) return "external-ref";
  if (isRawSecret(value)) return "raw";
  return "empty";
}

function safePart(value) {
  return String(value || "unknown")
    .toLowerCase()
    .replace(/[^a-z0-9_.@-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "unknown";
}

function itemTitle(scope, owner, fieldPath) {
  return [
    "9router",
    safePart(scope),
    safePart(owner.provider || owner.type || "secret"),
    safePart(owner.name || owner.email || owner.id),
    safePart(owner.id),
    safePart(fieldPath),
  ].join("/");
}

function itemTemplate(scope, owner, fieldPath, secret) {
  const title = itemTitle(scope, owner, fieldPath);
  return {
    title,
    category: "PASSWORD",
    tags: ["9router", "9router-secret", `scope:${safePart(scope)}`, `provider:${safePart(owner.provider || owner.type || "unknown")}`],
    fields: [
      { id: "password", type: "CONCEALED", purpose: "PASSWORD", label: "password", value: secret },
      {
        id: "notesPlain",
        type: "STRING",
        purpose: "NOTES",
        label: "notesPlain",
        value: [
          "Managed by scripts/onepassword-secret-sync.cjs.",
          `scope=${scope}`,
          `provider=${owner.provider || ""}`,
          `ownerId=${owner.id || ""}`,
          `ownerName=${owner.name || owner.email || ""}`,
          `field=${fieldPath}`,
        ].join("\n"),
      },
    ],
  };
}

function getItem(title) {
  const out = tryRun(opBin, ["item", "get", title, "--vault", vault, "--format", "json"]);
  return out ? JSON.parse(out) : null;
}

function upsertSecret(scope, owner, fieldPath, secret) {
  const title = itemTitle(scope, owner, fieldPath);
  const template = itemTemplate(scope, owner, fieldPath, secret);
  const existing = getItem(title);
  const item = existing
    ? runJson(opBin, ["item", "edit", existing.id, "--vault", vault, "--template", "/dev/stdin"], { input: JSON.stringify(template) })
    : runJson(opBin, ["item", "create", "--vault", vault, "--template", "/dev/stdin"], { input: JSON.stringify(template) });

  return {
    source: "1password",
    vault,
    itemId: item.id || existing?.id,
    field: "password",
    title,
    ref: `op://${vault}/${item.id || existing?.id}/password`,
  };
}

function parseGcpReference(reference) {
  const raw = reference.trim().slice("gcp://".length);
  const parts = raw.split("/").filter(Boolean);
  if (parts[0] === "projects") {
    const project = parts[1];
    const secretsIndex = parts.indexOf("secrets");
    const versionsIndex = parts.indexOf("versions");
    const secret = secretsIndex >= 0 ? parts[secretsIndex + 1] : null;
    const version = versionsIndex >= 0 ? parts[versionsIndex + 1] : "latest";
    return secret ? { project, secret, version } : null;
  }
  return parts[0] ? { secret: parts[0], version: parts[1] || "latest" } : null;
}

function parseKeychainReference(reference) {
  const raw = reference.trim().slice("keychain://".length);
  const [pathPart, queryPart] = raw.split("?");
  const parts = pathPart.split("/").filter(Boolean).map(decodeURIComponent);
  if (!parts[0] || !parts[1]) return null;
  const query = new URLSearchParams(queryPart || "");
  return { service: parts[0], account: parts[1], keychain: query.get("keychain") || query.get("kc") || null };
}

function resolveExternalRef(value) {
  if (typeof value !== "string") return value;
  if (value.startsWith("gcp://")) {
    const parsed = parseGcpReference(value);
    if (!parsed) throw new Error(`Invalid GCP secret reference: ${value}`);
    const args = ["secrets", "versions", "access", parsed.version || "latest", "--secret", parsed.secret];
    if (parsed.project) args.push("--project", parsed.project);
    return run("gcloud", args).trim();
  }
  if (value.startsWith("keychain://")) {
    const parsed = parseKeychainReference(value);
    if (!parsed) throw new Error(`Invalid Keychain secret reference: ${value}`);
    const args = ["find-generic-password", "-s", parsed.service, "-a", parsed.account, "-w"];
    if (parsed.keychain) args.push(parsed.keychain);
    return run("/usr/bin/security", args).trim();
  }
  return value;
}

function valueForStorage(scope, owner, fieldPath, value, counts) {
  const state = secretState(value);
  counts[state] = (counts[state] || 0) + 1;
  if (!apply || state === "empty" || state === "op-ref") return { value, changed: false };

  const secret = state === "external-ref" ? resolveExternalRef(value) : value;
  const ref = upsertSecret(scope, owner, fieldPath, secret);
  return { value: ref, changed: true };
}

function readProviderRows() {
  return sqliteJson("SELECT id, provider, authType, name, email, data FROM providerConnections ORDER BY provider, name;")
    .map((row) => ({ ...row, data: JSON.parse(row.data || "{}") }));
}

function readProxyRows() {
  return sqliteJson("SELECT id, isActive, testStatus, data FROM proxyPools ORDER BY id;")
    .map((row) => ({ ...row, data: JSON.parse(row.data || "{}") }));
}

function readApiKeyRows() {
  return sqliteJson("SELECT id, key, name, machineId, isActive, createdAt FROM apiKeys ORDER BY createdAt;")
    .map((row) => ({ ...row }));
}

function readSettingsRow() {
  const rows = sqliteJson("SELECT data FROM settings WHERE id = 1;");
  return rows[0] ? JSON.parse(rows[0].data || "{}") : {};
}

function fingerprint(value) {
  if (!value || typeof value !== "string") return null;
  return `lookup-hmac:${createHmac("sha256", "9router-usage-lookup-v1").update(value).digest("hex").slice(0, 16)}`;
}

function apiKeyStorageId(value, keyRows) {
  if (!value || typeof value !== "string") return null;
  if (value.startsWith("key:") || value.startsWith("sha256:") || value.startsWith("lookup-hmac:")) return value;
  const direct = keyRows.find((row) => row.key === value);
  if (direct?.id) return `key:${direct.id}`;
  return fingerprint(value);
}

function migrateProviders(summary, detail) {
  for (const row of readProviderRows()) {
    let changed = false;
    const fields = [];
    for (const field of topSecretFields) {
      const result = valueForStorage("provider", row, field, row.data[field], summary.providerSecretFields);
      if (result.changed) {
        row.data[field] = result.value;
        changed = true;
      }
      fields.push(`${field}:${secretState(row.data[field])}`);
    }
    if (isPlainObject(row.data.providerSpecificData)) {
      for (const field of providerSpecificSecretFields) {
        const path = `providerSpecificData.${field}`;
        const result = valueForStorage("provider", row, path, row.data.providerSpecificData[field], summary.providerSecretFields);
        if (result.changed) {
          row.data.providerSpecificData[field] = result.value;
          changed = true;
        }
        fields.push(`${path}:${secretState(row.data.providerSpecificData[field])}`);
      }
    }
    if (apply && changed) {
      sqlite(`UPDATE providerConnections SET data = ${sqlQuote(JSON.stringify(row.data))}, updatedAt = ${sqlQuote(new Date().toISOString())} WHERE id = ${sqlQuote(row.id)};`);
      summary.changedProviderRows += 1;
    }
    detail.providers.push({ id: row.id, provider: row.provider, authType: row.authType, name: row.name, fields, changed });
  }
}

function migrateProxyPools(summary, detail) {
  for (const row of readProxyRows()) {
    let changed = false;
    const fields = [];
    for (const field of proxyPoolSecretFields) {
      const result = valueForStorage("proxy-pool", { id: row.id, name: row.data.name, type: row.data.type }, field, row.data[field], summary.proxyPoolSecretFields);
      if (result.changed) {
        row.data[field] = result.value;
        changed = true;
      }
      fields.push(`${field}:${secretState(row.data[field])}`);
    }
    if (apply && changed) {
      sqlite(`UPDATE proxyPools SET data = ${sqlQuote(JSON.stringify(row.data))}, updatedAt = ${sqlQuote(new Date().toISOString())} WHERE id = ${sqlQuote(row.id)};`);
      summary.changedProxyPoolRows += 1;
    }
    detail.proxyPools.push({ id: row.id, name: row.data.name, fields, changed });
  }
}

function migrateApiKeys(summary, detail) {
  for (const row of readApiKeyRows()) {
    const state = secretState(row.key);
    summary.apiKeySecretFields[state] = (summary.apiKeySecretFields[state] || 0) + 1;
    let changed = false;
    if (apply && (state === "raw" || state === "external-ref")) {
      const secret = state === "external-ref" ? resolveExternalRef(row.key) : row.key;
      const ref = upsertSecret("api-key", { id: row.id, name: row.name, type: "9router" }, "key", secret);
      sqlite(`UPDATE apiKeys SET key = ${sqlQuote(ref.ref)} WHERE id = ${sqlQuote(row.id)};`);
      changed = true;
      summary.changedApiKeyRows += 1;
    }
    detail.apiKeys.push({ id: row.id, name: row.name, state, changed });
  }
}

function migrateSettings(summary, detail) {
  const settings = readSettingsRow();
  let changed = false;
  const fields = [];
  for (const field of settingsSecretFields) {
    const result = valueForStorage("settings", { id: "settings", name: "local-settings", type: "settings" }, field, settings[field], summary.settingsSecretFields);
    if (result.changed) {
      settings[field] = result.value;
      changed = true;
    }
    fields.push(`${field}:${secretState(settings[field])}`);
  }
  if (apply && changed) {
    sqlite(`INSERT INTO settings(id, data) VALUES(1, ${sqlQuote(JSON.stringify(settings))}) ON CONFLICT(id) DO UPDATE SET data = excluded.data;`);
    summary.changedSettingsRows = 1;
  }
  detail.settings = { fields, changed };
}

function sanitizeUsage(summary, detail) {
  const keyRows = readApiKeyRows();
  const historyRows = sqliteJson("SELECT id, apiKey FROM usageHistory WHERE apiKey IS NOT NULL AND apiKey != '';");
  for (const row of historyRows) {
    const next = apiKeyStorageId(row.apiKey, keyRows);
    if (!next || next === row.apiKey) continue;
    summary.usageApiKeyFields.raw += 1;
    if (apply) {
      sqlite(`UPDATE usageHistory SET apiKey = ${sqlQuote(next)} WHERE id = ${row.id};`);
      summary.sanitizedUsageHistoryRows += 1;
    }
  }

  const dayRows = sqliteJson("SELECT dateKey, data FROM usageDaily;");
  for (const row of dayRows) {
    const day = JSON.parse(row.data || "{}");
    const nextByApiKey = {};
    let changed = false;
    for (const [oldKey, entry] of Object.entries(day.byApiKey || {})) {
      const oldApiKey = entry.apiKey;
      const nextApiKey = apiKeyStorageId(oldApiKey, keyRows);
      if (!nextApiKey || nextApiKey === oldApiKey) {
        nextByApiKey[oldKey] = entry;
        continue;
      }
      changed = true;
      const model = entry.rawModel || oldKey.split("|")[1] || "";
      const provider = entry.provider || oldKey.split("|")[2] || "unknown";
      const nextKey = `${nextApiKey}|${model}|${provider}`;
      const merged = nextByApiKey[nextKey] || { ...entry, requests: 0, promptTokens: 0, completionTokens: 0, cost: 0 };
      merged.apiKey = nextApiKey;
      merged.apiKeyKey = nextApiKey;
      merged.requests += entry.requests || 0;
      merged.promptTokens += entry.promptTokens || 0;
      merged.completionTokens += entry.completionTokens || 0;
      merged.cost += entry.cost || 0;
      nextByApiKey[nextKey] = merged;
    }
    if (changed) {
      day.byApiKey = nextByApiKey;
      if (apply) {
        sqlite(`UPDATE usageDaily SET data = ${sqlQuote(JSON.stringify(day))} WHERE dateKey = ${sqlQuote(row.dateKey)};`);
        summary.sanitizedUsageDailyRows += 1;
      }
    }
  }
  detail.usage = {
    historyRowsWithStoredApiKey: historyRows.length,
    sanitizedHistoryRows: summary.sanitizedUsageHistoryRows,
    sanitizedDailyRows: summary.sanitizedUsageDailyRows,
  };
}

function main() {
  if (!existsSync(dbPath)) throw new Error(`9Router DB not found: ${dbPath}`);
  mkdirSync(outRoot, { recursive: true });

  const summary = {
    mode: auditOnly ? "audit" : "apply",
    dbPath,
    vault,
    providerSecretFields: {},
    proxyPoolSecretFields: {},
    apiKeySecretFields: {},
    settingsSecretFields: {},
    usageApiKeyFields: { raw: 0 },
    changedProviderRows: 0,
    changedProxyPoolRows: 0,
    changedApiKeyRows: 0,
    changedSettingsRows: 0,
    sanitizedUsageHistoryRows: 0,
    sanitizedUsageDailyRows: 0,
    outRoot,
  };
  const detail = { providers: [], proxyPools: [], apiKeys: [], settings: null, usage: null };

  if (apply) {
    run(opBin, ["item", "create", "--vault", vault, "--dry-run", "--format", "json", "--template", "/dev/stdin"], {
      input: JSON.stringify({
        title: "9router/status/dry-run",
        category: "PASSWORD",
        fields: [{ id: "password", type: "CONCEALED", purpose: "PASSWORD", label: "password", value: "TEST_VALUE_DO_NOT_USE" }],
      }),
    });
    const backupDir = join(dirname(dbPath), "backups");
    mkdirSync(backupDir, { recursive: true });
    copyFileSync(dbPath, join(backupDir, `data.sqlite.before-1password-sync-${runId}`));
  }

  migrateProviders(summary, detail);
  migrateProxyPools(summary, detail);
  migrateApiKeys(summary, detail);
  migrateSettings(summary, detail);
  sanitizeUsage(summary, detail);

  writeFileSync(join(outRoot, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
  writeFileSync(join(outRoot, "secret-field-detail.json"), `${JSON.stringify(detail, null, 2)}\n`);
  writeFileSync(join(outRoot, "REPORT.md"), [
    "# 9Router 1Password Secret Sync",
    "",
    `Mode: ${summary.mode}`,
    `Vault: ${vault}`,
    `Provider secret fields: ${JSON.stringify(summary.providerSecretFields)}`,
    `Proxy pool secret fields: ${JSON.stringify(summary.proxyPoolSecretFields)}`,
    `API key fields: ${JSON.stringify(summary.apiKeySecretFields)}`,
    `Settings secret fields: ${JSON.stringify(summary.settingsSecretFields)}`,
    `Changed provider rows: ${summary.changedProviderRows}`,
    `Changed proxy pool rows: ${summary.changedProxyPoolRows}`,
    `Changed API key rows: ${summary.changedApiKeyRows}`,
    `Changed settings rows: ${summary.changedSettingsRows}`,
    `Sanitized usageHistory rows: ${summary.sanitizedUsageHistoryRows}`,
    `Sanitized usageDaily rows: ${summary.sanitizedUsageDailyRows}`,
    "",
    "No secret values are written to this report.",
    "",
    `Evidence: ${outRoot}`,
    "",
  ].join("\n"));

  console.log(join(outRoot, "REPORT.md"));
}

try {
  main();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
