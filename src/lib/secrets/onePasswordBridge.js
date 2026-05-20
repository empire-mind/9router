import { spawnSync } from "child_process";

const DEFAULT_VAULT = process.env.NINEROUTER_1PASSWORD_VAULT || "Empire";
const OP_BIN = process.env.NINEROUTER_OP_BIN || "op";
const BRIDGE_ENABLED = process.env.NINEROUTER_1PASSWORD_BRIDGE !== "false";
const DEFAULT_OP_TIMEOUT_MS = 15000;
const DEFAULT_OP_READ_TIMEOUT_MS = 10000;
const DEFAULT_READ_CACHE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_FAILED_READ_CACHE_TTL_MS = 30 * 1000;

const TOP_LEVEL_SECRET_FIELDS = ["apiKey", "accessToken", "refreshToken", "idToken"];
const PROVIDER_SPECIFIC_SECRET_FIELDS = ["copilotToken", "sessionToken", "ssoToken", "connectionProxyUrl"];
const BRIDGE_ERROR_CODE = "ONEPASSWORD_BRIDGE_UNAVAILABLE";
const SECRET_REF_PREFIXES = ["op://", "gcp://", "keychain://"];
const readCache = new Map();
const failedReadCache = new Map();

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function isSecretRef(value) {
  return isPlainObject(value) && value.source === "1password" && typeof value.ref === "string";
}

export function isOpUri(value) {
  return typeof value === "string" && value.startsWith("op://");
}

export function isStoredSecretReference(value) {
  if (isSecretRef(value)) return true;
  return typeof value === "string" && SECRET_REF_PREFIXES.some((prefix) => value.startsWith(prefix));
}

function shouldVaultize(value) {
  if (!BRIDGE_ENABLED) return false;
  if (typeof value !== "string") return false;
  if (!value.trim()) return false;
  if (isStoredSecretReference(value)) return false;
  if (value === "secretref-managed") return false;
  return true;
}

function safePart(value) {
  return String(value || "unknown")
    .toLowerCase()
    .replace(/[^a-z0-9_.@-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "unknown";
}

function itemTitle(conn, fieldPath) {
  return [
    "9router",
    safePart(conn.provider),
    safePart(conn.name || conn.email || conn.id),
    safePart(conn.id),
    safePart(fieldPath),
  ].join("/");
}

function scopedItemTitle(scope, owner, fieldPath) {
  return [
    "9router",
    safePart(scope),
    safePart(owner.provider || owner.type || "secret"),
    safePart(owner.name || owner.email || owner.id),
    safePart(owner.id),
    safePart(fieldPath),
  ].join("/");
}

function op(args, options = {}) {
  const result = spawnSync(OP_BIN, args, {
    input: options.input,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
    timeout: Number(options.timeout || process.env.NINEROUTER_OP_TIMEOUT_MS || DEFAULT_OP_TIMEOUT_MS),
    env: process.env,
  });
  if (result.status !== 0) {
    const message = (result.stderr || result.stdout || result.error?.message || "op command failed").trim();
    const error = new Error(message);
    error.code = BRIDGE_ERROR_CODE;
    throw error;
  }
  return result.stdout || "";
}

function opJson(args, options = {}) {
  const templateIndex = args.indexOf("-");
  const formattedArgs = templateIndex >= 0
    ? [...args.slice(0, templateIndex), "--format", "json", ...args.slice(templateIndex)]
    : [...args, "--format", "json"];
  const stdout = op(formattedArgs, options);
  return JSON.parse(stdout);
}

function readRef(ref) {
  const normalized = String(ref || "").trim();
  if (!normalized) return "";
  const now = Date.now();
  const cached = readCache.get(normalized);
  if (cached && cached.expiresAt > now) return cached.value;
  const failed = failedReadCache.get(normalized);
  if (failed && failed.expiresAt > now) throw failed.error;

  try {
    const value = op(["read", "--no-newline", normalized], {
      timeout: Number(process.env.NINEROUTER_OP_READ_TIMEOUT_MS || DEFAULT_OP_READ_TIMEOUT_MS),
    });
    failedReadCache.delete(normalized);
    readCache.set(normalized, {
      value,
      expiresAt: now + Number(process.env.NINEROUTER_OP_READ_CACHE_TTL_MS || DEFAULT_READ_CACHE_TTL_MS),
    });
    return value;
  } catch (error) {
    failedReadCache.set(normalized, {
      error,
      expiresAt: now + Number(process.env.NINEROUTER_OP_FAILED_READ_CACHE_TTL_MS || DEFAULT_FAILED_READ_CACHE_TTL_MS),
    });
    throw error;
  }
}

function tryReadRef(ref, fallback) {
  try {
    return readRef(ref);
  } catch {
    return fallback;
  }
}

function buildItemTemplate(conn, fieldPath, secret) {
  const title = itemTitle(conn, fieldPath);
  return buildScopedItemTemplate("provider", conn, fieldPath, secret, title);
}

function buildScopedItemTemplate(scope, owner, fieldPath, secret, title = scopedItemTitle(scope, owner, fieldPath)) {
  return {
    title,
    category: "PASSWORD",
    tags: ["9router", "9router-secret", `scope:${safePart(scope)}`, `provider:${safePart(owner.provider || owner.type || "unknown")}`],
    fields: [
      {
        id: "password",
        type: "CONCEALED",
        purpose: "PASSWORD",
        label: "password",
        value: secret,
      },
      {
        id: "notesPlain",
        type: "STRING",
        purpose: "NOTES",
        label: "notesPlain",
        value: [
          "Managed by 9Router 1Password bridge.",
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

function getItemIdFromRef(ref) {
  if (!ref || !ref.startsWith("op://")) return null;
  const parts = ref.split("/");
  return parts.length >= 4 ? parts[3] : null;
}

function createItem(conn, fieldPath, secret) {
  const template = buildItemTemplate(conn, fieldPath, secret);
  return createItemFromTemplate(template);
}

function createItemFromTemplate(template) {
  const item = opJson(["item", "create", "--vault", DEFAULT_VAULT, "--template", "/dev/stdin"], {
    input: JSON.stringify(template),
  });
  return {
    source: "1password",
    vault: DEFAULT_VAULT,
    itemId: item.id,
    field: "password",
    title: template.title,
    ref: `op://${DEFAULT_VAULT}/${item.id}/password`,
  };
}

function editItem(existingRef, conn, fieldPath, secret) {
  const itemId = existingRef?.itemId || getItemIdFromRef(existingRef?.ref);
  if (!itemId) return createItem(conn, fieldPath, secret);
  const template = buildItemTemplate(conn, fieldPath, secret);
  return editItemFromTemplate(existingRef, template);
}

function editItemFromTemplate(existingRef, template) {
  const itemId = existingRef?.itemId || getItemIdFromRef(existingRef?.ref);
  if (!itemId) return createItemFromTemplate(template);
  try {
    const item = opJson(["item", "edit", itemId, "--vault", existingRef.vault || DEFAULT_VAULT, "--template", "/dev/stdin"], {
      input: JSON.stringify(template),
    });
    if (existingRef?.ref) readCache.delete(existingRef.ref);
    return {
      source: "1password",
      vault: existingRef.vault || DEFAULT_VAULT,
      itemId: item.id || itemId,
      field: "password",
      title: template.title,
      ref: `op://${existingRef.vault || DEFAULT_VAULT}/${item.id || itemId}/password`,
    };
  } catch {
    return createItemFromTemplate(template);
  }
}

function vaultizeField(conn, storageConn, runtimeConn, fieldPath, existingRef) {
  const value = runtimeConn[fieldPath];
  if (!shouldVaultize(value)) return;
  storageConn[fieldPath] = isSecretRef(existingRef)
    ? editItem(existingRef, conn, fieldPath, value)
    : createItem(conn, fieldPath, value);
}

function vaultizeProviderSpecificField(conn, storageConn, runtimeConn, fieldName, existingRef) {
  const value = runtimeConn.providerSpecificData?.[fieldName];
  if (!shouldVaultize(value)) return;
  if (!storageConn.providerSpecificData) storageConn.providerSpecificData = {};
  storageConn.providerSpecificData[fieldName] = isSecretRef(existingRef)
    ? editItem(existingRef, conn, `providerSpecificData.${fieldName}`, value)
    : createItem(conn, `providerSpecificData.${fieldName}`, value);
}

export function vaultizeConnectionSecretsForStorage(conn, existingConn = null) {
  if (!BRIDGE_ENABLED) return conn;
  const storageConn = {
    ...conn,
    providerSpecificData: isPlainObject(conn.providerSpecificData) ? { ...conn.providerSpecificData } : conn.providerSpecificData,
  };

  for (const field of TOP_LEVEL_SECRET_FIELDS) {
    vaultizeField(conn, storageConn, conn, field, existingConn?.[field]);
  }

  for (const field of PROVIDER_SPECIFIC_SECRET_FIELDS) {
    vaultizeProviderSpecificField(conn, storageConn, conn, field, existingConn?.providerSpecificData?.[field]);
  }

  return storageConn;
}

export function hydrateConnectionSecretsForRuntime(conn) {
  if (!BRIDGE_ENABLED || !conn) return conn;
  const runtimeConn = {
    ...conn,
    providerSpecificData: isPlainObject(conn.providerSpecificData) ? { ...conn.providerSpecificData } : conn.providerSpecificData,
  };

  for (const field of TOP_LEVEL_SECRET_FIELDS) {
    const value = runtimeConn[field];
    if (isSecretRef(value)) runtimeConn[field] = tryReadRef(value.ref, value);
    else if (isOpUri(value)) runtimeConn[field] = tryReadRef(value, value);
  }

  if (runtimeConn.providerSpecificData) {
    for (const field of PROVIDER_SPECIFIC_SECRET_FIELDS) {
      const value = runtimeConn.providerSpecificData[field];
      if (isSecretRef(value)) runtimeConn.providerSpecificData[field] = tryReadRef(value.ref, value);
      else if (isOpUri(value)) runtimeConn.providerSpecificData[field] = tryReadRef(value, value);
    }
  }

  return runtimeConn;
}

export function vaultizeSecretForStorage({ scope, owner, fieldPath, value, existingRef = null }) {
  if (!shouldVaultize(value)) return value;
  const template = buildScopedItemTemplate(scope, owner || {}, fieldPath, value);
  const normalizedExistingRef = isOpUri(existingRef)
    ? { source: "1password", vault: DEFAULT_VAULT, ref: existingRef }
    : existingRef;
  return isSecretRef(normalizedExistingRef)
    ? editItemFromTemplate(normalizedExistingRef, template)
    : createItemFromTemplate(template);
}

export function hydrateSecretForRuntime(value) {
  if (!BRIDGE_ENABLED || !value) return value;
  if (isSecretRef(value)) return tryReadRef(value.ref, value);
  if (isOpUri(value)) return tryReadRef(value, value);
  return value;
}

export function onePasswordBridgeStatus() {
  if (!BRIDGE_ENABLED) return { enabled: false };
  try {
    op(["item", "create", "--vault", DEFAULT_VAULT, "--dry-run", "--format", "json", "--template", "/dev/stdin"], {
      input: JSON.stringify({
        title: "9router/status/dry-run",
        category: "PASSWORD",
        fields: [{ id: "password", type: "CONCEALED", purpose: "PASSWORD", label: "password", value: "TEST_VALUE_DO_NOT_USE" }],
      }),
    });
    return { enabled: true, signedIn: true, vault: DEFAULT_VAULT };
  } catch (error) {
    return { enabled: true, signedIn: false, vault: DEFAULT_VAULT, error: error.message };
  }
}

export function isOnePasswordBridgeUnavailable(error) {
  return !!error && error.code === BRIDGE_ERROR_CODE;
}
