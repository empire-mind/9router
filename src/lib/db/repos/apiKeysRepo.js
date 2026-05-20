import { v4 as uuidv4 } from "uuid";
import { getAdapter } from "../driver.js";
import { createHmac } from "node:crypto";
import { hydrateSecretForRuntime, isStoredSecretReference, vaultizeSecretForStorage } from "../../secrets/onePasswordBridge.js";

function apiKeyFingerprint(key) {
  if (!key || typeof key !== "string") return "";
  return `lookup-hmac:${createHmac("sha256", "9router-usage-lookup-v1").update(key).digest("hex").slice(0, 16)}`;
}

function rowToKey(row) {
  if (!row) return null;
  const storedReference = isStoredSecretReference(row.key);
  const hydratedKey = hydrateSecretForRuntime(row.key);
  const unresolved = storedReference && hydratedKey === row.key;
  return {
    id: row.id,
    key: storedReference ? "" : hydratedKey,
    keyRef: storedReference ? row.key : null,
    keyAvailable: !unresolved,
    keyFingerprint: storedReference || unresolved ? "" : apiKeyFingerprint(hydratedKey),
    name: row.name,
    machineId: row.machineId,
    isActive: row.isActive === 1 || row.isActive === true,
    createdAt: row.createdAt,
  };
}

export async function getApiKeys() {
  const db = await getAdapter();
  const rows = db.all(`SELECT * FROM apiKeys ORDER BY createdAt ASC`);
  return rows.map(rowToKey);
}

export async function getApiKeyById(id) {
  const db = await getAdapter();
  const row = db.get(`SELECT * FROM apiKeys WHERE id = ?`, [id]);
  return rowToKey(row);
}

export async function createApiKey(name, machineId) {
  if (!machineId) throw new Error("machineId is required");
  const db = await getAdapter();
  const { generateApiKeyWithMachine } = await import("@/shared/utils/apiKey");
  const result = generateApiKeyWithMachine(machineId);
  const id = uuidv4();
  const ref = vaultizeSecretForStorage({
    scope: "api-key",
    owner: { id, name, type: "9router" },
    fieldPath: "key",
    value: result.key,
  });
  const apiKey = {
    id,
    name,
    key: result.key,
    keyRef: ref?.ref || null,
    machineId,
    isActive: true,
    createdAt: new Date().toISOString(),
  };
  db.run(
    `INSERT INTO apiKeys(id, key, name, machineId, isActive, createdAt) VALUES(?, ?, ?, ?, ?, ?)`,
    [apiKey.id, ref?.ref || apiKey.key, apiKey.name, apiKey.machineId, 1, apiKey.createdAt]
  );
  return apiKey;
}

export async function updateApiKey(id, data) {
  const db = await getAdapter();
  let result = null;
  db.transaction(() => {
    const row = db.get(`SELECT * FROM apiKeys WHERE id = ?`, [id]);
    if (!row) return;
    const merged = { ...rowToKey(row), ...data };
    let keyForStorage = row.key;
    if (data.key) {
      const ref = vaultizeSecretForStorage({
        scope: "api-key",
        owner: { id, name: merged.name, type: "9router" },
        fieldPath: "key",
        value: data.key,
        existingRef: isStoredSecretReference(row.key) ? { ref: row.key } : null,
      });
      keyForStorage = ref?.ref || data.key;
    }
    db.run(
      `UPDATE apiKeys SET key = ?, name = ?, machineId = ?, isActive = ? WHERE id = ?`,
      [keyForStorage, merged.name, merged.machineId, merged.isActive ? 1 : 0, id]
    );
    result = merged;
  });
  return result;
}

export async function deleteApiKey(id) {
  const db = await getAdapter();
  const res = db.run(`DELETE FROM apiKeys WHERE id = ?`, [id]);
  return (res?.changes ?? 0) > 0;
}

export async function validateApiKey(key) {
  const db = await getAdapter();
  const rows = db.all(`SELECT key, isActive FROM apiKeys WHERE isActive = 1`);
  for (const row of rows) {
    const storedKey = hydrateSecretForRuntime(row.key);
    if (isStoredSecretReference(row.key) && storedKey === row.key) continue;
    if (storedKey === key) return true;
  }
  return false;
}

export function getApiKeyFingerprint(key) {
  return apiKeyFingerprint(key);
}
