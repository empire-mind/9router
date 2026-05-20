import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const ONE_PASSWORD_REF_PREFIX = "op://";
const GCP_SECRET_REF_PREFIX = "gcp://";
const KEYCHAIN_SECRET_REF_PREFIX = "keychain://";
const DEFAULT_OP_TIMEOUT_MS = 5000;
const DEFAULT_GCLOUD_TIMEOUT_MS = 10000;
const DEFAULT_KEYCHAIN_TIMEOUT_MS = 5000;

let cachedOpPath;
let warnedMissingCli = false;
let warnedReadFailure = false;
let warnedGcloudReadFailure = false;
let warnedKeychainReadFailure = false;
const secretCache = new Map();

export function isOnePasswordReference(value) {
  return typeof value === "string" && value.trim().startsWith(ONE_PASSWORD_REF_PREFIX);
}

export function isGcpSecretReference(value) {
  return typeof value === "string" && value.trim().startsWith(GCP_SECRET_REF_PREFIX);
}

export function isKeychainSecretReference(value) {
  return typeof value === "string" && value.trim().startsWith(KEYCHAIN_SECRET_REF_PREFIX);
}

export function isSecretReference(value) {
  return isOnePasswordReference(value) || isGcpSecretReference(value) || isKeychainSecretReference(value);
}

function opCandidates() {
  return [
    process.env.OP_CLI_PATH,
    path.join(os.homedir(), ".local/bin/op"),
    "/opt/homebrew/bin/op",
    "/usr/local/bin/op",
    "op",
  ].filter(Boolean);
}

function gcloudCandidates() {
  return [
    process.env.GCLOUD_CLI_PATH,
    path.join(os.homedir(), ".local/bin/gcloud"),
    "/opt/homebrew/bin/gcloud",
    "/usr/local/bin/gcloud",
    "/usr/bin/gcloud",
    "gcloud",
  ].filter(Boolean);
}

function findExecutable(candidates, args = ["--version"], timeout = 2000) {
  for (const candidate of candidates) {
    if (candidate.includes("/") && !fs.existsSync(candidate)) continue;
    try {
      execFileSync(candidate, args, {
        stdio: ["ignore", "ignore", "ignore"],
        timeout,
      });
      return candidate;
    } catch {}
  }
  return null;
}

function findOpCli() {
  if (cachedOpPath) return cachedOpPath;

  cachedOpPath = findExecutable(opCandidates());
  if (cachedOpPath) return cachedOpPath;

  if (!warnedMissingCli) {
    console.warn("[SECRETS] 1Password CLI not available; unresolved op:// references will fall back.");
    warnedMissingCli = true;
  }
  return null;
}

export function readOnePasswordSecret(reference) {
  if (!isOnePasswordReference(reference)) return null;

  const normalized = reference.trim();
  if (secretCache.has(normalized)) return secretCache.get(normalized);

  const op = findOpCli();
  if (!op) return null;

  try {
    const value = execFileSync(op, ["read", normalized], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: Number(process.env.OP_READ_TIMEOUT_MS || DEFAULT_OP_TIMEOUT_MS),
    }).trim();
    if (!value) return null;
    secretCache.set(normalized, value);
    return value;
  } catch {
    if (!warnedReadFailure) {
      console.warn("[SECRETS] 1Password secret reference could not be resolved; falling back.");
      warnedReadFailure = true;
    }
    return null;
  }
}

function parseGcpReference(reference) {
  const raw = reference.trim().slice(GCP_SECRET_REF_PREFIX.length);
  if (!raw) return null;

  const parts = raw.split("/").filter(Boolean);
  if (parts[0] === "projects") {
    const project = parts[1];
    const secretsIndex = parts.indexOf("secrets");
    const versionsIndex = parts.indexOf("versions");
    const secret = secretsIndex >= 0 ? parts[secretsIndex + 1] : null;
    const version = versionsIndex >= 0 ? parts[versionsIndex + 1] : "latest";
    if (!project || !secret) return null;
    return { project, secret, version: version || "latest" };
  }

  const [secret, version = "latest"] = parts;
  return secret ? { secret, version } : null;
}

export function readGcpSecret(reference) {
  if (!isGcpSecretReference(reference)) return null;

  const normalized = reference.trim();
  if (secretCache.has(normalized)) return secretCache.get(normalized);

  const parsed = parseGcpReference(normalized);
  if (!parsed) return null;

  const gcloud = findExecutable(gcloudCandidates());
  if (!gcloud) {
    if (!warnedGcloudReadFailure) {
      console.warn("[SECRETS] gcloud CLI not available; unresolved gcp:// references will fall back.");
      warnedGcloudReadFailure = true;
    }
    return null;
  }

  const args = [
    "secrets",
    "versions",
    "access",
    parsed.version || "latest",
    "--secret",
    parsed.secret,
  ];
  if (parsed.project) args.push("--project", parsed.project);

  try {
    const value = execFileSync(gcloud, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: Number(process.env.GCP_SECRET_READ_TIMEOUT_MS || DEFAULT_GCLOUD_TIMEOUT_MS),
    }).trim();
    if (!value) return null;
    secretCache.set(normalized, value);
    return value;
  } catch {
    if (!warnedGcloudReadFailure) {
      console.warn("[SECRETS] GCP Secret Manager reference could not be resolved; falling back.");
      warnedGcloudReadFailure = true;
    }
    return null;
  }
}

function parseKeychainReference(reference) {
  const raw = reference.trim().slice(KEYCHAIN_SECRET_REF_PREFIX.length);
  if (!raw) return null;

  const [pathPart, queryPart] = raw.split("?");
  const parts = pathPart.split("/").filter(Boolean).map(decodeURIComponent);
  const service = parts[0];
  const account = parts[1];
  if (!service || !account) return null;

  const query = new URLSearchParams(queryPart || "");
  const keychain = query.get("keychain") || query.get("kc") || null;
  return { service, account, keychain };
}

export function readKeychainSecret(reference) {
  if (!isKeychainSecretReference(reference)) return null;

  const normalized = reference.trim();
  if (secretCache.has(normalized)) return secretCache.get(normalized);

  const parsed = parseKeychainReference(normalized);
  if (!parsed) return null;

  const keychains = parsed.keychain
    ? [parsed.keychain]
    : ["/Library/Keychains/System.keychain", null];

  for (const keychain of keychains) {
    const args = [
      "find-generic-password",
      "-s",
      parsed.service,
      "-a",
      parsed.account,
      "-w",
    ];
    if (keychain) args.push(keychain);

    try {
      const value = execFileSync("/usr/bin/security", args, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
        timeout: Number(process.env.KEYCHAIN_SECRET_READ_TIMEOUT_MS || DEFAULT_KEYCHAIN_TIMEOUT_MS),
      }).trim();
      if (!value) continue;
      secretCache.set(normalized, value);
      return value;
    } catch {}
  }

  if (!warnedKeychainReadFailure) {
    console.warn("[SECRETS] Keychain secret reference could not be resolved; falling back.");
    warnedKeychainReadFailure = true;
  }
  return null;
}

export function resolveSecretValue(value) {
  if (value === undefined || value === null || value === "") return null;
  if (isOnePasswordReference(value)) return readOnePasswordSecret(value);
  if (isGcpSecretReference(value)) return readGcpSecret(value);
  if (isKeychainSecretReference(value)) return readKeychainSecret(value);
  return value;
}

export function resolveSecretFromEnv(...envNames) {
  for (const name of envNames) {
    const resolved = resolveSecretValue(process.env[name]);
    if (resolved) return resolved;
  }
  return null;
}
