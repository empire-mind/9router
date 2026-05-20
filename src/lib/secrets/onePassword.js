import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const ONE_PASSWORD_REF_PREFIX = "op://";
const DEFAULT_OP_TIMEOUT_MS = 5000;

let cachedOpPath;
let warnedMissingCli = false;
let warnedReadFailure = false;
const secretCache = new Map();

export function isOnePasswordReference(value) {
  return typeof value === "string" && value.trim().startsWith(ONE_PASSWORD_REF_PREFIX);
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

function canRunOp(candidate) {
  try {
    execFileSync(candidate, ["--version"], {
      stdio: ["ignore", "ignore", "ignore"],
      timeout: 2000,
    });
    return true;
  } catch {
    return false;
  }
}

function findOpCli() {
  if (cachedOpPath) return cachedOpPath;

  for (const candidate of opCandidates()) {
    if (candidate.includes("/") && !fs.existsSync(candidate)) continue;
    if (canRunOp(candidate)) {
      cachedOpPath = candidate;
      return cachedOpPath;
    }
  }

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

export function resolveSecretValue(value) {
  if (value === undefined || value === null || value === "") return null;
  if (isOnePasswordReference(value)) return readOnePasswordSecret(value);
  return value;
}

export function resolveSecretFromEnv(...envNames) {
  for (const name of envNames) {
    const resolved = resolveSecretValue(process.env[name]);
    if (resolved) return resolved;
  }
  return null;
}
