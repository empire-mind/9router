import { SignJWT, jwtVerify } from "jose";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { DATA_DIR } from "@/lib/dataDir";
import { resolveSecretFromEnv } from "../secrets/onePassword.js";

const KEYCHAIN_SERVICE = "halvo-shared";
const KEYCHAIN_ACCOUNT = "9ROUTER_JWT_SECRET";
const SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain";
const LOGIN_KEYCHAIN_SERVICE = "9router";
const LOGIN_KEYCHAIN_ACCOUNT = "jwt-secret";
let SECRET_KEY;
let warnedEphemeralSecret = false;

function readKeychainSecret(service, account, keychain) {
  try {
    const args = ["find-generic-password", "-s", service, "-a", account, "-w"];
    if (keychain) args.push(keychain);
    const value = execFileSync("/usr/bin/security", args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return value || null;
  } catch {
    return null;
  }
}

function writeKeychainSecret(service, account, secret, keychain) {
  const args = ["add-generic-password", "-U", "-s", service, "-a", account, "-w", secret];
  if (keychain) args.push(keychain);
  try {
    execFileSync("/usr/bin/security", args, {
      stdio: ["ignore", "ignore", "ignore"],
    });
    return true;
  } catch {
    return false;
  }
}

function loadMacJwtSecret(file) {
  const systemSecret = readKeychainSecret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, SYSTEM_KEYCHAIN);
  if (systemSecret) return systemSecret;

  const loginSecret = readKeychainSecret(LOGIN_KEYCHAIN_SERVICE, LOGIN_KEYCHAIN_ACCOUNT);
  if (loginSecret) return loginSecret;

  let migratedSecret = null;
  try {
    migratedSecret = fs.readFileSync(file, "utf8").trim();
  } catch {}

  if (migratedSecret) {
    try {
      fs.rmSync(file, { force: true });
    } catch {}
  }

  const generated = crypto.randomBytes(32).toString("hex");
  const keychainStored =
    writeKeychainSecret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, generated, SYSTEM_KEYCHAIN) ||
    writeKeychainSecret(LOGIN_KEYCHAIN_SERVICE, LOGIN_KEYCHAIN_ACCOUNT, generated);

  if (keychainStored) return generated;

  if (!warnedEphemeralSecret) {
    console.warn("[AUTH] Keychain write unavailable; using an in-memory JWT secret for this process only.");
    warnedEphemeralSecret = true;
  }
  return generated;
}

function loadJwtSecret() {
  const configuredSecret = resolveSecretFromEnv(
    "JWT_SECRET",
    "OP_9ROUTER_JWT_SECRET_REF",
    "ONEPASSWORD_9ROUTER_JWT_SECRET_REF",
    "ONEPASSWORD_JWT_SECRET_REF"
  );
  if (configuredSecret) return configuredSecret;

  const file = path.join(DATA_DIR, "jwt-secret");
  if (process.platform === "darwin") {
    return loadMacJwtSecret(file);
  }
  try {
    return fs.readFileSync(file, "utf8").trim();
  } catch {}
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const generated = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(file, generated, { mode: 0o600 });
  return generated;
}

function getSecretKey() {
  if (!SECRET_KEY) {
    SECRET_KEY = new TextEncoder().encode(loadJwtSecret());
  }
  return SECRET_KEY;
}

export function shouldUseSecureCookie(request) {
  const forceSecureCookie = process.env.AUTH_COOKIE_SECURE === "true";
  const forwardedProto = request?.headers?.get?.("x-forwarded-proto");
  const isHttpsRequest = forwardedProto === "https";
  return forceSecureCookie || isHttpsRequest;
}

export async function createDashboardAuthToken(claims = {}) {
  return new SignJWT({ authenticated: true, ...claims })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("24h")
    .sign(getSecretKey());
}

export async function verifyDashboardAuthToken(token) {
  if (!token) return false;
  try {
    await jwtVerify(token, getSecretKey());
    return true;
  } catch {
    return false;
  }
}

export async function getDashboardAuthSession(token) {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, getSecretKey());
    return payload;
  } catch {
    return null;
  }
}

export async function setDashboardAuthCookie(cookieStore, request, claims = {}) {
  const token = await createDashboardAuthToken(claims);
  cookieStore.set("auth_token", token, {
    httpOnly: true,
    secure: shouldUseSecureCookie(request),
    sameSite: "lax",
    path: "/",
  });
}

export function clearDashboardAuthCookie(cookieStore) {
  cookieStore.delete("auth_token");
}
