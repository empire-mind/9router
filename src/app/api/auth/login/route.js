import { NextResponse } from "next/server";
import { getSettings } from "@/lib/localDb";
import bcrypt from "bcryptjs";
import { cookies } from "next/headers";
import { setDashboardAuthCookie } from "@/lib/auth/dashboardSession";
import { isOidcConfigured } from "@/lib/auth/oidc";

const MAX_FAILED_LOGINS = 5;
const LOGIN_WINDOW_MS = 5 * 60 * 1000;
const loginAttempts = new Map();

function clientKey(request) {
  const forwardedFor = request.headers.get("x-forwarded-for");
  if (forwardedFor) return forwardedFor.split(",")[0].trim();
  return request.headers.get("x-real-ip") || request.headers.get("host") || "unknown";
}

function getAttemptState(key, now = Date.now()) {
  const current = loginAttempts.get(key);
  if (!current || now >= current.resetAt) {
    const resetAt = now + LOGIN_WINDOW_MS;
    const fresh = { count: 0, resetAt };
    loginAttempts.set(key, fresh);
    return fresh;
  }
  return current;
}

function retryAfterSeconds(state, now = Date.now()) {
  return Math.max(1, Math.ceil((state.resetAt - now) / 1000));
}

function tooManyAttempts(key, now = Date.now()) {
  const state = getAttemptState(key, now);
  return state.count >= MAX_FAILED_LOGINS ? state : null;
}

function recordFailedAttempt(key, now = Date.now()) {
  const state = getAttemptState(key, now);
  state.count += 1;
  return state;
}

function throttledResponse(state) {
  return NextResponse.json(
    { error: "Too many login attempts. Try again later." },
    {
      status: 429,
      headers: { "Retry-After": String(retryAfterSeconds(state)) },
    },
  );
}

function clearAttempts(key) {
  loginAttempts.delete(key);
}

function isTunnelRequest(request, settings) {
  const host = (request.headers.get("host") || "").split(":")[0].toLowerCase();
  const tunnelHost = settings.tunnelUrl ? new URL(settings.tunnelUrl).hostname.toLowerCase() : "";
  const tailscaleHost = settings.tailscaleUrl ? new URL(settings.tailscaleUrl).hostname.toLowerCase() : "";
  return (tunnelHost && host === tunnelHost) || (tailscaleHost && host === tailscaleHost);
}

export async function POST(request) {
  try {
    const { password } = await request.json();
    const settings = await getSettings();
    const key = clientKey(request);
    const throttled = tooManyAttempts(key);
    if (throttled) return throttledResponse(throttled);

    // Block login via tunnel/tailscale if dashboard access is disabled
    if (isTunnelRequest(request, settings) && settings.tunnelDashboardAccess !== true) {
      return NextResponse.json({ error: "Dashboard access via tunnel is disabled" }, { status: 403 });
    }

    const storedHash = settings.password;

    if (settings.authMode === "oidc" && isOidcConfigured(settings)) {
      return NextResponse.json({ error: "Password login is disabled. Use OIDC sign in." }, { status: 403 });
    }

    let isValid = false;
    if (storedHash) {
      isValid = await bcrypt.compare(password, storedHash);
    } else {
      const initialPassword = process.env.INITIAL_PASSWORD;
      if (!initialPassword) {
        return NextResponse.json({ error: "Dashboard password is not configured" }, { status: 503 });
      }
      isValid = password === initialPassword;
    }

    if (isValid) {
      const cookieStore = await cookies();
      await setDashboardAuthCookie(cookieStore, request);
      clearAttempts(key);

      return NextResponse.json({ success: true });
    }

    const failedState = recordFailedAttempt(key);
    if (failedState.count >= MAX_FAILED_LOGINS) return throttledResponse(failedState);
    return NextResponse.json({ error: "Invalid password" }, { status: 401 });
  } catch (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export const __test__ = {
  clearAttempts,
  loginAttempts,
};
