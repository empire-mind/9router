import { NextResponse } from "next/server";
import { createProxyPool } from "@/models";
import { randomBytes } from "node:crypto";

const VERCEL_API = "https://api.vercel.com";
const RELAY_ALLOWED_HOSTS = [
  "api.openai.com",
  "api.anthropic.com",
  "api.deepseek.com",
  "api.groq.com",
  "api.mistral.ai",
  "api.fireworks.ai",
  "api.cohere.ai",
  "api.together.xyz",
  "generativelanguage.googleapis.com",
  "api.minimax.io",
  "api.minimaxi.com",
  "api.deepgram.com",
  "api.elevenlabs.io",
  "api.inworld.ai",
  "openrouter.ai",
];

// Relay function source code deployed to Vercel
// Forwards requests to target URL specified in x-relay-target header
function buildRelayFunctionCode(relayToken) {
  return `
export const config = { runtime: "edge" };

const RELAY_TOKEN = ${JSON.stringify(relayToken)};
const ALLOWED_HOSTS = new Set(${JSON.stringify(RELAY_ALLOWED_HOSTS)});
const PRIVATE_HOST_RE = /^(localhost|127\\.|10\\.|192\\.168\\.|169\\.254\\.|172\\.(1[6-9]|2\\d|3[01])\\.|0\\.|::1$|\\[::1\\]$)/i;

export default async function handler(req) {
  if (req.headers.get("x-relay-token") !== RELAY_TOKEN) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "content-type": "application/json" },
    });
  }

  const target = req.headers.get("x-relay-target");
  const relayPath = req.headers.get("x-relay-path") || "/";
  if (!target) {
    return new Response(JSON.stringify({ error: "Missing x-relay-target header" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }

  let targetUrl;
  try {
    const parsed = new URL(target.replace(/\\/$/, "") + relayPath);
    if (parsed.protocol !== "https:") throw new Error("Only https targets are allowed");
    if (PRIVATE_HOST_RE.test(parsed.hostname)) throw new Error("Private targets are blocked");
    if (!ALLOWED_HOSTS.has(parsed.hostname)) throw new Error("Target host is not allowed");
    targetUrl = parsed.toString();
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message || "Invalid target" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }

  const headers = new Headers(req.headers);
  headers.delete("x-relay-target");
  headers.delete("x-relay-path");
  headers.delete("x-relay-token");
  headers.delete("host");

  const response = await fetch(targetUrl, {
    method: req.method,
    headers,
    body: req.method !== "GET" && req.method !== "HEAD" ? req.body : undefined,
    duplex: "half",
  });

  return new Response(response.body, {
    status: response.status,
    headers: response.headers,
  });
}
`;
}

async function pollDeployment(deploymentId, token, maxMs = 120000) {
  const start = Date.now();
  while (Date.now() - start < maxMs) {
    const res = await fetch(`${VERCEL_API}/v13/deployments/${deploymentId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    if (data.readyState === "READY") return data;
    if (data.readyState === "ERROR" || data.readyState === "CANCELED") {
      throw new Error(`Deployment failed: ${data.readyState}`);
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  throw new Error("Deployment timed out");
}

// POST /api/proxy-pools/vercel-deploy
export async function POST(request) {
  try {
    const body = await request.json();
    const vercelToken = body.vercelToken;
    const projectName = body.projectName?.trim() || `relay-${Date.now().toString(36)}`;

    if (!vercelToken) {
      return NextResponse.json({ error: "Vercel API token is required" }, { status: 400 });
    }
    const relayToken = randomBytes(32).toString("base64url");

    // Deploy relay function to Vercel
    const deployRes = await fetch(`${VERCEL_API}/v13/deployments`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${vercelToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name: projectName,
        files: [
          {
            file: "api/relay.js",
            data: buildRelayFunctionCode(relayToken),
          },
          {
            file: "package.json",
            data: JSON.stringify({ name: projectName, version: "1.0.0" }),
          },
          {
            file: "vercel.json",
            data: JSON.stringify({
              rewrites: [{ source: "/(.*)", destination: "/api/relay" }],
            }),
          },
        ],
        projectSettings: {
          framework: null,
        },
        target: "production",
      }),
    });

    if (!deployRes.ok) {
      const err = await deployRes.json().catch(() => ({}));
      return NextResponse.json(
        { error: err.error?.message || "Failed to create Vercel deployment" },
        { status: deployRes.status }
      );
    }

    const deployment = await deployRes.json();
    const deploymentId = deployment.id || deployment.uid;

    // Disable deployment protection (Vercel Authentication)
    const projectId = deployment.projectId || projectName;
    await fetch(`${VERCEL_API}/v9/projects/${projectId}`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${vercelToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ssoProtection: null }),
    });

    // Poll until deployment is ready
    const ready = await pollDeployment(deploymentId, vercelToken);
    const deployUrl = `https://${ready.url}`;

    // Create proxy pool entry with type vercel
    const proxyPool = await createProxyPool({
      name: projectName,
      proxyUrl: deployUrl,
      relayToken,
      type: "vercel",
      noProxy: "",
      isActive: true,
      strictProxy: false,
    });

    return NextResponse.json({
      proxyPool: {
        ...proxyPool,
        proxyUrl: undefined,
        relayToken: undefined,
        hasProxyUrl: true,
        relayTokenConfigured: true,
      },
      deployUrl,
    }, { status: 201 });
  } catch (error) {
    console.log("Error deploying Vercel relay:", error);
    return NextResponse.json({ error: error.message || "Deploy failed" }, { status: 500 });
  }
}
