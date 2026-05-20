"use server";

import { NextResponse } from "next/server";
import { exec, spawn } from "child_process";
import { promisify } from "util";
import fs from "fs/promises";
import path from "path";
import os from "os";

const execAsync = promisify(exec);

// OpenClaw 2026.5.x writes agents[].model as either a plain string
// (legacy) or as an object `{ primary, fallbacks }`. Normalize to the
// string id so downstream consumers can call `.startsWith()` safely.
const resolveAgentModel = (m) => {
  if (typeof m === "string") return m;
  if (m && typeof m === "object") return m.primary ?? "";
  return "";
};

const getOpenClawDir = () => path.join(os.homedir(), ".openclaw");
const getOpenClawSettingsPath = () => path.join(getOpenClawDir(), "openclaw.json");
const NINE_ROUTER_API_KEY_REF = {
  source: "exec",
  provider: "onepassword",
  id: "NINE_ROUTER_API_KEY",
};

const timestamp = () => new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "T");

const backupFile = async (filePath) => {
  try {
    const content = await fs.readFile(filePath, "utf-8");
    const backupPath = `${filePath}.bak-${timestamp()}`;
    await fs.writeFile(backupPath, content, { mode: 0o600 });
    return backupPath;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
};

const ensureDefaultModelObject = (defaults) => {
  if (typeof defaults.model === "string") {
    defaults.model = { primary: defaults.model };
  } else if (!defaults.model || typeof defaults.model !== "object" || Array.isArray(defaults.model)) {
    defaults.model = {};
  }
};

const remove9RouterAgentModel = (agent) => {
  if (typeof agent.model === "string") {
    if (!agent.model.startsWith("9router/")) return agent;
    const { model: _, ...rest } = agent;
    return rest;
  }

  if (agent.model && typeof agent.model === "object" && !Array.isArray(agent.model)) {
    const nextModel = { ...agent.model };
    if (typeof nextModel.primary === "string" && nextModel.primary.startsWith("9router/")) {
      delete nextModel.primary;
    }
    if (Object.keys(nextModel).length === 0) {
      const { model: _, ...rest } = agent;
      return rest;
    }
    return { ...agent, model: nextModel };
  }

  return agent;
};

const parseJsonOutput = (stdout) => {
  const trimmed = String(stdout || "").trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    const line = trimmed.split(/\r?\n/).reverse().find((entry) => entry.trim().startsWith("{"));
    return line ? JSON.parse(line) : null;
  }
};

const runOpenClawConfigDryRun = (patch) => new Promise((resolve, reject) => {
  const child = spawn("openclaw", ["config", "patch", "--stdin", "--dry-run", "--json", "--allow-exec"], {
    env: process.env,
    windowsHide: true,
  });
  let stdout = "";
  let stderr = "";

  child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
  child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
  child.on("error", reject);
  child.on("close", (code) => {
    if (code !== 0) {
      reject(new Error((stderr || stdout || `openclaw config patch failed with code ${code}`).trim()));
      return;
    }
    try {
      const result = parseJsonOutput(stdout);
      if (result && (result.schema === false || result.resolvability === false || result.resolvabilityComplete === false)) {
        reject(new Error(`OpenClaw dry-run failed: ${JSON.stringify(result)}`));
        return;
      }
      resolve(result);
    } catch (error) {
      reject(error);
    }
  });
  child.stdin.end(JSON.stringify(patch));
});

// Check if openclaw CLI is installed (via which/where or config file exists)
const checkOpenClawInstalled = async () => {
  try {
    const isWindows = os.platform() === "win32";
    const command = isWindows ? "where openclaw" : "which openclaw";
    // On Windows, inject %APPDATA%\npm into PATH so npm global packages are found
    const env = isWindows
      ? { ...process.env, PATH: `${process.env.APPDATA}\\npm;${process.env.PATH}` }
      : process.env;
    await execAsync(command, { windowsHide: true, env });
    return true;
  } catch {
    try {
      await fs.access(getOpenClawSettingsPath());
      return true;
    } catch {
      return false;
    }
  }
};

const checkOpenClawCliAvailable = async () => {
  try {
    const isWindows = os.platform() === "win32";
    const command = isWindows ? "where openclaw" : "which openclaw";
    await execAsync(command, { windowsHide: true, env: process.env });
    return true;
  } catch {
    return false;
  }
};

// Read current settings.json
const readSettings = async () => {
  try {
    const settingsPath = getOpenClawSettingsPath();
    const content = await fs.readFile(settingsPath, "utf-8");
    return JSON.parse(content);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
};

// Check if settings has 9Router config
const has9RouterConfig = (settings) => {
  if (!settings || !settings.models || !settings.models.providers) return false;
  return !!settings.models.providers["9router"];
};

// Read per-agent models.json and return current model id (without "9router/" prefix)
const readAgentModel = async (agentDir) => {
  try {
    const modelsPath = path.join(agentDir, "models.json");
    const content = await fs.readFile(modelsPath, "utf-8");
    const data = JSON.parse(content);
    const models = data?.providers?.["9router"]?.models;
    return models?.[0]?.id || null;
  } catch {
    return null;
  }
};

// GET - Check openclaw CLI and read current settings
export async function GET() {
  try {
    const isInstalled = await checkOpenClawInstalled();
    
    if (!isInstalled) {
      return NextResponse.json({
        installed: false,
        settings: null,
        message: "Open Claw CLI is not installed",
      });
    }

    const settings = await readSettings();

    // Enrich agents list with current per-agent model from models.json.
    // Coerce agent.model to its string id when OpenClaw stores it as
    // `{ primary, fallbacks }` so downstream `.startsWith()` calls work.
    const agentList = settings?.agents?.list || [];
    const enrichedAgents = await Promise.all(
      agentList.map(async (agent) => {
        const agentModel = agent.agentDir ? await readAgentModel(agent.agentDir) : null;
        return { ...agent, model: resolveAgentModel(agent.model), currentModel: agentModel };
      })
    );

    return NextResponse.json({
      installed: true,
      settings,
      agents: enrichedAgents,
      has9Router: has9RouterConfig(settings),
      settingsPath: getOpenClawSettingsPath(),
    });
  } catch (error) {
    console.log("Error checking openclaw settings:", error);
    return NextResponse.json({ error: "Failed to check openclaw settings" }, { status: 500 });
  }
}

// Write per-agent models.json
const writeAgentModels = async (agentDir, model, baseUrl) => {
  await fs.mkdir(agentDir, { recursive: true });
  const modelsPath = path.join(agentDir, "models.json");
  let existing = {};
  try {
    const content = await fs.readFile(modelsPath, "utf-8");
    existing = JSON.parse(content);
  } catch { /* No existing */ }

  if (!existing.providers) existing.providers = {};
  existing.providers["9router"] = {
    baseUrl,
    apiKey: NINE_ROUTER_API_KEY_REF,
    api: "openai-completions",
    models: [{ id: model, name: model.split("/").pop() || model }],
  };
  await fs.writeFile(modelsPath, JSON.stringify(existing, null, 2));
};

const removeAgentModels = async (agentDir) => {
  try {
    const modelsPath = path.join(agentDir, "models.json");
    const content = await fs.readFile(modelsPath, "utf-8");
    const existing = JSON.parse(content);
    if (!existing?.providers?.["9router"]) return;

    await backupFile(modelsPath);
    delete existing.providers["9router"];
    if (Object.keys(existing.providers).length === 0) delete existing.providers;
    await fs.writeFile(modelsPath, JSON.stringify(existing, null, 2));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
};

// POST - Update 9Router settings (merge with existing settings)
export async function POST(request) {
  try {
    // agentModels: { [agentId]: modelId } for per-agent override
    const { baseUrl, model, agentModels = {} } = await request.json();
    
    if (!baseUrl || !model) {
      return NextResponse.json({ error: "baseUrl and model are required" }, { status: 400 });
    }

    const openclawDir = getOpenClawDir();
    const settingsPath = getOpenClawSettingsPath();
    const cliAvailable = await checkOpenClawCliAvailable();

    if (!cliAvailable) {
      return NextResponse.json(
        { error: "OpenClaw CLI is required to validate 1Password SecretRef before writing settings" },
        { status: 503 }
      );
    }

    await fs.mkdir(openclawDir, { recursive: true });

    let settings = {};
    try {
      const existingSettings = await fs.readFile(settingsPath, "utf-8");
      settings = JSON.parse(existingSettings);
    } catch { /* No existing settings */ }

    if (!settings.agents) settings.agents = {};
    if (!settings.agents.defaults) settings.agents.defaults = {};
    ensureDefaultModelObject(settings.agents.defaults);
    if (!settings.agents.defaults.models) settings.agents.defaults.models = {};
    if (!settings.models) settings.models = {};
    if (!settings.models.providers) settings.models.providers = {};

    const normalizedBaseUrl = baseUrl.endsWith("/v1") ? baseUrl : `${baseUrl}/v1`;
    const fullModelId = `9router/${model}`;

    // Remove all old 9router/* entries from agents.defaults.models
    Object.keys(settings.agents.defaults.models)
      .filter((k) => k.startsWith("9router/"))
      .forEach((k) => { delete settings.agents.defaults.models[k]; });

    // Update default model
    settings.agents.defaults.model.primary = fullModelId;

    // Collect all unique models (default + per-agent)
    const allModelIds = new Set([model]);
    Object.values(agentModels).forEach((m) => { if (m) allModelIds.add(m); });

    // Add fresh 9router models to allowlist
    allModelIds.forEach((m) => {
      settings.agents.defaults.models[`9router/${m}`] = {};
    });

    // Remove old 9router model from each agent in agents.list. The
    // model field may be a plain string or `{ primary, fallbacks }`.
    if (settings.agents.list) {
      settings.agents.list = settings.agents.list.map((agent) => {
        if (resolveAgentModel(agent.model).startsWith("9router/")) {
          const { model: _, ...rest } = agent;
          return rest;
        }
        return agent;
      });
    }

    // Update models.providers.9router with all models
    const providerConfig = {
      baseUrl: normalizedBaseUrl,
      apiKey: NINE_ROUTER_API_KEY_REF,
      api: "openai-completions",
      models: [...allModelIds].map((m) => ({ id: m, name: m.split("/").pop() || m })),
    };
    settings.models.providers["9router"] = providerConfig;

    // Set per-agent model in agents.list and write models.json
    if (settings.agents.list) {
      settings.agents.list = settings.agents.list.map((agent) => {
        const agentModel = agentModels[agent.id];
        if (agentModel) return { ...agent, model: `9router/${agentModel}` };
        return agent;
      });

      // Write per-agent models.json for agents with agentDir
      await Promise.all(
        settings.agents.list.map(async (agent) => {
          if (!agent.agentDir) return;
          const agentModel = agentModels[agent.id];
          const modelToWrite = agentModel || model; // fallback to default
          await writeAgentModels(agent.agentDir, modelToWrite, normalizedBaseUrl);
        })
      );
    }

    await runOpenClawConfigDryRun({
      models: { providers: { "9router": providerConfig } },
      agents: {
        defaults: {
          model: settings.agents.defaults.model,
          models: Object.fromEntries(
            Object.entries(settings.agents.defaults.models).filter(([key]) => key.startsWith("9router/"))
          ),
        },
      },
    });

    await backupFile(settingsPath);
    await fs.writeFile(settingsPath, JSON.stringify(settings, null, 2));

    return NextResponse.json({
      success: true,
      message: "Open Claw settings applied successfully!",
      settingsPath,
    });
  } catch (error) {
    console.log("Error updating openclaw settings:", error);
    return NextResponse.json({ error: "Failed to update openclaw settings" }, { status: 500 });
  }
}

// DELETE - Remove 9Router settings only (keep other settings)
export async function DELETE() {
  try {
    const settingsPath = getOpenClawSettingsPath();

    // Read existing settings
    let settings = {};
    try {
      const existingSettings = await fs.readFile(settingsPath, "utf-8");
      settings = JSON.parse(existingSettings);
    } catch (error) {
      if (error.code === "ENOENT") {
        return NextResponse.json({
          success: true,
          message: "No settings file to reset",
        });
      }
      throw error;
    }

    // Remove 9Router from models.providers
    if (settings.models && settings.models.providers) {
      delete settings.models.providers["9router"];
      
      // Remove providers object if empty
      if (Object.keys(settings.models.providers).length === 0) {
        delete settings.models.providers;
      }
    }

    // Remove 9router models from agents.defaults.models allowlist
    if (settings.agents?.defaults?.models) {
      const keysToRemove = Object.keys(settings.agents.defaults.models).filter((k) => k.startsWith("9router/"));
      for (const key of keysToRemove) {
        delete settings.agents.defaults.models[key];
      }
      if (Object.keys(settings.agents.defaults.models).length === 0) {
        delete settings.agents.defaults.models;
      }
    }

    // Reset agents.defaults.model.primary if it uses 9router
    if (settings.agents?.defaults) {
      if (typeof settings.agents.defaults.model === "string") {
        if (settings.agents.defaults.model.startsWith("9router/")) delete settings.agents.defaults.model;
      } else if (settings.agents.defaults.model?.primary?.startsWith("9router/")) {
        delete settings.agents.defaults.model.primary;
      }
    }

    if (settings.agents?.list) {
      settings.agents.list = settings.agents.list.map(remove9RouterAgentModel);
      await Promise.all(
        settings.agents.list.map(async (agent) => {
          if (agent.agentDir) await removeAgentModels(agent.agentDir);
        })
      );
    }

    // Write updated settings
    await backupFile(settingsPath);
    await fs.writeFile(settingsPath, JSON.stringify(settings, null, 2));

    return NextResponse.json({
      success: true,
      message: "9Router settings removed successfully",
    });
  } catch (error) {
    console.log("Error resetting openclaw settings:", error);
    return NextResponse.json({ error: "Failed to reset openclaw settings" }, { status: 500 });
  }
}
