import { NextResponse } from "next/server";
import { getApiKeys, createApiKey } from "@/lib/localDb";
import { getConsistentMachineId } from "@/shared/utils/machineId";
import { isOnePasswordBridgeUnavailable } from "@/lib/secrets/onePasswordBridge";

export const dynamic = "force-dynamic";

function sanitizeApiKey(key) {
  if (!key) return key;
  return {
    ...key,
    key: undefined,
    keyRef: key.keyRef ? "1password" : null,
  };
}

// GET /api/keys - List API keys
export async function GET() {
  try {
    const keys = await getApiKeys();
    return NextResponse.json({ keys: keys.map(sanitizeApiKey) });
  } catch (error) {
    console.log("Error fetching keys:", error);
    return NextResponse.json({ error: "Failed to fetch keys" }, { status: 500 });
  }
}

// POST /api/keys - Create new API key
export async function POST(request) {
  try {
    const body = await request.json();
    const { name } = body;

    if (!name) {
      return NextResponse.json({ error: "Name is required" }, { status: 400 });
    }

    // Always get machineId from server
    const machineId = await getConsistentMachineId();
    const apiKey = await createApiKey(name, machineId);

    return NextResponse.json({
      key: apiKey.key,
      name: apiKey.name,
      id: apiKey.id,
      machineId: apiKey.machineId,
    }, { status: 201 });
  } catch (error) {
    console.log("Error creating key:", error);
    if (isOnePasswordBridgeUnavailable(error)) {
      return NextResponse.json(
        { error: "1Password bridge is unavailable. Sign in to 1Password CLI and retry; the API key was not saved to disk." },
        { status: 503 }
      );
    }
    return NextResponse.json({ error: "Failed to create key" }, { status: 500 });
  }
}
