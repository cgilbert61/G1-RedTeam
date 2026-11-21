import { NextResponse } from "next/server";
import { getDatabase, saveDatabase } from "../../jobs_store";

export async function GET() {
  try {
    const db = getDatabase();
    return NextResponse.json({ success: true, siem_config: db.siem_config || { provider: "none", endpoint: "", apiKey: "" } });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { provider, endpoint, apiKey, customHeaderName } = body;
    
    if (!provider) {
      return NextResponse.json({ error: "Missing provider" }, { status: 400 });
    }
    
    const db = getDatabase();
    db.siem_config = {
      provider,
      endpoint: endpoint || "",
      apiKey: apiKey || "",
      customHeaderName: customHeaderName || ""
    };
    saveDatabase(db);
    return NextResponse.json({ success: true, siem_config: db.siem_config });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
