import { NextResponse } from "next/server";
import { getDatabase, saveDatabase } from "../../jobs_store";

export async function GET() {
  try {
    const db = getDatabase();
    return NextResponse.json({ success: true, threat_intel_url: db.threat_intel_url || "" });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { threat_intel_url } = body;
    const db = getDatabase();
    db.threat_intel_url = threat_intel_url || "";
    saveDatabase(db);
    return NextResponse.json({ success: true, threat_intel_url: db.threat_intel_url });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
