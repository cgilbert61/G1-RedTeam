import { NextResponse } from "next/server";
import { getDatabase, saveDatabase } from "../../jobs_store";

export async function GET() {
  try {
    const db = getDatabase();
    return NextResponse.json({ config: db.pyrit_config || "" });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { config } = body;

    if (config === undefined) {
      return NextResponse.json({ error: "Missing config string" }, { status: 400 });
    }

    const db = getDatabase();
    db.pyrit_config = config;
    saveDatabase(db);

    return NextResponse.json({ success: true });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
