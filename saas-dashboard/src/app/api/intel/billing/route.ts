import { NextResponse } from "next/server";
import { getDatabase, saveDatabase } from "../../jobs_store";

export async function GET() {
  try {
    const db = getDatabase();
    return NextResponse.json({ success: true, billing: db.billing });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { status, plan, key } = body;
    const db = getDatabase();
    
    if (!db.billing) {
      db.billing = {
        plan: "enterprise",
        status: "active",
        key: "ent_key_secops_wallstreet_9921"
      };
    }
    
    if (status !== undefined) db.billing.status = status;
    if (plan !== undefined) db.billing.plan = plan;
    if (key !== undefined) db.billing.key = key;
    
    saveDatabase(db);
    return NextResponse.json({ success: true, billing: db.billing });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
