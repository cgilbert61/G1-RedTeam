import { NextResponse } from "next/server";

const TRANSPILER_BASE = process.env.THREAT_TRANSPILER_URL || "http://threat-transpiler:5005";

export async function GET() {
  try {
    const res = await fetch(`${TRANSPILER_BASE}/compliance/frameworks`, {
      cache: "no-store",
    });
    if (!res.ok) {
      const text = await res.text();
      return NextResponse.json(
        { error: `Threat transpiler error: ${text}` },
        { status: res.status }
      );
    }
    const data = await res.json();
    return NextResponse.json(data);
  } catch (error: any) {
    return NextResponse.json(
      { error: `Unable to reach threat-transpiler: ${error.message}` },
      { status: 502 }
    );
  }
}
