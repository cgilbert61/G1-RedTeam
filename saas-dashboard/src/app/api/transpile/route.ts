import { NextResponse } from "next/server";

const TRANSPILER_BASE = process.env.THREAT_TRANSPILER_URL || "http://threat-transpiler:5005";

export async function POST(request: Request) {
  try {
    const body = await request.json();

    const isArray = Array.isArray(body);
    const isObjectWithFeed = body && typeof body === "object" && Array.isArray(body.feed);
    if (!isArray && !isObjectWithFeed) {
      return NextResponse.json(
        { error: "Payload must be a JSON array of threat objects or { feed: [...], mutators?: [...], seed?: number }" },
        { status: 400 }
      );
    }

    const response = await fetch(`${TRANSPILER_BASE}/transpile`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return NextResponse.json(
        { error: `Transpiler microservice error: ${errorText}` },
        { status: response.status }
      );
    }

    const compiledManifest = await response.json();
    return NextResponse.json(compiledManifest);
  } catch (error: any) {
    return NextResponse.json(
      { error: `Dashboard API error: ${error.message}` },
      { status: 500 }
    );
  }
}
