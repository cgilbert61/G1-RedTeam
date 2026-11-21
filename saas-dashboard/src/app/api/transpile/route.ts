import { NextResponse } from "next/server";

export async function POST(request: Request) {
  try {
    const rawFeed = await request.json();
    
    if (!Array.isArray(rawFeed)) {
      return NextResponse.json({ error: "Threat feed payload must be a JSON array of objects" }, { status: 400 });
    }

    // Forward compilation request to internal python microservice
    const response = await fetch("http://threat-transpiler:5005/transpile", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(rawFeed),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return NextResponse.json({ error: `Transpiler microservice error: ${errorText}` }, { status: response.status });
    }

    const compiledManifest = await response.json();
    return NextResponse.json(compiledManifest);
  } catch (error: any) {
    return NextResponse.json({ error: `Dashboard API error: ${error.message}` }, { status: 500 });
  }
}
