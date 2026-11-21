import { NextResponse } from "next/server";
import { getDatabase, saveDatabase, CustomDataset } from "../jobs_store";
import crypto from "crypto";

// GET: List all custom datasets
export async function GET() {
  const db = getDatabase();
  return NextResponse.json({ datasets: db.datasets || [] });
}

// POST: Add or update a custom dataset
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { id, name, prompts } = body;

    if (!name || !prompts || !Array.isArray(prompts)) {
      return NextResponse.json({ error: "Missing required fields (name, prompts as array)" }, { status: 400 });
    }

    const db = getDatabase();
    if (!db.datasets) db.datasets = [];

    let dataset: CustomDataset | undefined;
    if (id) {
      dataset = db.datasets.find(d => d.id === id);
    }

    if (dataset) {
      // Update
      dataset.name = name;
      dataset.prompts = prompts;
    } else {
      // Add
      const newDataset: CustomDataset = {
        id: id || "dataset-" + crypto.randomUUID().substring(0, 8),
        name,
        prompts
      };
      db.datasets.push(newDataset);
    }

    saveDatabase(db);
    return NextResponse.json({ success: true, datasets: db.datasets });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

// DELETE: Remove a custom dataset
export async function DELETE(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const id = searchParams.get("id");

    if (!id) {
      return NextResponse.json({ error: "Missing dataset ID" }, { status: 400 });
    }

    const db = getDatabase();
    if (!db.datasets) db.datasets = [];

    db.datasets = db.datasets.filter(d => d.id !== id);
    saveDatabase(db);

    return NextResponse.json({ success: true, datasets: db.datasets });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
