import { NextResponse } from "next/server";
import { getDatabase, saveDatabase, Target } from "../jobs_store";
import crypto from "crypto";

// GET: List all targets
export async function GET() {
  const db = getDatabase();
  return NextResponse.json({ targets: db.targets });
}

// POST: Add or update a target
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { id, name, endpoint, adapter_type, model_name, headers, request_template, response_selector, python_entrypoint_file } = body;

    if (!name || (!endpoint && !python_entrypoint_file) || !adapter_type) {
      return NextResponse.json({ error: "Missing required fields (name, endpoint, adapter_type)" }, { status: 400 });
    }

    const db = getDatabase();
    let target: Target | undefined;

    if (id) {
      target = db.targets.find(t => t.id === id);
    }

    if (target) {
      // Update
      target.name = name;
      target.endpoint = endpoint || python_entrypoint_file || "";
      target.adapter_type = adapter_type;
      target.model_name = model_name || "";
      target.headers = headers || {};
      target.request_template = request_template;
      target.response_selector = response_selector;
      target.python_entrypoint_file = python_entrypoint_file;
    } else {
      // Add
      const newTarget: Target = {
        id: id || "target-" + crypto.randomUUID().substring(0, 8),
        name,
        endpoint: endpoint || python_entrypoint_file || "",
        adapter_type,
        model_name: model_name || "",
        headers: headers || {},
        request_template,
        response_selector,
        python_entrypoint_file
      };
      db.targets.push(newTarget);
    }

    saveDatabase(db);
    return NextResponse.json({ success: true, targets: db.targets });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
