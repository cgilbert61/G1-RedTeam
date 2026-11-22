import { NextResponse } from "next/server";
import { getDatabase, saveDatabase, Job, Target } from "../jobs_store";
import crypto from "crypto";

// GET: Poller endpoint for the runner agent
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const runnerId = searchParams.get("runner_id");
  
  if (!runnerId) {
    // If no runner_id, this is a dashboard request to list all jobs
    const db = getDatabase();
    return NextResponse.json({ jobs: db.jobs });
  }

  const db = getDatabase();
  
  // Find a pending job
  const pendingJob = db.jobs.find(job => job.status === "pending" && (!job.runner_id || job.runner_id === runnerId));
  
  if (pendingJob) {
    // Assign runner ID to it
    pendingJob.runner_id = runnerId;
    pendingJob.updated_at = new Date().toISOString();
    (pendingJob as any).promptfoo_config = db.promptfoo_config || "";
    (pendingJob as any).garak_config = db.garak_config || "";
    (pendingJob as any).beavertails_config = db.beavertails_config || "";
    (pendingJob as any).jailbreakbench_config = db.jailbreakbench_config || "";
    (pendingJob as any).pyrit_config = db.pyrit_config || "";
    (pendingJob as any).deepeval_config = db.deepeval_config || "";
    (pendingJob as any).mcp_config = db.mcp_config || "";
    saveDatabase(db);
    return NextResponse.json({ job: pendingJob, threat_intel_url: db.threat_intel_url || "" });
  }

  return NextResponse.json({ job: null, threat_intel_url: db.threat_intel_url || "" });
}

// POST: Trigger a new job from the dashboard
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { targetId, tests, seed } = body;

    if (!targetId) {
      return NextResponse.json({ error: "Missing targetId" }, { status: 400 });
    }

    const db = getDatabase();
    const target = db.targets.find(t => t.id === targetId);
    
    if (!target) {
      return NextResponse.json({ error: "Target not found" }, { status: 404 });
    }

    // Resolve any selected custom datasets
    const custom_datasets: Record<string, string[]> = {};
    if (db.datasets) {
      for (const dataset of db.datasets) {
        if (tests && tests[dataset.id]) {
          custom_datasets[dataset.name] = dataset.prompts;
        }
      }
    }

    const parsedSeed =
      seed !== undefined && seed !== null && seed !== "" && !Number.isNaN(Number(seed))
        ? Number(seed)
        : undefined;

    const newJob: Job = {
      id: "job-" + crypto.randomUUID().substring(0, 8),
      status: "pending",
      target,
      tests: tests || {},
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      custom_datasets,
      ...(parsedSeed !== undefined ? { seed: parsedSeed } : {}),
      live_events: []
    };
    (newJob as any).promptfoo_config = db.promptfoo_config || "";
    (newJob as any).garak_config = db.garak_config || "";
    (newJob as any).beavertails_config = db.beavertails_config || "";
    (newJob as any).jailbreakbench_config = db.jailbreakbench_config || "";
    (newJob as any).pyrit_config = db.pyrit_config || "";
    (newJob as any).deepeval_config = db.deepeval_config || "";
    (newJob as any).mcp_config = db.mcp_config || "";

    db.jobs.unshift(newJob); // Put newest first
    
    // Cap jobs history at 50 to prevent file blowup
    if (db.jobs.length > 50) {
      db.jobs = db.jobs.slice(0, 50);
    }
    
    saveDatabase(db);
    return NextResponse.json({ success: true, job: newJob });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

// DELETE: Clear all jobs/results
export async function DELETE() {
  try {
    const db = getDatabase();
    db.jobs = [];
    saveDatabase(db);
    return NextResponse.json({ success: true });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
