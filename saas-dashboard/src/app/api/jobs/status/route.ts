import { NextResponse } from "next/server";
import { getDatabase, saveDatabase } from "../../jobs_store";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { job_id, status, runner_id, progress, progress_text, live_event } = body;

    if (!job_id || !status) {
      return NextResponse.json({ error: "Missing job_id or status" }, { status: 400 });
    }

    const db = getDatabase();
    const job = db.jobs.find(j => j.id === job_id);

    if (!job) {
      return NextResponse.json({ error: "Job not found" }, { status: 404 });
    }

    job.status = status;
    if (runner_id) {
      job.runner_id = runner_id;
    }
    if (progress !== undefined) {
      job.progress = progress;
    }
    if (progress_text !== undefined) {
      job.progress_text = progress_text;
    }
    if (live_event && typeof live_event === "object") {
      if (!Array.isArray(job.live_events)) {
        job.live_events = [];
      }
      job.live_events.push(live_event);
      if (job.live_events.length > 200) {
        job.live_events = job.live_events.slice(-200);
      }
    }
    job.updated_at = new Date().toISOString();
    
    saveDatabase(db);
    return NextResponse.json({ success: true });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
