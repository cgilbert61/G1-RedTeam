import { NextResponse } from "next/server";
import { getDatabase, saveDatabase } from "../../jobs_store";

async function sendSiemWebhook(siemConfig: any, report: any, job: any) {
  if (!siemConfig || siemConfig.provider === "none" || !siemConfig.endpoint) {
    return;
  }

  const { provider, endpoint, apiKey, customHeaderName } = siemConfig;

  // Resolve API Key from environment variable if it starts with "$" or is empty
  let resolvedKey = apiKey || "";
  if (resolvedKey.startsWith("$")) {
    const envVarName = resolvedKey.substring(1);
    resolvedKey = process.env[envVarName] || "";
  } else if (!resolvedKey) {
    if (provider === "datadog") {
      resolvedKey = process.env.DD_API_KEY || "";
    } else if (provider === "splunk") {
      resolvedKey = process.env.SPLUNK_TOKEN || "";
    }
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  let payload: any = null;

  if (provider === "splunk") {
    if (resolvedKey) {
      headers["Authorization"] = `Splunk ${resolvedKey}`;
    }
    payload = {
      event: {
        message: "G1 Red-Team Job Completed",
        job_id: job.id,
        status: job.status,
        target: job.target,
        stats: report.stats || {},
        logs: report.logs || [],
        completed_at: new Date().toISOString()
      }
    };
  } else if (provider === "datadog") {
    if (resolvedKey) {
      headers["DD-API-KEY"] = resolvedKey;
    }
    payload = {
      message: "G1 Red-Team Job Completed",
      job_id: job.id,
      status: job.status,
      target: job.target,
      stats: report.stats || {},
      logs: report.logs || [],
      ddsource: "g1-redteam",
      service: "g1-redteam-engine",
      completed_at: new Date().toISOString()
    };
  } else {
    // "other" / Custom Webhook
    if (resolvedKey) {
      const headerName = customHeaderName || "Authorization";
      headers[headerName] = resolvedKey;
    }
    payload = {
      message: "G1 Red-Team Job Completed",
      job_id: job.id,
      status: job.status,
      target: job.target,
      stats: report.stats || {},
      logs: report.logs || [],
      completed_at: new Date().toISOString()
    };
  }

  try {
    console.log(`[SIEM] Dispatching webhook to ${provider} endpoint: ${endpoint}`);
    const res = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000)
    });

    if (!res.ok) {
      console.warn(`[SIEM] Webhook dispatch returned error status: ${res.status} ${res.statusText}`);
    } else {
      console.log(`[SIEM] Webhook successfully dispatched to ${provider}.`);
    }
  } catch (err: any) {
    console.warn(`[SIEM] Failed to send webhook to ${provider}: ${err.message || err}`);
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { job_id, runner_id, report } = body;

    if (!job_id || !report) {
      return NextResponse.json({ error: "Missing job_id or report data" }, { status: 400 });
    }

    const db = getDatabase();
    const job = db.jobs.find(j => j.id === job_id);

    if (!job) {
      return NextResponse.json({ error: "Job not found" }, { status: 404 });
    }

    job.status = report.status || "completed";
    job.report = {
      stats: report.stats || { total_cases: 0, failed_cases: 0, passed_cases: 0, vulnerabilities_detected: 0 },
      logs: report.logs || [],
      completed_at: new Date().toISOString()
    };
    if (runner_id) {
      job.runner_id = runner_id;
    }
    job.updated_at = new Date().toISOString();
    
    saveDatabase(db);

    // Dispatch SIEM webhook asynchronously (fail-safe)
    if (db.siem_config && db.siem_config.provider !== "none") {
      sendSiemWebhook(db.siem_config, report, job).catch(err => {
        console.warn("[SIEM] Uncaught error in background webhook dispatcher:", err);
      });
    }

    return NextResponse.json({ success: true });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
