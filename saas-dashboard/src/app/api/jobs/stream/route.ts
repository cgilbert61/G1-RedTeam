import { getDatabase } from "../../jobs_store";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const jobId = searchParams.get("job_id");

  if (!jobId) {
    return new Response(JSON.stringify({ error: "Missing job_id query parameter" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    start(controller) {
      let sentEventCount = 0;
      let lastStatus = "";
      let lastProgress = -1;
      let closed = false;

      const sendSse = (eventName: string, payload: unknown) => {
        if (closed) return;
        try {
          controller.enqueue(
            encoder.encode(`event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`)
          );
        } catch {
          closed = true;
        }
      };

      const poll = () => {
        if (closed) return;
        try {
          const db = getDatabase();
          const job = db.jobs.find((j) => j.id === jobId);
          if (!job) {
            sendSse("error", { error: "Job not found", job_id: jobId });
            closed = true;
            controller.close();
            return;
          }

          const events = Array.isArray(job.live_events) ? job.live_events : [];
          if (events.length > sentEventCount) {
            const newEvents = events.slice(sentEventCount);
            for (const evt of newEvents) {
              sendSse("turn", evt);
            }
            sentEventCount = events.length;
          }

          const currentProgress = job.progress ?? 0;
          if (job.status !== lastStatus || currentProgress !== lastProgress) {
            lastStatus = job.status;
            lastProgress = currentProgress;
            sendSse("progress", {
              job_id: job.id,
              status: job.status,
              progress: currentProgress,
              progress_text: job.progress_text || "",
              seed: job.seed,
            });
          }

          if (job.status === "completed" || job.status === "failed") {
            sendSse("done", {
              job_id: job.id,
              status: job.status,
              system_risk_score: job.report?.system_risk_score || null,
              compliance_matrix: job.report?.compliance_matrix || null,
              stats: job.report?.stats || null,
            });
            closed = true;
            clearInterval(timer);
            controller.close();
          }
        } catch (err: any) {
          sendSse("error", { error: err?.message || "Stream read error" });
        }
      };

      poll();
      const timer = setInterval(poll, 750);

      request.signal.addEventListener("abort", () => {
        closed = true;
        clearInterval(timer);
        try {
          controller.close();
        } catch {
          // already closed
        }
      });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
