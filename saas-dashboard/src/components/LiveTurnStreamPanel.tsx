"use client";

import React, { useEffect, useState } from "react";

interface LiveTurnEvent {
  suite?: string;
  turn?: number;
  role?: string;
  content?: string;
  prompt?: string;
  response?: string;
  timestamp?: string;
}

interface LiveTurnStreamPanelProps {
  jobId: string;
  status: string;
  initialEvents?: LiveTurnEvent[];
}

export function LiveTurnStreamPanel({ jobId, status, initialEvents = [] }: LiveTurnStreamPanelProps) {
  const [events, setEvents] = useState<LiveTurnEvent[]>(initialEvents);
  const [connected, setConnected] = useState(false);
  const [liveProgressText, setLiveProgressText] = useState<string>("");

  useEffect(() => {
    setEvents(initialEvents);
  }, [jobId]);

  useEffect(() => {
    if (!jobId || (status !== "running" && status !== "pending")) {
      setConnected(false);
      return;
    }

    const es = new EventSource(`/api/jobs/stream?job_id=${encodeURIComponent(jobId)}`);
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    es.addEventListener("turn", (evt: MessageEvent) => {
      try {
        const parsed = JSON.parse(evt.data);
        setEvents((prev) => [...prev.slice(-99), parsed]);
      } catch {
        // ignore malformed event
      }
    });

    es.addEventListener("progress", (evt: MessageEvent) => {
      try {
        const parsed = JSON.parse(evt.data);
        if (parsed.progress_text) setLiveProgressText(parsed.progress_text);
      } catch {
        // ignore
      }
    });

    es.addEventListener("done", () => {
      setConnected(false);
      es.close();
    });

    return () => {
      setConnected(false);
      es.close();
    };
  }, [jobId, status]);

  if (events.length === 0 && status !== "running" && status !== "pending") {
    return null;
  }

  return (
    <div className="rounded-xl border border-cyan-500/30 bg-slate-950/80 p-4 mt-4">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span
            className={`inline-block w-2 h-2 rounded-full ${
              connected ? "bg-emerald-400 animate-pulse" : "bg-slate-500"
            }`}
          />
          <h4 className="text-xs uppercase tracking-wider text-cyan-300 font-bold">
            Live Turn Stream (SSE)
          </h4>
        </div>
        <span className="text-[11px] text-slate-400 font-mono">
          {liveProgressText || (connected ? "Streaming..." : `${events.length} turns recorded`)}
        </span>
      </div>

      <div className="max-h-64 overflow-y-auto space-y-2 pr-1">
        {events.length === 0 ? (
          <div className="text-xs text-slate-500 italic py-2">
            Waiting for live conversation turns from hybrid-runner...
          </div>
        ) : (
          events.map((ev, idx) => (
            <div
              key={idx}
              className="rounded-lg border border-slate-800 bg-slate-900/70 p-2.5 text-xs space-y-1"
            >
              <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono">
                <span className="text-cyan-400 font-semibold">
                  {ev.suite || "Engine"} {ev.turn ? `• Turn ${ev.turn}` : ""} {ev.role ? `(${ev.role})` : ""}
                </span>
                <span>{ev.timestamp || ""}</span>
              </div>
              {ev.content && (
                <div className="text-slate-200 whitespace-pre-wrap break-words">{ev.content}</div>
              )}
              {ev.prompt && (
                <div className="text-amber-200/90 whitespace-pre-wrap break-words">
                  <strong className="text-amber-400">Prompt:</strong> {ev.prompt}
                </div>
              )}
              {ev.response && (
                <div className="text-slate-300 whitespace-pre-wrap break-words">
                  <strong className="text-emerald-400">Response:</strong> {ev.response}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
