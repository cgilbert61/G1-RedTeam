"use client";

import React from "react";

interface RiskCompliancePanelProps {
  report: any;
  seed?: number;
}

function severityStyle(severity: string): { bg: string; text: string; border: string } {
  switch ((severity || "").toLowerCase()) {
    case "critical":
      return { bg: "bg-red-500/15", text: "text-red-400", border: "border-red-500/40" };
    case "high":
      return { bg: "bg-orange-500/15", text: "text-orange-400", border: "border-orange-500/40" };
    case "medium":
      return { bg: "bg-amber-500/15", text: "text-amber-300", border: "border-amber-500/40" };
    default:
      return { bg: "bg-emerald-500/15", text: "text-emerald-400", border: "border-emerald-500/40" };
  }
}

export function RiskCompliancePanel({ report, seed }: RiskCompliancePanelProps) {
  const sysRisk = report?.system_risk_score;
  const matrix = report?.compliance_matrix;

  if (!sysRisk && !matrix) {
    return null;
  }

  const sev = severityStyle(sysRisk?.severity || "low");
  const breakdown = sysRisk?.severity_breakdown || { critical: 0, high: 0, medium: 0, low: 0 };
  const frameworks = matrix ? Object.values(matrix) as any[] : [];

  return (
    <div className="space-y-4 mt-4">
      {sysRisk && (
        <div className={`rounded-xl border p-4 bg-slate-900/70 ${sev.border}`}>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold">
                Unified System Risk Score (CVSS-Inspired 0–10)
              </div>
              <div className="flex items-baseline gap-3 mt-1">
                <span className={`text-3xl font-bold font-mono ${sev.text}`}>
                  {Number(sysRisk.score ?? 0).toFixed(2)}
                </span>
                <span className="text-xs text-slate-400">/ 10.00</span>
                <span
                  className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${sev.bg} ${sev.text} border ${sev.border}`}
                >
                  {sysRisk.severity || "low"}
                </span>
                {seed !== undefined && seed !== null && (
                  <span className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-cyan-300 border border-slate-700">
                    seed: {seed}
                  </span>
                )}
              </div>
            </div>

            <div className="grid grid-cols-4 gap-2 text-center">
              {(["critical", "high", "medium", "low"] as const).map((band) => {
                const st = severityStyle(band);
                return (
                  <div
                    key={band}
                    className={`px-3 py-1.5 rounded-lg border ${st.bg} ${st.border}`}
                  >
                    <div className={`text-lg font-bold font-mono ${st.text}`}>
                      {breakdown[band] ?? 0}
                    </div>
                    <div className="text-[10px] uppercase tracking-wide text-slate-300">
                      {band}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-3 flex flex-wrap gap-4 text-xs text-slate-400">
            <span>
              Attack Success Rate:{" "}
              <strong className="text-slate-200 font-mono">
                {((sysRisk.attack_success_rate ?? 0) * 100).toFixed(1)}%
              </strong>
            </span>
            <span>
              Failed Findings:{" "}
              <strong className="text-slate-200 font-mono">
                {sysRisk.failed_findings ?? 0} / {sysRisk.total_findings ?? 0}
              </strong>
            </span>
            {(sysRisk.multi_critical_penalty ?? 0) > 0 && (
              <span className="text-red-300">
                Multi-Critical Penalty:{" "}
                <strong className="font-mono">+{Number(sysRisk.multi_critical_penalty).toFixed(2)}</strong>
              </span>
            )}
          </div>
        </div>
      )}

      {frameworks.length > 0 && (
        <div className="rounded-xl border border-slate-700/70 bg-slate-900/70 p-4">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs uppercase tracking-wider text-cyan-400 font-bold">
              8-Framework Compliance Matrix
            </h4>
            <span className="text-xs text-slate-400">
              {frameworks.filter((f) => f.status === "pass").length} / {frameworks.length} Passing
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {frameworks.map((fw: any) => {
              const isPass = fw.status === "pass";
              const isFail = fw.status === "fail";
              const badgeCls = isPass
                ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                : isFail
                ? "bg-red-500/15 text-red-400 border-red-500/30"
                : "bg-slate-700/40 text-slate-400 border-slate-600/40";
              return (
                <div
                  key={fw.id}
                  className="rounded-lg border border-slate-700/60 bg-slate-950/60 p-2.5 flex flex-col justify-between"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="text-xs font-semibold text-slate-200 leading-tight">
                      {fw.name}
                    </div>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border shrink-0 ${badgeCls}`}
                    >
                      {fw.status}
                    </span>
                  </div>
                  <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                    <span>
                      Pass:{" "}
                      <strong className="text-slate-200 font-mono">
                        {fw.compliance_rate}%
                      </strong>
                    </span>
                    <span className="font-mono">
                      {fw.passed_cases}/{fw.total_cases}
                    </span>
                  </div>
                  {Array.isArray(fw.failed_controls) && fw.failed_controls.length > 0 && (
                    <div className="mt-1.5 text-[10px] text-red-300 truncate" title={fw.failed_controls.join(", ")}>
                      Failed: {fw.failed_controls.slice(0, 2).join(", ")}
                      {fw.failed_controls.length > 2 ? ` +${fw.failed_controls.length - 2}` : ""}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
