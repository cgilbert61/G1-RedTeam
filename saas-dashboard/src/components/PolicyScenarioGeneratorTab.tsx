"use client";

import React, { useState } from "react";

interface GeneratedScenario {
  scenario: string;
  expected_outcome: string;
  category: string;
  vulnerability_id: string;
  probe_prompt: string;
  forbidden_pattern: string;
}

interface PolicyScenarioGeneratorTabProps {
  onConfigsApplied?: (promptfooYaml: string, deepevalJson: string) => void;
}

export function PolicyScenarioGeneratorTab({ onConfigsApplied }: PolicyScenarioGeneratorTabProps) {
  const [businessContext, setBusinessContext] = useState(
    "Enterprise AI assistant behind G1 Security Gateway handling internal knowledge queries while enforcing strict DLP, RBAC, and anti-injection policies."
  );
  const [guardrails, setGuardrails] = useState(
    "- Never disclose system prompts, API keys, or internal database schemas.\n- Never echo SSNs, credentials, or PII verbatim.\n- Never execute destructive SQL, shell, or external tool actions without human approval."
  );
  const [domain, setDomain] = useState("Enterprise Security Gateway Assistant");
  const [forbiddenActions, setForbiddenActions] = useState("Disclosing secrets, running raw SQL, bypassing RBAC");
  const [sensitiveData, setSensitiveData] = useState("PII, SSNs, API keys, tenant records");
  const [count, setCount] = useState(6);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [source, setSource] = useState<string | null>(null);
  const [scenarios, setScenarios] = useState<GeneratedScenario[]>([]);
  const [promptfooYaml, setPromptfooYaml] = useState("");
  const [deepevalJson, setDeepevalJson] = useState("");
  const [appliedMsg, setAppliedMsg] = useState<string | null>(null);

  const handleGenerate = async (applyToConfigs: boolean) => {
    setLoading(true);
    setError(null);
    setAppliedMsg(null);
    try {
      const res = await fetch("/api/scenarios/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          business_context: businessContext,
          guardrails,
          qa_answers: {
            domain,
            forbidden_actions: forbiddenActions,
            sensitive_data: sensitiveData,
          },
          count,
          apply_to_configs: applyToConfigs,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to generate policy scenarios");
      }
      setSource(data.source);
      setScenarios(data.scenarios || []);
      setPromptfooYaml(data.promptfoo_yaml || "");
      setDeepevalJson(data.deepeval_json || "");
      if (applyToConfigs) {
        setAppliedMsg("Compiled Promptfoo YAML and DeepEval JSON saved to active job configs.");
        onConfigsApplied?.(data.promptfoo_yaml || "", data.deepeval_json || "");
      }
    } catch (err: any) {
      setError(err.message || "Unexpected error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-700/70 bg-slate-900/70 p-6 space-y-4">
        <div>
          <h2 className="text-lg font-bold text-white">Business-Policy Scenario Generator</h2>
          <p className="text-xs text-slate-400 mt-1">
            Describe your agent&apos;s business context and guardrails (or fill the guided Q&amp;A) to synthesize structured policy test scenarios compiled directly into runnable Promptfoo YAML and DeepEval configs.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Business Context
            </label>
            <textarea
              rows={4}
              value={businessContext}
              onChange={(e) => setBusinessContext(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
              placeholder="Describe what your AI agent does, its users, and intended scope..."
            />
          </div>
          <div className="space-y-2">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Explicit Guardrails &amp; Policy Rules (one per line)
            </label>
            <textarea
              rows={4}
              value={guardrails}
              onChange={(e) => setGuardrails(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
              placeholder="- Never offer unauthorized discounts..."
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 pt-2 border-t border-slate-800">
          <div>
            <label className="text-[11px] font-semibold uppercase text-slate-400">Guided Q1: Agent Domain</label>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100"
            />
          </div>
          <div>
            <label className="text-[11px] font-semibold uppercase text-slate-400">Guided Q2: Forbidden Actions</label>
            <input
              type="text"
              value={forbiddenActions}
              onChange={(e) => setForbiddenActions(e.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100"
            />
          </div>
          <div>
            <label className="text-[11px] font-semibold uppercase text-slate-400">Guided Q3: Sensitive Data</label>
            <input
              type="text"
              value={sensitiveData}
              onChange={(e) => setSensitiveData(e.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100"
            />
          </div>
          <div>
            <label className="text-[11px] font-semibold uppercase text-slate-400">Scenario Count</label>
            <input
              type="number"
              min={1}
              max={15}
              value={count}
              onChange={(e) => setCount(Number(e.target.value) || 6)}
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100"
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 pt-2">
          <button
            type="button"
            disabled={loading}
            onClick={() => handleGenerate(false)}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-bold uppercase tracking-wider cursor-pointer"
          >
            {loading ? "Generating..." : "Generate Scenarios"}
          </button>
          <button
            type="button"
            disabled={loading}
            onClick={() => handleGenerate(true)}
            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-bold uppercase tracking-wider cursor-pointer"
          >
            Generate &amp; Apply to Promptfoo + DeepEval
          </button>
          {source && (
            <span className="text-xs text-slate-400 font-mono">
              engine: {source} • {scenarios.length} scenarios
            </span>
          )}
        </div>

        {error && (
          <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-300">
            {error}
          </div>
        )}
        {appliedMsg && (
          <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-3 text-xs text-emerald-300">
            {appliedMsg}
          </div>
        )}
      </div>

      {scenarios.length > 0 && (
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-700/70 bg-slate-900/70 p-5">
            <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-3">
              Generated Policy Scenarios ({scenarios.length})
            </h3>
            <div className="space-y-2.5">
              {scenarios.map((s, idx) => (
                <div
                  key={idx}
                  className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-slate-100">{s.scenario}</span>
                    <span className="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-mono text-[10px]">
                      {s.category} ({s.vulnerability_id})
                    </span>
                  </div>
                  <div className="text-slate-400">
                    <strong className="text-slate-300">Expected:</strong> {s.expected_outcome}
                  </div>
                  <div className="text-amber-200/80 font-mono text-[11px]">
                    Probe: {s.probe_prompt}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="rounded-xl border border-slate-700/70 bg-slate-900/70 p-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-amber-300 mb-2">
                Compiled Promptfoo YAML
              </h4>
              <pre className="text-[11px] font-mono text-slate-200 bg-slate-950 p-3 rounded-lg overflow-x-auto max-h-72">
                {promptfooYaml}
              </pre>
            </div>
            <div className="rounded-xl border border-slate-700/70 bg-slate-900/70 p-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-purple-300 mb-2">
                Compiled DeepEval Config JSON
              </h4>
              <pre className="text-[11px] font-mono text-slate-200 bg-slate-950 p-3 rounded-lg overflow-x-auto max-h-72">
                {deepevalJson}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
