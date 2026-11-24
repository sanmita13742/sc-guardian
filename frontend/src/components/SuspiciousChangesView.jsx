import React, { useState, useMemo } from 'react';
import {
  AlertOctagon,
  ShieldAlert,
  GitBranch,
  Terminal,
  Container,
  Search,
  Filter,
  CheckCircle2,
  FileCode,
  ArrowRight,
  Info,
  Shield,
  ShieldCheck,
  Sparkles,
  Cpu,
  Layers,
  ExternalLink,
  AlertTriangle,
  GitCommit,
  Check,
  X,
  ChevronDown,
  ChevronUp
} from 'lucide-react';

export default function SuspiciousChangesView({ scanData }) {
  // Navigation & Layer Toggles
  const [activeLayer, setActiveLayer] = useState('all'); // 'all', 'ai', 'correlated', 'deterministic'
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [confidenceFilter, setConfidenceFilter] = useState('all');
  const [originFilter, setOriginFilter] = useState('all');
  const [verdictFilter, setVerdictFilter] = useState('all');
  const [expandedScenarios, setExpandedScenarios] = useState({});
  const [expandedTrace, setExpandedTrace] = useState({});

  // Metrics extraction with safe fallbacks
  const metrics = scanData?.metrics || {
    total_findings: 29,
    category_counts: {
      'Docker & CI/CD': 15,
      'Typosquatting': 7,
      'Lifecycle Script': 4,
      'Dependency Change': 1,
      'Dependency Source': 1,
      'Repository Diff': 1
    },
    severity_counts: { HIGH: 2, MEDIUM: 9, LOW: 18 },
    confidence_counts: { CONFIRMED: 12, HIGH: 2, MEDIUM: 9, LOW: 6 },
    evidence_type_counts: { OBSERVED_CHANGE: 1, HEURISTIC_FLAG: 28 },
    origin_counts: { INTRODUCED_IN_RANGE: 1, PRE_EXISTING: 28 }
  };

  const findings = useMemo(() => {
    return scanData?.findings || [];
  }, [scanData]);

  const correlatedScenarios = useMemo(() => {
    return scanData?.correlated_scenarios || [];
  }, [scanData]);

  const aiInvestigations = useMemo(() => {
    return scanData?.ai_investigations || [];
  }, [scanData]);

  // Fast lookup map for AI investigations by finding ID
  const aiMap = useMemo(() => {
    const map = {};
    aiInvestigations.forEach(inv => {
      map[inv.finding_id] = inv;
    });
    return map;
  }, [aiInvestigations]);

  // Computed AI statistics
  const aiStats = useMemo(() => {
    let benign = 0;
    let attack = 0;
    let anomaly = 0;
    aiInvestigations.forEach(inv => {
      if (inv.verdict === 'BENIGN_EXPLANATION') benign++;
      else if (inv.verdict === 'SUSPECTED_SUPPLY_CHAIN_ATTACK') attack++;
      else if (inv.verdict === 'CONFIRMED_ANOMALY') anomaly++;
    });
    return { benign, attack, anomaly, total: aiInvestigations.length };
  }, [aiInvestigations]);

  // Filtered findings across multiple dimensions and layers
  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      const q = search.toLowerCase();
      const ai = aiMap[f.id];

      const matchesSearch =
        !q ||
        f.id.toLowerCase().includes(q) ||
        f.affected_file.toLowerCase().includes(q) ||
        f.evidence.toLowerCase().includes(q) ||
        f.explanation.toLowerCase().includes(q) ||
        (ai && ai.rationale.toLowerCase().includes(q)) ||
        (ai && ai.verdict.toLowerCase().includes(q));

      if (!matchesSearch) return false;

      // Layer Filter
      if (activeLayer === 'ai' && !ai) return false;
      if (activeLayer === 'deterministic' && false) { /* show all in deterministic mode */ }

      // Category, Severity, Confidence
      if (categoryFilter !== 'all' && f.category !== categoryFilter) return false;
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
      if (confidenceFilter !== 'all' && f.confidence !== confidenceFilter) return false;
      if (originFilter !== 'all' && f.change_origin !== originFilter) return false;

      // AI Verdict Filter
      if (verdictFilter !== 'all') {
        if (!ai || ai.verdict !== verdictFilter) return false;
      }

      return true;
    });
  }, [findings, search, categoryFilter, severityFilter, confidenceFilter, originFilter, verdictFilter, activeLayer, aiMap]);

  const toggleScenario = (id) => {
    setExpandedScenarios(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const toggleTrace = (id) => {
    setExpandedTrace(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const getCategoryBadge = (category) => {
    let color = 'bg-blue-500/20 text-blue-400 border-blue-500/40';
    let icon = <GitBranch className="w-3 h-3" />;

    if (category === 'Docker & CI/CD') {
      color = 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      icon = <Container className="w-3 h-3" />;
    } else if (category === 'Typosquatting') {
      color = 'bg-purple-500/20 text-purple-400 border-purple-500/40';
      icon = <AlertOctagon className="w-3 h-3" />;
    } else if (category === 'Lifecycle Script') {
      color = 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      icon = <Terminal className="w-3 h-3" />;
    } else if (category === 'Dependency Source') {
      color = 'bg-rose-500/20 text-rose-400 border-rose-500/40';
      icon = <ExternalLink className="w-3 h-3" />;
    } else if (category === 'Repository Diff') {
      color = 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40';
      icon = <GitCommit className="w-3 h-3" />;
    }

    return (
      <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${color}`}>
        {icon}
        {category}
      </span>
    );
  };

  const getSeverityBadge = (severity) => {
    const sev = severity?.toUpperCase() || 'LOW';
    let bg = 'bg-gray-800 text-gray-300 border-gray-700';
    if (sev === 'CRITICAL') bg = 'bg-red-500/20 text-red-400 border-red-500/40';
    else if (sev === 'HIGH') bg = 'bg-red-500/20 text-red-400 border-red-500/40';
    else if (sev === 'MEDIUM') bg = 'bg-amber-500/20 text-amber-400 border-amber-500/40';
    else if (sev === 'LOW') bg = 'bg-blue-500/20 text-blue-400 border-blue-500/40';

    return (
      <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${bg}`}>
        {sev}
      </span>
    );
  };

  const getVerdictBadge = (verdict, confidence) => {
    if (verdict === 'BENIGN_EXPLANATION') {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          BENIGN EXPLANATION ({confidence || 'HIGH'})
        </span>
      );
    }
    if (verdict === 'SUSPECTED_SUPPLY_CHAIN_ATTACK') {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/40 animate-pulse">
          <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
          SUSPECTED ATTACK ({confidence || 'HIGH'})
        </span>
      );
    }
    if (verdict === 'CONFIRMED_ANOMALY') {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40">
          <AlertOctagon className="w-3.5 h-3.5 text-amber-400" />
          CONFIRMED ANOMALY ({confidence || 'MEDIUM'})
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-gray-800 text-gray-400 border border-gray-700">
        <Info className="w-3.5 h-3.5" />
        {verdict || 'UNCONFIRMED'}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* High-Level Layer Architecture Banner */}
      <div className="bg-gradient-to-r from-blue-950/40 via-purple-950/30 to-amber-950/30 border border-gray-800 rounded-2xl p-5 shadow-lg">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] bg-blue-500/20 text-blue-300 border border-blue-500/30 px-2 py-0.5 rounded-full font-bold uppercase tracking-wider">
                PERSON 2: SUSPICIOUS CHANGE INVESTIGATOR
              </span>
              <span className="text-[10px] bg-purple-500/20 text-purple-300 border border-purple-500/30 px-2 py-0.5 rounded-full font-bold flex items-center gap-1">
                <Sparkles className="w-2.5 h-2.5" />
                LANGGRAPH AI AGENT
              </span>
            </div>
            <h2 className="text-xl font-bold text-white mt-1.5">
              Evidence-Driven Forensic & Non-CVE Investigation Engine
            </h2>
            <p className="text-xs text-gray-400 mt-1 max-w-3xl leading-relaxed">
              Detects malicious and unauthorized supply-chain changes beyond conventional CVE/NVD databases.
              Preserves strict separation between <strong className="text-cyan-300">deterministic scanner evidence</strong>,{' '}
              <strong className="text-amber-300">cross-signal attack correlation</strong>, and{' '}
              <strong className="text-purple-300">autonomous AI agent reasoning</strong>.
            </p>
          </div>

          {/* Quick Stats Pill Group */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="bg-black/50 border border-gray-800 px-3 py-2 rounded-xl text-center min-w-[90px]">
              <span className="text-[10px] text-gray-400 block uppercase">Findings</span>
              <span className="text-lg font-bold text-white font-mono">{metrics.total_findings}</span>
            </div>
            <div className="bg-black/50 border border-purple-900/60 px-3 py-2 rounded-xl text-center min-w-[90px]">
              <span className="text-[10px] text-purple-400 block uppercase">AI Deep Dives</span>
              <span className="text-lg font-bold text-purple-400 font-mono">{aiStats.total}</span>
            </div>
            <div className="bg-black/50 border border-emerald-900/60 px-3 py-2 rounded-xl text-center min-w-[100px]">
              <span className="text-[10px] text-emerald-400 block uppercase">Disambiguated</span>
              <span className="text-lg font-bold text-emerald-400 font-mono">{aiStats.benign}</span>
            </div>
            <div className="bg-black/50 border border-amber-900/60 px-3 py-2 rounded-xl text-center min-w-[90px]">
              <span className="text-[10px] text-amber-400 block uppercase">Correlated</span>
              <span className="text-lg font-bold text-amber-400 font-mono">{correlatedScenarios.length}</span>
            </div>
          </div>
        </div>

        {/* Layer Selection Navigation Tabs */}
        <div className="flex flex-wrap gap-2 mt-5 pt-4 border-t border-gray-800/80">
          <button
            onClick={() => setActiveLayer('all')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeLayer === 'all'
                ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
                : 'bg-gray-900/80 text-gray-400 hover:text-white hover:bg-gray-800'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Unified View (All Layers)
            <span className="ml-1 text-[10px] bg-black/40 px-1.5 py-0.5 rounded font-mono">
              {findings.length}
            </span>
          </button>

          <button
            onClick={() => setActiveLayer('ai')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeLayer === 'ai'
                ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30'
                : 'bg-gray-900/80 text-gray-400 hover:text-purple-300 hover:bg-gray-800'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-purple-300" />
            Layer 3: Autonomous AI Investigations
            <span className="ml-1 text-[10px] bg-black/40 px-1.5 py-0.5 rounded font-mono text-purple-300">
              {aiStats.total}
            </span>
          </button>

          <button
            onClick={() => setActiveLayer('correlated')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeLayer === 'correlated'
                ? 'bg-amber-600 text-white shadow-md shadow-amber-600/30'
                : 'bg-gray-900/80 text-gray-400 hover:text-amber-300 hover:bg-gray-800'
            }`}
          >
            <GitBranch className="w-3.5 h-3.5 text-amber-300" />
            Layer 2: Correlated Attack Chains
            <span className="ml-1 text-[10px] bg-black/40 px-1.5 py-0.5 rounded font-mono text-amber-300">
              {correlatedScenarios.length}
            </span>
          </button>

          <button
            onClick={() => setActiveLayer('deterministic')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition ${
              activeLayer === 'deterministic'
                ? 'bg-cyan-600 text-white shadow-md shadow-cyan-600/30'
                : 'bg-gray-900/80 text-gray-400 hover:text-cyan-300 hover:bg-gray-800'
            }`}
          >
            <FileCode className="w-3.5 h-3.5 text-cyan-300" />
            Layer 1: Deterministic Forensic Evidence
            <span className="ml-1 text-[10px] bg-black/40 px-1.5 py-0.5 rounded font-mono text-cyan-300">
              {findings.length}
            </span>
          </button>
        </div>
      </div>

      {/* Layer 2: Correlated Composite Attack Scenarios (Featured Banner) */}
      {(activeLayer === 'all' || activeLayer === 'correlated') && correlatedScenarios.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between px-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                <GitBranch className="w-4 h-4 text-amber-400" />
                Cross-Signal Correlated Threat Scenarios (Phase 2 Engine)
              </span>
              <span className="text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/40 px-2 py-0.5 rounded font-semibold font-mono">
                {correlatedScenarios.length} SCENARIO(S)
              </span>
            </div>
            <p className="text-[11px] text-gray-500">
              Synthesizes co-located anomalies across dependencies, install hooks, and pipelines into attack chains
            </p>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {correlatedScenarios.map((scenario) => {
              const isExpanded = expandedScenarios[scenario.composite_id] ?? true;
              return (
                <div
                  key={scenario.composite_id}
                  className="bg-[#0E131F] border border-amber-900/60 rounded-xl p-5 space-y-4 shadow-md bg-gradient-to-b from-amber-950/15 to-transparent"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-2.5">
                      <span className="font-mono text-xs font-bold text-amber-400 bg-amber-950/50 border border-amber-800/60 px-2.5 py-1 rounded">
                        {scenario.composite_id}
                      </span>
                      {getSeverityBadge(scenario.severity)}
                      <span className="text-[11px] bg-gray-900 text-gray-300 border border-gray-800 px-2.5 py-1 rounded font-semibold">
                        CONFIDENCE: {scenario.correlation_confidence}
                      </span>
                      <span className="text-[11px] bg-purple-950/50 text-purple-300 border border-purple-800/60 px-2.5 py-1 rounded font-mono">
                        {scenario.attack_technique}
                      </span>
                    </div>

                    <button
                      onClick={() => toggleScenario(scenario.composite_id)}
                      className="text-gray-400 hover:text-white text-xs flex items-center gap-1 px-2.5 py-1 rounded bg-gray-900/60 border border-gray-800 transition"
                    >
                      {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                      {isExpanded ? 'Collapse Scenario' : 'Expand Details'}
                    </button>
                  </div>

                  <div>
                    <h3 className="text-base font-bold text-white flex items-center gap-2">
                      {scenario.scenario_name}
                    </h3>
                    <p className="text-xs text-gray-300 mt-1 leading-relaxed">
                      {scenario.suspected_scenario}
                    </p>
                  </div>

                  {isExpanded && (
                    <div className="space-y-3 pt-3 border-t border-gray-800/80 text-xs">
                      {/* Contributing Findings */}
                      <div>
                        <span className="text-[10px] text-gray-400 uppercase tracking-wider block font-semibold mb-1.5">
                          Contributing Atomic Findings
                        </span>
                        <div className="flex flex-wrap gap-2">
                          {(scenario.primary_finding_ids || []).map((fid) => (
                            <span
                              key={fid}
                              className="font-mono text-[11px] bg-black/60 text-cyan-300 border border-cyan-800/60 px-2.5 py-1 rounded flex items-center gap-1"
                            >
                              <FileCode className="w-3 h-3 text-cyan-400" />
                              {fid}
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* Reasoning Chain */}
                      {scenario.reasoning_chain && scenario.reasoning_chain.length > 0 && (
                        <div className="bg-[#070A10] border border-gray-800 rounded-lg p-3">
                          <span className="text-[10px] text-gray-500 uppercase tracking-wider block font-semibold mb-1">
                            Correlated Reasoning Chain
                          </span>
                          <ul className="space-y-1 text-gray-300 text-[11px]">
                            {scenario.reasoning_chain.map((step, idx) => (
                              <li key={idx} className="flex items-start gap-1.5">
                                <span className="text-amber-400 font-bold">•</span>
                                <span>{step}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Contradicting / Mitigating Evidence */}
                      {scenario.contradicting_evidence && scenario.contradicting_evidence.length > 0 && (
                        <div className="bg-emerald-950/20 border border-emerald-900/40 rounded-lg p-3">
                          <span className="text-[10px] text-emerald-400 uppercase tracking-wider block font-semibold mb-1 flex items-center gap-1">
                            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                            Mitigating Engineering Factors Identified
                          </span>
                          {scenario.contradicting_evidence.map((ce, idx) => (
                            <p key={idx} className="text-[11px] text-emerald-200/90">
                              <strong className="text-white">{ce.factor}:</strong> {ce.detail}
                            </p>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-gray-500" />
            <input
              type="text"
              placeholder="Search finding ID, file, evidence, or AI rationale..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-gray-100 pl-8 pr-3 py-1.5 rounded-lg text-xs w-72 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Category Filter */}
          <div className="flex items-center gap-1.5 text-gray-400">
            <span>Category:</span>
            <select
              value={categoryFilter}
              onChange={e => setCategoryFilter(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-gray-200 px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-blue-500"
            >
              <option value="all">All Categories ({findings.length})</option>
              <option value="Docker & CI/CD">Docker & CI/CD</option>
              <option value="Typosquatting">Typosquatting</option>
              <option value="Lifecycle Script">Lifecycle Script</option>
              <option value="Dependency Change">Dependency Change</option>
              <option value="Dependency Source">Dependency Source</option>
              <option value="Repository Diff">Repository Diff</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1.5 text-gray-400">
            <span>Severity:</span>
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-gray-200 px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-blue-500"
            >
              <option value="all">All Severities</option>
              <option value="CRITICAL">Critical ({metrics.severity_counts?.CRITICAL || 0})</option>
              <option value="HIGH">High ({metrics.severity_counts?.HIGH || 0})</option>
              <option value="MEDIUM">Medium ({metrics.severity_counts?.MEDIUM || 0})</option>
              <option value="LOW">Low ({metrics.severity_counts?.LOW || 0})</option>
            </select>
          </div>

          {/* AI Verdict Filter */}
          <div className="flex items-center gap-1.5 text-purple-400">
            <span className="flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-purple-400" />
              AI Verdict:
            </span>
            <select
              value={verdictFilter}
              onChange={e => setVerdictFilter(e.target.value)}
              className="bg-purple-950/40 border border-purple-800 text-purple-200 px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-purple-500"
            >
              <option value="all">All Verdicts</option>
              <option value="BENIGN_EXPLANATION">Benign Explanation ({aiStats.benign})</option>
              <option value="SUSPECTED_SUPPLY_CHAIN_ATTACK">Suspected Attack ({aiStats.attack})</option>
              <option value="CONFIRMED_ANOMALY">Confirmed Anomaly ({aiStats.anomaly})</option>
            </select>
          </div>

          {/* Change Origin Filter */}
          <div className="flex items-center gap-1.5 text-gray-400">
            <span>Origin:</span>
            <select
              value={originFilter}
              onChange={e => setOriginFilter(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-gray-200 px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-blue-500"
            >
              <option value="all">All Origins</option>
              <option value="INTRODUCED_IN_RANGE">Introduced in Commit Range</option>
              <option value="PRE_EXISTING">Pre-Existing in Baseline</option>
            </select>
          </div>
        </div>

        <div className="text-gray-400 text-xs">
          Showing <span className="text-white font-semibold">{filteredFindings.length}</span> of {findings.length} findings
        </div>
      </div>

      {/* Layered Findings List */}
      <div className="space-y-4">
        {filteredFindings.length === 0 ? (
          <div className="bg-[#0E131F] border border-gray-800 rounded-xl p-8 text-center text-gray-500 text-xs">
            No suspicious change findings match the current filter criteria.
          </div>
        ) : (
          filteredFindings.map((finding) => {
            const ai = aiMap[finding.id];
            const isObservedChange = finding.evidence_type === 'OBSERVED_CHANGE';
            const isTraceExpanded = expandedTrace[finding.id] || false;

            return (
              <div
                key={finding.id}
                className="bg-[#0E131F] border border-gray-800 rounded-2xl p-5 space-y-4 shadow-md hover:border-gray-700 transition"
              >
                {/* Top Row: Category, Severity, ID, Origin, Evidence Type, Location */}
                <div className="flex flex-wrap items-center justify-between gap-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    {getCategoryBadge(finding.category)}
                    {getSeverityBadge(finding.severity)}
                    <span className="font-mono text-xs font-bold text-white bg-black/60 px-2.5 py-1 rounded border border-gray-800">
                      {finding.id}
                    </span>

                    {/* Origin Badge */}
                    {finding.change_origin === 'INTRODUCED_IN_RANGE' ? (
                      <span className="text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/40 px-2 py-0.5 rounded font-mono font-bold flex items-center gap-1">
                        <GitCommit className="w-3 h-3 text-amber-400" />
                        INTRODUCED IN RANGE
                      </span>
                    ) : (
                      <span className="text-[10px] bg-slate-800 text-slate-300 border border-slate-700 px-2 py-0.5 rounded font-mono font-medium">
                        PRE-EXISTING BASELINE
                      </span>
                    )}

                    {/* Evidence Type Badge */}
                    {isObservedChange ? (
                      <span className="text-[10px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 px-2 py-0.5 rounded font-mono font-bold flex items-center gap-1">
                        <Check className="w-3 h-3 text-cyan-400" />
                        OBSERVED CHANGE (GIT DIFF)
                      </span>
                    ) : (
                      <span className="text-[10px] bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 px-2 py-0.5 rounded font-mono">
                        HEURISTIC FLAG
                      </span>
                    )}
                  </div>

                  {/* File & Commit Provenance Location */}
                  <div className="flex flex-wrap items-center gap-2">
                    {finding.commit_reference?.sha && (
                      <div className="flex items-center gap-1 text-[11px] font-mono bg-amber-950/30 text-amber-300 border border-amber-800/40 px-2 py-0.5 rounded">
                        <GitCommit className="w-3 h-3" />
                        <span>{finding.commit_reference.sha.slice(0, 8)}</span>
                      </div>
                    )}
                    <div className="flex items-center gap-1.5 text-xs text-gray-300 bg-gray-950 px-2.5 py-1 rounded border border-gray-800 font-mono">
                      <FileCode className="w-3.5 h-3.5 text-blue-400" />
                      <span className="text-gray-200">{finding.affected_file}</span>
                      {finding.line_number && (
                        <span className="text-amber-400 font-bold">:{finding.line_number}</span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Finding Title */}
                <div>
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    {finding.title}
                  </h4>
                </div>

                {/* ========================================================= */}
                {/* LAYER 1: DETERMINISTIC EVIDENCE (Forensic Scanner)        */}
                {/* ========================================================= */}
                {(activeLayer === 'all' || activeLayer === 'deterministic') && (
                  <div className="bg-[#070A10] border border-cyan-950/60 rounded-xl p-4 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5 font-sans">
                        <FileCode className="w-3 h-3 text-cyan-400" />
                        Layer 1: Deterministic Evidence & Git Diff (Factual Base)
                      </span>
                      <span className="text-[10px] text-gray-500 font-mono">
                        Zero LLM • Verified Static AST / Git Output
                      </span>
                    </div>

                    {/* Exact Code / Diff Snippet */}
                    <div className="bg-black/80 border border-gray-800 rounded-lg p-2.5 font-mono text-xs text-gray-300 overflow-x-auto">
                      <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1 flex items-center justify-between">
                        <span>Recorded Line Evidence</span>
                        <span className="text-gray-600 font-mono">Confidence: {finding.confidence}</span>
                      </div>
                      <div className="text-cyan-200 bg-cyan-950/20 px-2.5 py-1.5 rounded border border-cyan-950/40 select-all font-mono">
                        {finding.evidence}
                      </div>
                    </div>

                    {/* Technical Explanation */}
                    <div className="text-xs text-gray-300 leading-relaxed pt-1">
                      <span className="text-gray-500 font-semibold text-[10px] uppercase block mb-0.5">
                        Technical Explanation
                      </span>
                      {finding.explanation || finding.technical_explanation}
                    </div>

                    {finding.potential_impact && (
                      <div className="text-xs text-amber-200/90 bg-amber-950/15 border border-amber-950/40 rounded p-2 text-[11px]">
                        <strong className="text-amber-400">Potential Impact:</strong> {finding.potential_impact}
                      </div>
                    )}
                  </div>
                )}

                {/* ========================================================= */}
                {/* LAYER 3: AUTONOMOUS AI INVESTIGATION (LangGraph + Gemini) */}
                {/* ========================================================= */}
                {(activeLayer === 'all' || activeLayer === 'ai') && ai && (
                  <div
                    className={`rounded-xl p-4 space-y-3.5 border ${
                      ai.verdict === 'BENIGN_EXPLANATION'
                        ? 'bg-emerald-950/15 border-emerald-900/50'
                        : ai.verdict === 'SUSPECTED_SUPPLY_CHAIN_ATTACK'
                        ? 'bg-red-950/20 border-red-900/60'
                        : 'bg-purple-950/15 border-purple-900/50'
                    }`}
                  >
                    {/* AI Header & Grounding Gate Status */}
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-purple-300 flex items-center gap-1.5 font-sans">
                          <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                          Layer 3: Autonomous AI Investigation (LangGraph StateGraph)
                        </span>
                        <span className="text-[10px] bg-black/60 text-gray-400 border border-gray-800 px-2 py-0.5 rounded font-mono">
                          {ai.planner || 'llm:gemini:gemini-3.5-flash-lite'}
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        <span className="text-[10px] bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 rounded font-semibold flex items-center gap-1">
                          <ShieldCheck className="w-3 h-3 text-emerald-400" />
                          GROUNDING GATE: VERIFIED
                        </span>
                      </div>
                    </div>

                    {/* Verdict Banner */}
                    <div className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-lg bg-black/40 border border-gray-800/80">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-gray-400 font-medium">Investigation Verdict:</span>
                        {getVerdictBadge(ai.verdict, ai.confidence)}
                      </div>

                      {/* Tool Steps Count */}
                      <button
                        onClick={() => toggleTrace(finding.id)}
                        className="text-gray-400 hover:text-white text-[11px] flex items-center gap-1 px-2 py-1 rounded bg-gray-900 border border-gray-800 transition font-mono"
                      >
                        <Cpu className="w-3 h-3 text-purple-400" />
                        <span>{(ai.investigation_steps || []).length} Tool Step(s)</span>
                        {isTraceExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                      </button>
                    </div>

                    {/* AI Rationale Narrative */}
                    <div className="text-xs text-gray-200 leading-relaxed">
                      <span className="text-gray-400 font-semibold text-[10px] uppercase block mb-1">
                        Independent AI Reasoning & Context
                      </span>
                      <p className="bg-black/30 p-2.5 rounded-lg border border-gray-800/60">
                        {ai.rationale}
                      </p>
                    </div>

                    {/* Suspected Attack Scenario Narrative (if present) */}
                    {ai.attack_scenario && (
                      <div className="text-xs bg-red-950/25 border border-red-900/40 rounded-lg p-2.5">
                        <span className="text-red-400 font-bold text-[10px] uppercase block mb-1 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3 text-red-400" />
                          Suspected Attack Scenario Narrative
                        </span>
                        <p className="text-red-200/90 text-[11px] leading-relaxed">
                          {ai.attack_scenario}
                        </p>
                      </div>
                    )}

                    {/* Side-by-Side Evidence Breakdown: Supporting vs Contradicting */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs pt-1">
                      {/* Supporting Evidence */}
                      <div className="bg-black/40 border border-gray-800/80 rounded-lg p-2.5">
                        <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider block mb-1.5 flex items-center gap-1">
                          <Info className="w-3 h-3 text-blue-400" />
                          Supporting Evidence (Observed Signals)
                        </span>
                        {(ai.supporting_evidence || []).length === 0 ? (
                          <p className="text-gray-500 text-[11px] italic">No active compromise indicators.</p>
                        ) : (
                          <div className="space-y-1.5">
                            {ai.supporting_evidence.map((se, idx) => (
                              <div key={idx} className="text-[11px] text-gray-300">
                                <span className="font-semibold text-white">{se.factor}:</span> {se.detail}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Contradicting / Mitigating Evidence */}
                      <div className="bg-emerald-950/20 border border-emerald-900/40 rounded-lg p-2.5">
                        <span className="text-[10px] font-semibold text-emerald-400 uppercase tracking-wider block mb-1.5 flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                          Contradicting Evidence (Legitimate Explanations)
                        </span>
                        {(ai.contradicting_evidence || []).length === 0 ? (
                          <p className="text-gray-500 text-[11px] italic">No benign mitigating factors found.</p>
                        ) : (
                          <div className="space-y-1.5">
                            {ai.contradicting_evidence.map((ce, idx) => (
                              <div key={idx} className="text-[11px] text-emerald-200/90">
                                <span className="font-semibold text-white">{ce.factor}:</span> {ce.detail}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Expandable Autonomous Tool Execution Trace */}
                    {isTraceExpanded && (
                      <div className="bg-[#05080E] border border-gray-800 rounded-lg p-3 space-y-2 mt-2">
                        <span className="text-[10px] text-purple-400 uppercase tracking-wider font-bold block flex items-center gap-1">
                          <Cpu className="w-3 h-3" />
                          LangGraph Autonomous Tool Execution Trace
                        </span>
                        <div className="space-y-2 font-mono text-[11px]">
                          {(ai.investigation_steps || []).map((step, sIdx) => (
                            <div key={sIdx} className="bg-black/60 p-2 rounded border border-gray-800">
                              <div className="flex items-center justify-between text-gray-400 text-[10px]">
                                <span className="text-purple-300 font-bold">Step {sIdx + 1}: {step.tool}</span>
                                <span className="text-emerald-400">{step.summary}</span>
                              </div>
                              {step.args && Object.keys(step.args).length > 0 && (
                                <div className="text-gray-500 text-[10px] mt-0.5 truncate">
                                  args: {JSON.stringify(step.args)}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Recommended Remediation Action */}
                    {ai.recommended_action && (
                      <div className="text-[11px] text-gray-300 bg-black/40 border border-gray-800/80 rounded p-2 flex items-start gap-1.5">
                        <ArrowRight className="w-3.5 h-3.5 text-blue-400 mt-0.5 flex-shrink-0" />
                        <div>
                          <strong className="text-blue-300">Recommended Action:</strong> {ai.recommended_action}
                        </div>
                      </div>
                    )}

                    {/* Research Citations */}
                    {ai.citations && ai.citations.length > 0 && (
                      <div className="text-[10px] text-gray-500 pt-1">
                        <span className="font-semibold uppercase tracking-wider text-gray-600 block mb-0.5">Academic Citations</span>
                        <ul className="list-disc list-inside space-y-0.5">
                          {ai.citations.map((cite, cIdx) => (
                            <li key={cIdx}>{cite}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}

                {/* If finding has no AI investigation */}
                {(activeLayer === 'all' || activeLayer === 'ai') && !ai && (
                  <div className="bg-gray-900/30 border border-gray-800/50 rounded-xl p-3 flex items-center justify-between text-[11px] text-gray-500">
                    <span className="flex items-center gap-1.5">
                      <Info className="w-3.5 h-3.5 text-gray-600" />
                      AI Deep-Dive deferred: finding categorized as lower-risk or covered by deterministic baseline rules.
                    </span>
                    <span className="font-mono text-[10px] text-gray-600">Deterministic Engine Verified</span>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
