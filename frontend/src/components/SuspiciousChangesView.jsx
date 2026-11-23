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
  Info
} from 'lucide-react';

export default function SuspiciousChangesView({ scanData }) {
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [confidenceFilter, setConfidenceFilter] = useState('all');

  const metrics = scanData?.metrics || {
    total_findings: 24,
    category_counts: {
      'Docker & CI/CD': 11,
      'Typosquatting': 7,
      'Lifecycle Script': 4,
      'Dependency Change': 2
    },
    severity_counts: { HIGH: 11, MEDIUM: 6, LOW: 7 },
    confidence_counts: { CONFIRMED: 17, MEDIUM: 3, LOW: 3, HIGH: 1 }
  };

  const findings = useMemo(() => {
    return scanData?.findings || [];
  }, [scanData]);

  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      const q = search.toLowerCase();
      const matchesSearch =
        !q ||
        f.id.toLowerCase().includes(q) ||
        f.affected_file.toLowerCase().includes(q) ||
        f.evidence.toLowerCase().includes(q) ||
        f.explanation.toLowerCase().includes(q);

      if (!matchesSearch) return false;

      if (categoryFilter !== 'all' && f.category !== categoryFilter) return false;
      if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
      if (confidenceFilter !== 'all' && f.confidence !== confidenceFilter) return false;

      return true;
    });
  }, [findings, search, categoryFilter, severityFilter, confidenceFilter]);

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

  return (
    <div className="space-y-6">
      {/* Category Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
        <div className="bg-[#0E131F] border border-gray-800 p-3.5 rounded-xl">
          <span className="text-[11px] text-gray-400">Total Findings</span>
          <div className="text-2xl font-bold text-white font-mono mt-0.5">
            {metrics.total_findings}
          </div>
          <p className="text-[10px] text-gray-500 mt-0.5">Across 4 detection modules</p>
        </div>

        <div className="bg-[#0E131F] border border-orange-950/60 p-3.5 rounded-xl bg-gradient-to-b from-orange-950/20 to-transparent">
          <span className="text-[11px] text-orange-400 font-medium flex items-center gap-1">
            <Container className="w-3 h-3" />
            Docker & CI/CD
          </span>
          <div className="text-2xl font-bold text-orange-400 font-mono mt-0.5">
            {metrics.category_counts?.['Docker & CI/CD'] || 0}
          </div>
          <p className="text-[10px] text-orange-500/80 mt-0.5">Mutable tags & action refs</p>
        </div>

        <div className="bg-[#0E131F] border border-purple-950/60 p-3.5 rounded-xl bg-gradient-to-b from-purple-950/20 to-transparent">
          <span className="text-[11px] text-purple-400 font-medium flex items-center gap-1">
            <AlertOctagon className="w-3 h-3" />
            Typosquatting
          </span>
          <div className="text-2xl font-bold text-purple-400 font-mono mt-0.5">
            {metrics.category_counts?.['Typosquatting'] || 0}
          </div>
          <p className="text-[10px] text-purple-500/80 mt-0.5">Name similarity candidates</p>
        </div>

        <div className="bg-[#0E131F] border border-amber-950/60 p-3.5 rounded-xl bg-gradient-to-b from-amber-950/20 to-transparent">
          <span className="text-[11px] text-amber-400 font-medium flex items-center gap-1">
            <Terminal className="w-3 h-3" />
            Lifecycle Scripts
          </span>
          <div className="text-2xl font-bold text-amber-400 font-mono mt-0.5">
            {metrics.category_counts?.['Lifecycle Script'] || 0}
          </div>
          <p className="text-[10px] text-amber-500/80 mt-0.5">Hook triggers & shell exec</p>
        </div>

        <div className="bg-[#0E131F] border border-blue-950/60 p-3.5 rounded-xl bg-gradient-to-b from-blue-950/20 to-transparent">
          <span className="text-[11px] text-blue-400 font-medium flex items-center gap-1">
            <GitBranch className="w-3 h-3" />
            Dependency Change
          </span>
          <div className="text-2xl font-bold text-blue-400 font-mono mt-0.5">
            {metrics.category_counts?.['Dependency Change'] || 0}
          </div>
          <p className="text-[10px] text-blue-500/80 mt-0.5">Floating constraints</p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-gray-500" />
            <input
              type="text"
              placeholder="Search finding ID, file, or evidence..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-gray-100 pl-8 pr-3 py-1.5 rounded-lg text-xs w-64 focus:outline-none focus:border-blue-500"
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
              <option value="HIGH">High ({metrics.severity_counts?.HIGH || 0})</option>
              <option value="MEDIUM">Medium ({metrics.severity_counts?.MEDIUM || 0})</option>
              <option value="LOW">Low ({metrics.severity_counts?.LOW || 0})</option>
            </select>
          </div>

          {/* Confidence Filter */}
          <div className="flex items-center gap-1.5 text-gray-400">
            <span>Confidence:</span>
            <select
              value={confidenceFilter}
              onChange={e => setConfidenceFilter(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-gray-200 px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-blue-500"
            >
              <option value="all">All Confidence Levels</option>
              <option value="CONFIRMED">Confirmed</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>

        <div className="text-gray-400 text-xs">
          Showing <span className="text-white font-semibold">{filteredFindings.length}</span> of {findings.length} findings
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filteredFindings.length === 0 ? (
          <div className="bg-[#0E131F] border border-gray-800 rounded-xl p-8 text-center text-gray-500 text-xs">
            No suspicious change findings match the current filter criteria.
          </div>
        ) : (
          filteredFindings.map((finding) => (
            <div
              key={finding.id}
              className="bg-[#0E131F] border border-gray-800 rounded-xl p-5 space-y-3.5 shadow-sm hover:border-gray-700 transition"
            >
              {/* Top Row: Category, Severity, ID, and File Location */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  {getCategoryBadge(finding.category)}
                  {getSeverityBadge(finding.severity)}
                  <span className="font-mono text-xs font-bold text-white">
                    {finding.id}
                  </span>
                  <span className="text-[10px] bg-gray-900 text-gray-400 border border-gray-800 px-2 py-0.5 rounded font-mono">
                    CONFIDENCE: {finding.confidence}
                  </span>
                </div>

                <div className="flex items-center gap-1.5 text-xs text-gray-400 bg-gray-950 px-2.5 py-1 rounded border border-gray-800 font-mono">
                  <FileCode className="w-3.5 h-3.5 text-blue-400" />
                  <span className="text-gray-200">{finding.affected_file}</span>
                  {finding.line_number && (
                    <span className="text-amber-400">:{finding.line_number}</span>
                  )}
                </div>
              </div>

              {/* Evidence Snippet */}
              <div className="bg-[#070A10] border border-gray-800/90 rounded-lg p-3 font-mono text-xs text-gray-300">
                <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1 flex items-center gap-1 font-sans">
                  <span>Exact Line Evidence</span>
                </div>
                <div className="text-red-300/90 bg-red-950/20 px-2 py-1 rounded border border-red-950/40 select-all">
                  {finding.evidence}
                </div>
              </div>

              {/* Technical Explanation */}
              <div className="text-xs text-gray-300 leading-relaxed">
                <span className="text-gray-500 font-semibold text-[11px] block mb-0.5">TECHNICAL EXPLANATION</span>
                {finding.explanation}
              </div>

              {/* Recommended Action Box */}
              <div className="bg-emerald-950/15 border border-emerald-800/40 rounded-lg p-3 text-xs text-emerald-300 flex items-start gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold text-[11px] uppercase tracking-wider block text-emerald-400">
                    Recommended Remediation Action
                  </span>
                  <p className="mt-0.5 text-gray-200">{finding.recommended_action}</p>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
