import React, { useState, useMemo } from 'react';
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Search,
  Filter,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  GitCommit,
  Layers,
  ArrowRight
} from 'lucide-react';

export default function VulnerabilitiesView({ scanData }) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [envFilter, setEnvFilter] = useState('all');
  const [depTypeFilter, setDepTypeFilter] = useState('all');
  const [expandedId, setExpandedId] = useState(null);

  const metrics = scanData?.metrics || {
    total_packages_scanned: 1091,
    vulnerable_packages_count: 98,
    total_vulnerabilities: 201,
    unique_advisory_ids: 141,
    production_vulnerabilities: 111,
    development_vulnerabilities: 90,
    severity_counts: { CRITICAL: 22, HIGH: 106, MODERATE: 60, LOW: 12, UNKNOWN: 1 }
  };

  const findings = useMemo(() => {
    return scanData?.findings || [];
  }, [scanData]);

  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      // Search matches CVE ID, package name, or summary
      const q = search.toLowerCase();
      const matchesSearch =
        !q ||
        f.id.toLowerCase().includes(q) ||
        f.osv_id.toLowerCase().includes(q) ||
        f.package_name.toLowerCase().includes(q) ||
        f.summary.toLowerCase().includes(q);

      if (!matchesSearch) return false;

      // Severity filter
      if (severityFilter !== 'all' && f.severity.toUpperCase() !== severityFilter) {
        return false;
      }

      // Environment filter
      if (envFilter !== 'all' && f.environment !== envFilter) {
        return false;
      }

      // Dependency type filter
      if (depTypeFilter !== 'all' && f.dependency_type !== depTypeFilter) {
        return false;
      }

      return true;
    });
  }, [findings, search, severityFilter, envFilter, depTypeFilter]);

  const getSeverityBadge = (severity, score) => {
    const sev = severity?.toUpperCase() || 'UNKNOWN';
    let bg = 'bg-gray-800 text-gray-300 border-gray-700';
    if (sev === 'CRITICAL') bg = 'bg-red-500/20 text-red-400 border-red-500/40';
    else if (sev === 'HIGH') bg = 'bg-orange-500/20 text-orange-400 border-orange-500/40';
    else if (sev === 'MODERATE' || sev === 'MEDIUM') bg = 'bg-amber-500/20 text-amber-400 border-amber-500/40';
    else if (sev === 'LOW') bg = 'bg-blue-500/20 text-blue-400 border-blue-500/40';

    return (
      <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${bg}`}>
        <span>{sev}</span>
        {score !== null && score !== undefined && (
          <span className="font-mono text-[10px] opacity-80">({score})</span>
        )}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Metrics Banner */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <div className="bg-[#0E131F] border border-gray-800 p-3.5 rounded-xl">
          <span className="text-[11px] text-gray-400">Total Vulnerabilities</span>
          <div className="text-2xl font-bold text-white font-mono mt-0.5">
            {metrics.total_vulnerabilities}
          </div>
          <p className="text-[10px] text-gray-500 mt-0.5">{metrics.unique_advisory_ids} unique CVEs</p>
        </div>

        <div className="bg-[#0E131F] border border-red-950/60 p-3.5 rounded-xl bg-gradient-to-b from-red-950/20 to-transparent">
          <span className="text-[11px] text-red-400 font-medium">Critical Severity</span>
          <div className="text-2xl font-bold text-red-400 font-mono mt-0.5">
            {metrics.severity_counts?.CRITICAL || 22}
          </div>
          <p className="text-[10px] text-red-500/80 mt-0.5">Immediate threat</p>
        </div>

        <div className="bg-[#0E131F] border border-orange-950/60 p-3.5 rounded-xl bg-gradient-to-b from-orange-950/20 to-transparent">
          <span className="text-[11px] text-orange-400 font-medium">High Severity</span>
          <div className="text-2xl font-bold text-orange-400 font-mono mt-0.5">
            {metrics.severity_counts?.HIGH || 106}
          </div>
          <p className="text-[10px] text-orange-500/80 mt-0.5">Severe impact</p>
        </div>

        <div className="bg-[#0E131F] border border-amber-950/60 p-3.5 rounded-xl bg-gradient-to-b from-amber-950/20 to-transparent">
          <span className="text-[11px] text-amber-400 font-medium">Moderate Severity</span>
          <div className="text-2xl font-bold text-amber-400 font-mono mt-0.5">
            {metrics.severity_counts?.MODERATE || 60}
          </div>
          <p className="text-[10px] text-amber-500/80 mt-0.5">Medium exposure</p>
        </div>

        <div className="bg-[#0E131F] border border-emerald-950/60 p-3.5 rounded-xl">
          <span className="text-[11px] text-emerald-400 font-medium">Production Scope</span>
          <div className="text-2xl font-bold text-emerald-400 font-mono mt-0.5">
            {metrics.production_vulnerabilities}
          </div>
          <p className="text-[10px] text-gray-500 mt-0.5">Reachable in runtime</p>
        </div>

        <div className="bg-[#0E131F] border border-blue-950/60 p-3.5 rounded-xl">
          <span className="text-[11px] text-blue-400 font-medium">Development Scope</span>
          <div className="text-2xl font-bold text-blue-400 font-mono mt-0.5">
            {metrics.development_vulnerabilities}
          </div>
          <p className="text-[10px] text-gray-500 mt-0.5">Build & test tools</p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-gray-500" />
            <input
              type="text"
              placeholder="Search CVE or package..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-gray-100 pl-8 pr-3 py-1.5 rounded-lg text-xs w-64 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1.5 text-gray-400">
            <span>Severity:</span>
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-gray-200 px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-blue-500"
            >
              <option value="all">All Severities ({findings.length})</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MODERATE">Moderate</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Environment Filter */}
          <div className="flex items-center gap-1.5 text-gray-400">
            <span>Environment:</span>
            <select
              value={envFilter}
              onChange={e => setEnvFilter(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-gray-200 px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-blue-500"
            >
              <option value="all">All Environments</option>
              <option value="production">Production Only ({metrics.production_vulnerabilities})</option>
              <option value="development">Development Only ({metrics.development_vulnerabilities})</option>
            </select>
          </div>

          {/* Dependency Type */}
          <div className="flex items-center gap-1.5 text-gray-400">
            <span>Type:</span>
            <select
              value={depTypeFilter}
              onChange={e => setDepTypeFilter(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-gray-200 px-2.5 py-1.5 rounded-lg focus:outline-none focus:border-blue-500"
            >
              <option value="all">Direct & Transitive</option>
              <option value="direct">Direct Only</option>
              <option value="transitive">Transitive Only</option>
            </select>
          </div>
        </div>

        <div className="text-gray-400 text-xs">
          Showing <span className="text-white font-semibold">{filteredFindings.length}</span> of {findings.length} findings
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-2">
        {filteredFindings.length === 0 ? (
          <div className="bg-[#0E131F] border border-gray-800 rounded-xl p-8 text-center text-gray-500 text-xs">
            No vulnerability findings match the current filter criteria.
          </div>
        ) : (
          filteredFindings.map((finding, idx) => {
            const isExpanded = expandedId === `${finding.id}-${finding.package_name}-${idx}`;
            const rowKey = `${finding.id}-${finding.package_name}-${idx}`;

            return (
              <div
                key={rowKey}
                className="bg-[#0E131F] border border-gray-800 hover:border-gray-700 rounded-xl transition duration-150 overflow-hidden shadow-sm"
              >
                {/* Header Row */}
                <div
                  onClick={() => setExpandedId(isExpanded ? null : rowKey)}
                  className="p-4 cursor-pointer flex items-center justify-between gap-4"
                >
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <button className="text-gray-500 hover:text-white transition">
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 text-blue-400" />
                      ) : (
                        <ChevronRight className="w-4 h-4" />
                      )}
                    </button>

                    {getSeverityBadge(finding.severity, finding.cvss_score)}

                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-bold text-white tracking-tight">
                          {finding.id}
                        </span>
                        {finding.osv_id && finding.osv_id !== finding.id && (
                          <span className="text-[10px] text-gray-500 font-mono">
                            ({finding.osv_id})
                          </span>
                        )}
                        <span className="text-xs text-gray-400 font-mono bg-gray-900 border border-gray-800 px-2 py-0.5 rounded">
                          {finding.package_name}@{finding.version}
                        </span>
                        <span
                          className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                            finding.environment === 'production'
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                              : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          }`}
                        >
                          {finding.environment.toUpperCase()}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Expanded Details Drawer */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-2 border-t border-gray-800/80 bg-gray-950/40 space-y-4 text-xs">
                    {/* Lineage Path */}
                    <div className="bg-[#0B0F19] border border-gray-800/80 p-3 rounded-lg">
                      <span className="text-gray-400 text-[11px] font-semibold block mb-1.5 flex items-center gap-1.5">
                        <Layers className="w-3.5 h-3.5 text-blue-400" />
                        Supply Chain Lineage (Root Path):
                      </span>
                      <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
                        {(finding.dependency_lineage || []).map((step, sIdx, arr) => (
                          <React.Fragment key={step}>
                            <span
                              className={`px-2 py-0.5 rounded ${
                                sIdx === 0
                                  ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30 font-bold'
                                  : sIdx === arr.length - 1
                                  ? 'bg-red-500/20 text-red-300 border border-red-500/30 font-bold'
                                  : 'bg-gray-900 text-gray-300 border border-gray-800'
                              }`}
                            >
                              {step === 'root' ? '★ owasp-nodejs-goat' : step}
                            </span>
                            {sIdx < arr.length - 1 && (
                              <ArrowRight className="w-3 h-3 text-gray-600" />
                            )}
                          </React.Fragment>
                        ))}
                      </div>
                    </div>

                    {/* Metadata Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      <div className="bg-[#0B0F19] border border-gray-800/80 p-3 rounded-lg">
                        <span className="text-gray-500 text-[10px] block mb-1">AFFECTED VERSIONS</span>
                        <div className="font-mono text-gray-200">{finding.affected_range}</div>
                      </div>
                      <div className="bg-[#0B0F19] border border-gray-800/80 p-3 rounded-lg">
                        <span className="text-gray-500 text-[10px] block mb-1">PACKAGE URL (PURL)</span>
                        <div className="font-mono text-blue-400 truncate">{finding.purl}</div>
                      </div>
                      <div className="bg-[#0B0F19] border border-gray-800/80 p-3 rounded-lg">
                        <span className="text-gray-500 text-[10px] block mb-1">INSTALLATION LOCATIONS</span>
                        <div className="font-mono text-gray-300 text-[11px] truncate">
                          {finding.installation_paths?.length || 1} path(s) in node_modules
                        </div>
                      </div>
                    </div>

                    {/* Technical Description */}
                    {finding.details && (
                      <div className="bg-[#0B0F19] border border-gray-800/80 p-3 rounded-lg space-y-1">
                        <span className="text-gray-500 text-[10px] font-semibold block">ADVISORY DETAILS</span>
                        <p className="text-gray-300 text-xs leading-relaxed whitespace-pre-wrap">
                          {finding.details}
                        </p>
                      </div>
                    )}

                    {/* Advisory References */}
                    {finding.references?.length > 0 && (
                      <div className="space-y-1">
                        <span className="text-gray-500 text-[10px] font-semibold block">OFFICIAL REFERENCES</span>
                        <div className="flex flex-wrap gap-2">
                          {finding.references.map((refUrl, rIdx) => (
                            <a
                              key={rIdx}
                              href={refUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300 bg-gray-900 border border-gray-800 px-2.5 py-1 rounded transition hover:border-blue-500/40"
                            >
                              <ExternalLink className="w-3 h-3" />
                              <span className="truncate max-w-xs">{refUrl}</span>
                            </a>
                          ))}
                        </div>
                      </div>
                    )}
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
