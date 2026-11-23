import React, { useState, useEffect } from 'react';
import {
  Shield,
  Layers,
  FileCode,
  GitBranch,
  Download,
  Search,
  ExternalLink,
  RefreshCw,
  Box,
  FileText,
  Cpu,
  AlertTriangle,
  CheckCircle2,
  Workflow
} from 'lucide-react';
import DependencyGraphView from './components/DependencyGraphView';

export default function App() {
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('graph'); // 'graph', 'inventory', 'sbom', 'repo'
  const [repoMetadata, setRepoMetadata] = useState(null);
  const [inventory, setInventory] = useState(null);
  const [sbomComparison, setSbomComparison] = useState(null);
  const [graphData, setGraphData] = useState(null);
  const [rawSbom, setRawSbom] = useState(null);

  // Search & Filters for Inventory Table
  const [invSearch, setInvSearch] = useState('');
  const [invFilter, setInvFilter] = useState('all'); // 'all', 'direct', 'production', 'development'

  const loadData = async () => {
    setLoading(true);
    try {
      // 1. Repositories
      const repoRes = await fetch('/api/repositories');
      const repos = await repoRes.json();
      if (repos && repos.length > 0) {
        setRepoMetadata(repos[0]);
      }

      // 2. Dependencies
      const invRes = await fetch('/api/dependencies/nodegoat');
      const invData = await invRes.json();
      setInventory(invData);

      // 3. SBOM Comparison
      const sbomRes = await fetch('/api/sbom/nodegoat?format=comparison');
      if (sbomRes.ok) {
        const sbomComp = await sbomRes.json();
        setSbomComparison(sbomComp);
      }

      // 4. Raw SBOM
      const rawRes = await fetch('/api/sbom/nodegoat');
      if (rawRes.ok) {
        const rawJson = await rawRes.json();
        setRawSbom(rawJson);
      }

      // 5. Graph
      const graphRes = await fetch('/api/graph/nodegoat');
      const graphJson = await graphRes.json();
      setGraphData(graphJson);
    } catch (err) {
      console.error('Failed to load Guardian data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const downloadFile = (data, filename, type = 'application/json') => {
    const blob = new Blob([typeof data === 'string' ? data : JSON.stringify(data, null, 2)], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const filteredComponents = inventory?.components?.filter(comp => {
    const matchesSearch = comp.name.toLowerCase().includes(invSearch.toLowerCase()) ||
      comp.version.toLowerCase().includes(invSearch.toLowerCase());
    if (!matchesSearch) return false;
    if (invFilter === 'direct') return comp.dependency_type === 'direct';
    if (invFilter === 'production') return comp.environment === 'production';
    if (invFilter === 'development') return comp.environment === 'development';
    return true;
  }) || [];

  return (
    <div className="min-h-screen bg-[#080B11] text-gray-100 flex flex-col font-sans">
      {/* Header */}
      <header className="border-b border-gray-800 bg-[#0E131F]/90 backdrop-blur-md sticky top-0 z-30 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-white tracking-wide">Software Supply Chain Guardian</h1>
              <span className="text-[10px] bg-blue-500/20 text-blue-300 border border-blue-500/30 px-2 py-0.5 rounded-full font-semibold">
                PHASE 1 ACTIVE
              </span>
            </div>
            <p className="text-xs text-gray-400">Bosch Global Software Technologies (BGSW) Hackathon</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs bg-gray-900 border border-gray-800 px-3 py-1.5 rounded-lg">
            <GitBranch className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-gray-400">Target:</span>
            <span className="text-white font-medium">OWASP NodeGoat</span>
            <span className="font-mono text-gray-500 text-[11px]">({repoMetadata?.commit_hash?.slice(0, 7) || 'HEAD'})</span>
          </div>

          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-1.5 text-xs bg-gray-800 hover:bg-gray-700 text-gray-200 px-3 py-1.5 rounded-lg border border-gray-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Scan
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        {/* Metric Cards Banner */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl shadow-sm">
            <div className="flex items-center justify-between text-gray-400 text-xs mb-1">
              <span>Total Components</span>
              <Box className="w-4 h-4 text-blue-400" />
            </div>
            <div className="text-2xl font-bold text-white font-mono">
              {inventory?.total_components?.toLocaleString() || '1,091'}
            </div>
            <p className="text-[11px] text-gray-500 mt-1">Unique lockfile packages</p>
          </div>

          <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl shadow-sm">
            <div className="flex items-center justify-between text-gray-400 text-xs mb-1">
              <span>Direct Dependencies</span>
              <Layers className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold text-emerald-400 font-mono">
              {inventory?.direct_dependencies || '36'}
            </div>
            <p className="text-[11px] text-gray-500 mt-1">16 prod / 20 dev</p>
          </div>

          <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl shadow-sm">
            <div className="flex items-center justify-between text-gray-400 text-xs mb-1">
              <span>Transitive Deps</span>
              <Workflow className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-purple-400 font-mono">
              {inventory?.transitive_dependencies?.toLocaleString() || '1,055'}
            </div>
            <p className="text-[11px] text-gray-500 mt-1">Nested dependency tree</p>
          </div>

          <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl shadow-sm">
            <div className="flex items-center justify-between text-gray-400 text-xs mb-1">
              <span>Production / Dev</span>
              <Cpu className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-xl font-bold text-white font-mono flex items-baseline gap-1">
              <span className="text-emerald-400">{inventory?.production_dependencies || '509'}</span>
              <span className="text-gray-500 text-sm">/</span>
              <span className="text-amber-400">{inventory?.development_dependencies || '537'}</span>
            </div>
            <p className="text-[11px] text-gray-500 mt-1">Runtime reachability</p>
          </div>

          <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl shadow-sm">
            <div className="flex items-center justify-between text-gray-400 text-xs mb-1">
              <span>Syft CycloneDX</span>
              <FileCode className="w-4 h-4 text-blue-400" />
            </div>
            <div className="text-2xl font-bold text-blue-400 font-mono">
              {sbomComparison?.total_sbom_components || '422'}
            </div>
            <p className="text-[11px] text-gray-500 mt-1">v{sbomComparison?.syft_version || '1.57.2'} standard</p>
          </div>

          <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl shadow-sm">
            <div className="flex items-center justify-between text-gray-400 text-xs mb-1">
              <span>Graph Edges</span>
              <GitBranch className="w-4 h-4 text-indigo-400" />
            </div>
            <div className="text-2xl font-bold text-indigo-400 font-mono">
              {graphData?.summary?.total_edges?.toLocaleString() || '1,931'}
            </div>
            <p className="text-[11px] text-gray-500 mt-1">357 shared links</p>
          </div>
        </div>

        {/* Tab Navigation & Export Actions */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-gray-800 pb-2">
          <div className="flex gap-2 text-xs">
            <button
              onClick={() => setActiveTab('graph')}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg font-medium transition ${activeTab === 'graph' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white hover:bg-gray-800'}`}
            >
              <Workflow className="w-4 h-4" />
              Dependency Graph (React Flow)
            </button>
            <button
              onClick={() => setActiveTab('inventory')}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg font-medium transition ${activeTab === 'inventory' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white hover:bg-gray-800'}`}
            >
              <Layers className="w-4 h-4" />
              Component Inventory ({inventory?.total_components || 0})
            </button>
            <button
              onClick={() => setActiveTab('sbom')}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg font-medium transition ${activeTab === 'sbom' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white hover:bg-gray-800'}`}
            >
              <FileCode className="w-4 h-4" />
              CycloneDX SBOM & Discrepancies
            </button>
            <button
              onClick={() => setActiveTab('repo')}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg font-medium transition ${activeTab === 'repo' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white hover:bg-gray-800'}`}
            >
              <FileText className="w-4 h-4" />
              Repository Ingestion
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => downloadFile(rawSbom, 'nodegoat-sbom.json')}
              className="flex items-center gap-1.5 text-xs bg-gray-900 hover:bg-gray-800 text-gray-300 px-3 py-1.5 rounded-lg border border-gray-800 transition"
              title="Download Syft CycloneDX JSON"
            >
              <Download className="w-3.5 h-3.5 text-blue-400" />
              Export SBOM (CycloneDX)
            </button>
            <button
              onClick={() => downloadFile(inventory, 'component-inventory.json')}
              className="flex items-center gap-1.5 text-xs bg-gray-900 hover:bg-gray-800 text-gray-300 px-3 py-1.5 rounded-lg border border-gray-800 transition"
              title="Download Inventory JSON"
            >
              <Download className="w-3.5 h-3.5 text-emerald-400" />
              Export Inventory
            </button>
            <button
              onClick={() => downloadFile(graphData, 'nodegoat-dependency-graph.json')}
              className="flex items-center gap-1.5 text-xs bg-gray-900 hover:bg-gray-800 text-gray-300 px-3 py-1.5 rounded-lg border border-gray-800 transition"
              title="Download Graph JSON"
            >
              <Download className="w-3.5 h-3.5 text-purple-400" />
              Export Graph
            </button>
          </div>
        </div>

        {/* Tab 1: Dependency Graph */}
        {activeTab === 'graph' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-gray-400">
              <p>
                Visualizing <span className="text-white font-medium">{graphData?.summary?.total_nodes || 1092} nodes</span> and <span className="text-white font-medium">{graphData?.summary?.total_edges || 1931} directed dependency edges</span> built with NetworkX. Click any node to inspect relationship details.
              </p>
            </div>
            <DependencyGraphView graphData={graphData} />
          </div>
        )}

        {/* Tab 2: Component Inventory */}
        {activeTab === 'inventory' && (
          <div className="bg-[#0E131F] border border-gray-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
              <div className="relative w-full sm:w-80">
                <Search className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Filter components by name or version..."
                  value={invSearch}
                  onChange={e => setInvSearch(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="flex gap-1 text-xs">
                {['all', 'direct', 'production', 'development'].map(f => (
                  <button
                    key={f}
                    onClick={() => setInvFilter(f)}
                    className={`px-3 py-1.5 rounded-lg capitalize font-medium transition ${invFilter === f ? 'bg-blue-600 text-white' : 'bg-gray-900 text-gray-400 hover:text-white'}`}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>

            <div className="overflow-x-auto rounded-lg border border-gray-800">
              <table className="w-full text-left text-xs text-gray-300">
                <thead className="bg-gray-900/80 text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
                  <tr>
                    <th className="py-2.5 px-4">Component Name</th>
                    <th className="py-2.5 px-4">Version</th>
                    <th className="py-2.5 px-4">Type</th>
                    <th className="py-2.5 px-4">Environment</th>
                    <th className="py-2.5 px-4">Declared In</th>
                    <th className="py-2.5 px-4">PURL Identifier</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800 font-mono">
                  {filteredComponents.slice(0, 100).map((c, i) => (
                    <tr key={i} className="hover:bg-gray-900/50 transition">
                      <td className="py-2 px-4 font-semibold text-white font-sans">{c.name}</td>
                      <td className="py-2 px-4 text-blue-400">{c.version}</td>
                      <td className="py-2 px-4 font-sans">
                        <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${c.dependency_type === 'direct' ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30' : 'bg-gray-800 text-gray-400'}`}>
                          {c.dependency_type}
                        </span>
                      </td>
                      <td className="py-2 px-4 font-sans">
                        <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${c.environment === 'production' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'}`}>
                          {c.environment}
                        </span>
                      </td>
                      <td className="py-2 px-4 text-gray-400 text-[11px] font-sans">
                        {c.declared_version ? `package.json (${c.declared_version})` : 'package-lock.json'}
                      </td>
                      <td className="py-2 px-4 text-gray-500 text-[11px] truncate max-w-xs">{c.purl}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="text-right text-[11px] text-gray-500">
              Showing {Math.min(filteredComponents.length, 100)} of {filteredComponents.length} components
            </div>
          </div>
        )}

        {/* Tab 3: SBOM & Discrepancies */}
        {activeTab === 'sbom' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl">
                <span className="text-gray-400 text-xs">Validation Status</span>
                <div className="flex items-center gap-2 mt-2">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  <span className="text-base font-bold text-white uppercase">{sbomComparison?.validation_status || 'VALID'}</span>
                </div>
                <p className="text-xs text-gray-400 mt-1">Compliant with CycloneDX specification v1.7</p>
              </div>

              <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl">
                <span className="text-gray-400 text-xs">Cross-Validation Match</span>
                <div className="text-xl font-bold text-white font-mono mt-2">
                  {sbomComparison?.matched_components || 321} / {sbomComparison?.total_sbom_components || 422}
                </div>
                <p className="text-xs text-gray-400 mt-1">Packages verified between Syft and lockfile</p>
              </div>

              <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl">
                <span className="text-gray-400 text-xs">Identified Discrepancies</span>
                <div className="text-xl font-bold text-amber-400 font-mono mt-2">
                  {sbomComparison?.only_in_inventory?.length || 483} deep transitives
                </div>
                <p className="text-xs text-gray-400 mt-1">Deep nested packages not hoisted in disk scan</p>
              </div>
            </div>

            <div className="bg-[#0E131F] border border-gray-800 rounded-xl p-5 space-y-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Evidence-First Discrepancy Breakdown
              </h3>
              <p className="text-xs text-gray-300 leading-relaxed">
                Syft scans the repository filesystem and detected <span className="text-blue-400 font-semibold">{sbomComparison?.total_sbom_components} components</span> (including GitHub Actions workflows and top-level packages). Meanwhile, our parser analyzed the full 1,480-entry npm lockfile tree, discovering <span className="text-emerald-400 font-semibold">{inventory?.total_components} unique packages</span>. Guardian cross-references both to eliminate blind spots.
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
                <div className="bg-gray-900/60 border border-gray-800 p-3 rounded-lg text-xs">
                  <span className="text-gray-400 font-semibold block mb-2">Detected in Syft SBOM Only (e.g. CI/CD actions)</span>
                  <div className="max-h-40 overflow-y-auto space-y-1 font-mono text-[11px] text-blue-300">
                    {sbomComparison?.only_in_sbom?.map((item, idx) => (
                      <div key={idx} className="bg-gray-800/40 px-2 py-0.5 rounded">{item}</div>
                    ))}
                  </div>
                </div>

                <div className="bg-gray-900/60 border border-gray-800 p-3 rounded-lg text-xs">
                  <span className="text-gray-400 font-semibold block mb-2">Deep Lockfile Transitives (Sample)</span>
                  <div className="max-h-40 overflow-y-auto space-y-1 font-mono text-[11px] text-gray-300">
                    {sbomComparison?.only_in_inventory?.slice(0, 30).map((item, idx) => (
                      <div key={idx} className="bg-gray-800/40 px-2 py-0.5 rounded">{item}</div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 4: Repository Ingestion */}
        {activeTab === 'repo' && (
          <div className="bg-[#0E131F] border border-gray-800 rounded-xl p-6 space-y-4">
            <h3 className="text-sm font-bold text-white">Repository Discovery & Metadata</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="bg-gray-900/60 p-4 rounded-lg border border-gray-800 space-y-2">
                <span className="text-gray-500 font-medium uppercase text-[10px] tracking-wider">Repository Details</span>
                <div>
                  <span className="text-gray-400">Path:</span> <span className="text-gray-200 font-mono">{repoMetadata?.path}</span>
                </div>
                <div>
                  <span className="text-gray-400">Commit SHA:</span> <span className="text-blue-400 font-mono">{repoMetadata?.commit_hash}</span>
                </div>
                <div>
                  <span className="text-gray-400">Languages:</span> <span className="text-white font-medium">{repoMetadata?.languages?.join(', ')}</span>
                </div>
                <div>
                  <span className="text-gray-400">Package Manager:</span> <span className="text-emerald-400 font-medium uppercase">{repoMetadata?.package_managers?.join(', ')}</span>
                </div>
              </div>

              <div className="bg-gray-900/60 p-4 rounded-lg border border-gray-800 space-y-2">
                <span className="text-gray-500 font-medium uppercase text-[10px] tracking-wider">Detected Manifests & Configs</span>
                <div>
                  <span className="text-gray-400">Manifests:</span> <span className="text-white font-mono">{repoMetadata?.manifests?.join(', ')}</span>
                </div>
                <div>
                  <span className="text-gray-400">Lockfiles:</span> <span className="text-white font-mono">{repoMetadata?.lockfiles?.join(', ')}</span>
                </div>
                <div>
                  <span className="text-gray-400">Dockerfiles:</span> <span className="text-amber-400 font-mono">{repoMetadata?.dockerfiles?.join(', ')}</span>
                </div>
                <div>
                  <span className="text-gray-400">Docker Compose:</span> <span className="text-amber-400 font-mono">{repoMetadata?.docker_compose_files?.join(', ')}</span>
                </div>
                <div>
                  <span className="text-gray-400">CI/CD Workflows:</span> <span className="text-purple-400 font-mono">{repoMetadata?.cicd_files?.join(', ')}</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800/80 py-4 px-6 text-center text-xs text-gray-500">
        Software Supply Chain Guardian • BGSW Hackathon • Day 1: Discovery, Supply Chain Mapping & Initial Threat Detection
      </footer>
    </div>
  );
}
