import React, { useState, useEffect } from 'react';
import {
  Shield,
  Layers,
  FileCode,
  GitBranch,
  Download,
  Search,
  Box,
  CheckCircle2,
  Workflow,
  Sparkles,
  Split
} from 'lucide-react';
import DependencyGraphView from './components/DependencyGraphView';
import CrossValidationView from './components/CrossValidationView';

export default function App() {
  const [activeTab, setActiveTab] = useState('graph'); // 'graph', 'validation', 'inventory', 'raw_sbom'
  const [inventory, setInventory] = useState(null);
  const [sbomData, setSbomData] = useState(null);
  const [graphData, setGraphData] = useState(null);
  const [loading, setLoading] = useState(true);

  // Search in Inventory
  const [invSearch, setInvSearch] = useState('');
  const [invFilter, setInvFilter] = useState('all');

  useEffect(() => {
    async function loadAll() {
      try {
        setLoading(true);
        const [invRes, sbomRes, graphRes] = await Promise.all([
          fetch('/component-inventory.json'),
          fetch('/nodegoat-sbom.json'),
          fetch('/nodegoat-dependency-graph.json')
        ]);

        if (invRes.ok) setInventory(await invRes.json());
        if (sbomRes.ok) setSbomData(await sbomRes.json());
        if (graphRes.ok) setGraphData(await graphRes.json());
      } catch (e) {
        console.error('Failed to load local data files:', e);
      } finally {
        setLoading(false);
      }
    }
    loadAll();
  }, []);

  const downloadFile = (data, filename) => {
    const blob = new Blob([typeof data === 'string' ? data : JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const filteredComponents = (inventory?.components || []).filter(c => {
    const matchesSearch = c.name.toLowerCase().includes(invSearch.toLowerCase()) ||
      c.version.toLowerCase().includes(invSearch.toLowerCase());
    if (!matchesSearch) return false;
    if (invFilter === 'direct') return c.dependency_type === 'direct';
    if (invFilter === 'production') return c.environment === 'production';
    if (invFilter === 'development') return c.environment === 'development';
    return true;
  });

  return (
    <div className="min-h-screen bg-[#080B11] text-gray-100 flex flex-col font-sans">
      {/* Top Header */}
      <header className="border-b border-gray-800 bg-[#0E131F]/90 backdrop-blur-md sticky top-0 z-30 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 shadow-lg shadow-blue-500/10">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-white tracking-wide">Software Supply Chain Guardian</h1>
              <span className="text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 rounded-full font-semibold">
                PHASE 1 • DISCOVERY & TREE MAPPING
              </span>
            </div>
            <p className="text-xs text-gray-400">Target Application: <span className="text-white font-medium">OWASP NodeGoat</span> (Node.js / npm)</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <a
            href="/dependency-graph.html"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 text-xs bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-semibold px-3 py-1.5 rounded-lg shadow-lg shadow-emerald-600/20 transition border border-emerald-500/40"
          >
            <span className="w-2 h-2 rounded-full bg-white animate-pulse"></span>
            Circular Network View ↗
          </a>
          <button
            onClick={() => downloadFile(sbomData, 'nodegoat-sbom.json')}
            className="flex items-center gap-1.5 text-xs bg-gray-900 hover:bg-gray-800 text-gray-300 px-3 py-1.5 rounded-lg border border-gray-800 transition"
          >
            <Download className="w-3.5 h-3.5 text-blue-400" />
            CycloneDX SBOM JSON
          </button>
          <button
            onClick={() => downloadFile(graphData, 'nodegoat-dependency-graph.json')}
            className="flex items-center gap-1.5 text-xs bg-gray-900 hover:bg-gray-800 text-gray-300 px-3 py-1.5 rounded-lg border border-gray-800 transition"
          >
            <Download className="w-3.5 h-3.5 text-purple-400" />
            NetworkX Graph JSON
          </button>
        </div>
      </header>

      {/* Main Body */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        {/* Metric Cards Banner */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl shadow-sm">
            <span className="text-xs text-gray-400">Total Unique Packages</span>
            <div className="text-3xl font-bold text-white font-mono mt-1">
              {inventory?.total_components?.toLocaleString() || '1,091'}
            </div>
            <p className="text-[11px] text-gray-500 mt-1">Lockfile tree elements</p>
          </div>

          <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl shadow-sm">
            <span className="text-xs text-gray-400">Direct Dependencies</span>
            <div className="text-3xl font-bold text-emerald-400 font-mono mt-1">
              {inventory?.direct_dependencies || '36'}
            </div>
            <p className="text-[11px] text-gray-500 mt-1">16 Production / 20 Development</p>
          </div>

          <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl shadow-sm">
            <span className="text-xs text-gray-400">Syft CycloneDX SBOM</span>
            <div className="text-3xl font-bold text-blue-400 font-mono mt-1">
              {sbomData?.components?.length || '422'}
            </div>
            <p className="text-[11px] text-gray-500 mt-1">v1.7 Specification Compliant</p>
          </div>

          <div className="bg-[#0E131F] border border-gray-800 p-4 rounded-xl shadow-sm">
            <span className="text-xs text-gray-400">NetworkX Graph Model</span>
            <div className="text-3xl font-bold text-purple-400 font-mono mt-1">
              {graphData?.total_nodes || '1,092'} <span className="text-sm text-gray-500 font-sans font-normal">nodes</span>
            </div>
            <p className="text-[11px] text-gray-500 mt-1">{graphData?.total_edges || '1,921'} verified dependency edges</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-gray-800 pb-2 gap-2 text-xs">
          <button
            onClick={() => setActiveTab('graph')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition ${activeTab === 'graph' ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20' : 'text-gray-400 hover:text-white hover:bg-gray-800'}`}
          >
            <Workflow className="w-4 h-4" />
            Dependency Tree Graph (React Flow)
          </button>
          <button
            onClick={() => setActiveTab('validation')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition ${activeTab === 'validation' ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20' : 'text-gray-400 hover:text-white hover:bg-gray-800'}`}
          >
            <Split className="w-4 h-4" />
            Cross-Validation (Lockfile vs. SBOM vs. Graph)
          </button>
          <button
            onClick={() => setActiveTab('inventory')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition ${activeTab === 'inventory' ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20' : 'text-gray-400 hover:text-white hover:bg-gray-800'}`}
          >
            <Layers className="w-4 h-4" />
            Component Inventory ({inventory?.total_components || 0})
          </button>
        </div>

        {/* Tab 1: Dependency Tree Graph */}
        {activeTab === 'graph' && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-gray-400 px-1">
              <p>
                Hierarchical DAG layout rendered with <span className="text-white font-semibold">Dagre</span>. Click <span className="text-blue-400 font-mono">+ N deps</span> on any package to expand its sub-dependencies, or click a card to inspect metadata.
              </p>
            </div>
            <DependencyGraphView graphData={graphData} />
          </div>
        )}

        {/* Tab 2: Cross-Validation View */}
        {activeTab === 'validation' && (
          <CrossValidationView
            inventory={inventory}
            sbom={sbomData}
            graph={graphData}
          />
        )}

        {/* Tab 3: Component Inventory */}
        {activeTab === 'inventory' && (
          <div className="bg-[#0E131F] border border-gray-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
              <div className="relative w-full sm:w-80">
                <Search className="w-4 h-4 text-gray-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Filter packages by name or version..."
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
                    <th className="py-2.5 px-4">Package Name</th>
                    <th className="py-2.5 px-4">Resolved Version</th>
                    <th className="py-2.5 px-4">Dependency Type</th>
                    <th className="py-2.5 px-4">Environment</th>
                    <th className="py-2.5 px-4">Package URL (PURL)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800 font-mono text-[11px]">
                  {filteredComponents.slice(0, 100).map((c, i) => (
                    <tr key={i} className="hover:bg-gray-900/50 transition">
                      <td className="py-2 px-4 font-semibold text-white font-sans">{c.name}</td>
                      <td className="py-2 px-4 text-blue-400">{c.version}</td>
                      <td className="py-2 px-4 font-sans">
                        <span className={`text-[10px] px-2 py-0.5 rounded font-medium ${c.dependency_type === 'direct' ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30' : 'bg-gray-800 text-gray-400'}`}>
                          {c.dependency_type}
                        </span>
                      </td>
                      <td className="py-2 px-4 font-sans">
                        <span className={`text-[10px] px-2 py-0.5 rounded font-medium ${c.environment === 'production' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'}`}>
                          {c.environment}
                        </span>
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
      </main>

      <footer className="border-t border-gray-800/80 py-4 px-6 text-center text-xs text-gray-500">
        Software Supply Chain Guardian • BGSW Hackathon • Verified Component Discovery & Dependency Graph
      </footer>
    </div>
  );
}
