import React, { useState, useMemo, useCallback } from 'react';
import ReactFlow, {
  Controls,
  Background,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType
} from 'reactflow';
import { Search, Filter, Layers, Share2, Info, ArrowRight, ShieldCheck, Box } from 'lucide-react';

export default function DependencyGraphView({ graphData }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('direct'); // 'direct', 'production', 'all', 'shared'
  const [selectedNode, setSelectedNode] = useState(null);
  const [maxDepth, setMaxDepth] = useState(2);

  // Filter nodes and edges based on search, filterType, and depth
  const { filteredNodes, filteredEdges } = useMemo(() => {
    if (!graphData || !graphData.nodes) return { filteredNodes: [], filteredEdges: [] };

    let eligibleNodeIds = new Set();
    const isSearching = searchTerm.trim().length > 0;

    // Filter nodes
    graphData.nodes.forEach(node => {
      if (node.id === 'root') {
        eligibleNodeIds.add('root');
        return;
      }

      if (isSearching) {
        if (node.label.toLowerCase().includes(searchTerm.toLowerCase())) {
          eligibleNodeIds.add(node.id);
        }
      } else {
        if (filterType === 'direct') {
          if (node.dependency_type === 'direct') eligibleNodeIds.add(node.id);
        } else if (filterType === 'production') {
          if (node.environment === 'production' && node.depth <= maxDepth) eligibleNodeIds.add(node.id);
        } else if (filterType === 'shared') {
          if (node.in_degree > 1 && node.depth <= maxDepth) eligibleNodeIds.add(node.id);
        } else {
          // 'all'
          if (node.depth <= maxDepth) eligibleNodeIds.add(node.id);
        }
      }
    });

    // If searching, also add parents of matching nodes so the graph is connected
    if (isSearching) {
      graphData.edges.forEach(edge => {
        if (eligibleNodeIds.has(edge.target)) {
          eligibleNodeIds.add(edge.source);
        }
      });
    }

    // Filter edges
    const matchedEdges = graphData.edges.filter(
      edge => eligibleNodeIds.has(edge.source) && eligibleNodeIds.has(edge.target)
    );

    // Compute layout positions (layered by depth)
    const depthGroups = {};
    graphData.nodes.forEach(node => {
      if (eligibleNodeIds.has(node.id)) {
        const d = node.depth || 0;
        if (!depthGroups[d]) depthGroups[d] = [];
        depthGroups[d].push(node);
      }
    });

    const flowNodes = [];
    Object.keys(depthGroups).forEach(dStr => {
      const d = parseInt(dStr, 10);
      const group = depthGroups[d];
      const spacingY = 90;
      const spacingX = 260;
      const startY = -((group.length - 1) * spacingY) / 2;

      group.forEach((node, idx) => {
        const isRoot = node.id === 'root';
        const isDirect = node.dependency_type === 'direct';
        const isProd = node.environment === 'production';

        let bgColor = '#1E293B';
        let borderColor = '#475569';
        let badgeColor = 'bg-gray-700 text-gray-200';

        if (isRoot) {
          bgColor = '#1E3A8A';
          borderColor = '#3B82F6';
          badgeColor = 'bg-blue-500/20 text-blue-300 border-blue-500/30';
        } else if (isProd) {
          bgColor = isDirect ? '#064E3B' : '#0F2D24';
          borderColor = '#10B981';
          badgeColor = 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
        } else {
          bgColor = isDirect ? '#78350F' : '#331B08';
          borderColor = '#F59E0B';
          badgeColor = 'bg-amber-500/20 text-amber-300 border-amber-500/30';
        }

        flowNodes.push({
          id: node.id,
          position: { x: d * spacingX + 50, y: startY + idx * spacingY + 250 },
          data: {
            ...node,
            title: node.label,
            version: node.version,
            badgeColor,
            isRoot
          },
          style: {
            background: bgColor,
            color: '#F8FAFC',
            border: `1.5px solid ${borderColor}`,
            borderRadius: '10px',
            padding: '10px 14px',
            fontSize: '12px',
            width: 200,
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.4)'
          }
        });
      });
    });

    const flowEdges = matchedEdges.slice(0, 500).map(edge => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      animated: edge.source === 'root',
      style: {
        stroke: edge.source === 'root' ? '#3B82F6' : '#64748B',
        strokeWidth: edge.source === 'root' ? 2 : 1
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: edge.source === 'root' ? '#3B82F6' : '#64748B'
      }
    }));

    return { filteredNodes: flowNodes, filteredEdges: flowEdges };
  }, [graphData, searchTerm, filterType, maxDepth]);

  const onNodeClick = useCallback((event, node) => {
    setSelectedNode(node.data);
  }, []);

  return (
    <div className="relative w-full h-[650px] bg-[#090D16] rounded-xl border border-gray-800 overflow-hidden flex">
      {/* Graph Area */}
      <div className="flex-1 h-full relative">
        {/* Controls Toolbar */}
        <div className="absolute top-4 left-4 z-10 flex flex-wrap gap-2 items-center bg-[#111827]/90 backdrop-blur-md p-2 rounded-lg border border-gray-800 shadow-xl">
          <div className="relative">
            <Search className="w-4 h-4 text-gray-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search package..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-xs rounded-md pl-8 pr-3 py-1.5 focus:outline-none focus:border-blue-500 w-44 text-gray-200"
            />
          </div>

          <div className="h-6 w-[1px] bg-gray-700 mx-1" />

          {/* Filter Pills */}
          <div className="flex gap-1 text-xs">
            <button
              onClick={() => { setFilterType('direct'); setSearchTerm(''); }}
              className={`px-2.5 py-1 rounded-md transition ${filterType === 'direct' ? 'bg-blue-600 text-white font-medium' : 'text-gray-400 hover:bg-gray-800'}`}
            >
              Direct ({graphData?.summary?.direct_dependencies_count || 0})
            </button>
            <button
              onClick={() => { setFilterType('production'); setSearchTerm(''); }}
              className={`px-2.5 py-1 rounded-md transition ${filterType === 'production' ? 'bg-emerald-600 text-white font-medium' : 'text-gray-400 hover:bg-gray-800'}`}
            >
              Production
            </button>
            <button
              onClick={() => { setFilterType('shared'); setSearchTerm(''); }}
              className={`px-2.5 py-1 rounded-md transition ${filterType === 'shared' ? 'bg-purple-600 text-white font-medium' : 'text-gray-400 hover:bg-gray-800'}`}
            >
              Shared ({graphData?.summary?.shared_dependencies_count || 0})
            </button>
            <button
              onClick={() => { setFilterType('all'); setSearchTerm(''); }}
              className={`px-2.5 py-1 rounded-md transition ${filterType === 'all' ? 'bg-gray-700 text-white font-medium' : 'text-gray-400 hover:bg-gray-800'}`}
            >
              All Nodes
            </button>
          </div>

          <div className="h-6 w-[1px] bg-gray-700 mx-1" />

          {/* Depth Slider */}
          <div className="flex items-center gap-2 text-xs text-gray-300">
            <span>Depth: {maxDepth}</span>
            <input
              type="range"
              min="1"
              max={graphData?.summary?.max_depth || 5}
              value={maxDepth}
              onChange={e => setMaxDepth(parseInt(e.target.value, 10))}
              className="w-16 accent-blue-500 cursor-pointer"
            />
          </div>
        </div>

        {/* Legend */}
        <div className="absolute bottom-4 left-4 z-10 bg-[#111827]/80 backdrop-blur-md px-3 py-2 rounded-lg border border-gray-800 text-[11px] flex gap-4 text-gray-300">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block"></span> Root Application
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block"></span> Production
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block"></span> Development
          </div>
          <div className="text-gray-400">
            Showing {filteredNodes.length} nodes / {filteredEdges.length} edges
          </div>
        </div>

        <ReactFlow
          nodes={filteredNodes}
          edges={filteredEdges}
          onNodeClick={onNodeClick}
          fitView
          attributionPosition="bottom-right"
        >
          <Background color="#1E293B" gap={20} size={1} />
          <Controls className="bg-gray-900 border-gray-800 text-white fill-white" />
          <MiniMap
            nodeColor={n => {
              if (n.data?.isRoot) return '#3B82F6';
              if (n.data?.environment === 'production') return '#10B981';
              return '#F59E0B';
            }}
            className="bg-gray-900 border-gray-800 rounded-lg"
          />
        </ReactFlow>
      </div>

      {/* Selected Node Details Side Panel */}
      {selectedNode && (
        <div className="w-80 h-full bg-[#111827] border-l border-gray-800 p-5 overflow-y-auto">
          <div className="flex justify-between items-start mb-4">
            <div>
              <span className={`text-[10px] px-2 py-0.5 rounded-full border uppercase tracking-wider font-semibold ${selectedNode.badgeColor}`}>
                {selectedNode.dependency_type || 'Package'}
              </span>
              <h3 className="text-base font-bold text-white mt-1 break-words">{selectedNode.label}</h3>
              <p className="text-xs text-gray-400">v{selectedNode.version}</p>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-gray-500 hover:text-gray-300 text-sm p-1"
            >
              ✕
            </button>
          </div>

          <div className="space-y-4 text-xs">
            <div className="bg-gray-900/60 p-3 rounded-lg border border-gray-800">
              <span className="text-gray-400 block mb-1">Environment</span>
              <span className={`font-semibold capitalize ${selectedNode.environment === 'production' ? 'text-emerald-400' : 'text-amber-400'}`}>
                {selectedNode.environment}
              </span>
            </div>

            <div className="bg-gray-900/60 p-3 rounded-lg border border-gray-800">
              <span className="text-gray-400 block mb-1">Graph Metrics</span>
              <div className="grid grid-cols-2 gap-2 mt-1">
                <div>
                  <span className="text-gray-500">In-degree (Parents):</span>
                  <p className="text-white font-mono font-medium">{selectedNode.in_degree}</p>
                </div>
                <div>
                  <span className="text-gray-500">Out-degree (Deps):</span>
                  <p className="text-white font-mono font-medium">{selectedNode.out_degree}</p>
                </div>
                <div>
                  <span className="text-gray-500">Tree Depth:</span>
                  <p className="text-white font-mono font-medium">{selectedNode.depth}</p>
                </div>
                <div>
                  <span className="text-gray-500">Ecosystem:</span>
                  <p className="text-white font-medium uppercase">{selectedNode.ecosystem}</p>
                </div>
              </div>
            </div>

            {selectedNode.metadata?.purl && (
              <div className="bg-gray-900/60 p-3 rounded-lg border border-gray-800">
                <span className="text-gray-400 block mb-1">Package URL (PURL)</span>
                <p className="font-mono text-[11px] text-blue-400 break-all">{selectedNode.metadata.purl}</p>
              </div>
            )}

            {selectedNode.metadata?.declared_version && (
              <div className="bg-gray-900/60 p-3 rounded-lg border border-gray-800">
                <span className="text-gray-400 block mb-1">Declared in Manifest</span>
                <p className="font-mono text-[11px] text-gray-200">{selectedNode.metadata.declared_version}</p>
              </div>
            )}

            <div className="pt-2 text-gray-500 text-[11px]">
              Source: <span className="text-gray-300 font-mono">{selectedNode.metadata?.source || 'package-lock.json'}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
