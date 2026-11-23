import React, { useState, useMemo, useCallback, useEffect } from 'react';
import ReactFlow, {
  Controls,
  Background,
  MiniMap,
  MarkerType,
  useReactFlow,
  ReactFlowProvider
} from 'reactflow';
import dagre from 'dagre';
import {
  Search,
  Maximize2,
  Minimize2,
  RotateCcw,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  Layers,
  Sparkles
} from 'lucide-react';

const NODE_WIDTH = 220;
const NODE_HEIGHT = 85;

function getLayoutedElements(nodes, edges, direction = 'TB') {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  dagreGraph.setGraph({
    rankdir: direction,
    nodesep: 50,
    ranksep: 100,
    align: 'DL'
  });

  nodes.forEach(node => {
    dagreGraph.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  });

  edges.forEach(edge => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map(node => {
    const nodeWithPosition = dagreGraph.node(node.id);
    return {
      ...node,
      position: {
        x: nodeWithPosition.x - NODE_WIDTH / 2,
        y: nodeWithPosition.y - NODE_HEIGHT / 2
      }
    };
  });

  return { nodes: layoutedNodes, edges };
}

function GraphCanvas({ graphData }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [viewFilter, setViewFilter] = useState('direct'); // 'direct', 'production', 'shared', 'all'
  const [selectedNode, setSelectedNode] = useState(null);
  const [expandedNodes, setExpandedNodes] = useState(new Set());
  const [layoutDirection, setLayoutDirection] = useState('TB');
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [nodeLimit, setNodeLimit] = useState(70);

  const reactFlowInstance = useReactFlow();

  // Escape key exits fullscreen
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isFullscreen) {
        setIsFullscreen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isFullscreen]);

  useEffect(() => {
    const timer = setTimeout(() => {
      if (reactFlowInstance) {
        reactFlowInstance.fitView({ padding: 0.2, duration: 400 });
      }
    }, 100);
    return () => clearTimeout(timer);
  }, [isFullscreen, viewFilter, layoutDirection, reactFlowInstance]);

  const toggleExpand = useCallback((nodeId) => {
    setExpandedNodes(prev => {
      const next = new Set(prev);
      if (next.has(nodeId)) {
        next.delete(nodeId);
      } else {
        next.add(nodeId);
      }
      return next;
    });
  }, []);

  // Compute Adjacency Maps & Path Finding
  const { childMap, parentMap, nodeLookup } = useMemo(() => {
    const cMap = {};
    const pMap = {};
    const nMap = {};

    if (graphData && graphData.nodes) {
      graphData.nodes.forEach(n => { nMap[n.id] = n; });
      graphData.edges.forEach(e => {
        if (!cMap[e.source]) cMap[e.source] = [];
        cMap[e.source].push(e.target);

        if (!pMap[e.target]) pMap[e.target] = [];
        pMap[e.target].push(e.source);
      });
    }
    return { childMap: cMap, parentMap: pMap, nodeLookup: nMap };
  }, [graphData]);

  // Find shortest path from root using BFS
  const findPathFromRoot = useCallback((targetId) => {
    if (targetId === 'root') return ['root'];
    const queue = [['root']];
    const visited = new Set(['root']);

    while (queue.length > 0) {
      const path = queue.shift();
      const curr = path[path.length - 1];

      for (const next of (childMap[curr] || [])) {
        if (next === targetId) {
          return [...path, next];
        }
        if (!visited.has(next)) {
          visited.add(next);
          queue.push([...path, next]);
        }
      }
    }
    return null;
  }, [childMap]);

  // Compute Layouted Nodes & Edges
  const { layoutedNodes, layoutedEdges, visibleStats, pathTrace } = useMemo(() => {
    if (!graphData || !graphData.nodes) {
      return { layoutedNodes: [], layoutedEdges: [], visibleStats: { total: 0, direct: 0, transitive: 0 }, pathTrace: [] };
    }

    const eligibleNodeIds = new Set(['root']);
    const isSearching = searchTerm.trim().length > 0;
    const lowerSearch = searchTerm.toLowerCase();

    if (isSearching) {
      graphData.nodes.forEach(node => {
        if (node.label?.toLowerCase().includes(lowerSearch) || node.id.toLowerCase().includes(lowerSearch)) {
          const path = findPathFromRoot(node.id);
          if (path) path.forEach(id => eligibleNodeIds.add(id));
          else eligibleNodeIds.add(node.id);
        }
      });
    } else if (viewFilter === 'shared') {
      // Verified Shared Hubs (in_degree >= 2) with their real parents!
      const sharedCandidates = graphData.nodes
        .filter(n => n.id !== 'root' && (parentMap[n.id] || []).length >= 2)
        .sort((a, b) => (parentMap[b.id] || []).length - (parentMap[a.id] || []).length);

      for (const hub of sharedCandidates) {
        if (eligibleNodeIds.size >= nodeLimit) break;
        eligibleNodeIds.add(hub.id);
        (parentMap[hub.id] || []).forEach(p => {
          eligibleNodeIds.add(p);
          if ((parentMap[p] || []).includes('root')) eligibleNodeIds.add('root');
        });
      }
    } else if (viewFilter === 'vuln') {
      // Filter for vulnerable packages and their paths back to root!
      const vulnCandidates = graphData.nodes
        .filter(n => n.has_vulnerability)
        .sort((a, b) => (b.vulnerability_count || 0) - (a.vulnerability_count || 0));

      for (const vn of vulnCandidates) {
        if (eligibleNodeIds.size >= nodeLimit) break;
        const path = findPathFromRoot(vn.id);
        if (path) path.forEach(id => eligibleNodeIds.add(id));
        else eligibleNodeIds.add(vn.id);
      }
    } else if (viewFilter === 'direct') {
      (childMap['root'] || []).forEach(childId => eligibleNodeIds.add(childId));
    } else if (viewFilter === 'production') {
      const queue = (childMap['root'] || []).filter(id => nodeLookup[id]?.environment === 'production');
      queue.forEach(id => eligibleNodeIds.add(id));

      while (queue.length > 0 && eligibleNodeIds.size < nodeLimit) {
        const curr = queue.shift();
        for (const next of (childMap[curr] || [])) {
          if (nodeLookup[next]?.environment === 'production' && !eligibleNodeIds.has(next)) {
            eligibleNodeIds.add(next);
            queue.push(next);
            if (eligibleNodeIds.size >= nodeLimit) break;
          }
        }
      }
    } else {
      // 'all': Level-order BFS from root
      const queue = [...(childMap['root'] || [])];
      queue.forEach(id => eligibleNodeIds.add(id));

      while (queue.length > 0 && eligibleNodeIds.size < nodeLimit) {
        const curr = queue.shift();
        for (const next of (childMap[curr] || [])) {
          if (!eligibleNodeIds.has(next)) {
            eligibleNodeIds.add(next);
            queue.push(next);
            if (eligibleNodeIds.size >= nodeLimit) break;
          }
        }
      }
    }

    // User expanded sub-trees
    expandedNodes.forEach(expandedId => {
      const children = childMap[expandedId] || [];
      children.forEach(cid => eligibleNodeIds.add(cid));
    });

    // Compute path trace if node is selected
    const pathNodes = new Set();
    const pathEdges = new Set();
    let computedPath = [];
    if (selectedNode) {
      computedPath = findPathFromRoot(selectedNode.id) || [];
      computedPath.forEach(id => pathNodes.add(id));
      for (let i = 0; i < computedPath.length - 1; i++) {
        pathEdges.add(`${computedPath[i]}->${computedPath[i+1]}`);
      }
    }

    let directCount = 0;
    let transitiveCount = 0;

    const rawNodes = graphData.nodes
      .filter(node => eligibleNodeIds.has(node.id))
      .map(node => {
        const isRoot = node.id === 'root';
        const isProd = node.environment === 'production';
        const isDirect = node.type === 'direct' || node.dependency_type === 'direct';
        const hasChildren = (childMap[node.id] || []).length > 0;
        const isExpanded = expandedNodes.has(node.id);
        const isPathHighlighted = pathNodes.has(node.id);

        if (isDirect) directCount++;
        else if (!isRoot) transitiveCount++;

        let bgColor = '#111827';
        let borderColor = '#374151';
        let badgeBg = 'bg-gray-800 text-gray-300';

        if (isPathHighlighted) {
          bgColor = '#7F1D1D';
          borderColor = '#EF4444';
          badgeBg = 'bg-red-500/20 text-red-300 border-red-500/40';
        } else if (node.has_vulnerability) {
          if (node.max_severity === 'CRITICAL') {
            bgColor = isDirect ? '#7F1D1D' : '#450A0A';
            borderColor = '#EF4444';
            badgeBg = 'bg-red-500/30 text-red-300 border-red-500/50';
          } else if (node.max_severity === 'HIGH') {
            bgColor = isDirect ? '#7C2D12' : '#431407';
            borderColor = '#F97316';
            badgeBg = 'bg-orange-500/30 text-orange-300 border-orange-500/50';
          } else {
            bgColor = isDirect ? '#713F12' : '#451A03';
            borderColor = '#F59E0B';
            badgeBg = 'bg-amber-500/30 text-amber-300 border-amber-500/50';
          }
        } else if (isRoot) {
          bgColor = '#1E3A8A';
          borderColor = '#3B82F6';
          badgeBg = 'bg-blue-500/20 text-blue-300 border-blue-500/30';
        } else if (isProd) {
          bgColor = isDirect ? '#064E3B' : '#092A20';
          borderColor = '#10B981';
          badgeBg = 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
        } else {
          bgColor = isDirect ? '#78350F' : '#331B08';
          borderColor = '#F59E0B';
          badgeBg = 'bg-amber-500/20 text-amber-300 border-amber-500/30';
        }

        return {
          id: node.id,
          data: {
            ...node,
            label: (
              <div className="flex flex-col h-full justify-between select-none">
                <div className="flex items-center justify-between gap-1 mb-1">
                  <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono uppercase font-semibold border ${badgeBg}`}>
                    {isRoot ? 'APPLICATION ROOT' : (isDirect ? 'DIRECT' : 'TRANSITIVE')}
                  </span>
                  {node.has_vulnerability ? (
                    <span className="text-[9px] bg-red-600/40 text-red-200 border border-red-500/60 px-1 py-0.5 rounded font-bold">
                      ⚠ {node.vulnerability_count}
                    </span>
                  ) : !isRoot && (
                    <span className={`text-[9px] font-medium capitalize ${isProd ? 'text-emerald-400' : 'text-amber-400'}`}>
                      {node.environment}
                    </span>
                  )}
                </div>

                <div className="font-bold text-white text-xs truncate" title={node.label}>
                  {node.label}
                </div>

                <div className="flex items-center justify-between text-[10px] text-gray-400 mt-1">
                  <span className="font-mono text-blue-300">v{node.version || '1.3.0'}</span>
                  {hasChildren && !isRoot && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleExpand(node.id);
                      }}
                      className="px-2 py-0.5 rounded bg-gray-800/80 hover:bg-blue-600 text-[10px] text-gray-200 border border-gray-700 hover:border-blue-500 transition font-medium"
                      title={isExpanded ? 'Collapse sub-dependencies' : 'Expand sub-dependencies'}
                    >
                      {isExpanded ? '− Collapse' : `+ ${(childMap[node.id] || []).length} deps`}
                    </button>
                  )}
                </div>
              </div>
            ),
            rawNode: node
          },
          style: {
            background: bgColor,
            border: `1.5px solid ${borderColor}`,
            borderRadius: '10px',
            padding: '10px 12px',
            width: NODE_WIDTH,
            height: NODE_HEIGHT,
            color: '#F9FAFB',
            boxShadow: isPathHighlighted ? '0 0 16px rgba(239, 68, 68, 0.5)' : '0 4px 12px rgba(0, 0, 0, 0.4)'
          }
        };
      });

    const rawEdges = graphData.edges
      .filter(e => eligibleNodeIds.has(e.source) && eligibleNodeIds.has(e.target))
      .map(e => {
        const edgeKey = `${e.source}->${e.target}`;
        const isPathEdge = pathEdges.has(edgeKey);

        return {
          id: edgeKey,
          source: e.source,
          target: e.target,
          type: 'smoothstep',
          animated: isPathEdge || e.source === 'root',
          style: {
            stroke: isPathEdge ? '#EF4444' : (e.source === 'root' ? '#3B82F6' : '#64748B'),
            strokeWidth: isPathEdge ? 3.5 : (e.source === 'root' ? 2 : 1.2)
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isPathEdge ? '#EF4444' : (e.source === 'root' ? '#3B82F6' : '#64748B')
          }
        };
      });

    const layouted = getLayoutedElements(rawNodes, rawEdges, layoutDirection);

    return {
      layoutedNodes: layouted.nodes,
      layoutedEdges: layouted.edges,
      visibleStats: { total: rawNodes.length, direct: directCount, transitive: transitiveCount },
      pathTrace: computedPath
    };
  }, [graphData, searchTerm, viewFilter, expandedNodes, layoutDirection, toggleExpand, nodeLimit, selectedNode, findPathFromRoot, childMap, parentMap, nodeLookup]);

  const onNodeClick = useCallback((_, node) => {
    setSelectedNode(node.data.rawNode);
  }, []);

  const handleFitView = () => {
    if (reactFlowInstance) {
      reactFlowInstance.fitView({ padding: 0.2, duration: 400 });
    }
  };

  const selectedParents = selectedNode ? (parentMap[selectedNode.id] || []) : [];
  const selectedChildren = selectedNode ? (childMap[selectedNode.id] || []) : [];

  return (
    <div
      className={`relative bg-[#070A10] transition-all duration-200 overflow-hidden flex ${
        isFullscreen
          ? 'fixed inset-0 z-50 w-screen h-screen'
          : 'w-full h-[720px] rounded-xl border border-gray-800 shadow-2xl'
      }`}
    >
      {/* Canvas Area */}
      <div className="flex-1 h-full relative">
        {/* Top Control Bar */}
        <div className="absolute top-4 left-4 z-10 flex flex-wrap gap-2 items-center bg-[#0E131F]/95 backdrop-blur-md p-2 rounded-xl border border-gray-800 shadow-2xl text-xs">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-gray-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search package (e.g. debug, express)..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-xs rounded-lg pl-8 pr-3 py-1.5 focus:outline-none focus:border-blue-500 w-60 text-gray-200"
            />
          </div>

          <div className="h-5 w-[1px] bg-gray-700 mx-1" />

          {/* Preset Filters */}
          <div className="flex gap-1">
            <button
              onClick={() => { setViewFilter('direct'); setSearchTerm(''); setExpandedNodes(new Set()); setSelectedNode(null); }}
              className={`px-3 py-1.5 rounded-lg transition font-medium ${viewFilter === 'direct' && !searchTerm ? 'bg-blue-600 text-white' : 'text-gray-400 hover:bg-gray-800'}`}
            >
              1. Direct Only (36)
            </button>
            <button
              onClick={() => { setViewFilter('production'); setSearchTerm(''); }}
              className={`px-3 py-1.5 rounded-lg transition font-medium ${viewFilter === 'production' && !searchTerm ? 'bg-emerald-600 text-white' : 'text-gray-400 hover:bg-gray-800'}`}
            >
              2. Production Only
            </button>
            <button
              onClick={() => { setViewFilter('shared'); setSearchTerm(''); }}
              className={`px-3 py-1.5 rounded-lg transition font-medium ${viewFilter === 'shared' && !searchTerm ? 'bg-purple-600 text-white' : 'text-gray-400 hover:bg-gray-800'}`}
            >
              3. Verified Shared Hubs
            </button>
            <button
              onClick={() => { setViewFilter('all'); setSearchTerm(''); }}
              className={`px-3 py-1.5 rounded-lg transition font-medium ${viewFilter === 'all' && !searchTerm ? 'bg-gray-700 text-white' : 'text-gray-400 hover:bg-gray-800'}`}
            >
              4. All Nodes
            </button>
            <button
              onClick={() => { setViewFilter('vuln'); setSearchTerm(''); }}
              className={`px-3 py-1.5 rounded-lg transition font-medium ${viewFilter === 'vuln' && !searchTerm ? 'bg-red-600 text-white font-semibold' : 'text-red-400 hover:bg-red-950/40 border border-red-900/40'}`}
            >
              5. Vulnerable (98)
            </button>
          </div>

          <div className="h-5 w-[1px] bg-gray-700 mx-1" />

          {/* Node Limit Slider & Direct Type Input */}
          <div className="flex items-center gap-1.5 text-xs text-gray-300">
            <span>Limit:</span>
            <input
              type="range"
              min="15"
              max="1092"
              value={nodeLimit}
              step="5"
              onChange={e => setNodeLimit(Math.min(1092, Math.max(1, parseInt(e.target.value, 10) || 1)))}
              className="w-16 accent-blue-500 cursor-pointer"
            />
            <input
              type="number"
              min="1"
              max="1092"
              value={nodeLimit}
              onChange={e => setNodeLimit(Math.min(1092, Math.max(1, parseInt(e.target.value, 10) || 1)))}
              className="w-14 bg-gray-900 border border-gray-700 text-blue-400 font-mono font-semibold rounded px-1 py-0.5 text-xs text-center focus:outline-none focus:border-blue-500"
            />
            <span className="text-gray-500 text-[10px]">/ 1,091</span>
          </div>

          <div className="h-5 w-[1px] bg-gray-700 mx-1" />

          {/* Orientation Toggle */}
          <button
            onClick={() => setLayoutDirection(prev => prev === 'TB' ? 'LR' : 'TB')}
            className="px-2.5 py-1.5 rounded-lg text-gray-300 hover:bg-gray-800 border border-gray-700 transition"
          >
            {layoutDirection === 'TB' ? 'Vertical ↓' : 'Horizontal →'}
          </button>

          {/* Fit View Button */}
          <button
            onClick={handleFitView}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 text-gray-300 border border-gray-700 transition"
          >
            <RotateCcw className="w-3.5 h-3.5 text-blue-400" />
            Fit View
          </button>

          {/* Fullscreen Button */}
          <button
            onClick={() => setIsFullscreen(prev => !prev)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600 text-blue-300 hover:text-white border border-blue-500/40 transition font-semibold"
          >
            {isFullscreen ? (
              <>
                <Minimize2 className="w-3.5 h-3.5" />
                Exit Fullscreen
              </>
            ) : (
              <>
                <Maximize2 className="w-3.5 h-3.5" />
                Fullscreen
              </>
            )}
          </button>
        </div>

        {/* Bottom Status & Transparent Limit Display */}
        <div className="absolute bottom-4 left-4 z-10 bg-[#0E131F]/95 backdrop-blur-md px-4 py-2 rounded-xl border border-gray-800 text-xs flex gap-5 text-gray-300 shadow-xl items-center">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-md bg-blue-600 border border-blue-400"></span> Application Root
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-md bg-emerald-700 border border-emerald-500"></span> Production Runtime
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-md bg-amber-700 border border-amber-500"></span> Development Tooling
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-md bg-red-600 border border-red-400"></span> Impact Path
          </div>
          <div className="h-4 w-[1px] bg-gray-700" />
          <div className="text-gray-200 font-semibold font-mono">
            Showing {visibleStats.total} of 1,091 packages ({visibleStats.direct} direct, {visibleStats.transitive} transitive) • All paths connected
          </div>
        </div>

        {/* React Flow Viewport */}
        <ReactFlow
          nodes={layoutedNodes}
          edges={layoutedEdges}
          onNodeClick={onNodeClick}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.1}
          maxZoom={1.5}
        >
          <Background color="#161D2F" gap={24} size={1} />
          <Controls className="bg-gray-900 border-gray-800 text-white fill-white rounded-lg" />
          <MiniMap
            nodeColor={n => {
              if (n.id === 'root') return '#3B82F6';
              if (n.data?.rawNode?.environment === 'production') return '#10B981';
              return '#F59E0B';
            }}
            className="bg-gray-900 border-gray-800 rounded-xl"
          />
        </ReactFlow>
      </div>

      {/* Selected Node Details - Dependency Impact Analysis Panel */}
      {selectedNode && (
        <div className="w-96 h-full bg-[#0E131F] border-l border-gray-800 p-5 overflow-y-auto space-y-4 shadow-2xl z-20">
          <div className="flex justify-between items-start">
            <div>
              <span className={`text-[10px] px-2 py-0.5 rounded font-mono uppercase font-bold border ${selectedNode.environment === 'production' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' : 'bg-amber-500/20 text-amber-300 border-amber-500/30'}`}>
                {selectedNode.type || selectedNode.dependency_type || 'Package'}
              </span>
              <h3 className="text-base font-bold text-white mt-1 break-words">{selectedNode.label || selectedNode.name}</h3>
              <p className="text-xs text-blue-400 font-mono">v{selectedNode.version}</p>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-gray-500 hover:text-gray-300 text-sm p-1 rounded-md hover:bg-gray-800"
            >
              ✕
            </button>
          </div>

          <div className="bg-red-500/10 border border-red-500/30 p-2.5 rounded-lg text-xs text-red-300 flex items-center gap-2 font-semibold">
            <span>⚡</span>
            <span>DEPENDENCY IMPACT & BLAST RADIUS</span>
          </div>

          <div className="space-y-3 text-xs">
            {/* Supply Chain Path from Root */}
            <div className="bg-gray-900/80 p-3 rounded-lg border border-gray-800 space-y-1.5">
              <span className="text-gray-400 block font-semibold text-[10px] uppercase tracking-wider">
                Supply Chain Trace from NodeGoat
              </span>
              <div className="space-y-1 font-mono text-[11px]">
                {pathTrace.map((pId, idx) => (
                  <div key={idx} className="flex items-center gap-1.5 bg-[#070A10] px-2 py-1 rounded border border-gray-800">
                    <span className={idx === pathTrace.length - 1 ? 'text-red-400 font-bold' : (idx === 0 ? 'text-blue-400 font-bold' : 'text-emerald-400')}>
                      {idx === 0 ? '★ ROOT' : `${idx}.`}
                    </span>
                    <span className={idx === pathTrace.length - 1 ? 'text-white font-bold' : 'text-gray-400'}>
                      {nodeLookup[pId]?.label || pId}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Upstream Parents Inflow */}
            <div className="bg-gray-900/80 p-3 rounded-lg border border-gray-800 space-y-1">
              <span className="text-gray-400 block font-semibold text-[10px] uppercase tracking-wider">
                Upstream Inflow: Imported by {selectedParents.length} parent packages
              </span>
              <div className="max-h-28 overflow-y-auto space-y-1 font-mono text-[10px] text-blue-300 mt-1">
                {selectedParents.length === 0 ? (
                  <span className="text-gray-500">Directly imported by Root</span>
                ) : (
                  selectedParents.slice(0, 15).map((pId, idx) => (
                    <div key={idx} className="bg-[#070A10] px-2 py-0.5 rounded border border-gray-800">
                      ← {nodeLookup[pId]?.label || pId}
                    </div>
                  ))
                )}
                {selectedParents.length > 15 && (
                  <div className="text-gray-500 text-[10px] text-center pt-1">+ {selectedParents.length - 15} more parents</div>
                )}
              </div>
            </div>

            {/* Downstream Children Outflow */}
            <div className="bg-gray-900/80 p-3 rounded-lg border border-gray-800 space-y-1">
              <span className="text-gray-400 block font-semibold text-[10px] uppercase tracking-wider">
                Downstream Blast Radius: {selectedChildren.length} dependencies
              </span>
              <div className="max-h-24 overflow-y-auto space-y-1 font-mono text-[10px] text-emerald-300 mt-1">
                {selectedChildren.length === 0 ? (
                  <span className="text-gray-500">Leaf package (0 dependencies)</span>
                ) : (
                  selectedChildren.slice(0, 10).map((cId, idx) => (
                    <div key={idx} className="bg-[#070A10] px-2 py-0.5 rounded border border-gray-800">
                      → {nodeLookup[cId]?.label || cId}
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Active Vulnerabilities Alert */}
            {selectedNode.has_vulnerability && (
              <div className="bg-red-950/40 border border-red-800/80 p-3 rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-red-400 font-bold text-[11px] uppercase tracking-wider flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-red-500 animate-ping"></span>
                    {selectedNode.vulnerability_count} Known Vulnerabilities
                  </span>
                  <span className="text-[10px] bg-red-500/20 text-red-300 border border-red-500/40 px-2 py-0.5 rounded font-mono font-bold">
                    {selectedNode.max_severity}
                  </span>
                </div>
                <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                  {(selectedNode.vulnerabilities || []).map((v, vIdx) => (
                    <div key={vIdx} className="bg-[#070A10] p-2 rounded border border-red-900/40 text-[11px]">
                      <div className="flex items-center justify-between font-mono">
                        <span className="text-red-400 font-bold">{v.id}</span>
                        {v.fixed_version ? (
                          <span className="text-[10px] text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/30">
                            Fixed: {v.fixed_version}
                          </span>
                        ) : (
                          <span className="text-[10px] text-gray-500">No fix</span>
                        )}
                      </div>
                      <p className="text-gray-300 text-[10px] mt-1 line-clamp-2">{v.summary}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Classification & Metadata */}
            <div className="bg-gray-900/80 p-3 rounded-lg border border-gray-800">
              <span className="text-gray-400 block mb-1">Runtime Classification</span>
              <span className={`font-semibold capitalize text-sm ${selectedNode.environment === 'production' ? 'text-emerald-400' : 'text-amber-400'}`}>
                {selectedNode.environment === 'production' ? 'Production (Runtime Dependency)' : 'Development (Test / Build Tool)'}
              </span>
            </div>

            {selectedNode.purl && (
              <div className="bg-gray-900/80 p-3 rounded-lg border border-gray-800">
                <span className="text-gray-400 block mb-1">Package URL (PURL)</span>
                <p className="font-mono text-[11px] text-blue-400 break-all">{selectedNode.purl}</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function DependencyGraphView(props) {
  return (
    <ReactFlowProvider>
      <GraphCanvas {...props} />
    </ReactFlowProvider>
  );
}
