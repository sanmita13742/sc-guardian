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
  Maximize,
  RotateCcw,
  Layers,
  ShieldCheck,
  Box,
  Eye,
  Sliders,
  Sparkles
} from 'lucide-react';

const NODE_WIDTH = 220;
const NODE_HEIGHT = 85;

// Automatic Hierarchical Layout using Dagre
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
  const [viewFilter, setViewFilter] = useState('direct'); // 'direct', 'production', 'shared'
  const [selectedNode, setSelectedNode] = useState(null);
  const [expandedNodes, setExpandedNodes] = useState(new Set());
  const [layoutDirection, setLayoutDirection] = useState('TB'); // 'TB' = Vertical, 'LR' = Horizontal
  const [isFullscreen, setIsFullscreen] = useState(false);

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

  // Re-fit view when entering/exiting fullscreen or changing filters
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

  const { layoutedNodes, layoutedEdges, visibleStats } = useMemo(() => {
    if (!graphData || !graphData.nodes) {
      return { layoutedNodes: [], layoutedEdges: [], visibleStats: { nodes: 0, edges: 0 } };
    }

    const eligibleNodeIds = new Set(['root']);
    const isSearching = searchTerm.trim().length > 0;
    const lowerSearch = searchTerm.toLowerCase();

    const childMap = {};
    const parentMap = {};
    graphData.edges.forEach(edge => {
      if (!childMap[edge.source]) childMap[edge.source] = [];
      childMap[edge.source].push(edge.target);

      if (!parentMap[edge.target]) parentMap[edge.target] = [];
      parentMap[edge.target].push(edge.source);
    });

    if (isSearching) {
      graphData.nodes.forEach(node => {
        if (node.label?.toLowerCase().includes(lowerSearch) || node.id.toLowerCase().includes(lowerSearch)) {
          eligibleNodeIds.add(node.id);
          let queue = [node.id];
          while (queue.length > 0) {
            const curr = queue.shift();
            (parentMap[curr] || []).forEach(parent => {
              if (!eligibleNodeIds.has(parent)) {
                eligibleNodeIds.add(parent);
                queue.push(parent);
              }
            });
          }
        }
      });
    } else {
      graphData.edges.forEach(edge => {
        if (edge.source === 'root') {
          const targetNode = graphData.nodes.find(n => n.id === edge.target);
          if (!targetNode) return;

          if (viewFilter === 'direct') {
            eligibleNodeIds.add(edge.target);
          } else if (viewFilter === 'production') {
            if (targetNode.environment === 'production') {
              eligibleNodeIds.add(edge.target);
            }
          } else if (viewFilter === 'shared') {
            eligibleNodeIds.add(edge.target);
          }
        }
      });

      expandedNodes.forEach(expandedId => {
        const children = childMap[expandedId] || [];
        children.forEach(cid => eligibleNodeIds.add(cid));
      });

      if (viewFilter === 'shared') {
        graphData.nodes.forEach(node => {
          if (node.in_degree > 1 && node.id !== 'root') {
            eligibleNodeIds.add(node.id);
            (parentMap[node.id] || []).slice(0, 3).forEach(p => eligibleNodeIds.add(p));
          }
        });
      }
    }

    const rawNodes = graphData.nodes
      .filter(node => eligibleNodeIds.has(node.id))
      .map(node => {
        const isRoot = node.id === 'root';
        const isProd = node.environment === 'production';
        const isDirect = node.type === 'direct' || node.dependency_type === 'direct';
        const hasChildren = (childMap[node.id] || []).length > 0;
        const isExpanded = expandedNodes.has(node.id);

        let bgColor = '#111827';
        let borderColor = '#374151';
        let badgeBg = 'bg-gray-800 text-gray-300';

        if (isRoot) {
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
                  {!isRoot && (
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
            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.4)'
          }
        };
      });

    const rawEdges = graphData.edges
      .filter(e => eligibleNodeIds.has(e.source) && eligibleNodeIds.has(e.target))
      .map(e => ({
        id: `${e.source}->${e.target}`,
        source: e.source,
        target: e.target,
        type: 'smoothstep',
        animated: e.source === 'root',
        style: {
          stroke: e.source === 'root' ? '#3B82F6' : '#64748B',
          strokeWidth: e.source === 'root' ? 2 : 1.2
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: e.source === 'root' ? '#3B82F6' : '#64748B'
        }
      }));

    const layouted = getLayoutedElements(rawNodes, rawEdges, layoutDirection);

    return {
      layoutedNodes: layouted.nodes,
      layoutedEdges: layouted.edges,
      visibleStats: { nodes: layouted.nodes.length, edges: layouted.edges.length }
    };
  }, [graphData, searchTerm, viewFilter, expandedNodes, layoutDirection, toggleExpand]);

  const onNodeClick = useCallback((_, node) => {
    setSelectedNode(node.data.rawNode);
  }, []);

  const handleFitView = () => {
    if (reactFlowInstance) {
      reactFlowInstance.fitView({ padding: 0.2, duration: 400 });
    }
  };

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
              placeholder="Search package (e.g. express, debug)..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="bg-gray-900 border border-gray-700 text-xs rounded-lg pl-8 pr-3 py-1.5 focus:outline-none focus:border-blue-500 w-60 text-gray-200"
            />
          </div>

          <div className="h-5 w-[1px] bg-gray-700 mx-1" />

          {/* Preset Filters */}
          <div className="flex gap-1">
            <button
              onClick={() => { setViewFilter('direct'); setSearchTerm(''); setExpandedNodes(new Set()); }}
              className={`px-3 py-1.5 rounded-lg transition font-medium ${viewFilter === 'direct' && !searchTerm ? 'bg-blue-600 text-white' : 'text-gray-400 hover:bg-gray-800'}`}
            >
              Direct Tree (36)
            </button>
            <button
              onClick={() => { setViewFilter('production'); setSearchTerm(''); }}
              className={`px-3 py-1.5 rounded-lg transition font-medium ${viewFilter === 'production' && !searchTerm ? 'bg-emerald-600 text-white' : 'text-gray-400 hover:bg-gray-800'}`}
            >
              Production Only
            </button>
            <button
              onClick={() => { setViewFilter('shared'); setSearchTerm(''); }}
              className={`px-3 py-1.5 rounded-lg transition font-medium ${viewFilter === 'shared' && !searchTerm ? 'bg-purple-600 text-white' : 'text-gray-400 hover:bg-gray-800'}`}
            >
              Shared Hubs (355)
            </button>
          </div>

          <div className="h-5 w-[1px] bg-gray-700 mx-1" />

          {/* Orientation Toggle */}
          <button
            onClick={() => setLayoutDirection(prev => prev === 'TB' ? 'LR' : 'TB')}
            className="px-2.5 py-1.5 rounded-lg text-gray-300 hover:bg-gray-800 border border-gray-700 transition"
            title="Toggle Top-to-Bottom / Left-to-Right orientation"
          >
            {layoutDirection === 'TB' ? 'Layout: Vertical ↓' : 'Layout: Horizontal →'}
          </button>

          {/* Fit View Button */}
          <button
            onClick={handleFitView}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 text-gray-300 border border-gray-700 transition"
            title="Fit to Screen"
          >
            <RotateCcw className="w-3.5 h-3.5 text-blue-400" />
            Fit View
          </button>

          <div className="h-5 w-[1px] bg-gray-700 mx-1" />

          {/* Fullscreen Button */}
          <button
            onClick={() => setIsFullscreen(prev => !prev)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600 text-blue-300 hover:text-white border border-blue-500/40 transition font-semibold"
            title={isFullscreen ? 'Exit Fullscreen (Esc)' : 'Enter Fullscreen Mode'}
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

        {/* Bottom Status & Legend */}
        <div className="absolute bottom-4 left-4 z-10 bg-[#0E131F]/90 backdrop-blur-md px-4 py-2 rounded-xl border border-gray-800 text-xs flex gap-5 text-gray-300 shadow-xl items-center">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-md bg-blue-600 border border-blue-400"></span> Application Root
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-md bg-emerald-700 border border-emerald-500"></span> Production Runtime
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-md bg-amber-700 border border-amber-500"></span> Development Tooling
          </div>
          <div className="h-4 w-[1px] bg-gray-700" />
          <div className="text-gray-400">
            Rendered: <span className="text-white font-mono font-semibold">{visibleStats.nodes}</span> nodes, <span className="text-white font-mono font-semibold">{visibleStats.edges}</span> edges
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

      {/* Selected Node Details Side Panel */}
      {selectedNode && (
        <div className="w-88 h-full bg-[#0E131F] border-l border-gray-800 p-5 overflow-y-auto space-y-4 shadow-2xl z-20">
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

          <div className="space-y-3 text-xs">
            <div className="bg-gray-900/80 p-3 rounded-lg border border-gray-800">
              <span className="text-gray-400 block mb-1">Runtime Reachability</span>
              <span className={`font-semibold capitalize text-sm ${selectedNode.environment === 'production' ? 'text-emerald-400' : 'text-amber-400'}`}>
                {selectedNode.environment === 'production' ? 'Production (Runtime Dependency)' : 'Development (Test / Build Tool)'}
              </span>
            </div>

            <div className="bg-gray-900/80 p-3 rounded-lg border border-gray-800 space-y-2">
              <span className="text-gray-400 block font-medium">Tree Statistics</span>
              <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                <div>
                  <span className="text-gray-500 block">Tree Depth:</span>
                  <span className="text-white font-bold">{selectedNode.depth} levels</span>
                </div>
                <div>
                  <span className="text-gray-500 block">Parents (In-deg):</span>
                  <span className="text-white font-bold">{selectedNode.in_degree}</span>
                </div>
                <div>
                  <span className="text-gray-500 block">Sub-deps (Out-deg):</span>
                  <span className="text-white font-bold">{selectedNode.out_degree}</span>
                </div>
                <div>
                  <span className="text-gray-500 block">License:</span>
                  <span className="text-gray-300">{selectedNode.license || 'Unknown'}</span>
                </div>
              </div>
            </div>

            {selectedNode.purl && (
              <div className="bg-gray-900/80 p-3 rounded-lg border border-gray-800">
                <span className="text-gray-400 block mb-1">Package URL (PURL)</span>
                <p className="font-mono text-[11px] text-blue-400 break-all">{selectedNode.purl}</p>
              </div>
            )}

            {selectedNode.declared_version && (
              <div className="bg-gray-900/80 p-3 rounded-lg border border-gray-800">
                <span className="text-gray-400 block mb-1">Declared in Manifest</span>
                <p className="font-mono text-[11px] text-gray-200">{selectedNode.declared_version}</p>
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
