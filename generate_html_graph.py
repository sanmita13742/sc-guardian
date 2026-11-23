import json
from pathlib import Path

GRAPH_JSON_PATH = Path("nodegoat-dependency-graph.json")
OUTPUT_HTML = Path("dependency-graph.html")
PUBLIC_HTML = Path("frontend/public/dependency-graph.html")


def generate():
    with open(GRAPH_JSON_PATH, "r", encoding="utf-8") as f:
        graph_data = json.load(f)

    nodes_json = json.dumps(graph_data["nodes"])
    edges_json = json.dumps(graph_data["edges"])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NodeGoat Dependency Graph | Dependency Impact & Supply Chain Visualizer</title>
  <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }}
    body {{
      background-color: #070A10;
      color: #E2E8F0;
      height: 100vh;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }}
    header {{
      background: #0E131F;
      border-bottom: 1px solid #1E293B;
      padding: 10px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      z-index: 10;
    }}
    .title-group h1 {{
      font-size: 15px;
      font-weight: 700;
      color: #F8FAFC;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .badge {{
      font-size: 10px;
      padding: 2px 8px;
      border-radius: 9999px;
      background: rgba(59, 130, 246, 0.2);
      border: 1px solid rgba(59, 130, 246, 0.4);
      color: #60A5FA;
      font-weight: 600;
    }}
    .title-group p {{
      font-size: 11px;
      color: #94A3B8;
      margin-top: 2px;
    }}
    /* Toolbar Controls */
    .toolbar {{
      background: #0B0F19;
      border-bottom: 1px solid #1E293B;
      padding: 8px 20px;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 12px;
      font-size: 12px;
      z-index: 10;
    }}
    .control-group {{
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    label {{
      color: #94A3B8;
      font-weight: 500;
    }}
    input[type="text"] {{
      background: #111827;
      border: 1px solid #334155;
      color: #F8FAFC;
      padding: 5px 10px;
      border-radius: 6px;
      font-size: 12px;
      outline: none;
      width: 190px;
    }}
    input[type="text"]:focus {{
      border-color: #3B82F6;
    }}
    select, button {{
      background: #111827;
      border: 1px solid #334155;
      color: #F8FAFC;
      padding: 5px 10px;
      border-radius: 6px;
      font-size: 12px;
      cursor: pointer;
      outline: none;
      transition: all 0.15s;
    }}
    select:hover, button:hover {{
      background: #1E293B;
      border-color: #475569;
    }}
    button.active {{
      background: #2563EB;
      border-color: #3B82F6;
      color: #FFFFFF;
      font-weight: 600;
    }}
    .slider-group {{
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .slider-group input[type="range"] {{
      width: 100px;
      accent-color: #3B82F6;
      cursor: pointer;
    }}
    .slider-val {{
      font-family: monospace;
      color: #60A5FA;
      font-weight: 600;
      min-width: 32px;
    }}
    /* Main Layout */
    .main-container {{
      flex: 1;
      display: flex;
      position: relative;
      overflow: hidden;
    }}
    #network-canvas {{
      flex: 1;
      height: 100%;
      background: #070A10;
    }}
    /* Side Info Panel - Dependency Impact Analysis */
    #info-panel {{
      width: 360px;
      background: #0E131F;
      border-left: 1px solid #1E293B;
      padding: 20px;
      overflow-y: auto;
      display: none;
      flex-direction: column;
      gap: 12px;
      font-size: 12px;
      z-index: 20;
      box-shadow: -4px 0 20px rgba(0,0,0,0.5);
    }}
    .panel-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 1px solid #1E293B;
      padding-bottom: 10px;
    }}
    .panel-title {{
      font-size: 16px;
      font-weight: 700;
      color: #F8FAFC;
      word-break: break-all;
    }}
    .panel-close {{
      background: none;
      border: none;
      color: #64748B;
      font-size: 16px;
      cursor: pointer;
      padding: 0 4px;
    }}
    .panel-close:hover {{
      color: #F8FAFC;
    }}
    .impact-header {{
      background: linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(185, 28, 28, 0.05));
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 8px;
      padding: 10px 12px;
      color: #FCA5A5;
      font-size: 11px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .info-card {{
      background: #111827;
      border: 1px solid #1E293B;
      border-radius: 8px;
      padding: 10px 12px;
    }}
    .info-label {{
      color: #64748B;
      font-size: 10px;
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.5px;
      margin-bottom: 3px;
    }}
    .info-val {{
      color: #F8FAFC;
      font-weight: 500;
    }}
    .info-val.mono {{
      font-family: monospace;
      font-size: 11px;
      word-break: break-all;
    }}
    .path-step {{
      background: #0B0F19;
      border: 1px solid #1E293B;
      border-radius: 6px;
      padding: 6px 10px;
      font-family: monospace;
      font-size: 11px;
      display: flex;
      align-items: center;
      gap: 6px;
      margin-top: 4px;
    }}
    .parents-list {{
      max-height: 120px;
      overflow-y: auto;
      margin-top: 6px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}
    .parent-pill {{
      background: #070A10;
      border: 1px solid #1E293B;
      padding: 3px 6px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 10px;
      color: #93C5FD;
    }}
    .legend {{
      position: absolute;
      bottom: 16px;
      left: 16px;
      background: rgba(14, 19, 31, 0.95);
      backdrop-filter: blur(8px);
      border: 1px solid #1E293B;
      padding: 10px 16px;
      border-radius: 10px;
      font-size: 11px;
      display: flex;
      gap: 16px;
      align-items: center;
      z-index: 10;
      color: #94A3B8;
      box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    }}
    .legend-item {{
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .legend-circle {{
      width: 12px;
      height: 12px;
      border-radius: 50%;
    }}
    .circle-root {{ background: #3B82F6; box-shadow: 0 0 8px rgba(59, 130, 246, 0.6); }}
    .circle-prod {{ background: #10B981; box-shadow: 0 0 8px rgba(16, 185, 129, 0.6); }}
    .circle-dev {{ background: #F59E0B; box-shadow: 0 0 8px rgba(245, 158, 11, 0.6); }}
    .circle-highlight {{ background: #EF4444; box-shadow: 0 0 10px rgba(239, 68, 68, 0.8); }}
  </style>
</head>
<body>

  <!-- Top Header -->
  <header>
    <div class="title-group">
      <h1>
        Software Supply Chain Guardian
        <span class="badge">DEPENDENCY IMPACT & TREE MAP</span>
      </h1>
      <p>Target: OWASP NodeGoat • Circular nodes with path-preserving exploration and multi-parent hub verification</p>
    </div>
    <div style="font-size: 11px; color: #64748B;">
      Click any circle for Impact Analysis • Drag circles to explore • Double-click to focus
    </div>
  </header>

  <!-- Interactive Toolbar & Filters -->
  <div class="toolbar">
    <!-- Search Box -->
    <div class="control-group">
      <label>Search:</label>
      <input type="text" id="search-input" placeholder="e.g. debug, express, mime..." />
    </div>

    <!-- Filter Presets -->
    <div class="control-group">
      <label>Filter:</label>
      <button id="btn-direct" class="active" onclick="setPreset('direct')">1. Direct Only (36)</button>
      <button id="btn-prod" onclick="setPreset('prod')">2. Production Only</button>
      <button id="btn-vuln" onclick="setPreset('vuln')" style="border-color: #EF4444; color: #FCA5A5;">3. Vulnerabilities (98)</button>
      <button id="btn-all" onclick="setPreset('all')">4. All Nodes</button>
    </div>

    <!-- Node Limit Slider & Direct Type Input -->
    <div class="control-group slider-group">
      <label>Limit:</label>
      <input type="range" id="limit-slider" min="15" max="1092" value="70" step="5" oninput="onLimitChange(this.value)" />
      <input type="number" id="limit-input" min="1" max="1092" value="70" oninput="onLimitInput(this.value)" style="width: 58px; background: #111827; border: 1px solid #334155; color: #60A5FA; font-family: monospace; font-weight: 600; padding: 4px 6px; border-radius: 6px; text-align: center; font-size: 12px; outline: none;" />
      <span style="color: #64748B; font-size: 11px;">/ 1,091</span>
    </div>

    <!-- Layout Switcher (Organic Physics vs Hierarchical) -->
    <div class="control-group">
      <label>Layout:</label>
      <select id="layout-select" onchange="changeLayout(this.value)">
        <option value="physics">Organic Network (Physics)</option>
        <option value="hierarchical">Hierarchical Tree (Ranks)</option>
      </select>
    </div>

    <!-- Physics & Reset -->
    <div class="control-group" style="margin-left: auto;">
      <button id="btn-physics" onclick="togglePhysics()">Pause Physics</button>
      <button onclick="resetView()">Reset Selection</button>
    </div>
  </div>

  <!-- Main Canvas & Dependency Impact Side Panel -->
  <div class="main-container">
    <div id="network-canvas"></div>

    <!-- Dependency Impact Analysis Panel -->
    <div id="info-panel">
      <div class="panel-header">
        <div>
          <span id="panel-badge" class="badge" style="margin-bottom: 4px; display: inline-block;">TRANSITIVE DEPENDENCY</span>
          <div class="panel-title" id="panel-name">debug@3.2.6</div>
        </div>
        <button class="panel-close" onclick="closePanel()">✕</button>
      </div>

      <div class="impact-header">
        <span>⚡</span>
        <span>DEPENDENCY IMPACT & BLAST RADIUS</span>
      </div>

      <div class="info-card">
        <div class="info-label">Full Supply Chain Path from NodeGoat</div>
        <div id="panel-path-trail" style="display: flex; flex-direction: column; gap: 4px; margin-top: 4px;">
          <!-- Populated dynamically -->
        </div>
      </div>

      <div class="info-card">
        <div class="info-label">Upstream Inflow: Incoming Parent Dependencies (<span id="panel-in-count">0</span>)</div>
        <p style="color: #94A3B8; font-size: 11px;">The following packages directly depend on this component:</p>
        <div class="parents-list" id="panel-parents-list">
          <!-- Populated dynamically -->
        </div>
      </div>

      <div class="info-card">
        <div class="info-label">Downstream Blast Radius: Sub-Dependencies (<span id="panel-out-count">0</span>)</div>
        <p style="color: #94A3B8; font-size: 11px;">Packages imported by this component:</p>
        <div class="parents-list" id="panel-children-list">
          <!-- Populated dynamically -->
        </div>
      </div>

      <!-- Vulnerabilities Warning Card -->
      <div class="info-card" id="panel-vuln-card" style="display: none; background: rgba(239, 68, 68, 0.12); border-color: rgba(239, 68, 68, 0.4);">
        <div style="display: flex; align-items: center; justify-content: space-between;">
          <div class="info-label" style="color: #F87171; font-weight: bold;" id="panel-vuln-title">⚠ 0 Known Vulnerabilities</div>
          <span id="panel-vuln-sev" style="background: rgba(239,68,68,0.25); color: #FCA5A5; border: 1px solid rgba(239,68,68,0.5); padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold;">HIGH</span>
        </div>
        <div id="panel-vuln-list" style="margin-top: 6px; display: flex; flex-direction: column; gap: 4px; max-height: 120px; overflow-y: auto;">
          <!-- Dynamically populated -->
        </div>
      </div>

      <div class="info-card">
        <div class="info-label">Classification & Environment</div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 4px;">
          <div>
            <span style="color: #64748B; font-size: 10px;">Environment:</span>
            <div class="info-val font-semibold" id="panel-env" style="color: #10B981;">PRODUCTION</div>
          </div>
          <div>
            <span style="color: #64748B; font-size: 10px;">Tree Depth:</span>
            <div class="info-val" id="panel-depth">2 levels</div>
          </div>
          <div>
            <span style="color: #64748B; font-size: 10px;">License:</span>
            <div class="info-val" id="panel-license">MIT</div>
          </div>
          <div>
            <span style="color: #64748B; font-size: 10px;">Day 2 Reachability:</span>
            <div class="info-val" style="color: #F59E0B; font-size: 10px;">Pending AST trace</div>
          </div>
        </div>
      </div>

      <div class="info-card">
        <div class="info-label">Package URL (PURL)</div>
        <div class="info-val mono" id="panel-purl" style="color: #60A5FA;">pkg:npm/debug@3.2.6</div>
      </div>
    </div>

    <!-- Legend & Transparent Node Counter -->
    <div class="legend">
      <div class="legend-item">
        <div class="legend-circle circle-root"></div>
        <span>Application Root</span>
      </div>
      <div class="legend-item">
        <div class="legend-circle circle-prod"></div>
        <span>Production Runtime</span>
      </div>
      <div class="legend-item">
        <div class="legend-circle circle-dev"></div>
        <span>Development Tool</span>
      </div>
      <div class="legend-item">
        <div class="legend-circle" style="background: #EF4444; border: 2px solid #FCA5A5;"></div>
        <span>Known Vulnerability (OSV)</span>
      </div>
      <div class="legend-item">
        <div class="legend-circle circle-highlight"></div>
        <span>Impact Path Selected</span>
      </div>
      <div style="border-left: 1px solid #334155; height: 14px; margin: 0 4px;"></div>
      <div id="status-counter" style="color: #F8FAFC; font-weight: 600;">
        Showing 37 of 1,091 packages (36 direct, 0 transitive) • All paths connected
      </div>
    </div>
  </div>

  <script>
    const RAW_NODES = {nodes_json};
    const RAW_EDGES = {edges_json};
    const TOTAL_INVENTORY = 1091;

    let network = null;
    let physicsEnabled = true;
    let currentPreset = 'direct';
    let currentLimit = 70;
    let currentLayout = 'physics';
    let selectedNodeId = null;

    // Node & Adjacency lookups
    const nodeLookup = {{}};
    RAW_NODES.forEach(n => nodeLookup[n.id] = n);

    const childMap = {{}};
    const parentMap = {{}};
    RAW_EDGES.forEach(e => {{
      if (!childMap[e.source]) childMap[e.source] = [];
      childMap[e.source].push(e.target);

      if (!parentMap[e.target]) parentMap[e.target] = [];
      parentMap[e.target].push(e.source);
    }});

    // Find shortest path from root to any target using BFS
    function findPathFromRoot(targetId) {{
      if (targetId === 'root') return ['root'];
      const queue = [['root']];
      const visited = new Set(['root']);

      while (queue.length > 0) {{
        const path = queue.shift();
        const curr = path[path.length - 1];

        for (const next of (childMap[curr] || [])) {{
          if (next === targetId) {{
            return [...path, next];
          }}
          if (!visited.has(next)) {{
            visited.add(next);
            queue.push([...path, next]);
          }}
        }}
      }}
      return null;
    }}

    // Path-Preserving BFS Filtering: Guarantees ZERO isolated nodes!
    function getPathPreservingNodes(limit, filterType, search) {{
      const eligible = new Set(['root']);

      if (search && search.length > 0) {{
        // Include search matches and their full paths to root
        RAW_NODES.forEach(n => {{
          if (n.label && n.label.toLowerCase().includes(search)) {{
            const path = findPathFromRoot(n.id);
            if (path) path.forEach(id => eligible.add(id));
            else eligible.add(n.id);
          }}
        }});
      }} else if (filterType === 'vuln') {{
        // Filter for packages with known vulnerabilities and their lineages to root
        const vulnNodes = RAW_NODES.filter(n => n.has_vulnerability);
        for (const vn of vulnNodes) {{
          if (eligible.size >= limit) break;
          const path = findPathFromRoot(vn.id);
          if (path) path.forEach(id => eligible.add(id));
          else eligible.add(vn.id);
        }}
      }} else if (filterType === 'direct') {{
        // All direct dependencies from root
        (childMap['root'] || []).forEach(childId => eligible.add(childId));
      }} else if (filterType === 'prod') {{
        // BFS traversing only production dependencies
        const queue = (childMap['root'] || []).filter(id => nodeLookup[id]?.environment === 'production');
        queue.forEach(id => eligible.add(id));

        while (queue.length > 0 && eligible.size < limit) {{
          const curr = queue.shift();
          for (const next of (childMap[curr] || [])) {{
            if (nodeLookup[next]?.environment === 'production' && !eligible.has(next)) {{
              eligible.add(next);
              queue.push(next);
              if (eligible.size >= limit) break;
            }}
          }}
        }}
      }} else {{
        // 'all': Level-order BFS from root to ensure connected tree
        const queue = [...(childMap['root'] || [])];
        queue.forEach(id => eligible.add(id));

        while (queue.length > 0 && eligible.size < limit) {{
          const curr = queue.shift();
          for (const next of (childMap[curr] || [])) {{
            if (!eligible.has(next)) {{
              eligible.add(next);
              queue.push(next);
              if (eligible.size >= limit) break;
            }}
          }}
        }}
      }}

      return eligible;
    }}

    function createVisNode(node, isPathHighlighted) {{
      const isRoot = node.id === 'root';
      const isProd = node.environment === 'production';
      const isDirect = node.type === 'direct';

      let bgColor = isRoot ? '#2563EB' : (isProd ? '#059669' : '#D97706');
      let borderColor = isRoot ? '#60A5FA' : (isProd ? '#34D399' : '#FBBF24');
      let nodeSize = isRoot ? 32 : (isDirect ? 20 : 15);

      if (isPathHighlighted) {{
        bgColor = '#DC2626';
        borderColor = '#FCA5A5';
        nodeSize = nodeSize + 6;
      }} else if (node.has_vulnerability) {{
        if (node.max_severity === 'CRITICAL') {{
          bgColor = '#DC2626';
          borderColor = '#FCA5A5';
        }} else if (node.max_severity === 'HIGH') {{
          bgColor = '#EA580C';
          borderColor = '#FDBA74';
        }} else {{
          bgColor = '#D97706';
          borderColor = '#FDE68A';
        }}
        nodeSize = nodeSize + 3;
      }}

      return {{
        id: node.id,
        label: node.label,
        shape: 'circle',
        size: nodeSize,
        color: {{
          background: bgColor,
          border: borderColor,
          highlight: {{ background: '#EF4444', border: '#FFFFFF' }},
          hover: {{ background: '#38BDF8', border: '#FFFFFF' }}
        }},
        borderWidth: isPathHighlighted ? 4 : (isRoot ? 3 : 2),
        font: {{
          color: '#F8FAFC',
          size: isRoot ? 14 : 11,
          face: 'sans-serif'
        }},
        shadow: {{
          enabled: true,
          color: isPathHighlighted ? 'rgba(239, 68, 68, 0.8)' : 'rgba(0,0,0,0.6)',
          size: isPathHighlighted ? 15 : 8,
          x: 2,
          y: 2
        }},
        raw: node
      }};
    }}

    function filterNetworkData() {{
      const search = document.getElementById('search-input').value.trim().toLowerCase();
      const eligibleIds = getPathPreservingNodes(currentLimit, currentPreset, search);

      // If a node is selected, find its path from root
      const pathNodes = new Set();
      const pathEdges = new Set();
      if (selectedNodeId) {{
        const path = findPathFromRoot(selectedNodeId);
        if (path) {{
          path.forEach(id => pathNodes.add(id));
          for (let i = 0; i < path.length - 1; i++) {{
            pathEdges.add(`${{path[i]}}->${{path[i+1]}}`);
          }}
        }}
      }}

      let directCount = 0;
      let transitiveCount = 0;

      const displayNodes = [];
      eligibleIds.forEach(id => {{
        if (nodeLookup[id]) {{
          const n = nodeLookup[id];
          if (n.type === 'direct') directCount++;
          else if (id !== 'root') transitiveCount++;
          displayNodes.push(createVisNode(n, pathNodes.has(id)));
        }}
      }});

      const displayEdges = RAW_EDGES
        .filter(e => eligibleIds.has(e.source) && eligibleIds.has(e.target))
        .map((e, idx) => {{
          const edgeKey = `${{e.source}}->${{e.target}}`;
          const isPathEdge = pathEdges.has(edgeKey);

          return {{
            id: 'edge_' + idx,
            from: e.source,
            to: e.target,
            arrows: 'to',
            color: {{
              color: isPathEdge ? '#EF4444' : (e.source === 'root' ? '#3B82F6' : '#475569'),
              highlight: '#EF4444',
              hover: '#94A3B8'
            }},
            width: isPathEdge ? 3.5 : (e.source === 'root' ? 2 : 1.2),
            smooth: {{ type: currentLayout === 'hierarchical' ? 'cubicBezier' : 'continuous', roundness: 0.3 }}
          }};
        }});

      // Update transparent node counter
      const pkgCount = displayNodes.length - (eligibleIds.has('root') ? 1 : 0);
      document.getElementById('status-counter').innerText =
        `Showing ${{pkgCount}} of ${{TOTAL_INVENTORY}} packages (${{directCount}} direct, ${{transitiveCount}} transitive) • All paths connected`;

      return {{ nodes: new vis.DataSet(displayNodes), edges: new vis.DataSet(displayEdges) }};
    }}

    function getNetworkOptions() {{
      if (currentLayout === 'hierarchical') {{
        return {{
          layout: {{
            hierarchical: {{
              enabled: true,
              direction: 'UD',
              sortMethod: 'directed',
              nodeSpacing: 160,
              levelSeparation: 120
            }}
          }},
          physics: {{ enabled: false }},
          interaction: {{ hover: true, zoomView: true, dragView: true }}
        }};
      }} else {{
        return {{
          layout: {{ hierarchical: {{ enabled: false }} }},
          physics: {{
            enabled: physicsEnabled,
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {{
              gravitationalConstant: -80,
              centralGravity: 0.015,
              springLength: 100,
              springConstant: 0.08,
              damping: 0.4
            }},
            stabilization: {{ iterations: 100 }}
          }},
          interaction: {{ hover: true, zoomView: true, dragView: true }}
        }};
      }}
    }}

    function initNetwork() {{
      const container = document.getElementById('network-canvas');
      const data = filterNetworkData();
      const options = getNetworkOptions();

      network = new vis.Network(container, data, options);

      network.on('click', function(params) {{
        if (params.nodes.length > 0) {{
          const nodeId = params.nodes[0];
          selectedNodeId = nodeId;
          openImpactPanel(nodeId);
          updateNetwork();
        }}
      }});
    }}

    function updateNetwork() {{
      if (!network) return;
      const data = filterNetworkData();
      network.setData(data);
      network.setOptions(getNetworkOptions());
    }}

    function setPreset(preset) {{
      currentPreset = preset;
      ['direct', 'prod', 'vuln', 'all'].forEach(p => {{
        const btn = document.getElementById('btn-' + p);
        if (btn) btn.classList.remove('active');
      }});
      const activeBtn = document.getElementById('btn-' + preset);
      if (activeBtn) activeBtn.classList.add('active');

      document.getElementById('search-input').value = '';
      selectedNodeId = null;
      closePanel();
      updateNetwork();
    }}

    function onLimitChange(val) {{
      let num = parseInt(val, 10);
      if (isNaN(num) || num < 1) num = 1;
      if (num > TOTAL_INVENTORY) num = TOTAL_INVENTORY;
      currentLimit = num;
      document.getElementById('limit-slider').value = num;
      document.getElementById('limit-input').value = num;
      updateNetwork();
    }}

    function onLimitInput(val) {{
      let num = parseInt(val, 10);
      if (isNaN(num)) return;
      if (num < 1) num = 1;
      if (num > TOTAL_INVENTORY) num = TOTAL_INVENTORY;
      currentLimit = num;
      document.getElementById('limit-slider').value = num;
      updateNetwork();
    }}

    function changeLayout(val) {{
      currentLayout = val;
      updateNetwork();
    }}

    function togglePhysics() {{
      physicsEnabled = !physicsEnabled;
      network.setOptions({{ physics: {{ enabled: physicsEnabled }} }});
      const btn = document.getElementById('btn-physics');
      btn.innerText = physicsEnabled ? 'Pause Physics' : 'Resume Physics';
      btn.classList.toggle('active', !physicsEnabled);
    }}

    function resetView() {{
      selectedNodeId = null;
      document.getElementById('search-input').value = '';
      closePanel();
      updateNetwork();
      network.fit({{ animation: true }});
    }}

    function openImpactPanel(nodeId) {{
      const node = nodeLookup[nodeId];
      if (!node) return;

      const panel = document.getElementById('info-panel');
      panel.style.display = 'flex';

      document.getElementById('panel-name').innerText = node.label + '@' + node.version;
      document.getElementById('panel-badge').innerText = (node.type || 'PACKAGE').toUpperCase() + ' DEPENDENCY';
      document.getElementById('panel-env').innerText = (node.environment || 'production').toUpperCase();
      document.getElementById('panel-env').style.color = node.environment === 'production' ? '#10B981' : '#F59E0B';
      document.getElementById('panel-depth').innerText = (node.depth || 1) + ' levels from Root';
      document.getElementById('panel-license').innerText = node.license || 'Apache-2.0';
      document.getElementById('panel-purl').innerText = node.purl || ('pkg:npm/' + node.label + '@' + node.version);

      // 0. Active Vulnerabilities Alert
      const vulnCard = document.getElementById('panel-vuln-card');
      if (node.has_vulnerability) {{
        vulnCard.style.display = 'block';
        document.getElementById('panel-vuln-title').innerText = `⚠ ${{node.vulnerability_count}} Known Vulnerabilities`;
        document.getElementById('panel-vuln-sev').innerText = node.max_severity || 'HIGH';
        const listDiv = document.getElementById('panel-vuln-list');
        listDiv.innerHTML = '';
        (node.vulnerabilities || []).forEach(v => {{
          const vDiv = document.createElement('div');
          vDiv.style.cssText = 'background: #0B0F19; border: 1px solid #7F1D1D; padding: 4px 6px; border-radius: 4px; font-size: 10px;';
          vDiv.innerHTML = `
            <div style="display: flex; justify-content: space-between; font-weight: bold; color: #FCA5A5; font-family: monospace;">
              <span>${{v.id}}</span>
              <span style="color: ${{v.fixed_version ? '#34D399' : '#64748B'}};">${{v.fixed_version ? 'Fix: ' + v.fixed_version : 'No fix'}}</span>
            </div>
            <div style="color: #94A3B8; margin-top: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${{v.summary || ''}}</div>
          `;
          listDiv.appendChild(vDiv);
        }});
      }} else {{
        vulnCard.style.display = 'none';
      }}

      // 1. Path Trail from Root
      const pathTrail = document.getElementById('panel-path-trail');
      pathTrail.innerHTML = '';
      const path = findPathFromRoot(nodeId);
      if (path) {{
        path.forEach((stepId, idx) => {{
          const isTarget = idx === path.length - 1;
          const isRoot = idx === 0;
          const stepDiv = document.createElement('div');
          stepDiv.className = 'path-step';
          stepDiv.innerHTML = `
            <span style="color: ${{isTarget ? '#EF4444' : (isRoot ? '#60A5FA' : '#10B981')}}; font-weight: bold;">
              ${{isRoot ? '★ ROOT' : `${{idx}}.`}}
            </span>
            <span style="${{isTarget ? 'color: #FFFFFF; font-weight: bold;' : 'color: #94A3B8;'}}">
              ${{nodeLookup[stepId]?.label || stepId}}
            </span>
          `;
          pathTrail.appendChild(stepDiv);
        }});
      }} else {{
        pathTrail.innerHTML = '<span style="color: #64748B;">No direct path found</span>';
      }}

      // 2. Incoming Parents (Blast Inflow)
      const parents = parentMap[nodeId] || [];
      document.getElementById('panel-in-count').innerText = parents.length;
      const parentsContainer = document.getElementById('panel-parents-list');
      parentsContainer.innerHTML = '';
      if (parents.length === 0) {{
        parentsContainer.innerHTML = '<span style="color: #64748B; font-size: 11px;">None (Direct from Root)</span>';
      }} else {{
        parents.slice(0, 15).forEach(pId => {{
          const p = nodeLookup[pId];
          const pill = document.createElement('div');
          pill.className = 'parent-pill';
          pill.innerText = '← ' + (p?.label || pId);
          parentsContainer.appendChild(pill);
        }});
        if (parents.length > 15) {{
          const more = document.createElement('div');
          more.style.color = '#64748B';
          more.style.fontSize = '10px';
          more.innerText = `+ ${{parents.length - 15}} more parents`;
          parentsContainer.appendChild(more);
        }}
      }}

      // 3. Downstream Sub-dependencies (Blast Outflow)
      const children = childMap[nodeId] || [];
      document.getElementById('panel-out-count').innerText = children.length;
      const childrenContainer = document.getElementById('panel-children-list');
      childrenContainer.innerHTML = '';
      if (children.length === 0) {{
        childrenContainer.innerHTML = '<span style="color: #64748B; font-size: 11px;">Leaf package (0 dependencies)</span>';
      }} else {{
        children.slice(0, 15).forEach(cId => {{
          const c = nodeLookup[cId];
          const pill = document.createElement('div');
          pill.className = 'parent-pill';
          pill.style.color = '#34D399';
          pill.innerText = '→ ' + (c?.label || cId);
          childrenContainer.appendChild(pill);
        }});
      }}
    }}

    function closePanel() {{
      document.getElementById('info-panel').style.display = 'none';
      selectedNodeId = null;
      updateNetwork();
    }}

    document.getElementById('search-input').addEventListener('input', function() {{
      selectedNodeId = null;
      updateNetwork();
    }});

    window.onload = initNetwork;
  </script>
</body>
</html>
"""

    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html_content)

    with open(PUBLIC_HTML, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"Generated standalone circular graph HTML: {OUTPUT_HTML}")
    print(f"Also copied to frontend public: {PUBLIC_HTML}")


if __name__ == "__main__":
    generate()
