import json
from pathlib import Path

GRAPH_JSON_PATH = Path("nodegoat-dependency-graph.json")
OUTPUT_HTML = Path("dependency-graph.html")
PUBLIC_HTML = Path("frontend/public/dependency-graph.html")

def generate():
    with open(GRAPH_JSON_PATH, "r", encoding="utf-8") as f:
        graph_data = json.load(f)

    # Convert nodes and edges into compact format for embedding
    nodes_json = json.dumps(graph_data["nodes"])
    edges_json = json.dumps(graph_data["edges"])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NodeGoat Dependency Graph | Circular Node Network</title>
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
      width: 180px;
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
    /* Side Info Panel */
    #info-panel {{
      width: 320px;
      background: #0E131F;
      border-left: 1px solid #1E293B;
      padding: 20px;
      overflow-y: auto;
      display: none;
      flex-direction: column;
      gap: 12px;
      font-size: 12px;
      z-index: 20;
    }}
    .panel-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 1px solid #1E293B;
      padding-bottom: 10px;
    }}
    .panel-title {{
      font-size: 15px;
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
    .legend {{
      position: absolute;
      bottom: 16px;
      left: 16px;
      background: rgba(14, 19, 31, 0.9);
      backdrop-filter: blur(8px);
      border: 1px solid #1E293B;
      padding: 10px 14px;
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
  </style>
</head>
<body>

  <!-- Top Header -->
  <header>
    <div class="title-group">
      <h1>
        Software Supply Chain Guardian
        <span class="badge">CIRCULAR NETWORK VIEW</span>
      </h1>
      <p>Target: OWASP NodeGoat • Visualizing dependency relationships as interconnected circular nodes</p>
    </div>
    <div style="font-size: 11px; color: #64748B;">
      Drag circles to inspect • Scroll to zoom • Click circle for details
    </div>
  </header>

  <!-- Interactive Toolbar & Filters -->
  <div class="toolbar">
    <!-- Search -->
    <div class="control-group">
      <label>Search:</label>
      <input type="text" id="search-input" placeholder="e.g. express, debug, mocha..." />
    </div>

    <!-- Filter Mode -->
    <div class="control-group">
      <label>Filter:</label>
      <button id="btn-direct" class="active" onclick="setPreset('direct')">Direct Only (36)</button>
      <button id="btn-prod" onclick="setPreset('prod')">Production Only</button>
      <button id="btn-shared" onclick="setPreset('shared')">Shared Hubs</button>
      <button id="btn-all" onclick="setPreset('all')">All Nodes</button>
    </div>

    <!-- Node Limit Slider -->
    <div class="control-group slider-group">
      <label>Node Limit:</label>
      <input type="range" id="limit-slider" min="15" max="350" value="50" step="5" oninput="onLimitChange(this.value)" />
      <span class="slider-val" id="limit-val">50</span>
    </div>

    <!-- Physics Toggle -->
    <div class="control-group" style="margin-left: auto;">
      <button id="btn-physics" onclick="togglePhysics()">Pause Physics</button>
      <button onclick="network.fit({{ animation: true }})">Reset View</button>
    </div>
  </div>

  <!-- Main Canvas & Info Side Panel -->
  <div class="main-container">
    <div id="network-canvas"></div>

    <!-- Selected Circle Inspector Panel -->
    <div id="info-panel">
      <div class="panel-header">
        <div>
          <span id="panel-badge" class="badge" style="margin-bottom: 4px; display: inline-block;">LIBRARY</span>
          <div class="panel-title" id="panel-name">package-name</div>
        </div>
        <button class="panel-close" onclick="closePanel()">✕</button>
      </div>

      <div class="info-card">
        <div class="info-label">Version</div>
        <div class="info-val mono" id="panel-ver">1.0.0</div>
      </div>

      <div class="info-card">
        <div class="info-label">Environment</div>
        <div class="info-val" id="panel-env">production</div>
      </div>

      <div class="info-card">
        <div class="info-label">Tree Position</div>
        <div class="info-val" id="panel-type">direct dependency</div>
      </div>

      <div class="info-card">
        <div class="info-label">Network Metrics</div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 4px;">
          <div>
            <span style="color: #64748B; font-size: 10px;">In-Degree (Parents):</span>
            <div class="info-val" id="panel-in">0</div>
          </div>
          <div>
            <span style="color: #64748B; font-size: 10px;">Out-Degree (Deps):</span>
            <div class="info-val" id="panel-out">0</div>
          </div>
          <div>
            <span style="color: #64748B; font-size: 10px;">Tree Depth:</span>
            <div class="info-val" id="panel-depth">1</div>
          </div>
          <div>
            <span style="color: #64748B; font-size: 10px;">License:</span>
            <div class="info-val" id="panel-license">Unknown</div>
          </div>
        </div>
      </div>

      <div class="info-card">
        <div class="info-label">Package URL (PURL)</div>
        <div class="info-val mono" id="panel-purl" style="color: #60A5FA;">pkg:npm/foo@1.0.0</div>
      </div>
    </div>

    <!-- Legend -->
    <div class="legend">
      <div class="legend-item">
        <div class="legend-circle circle-root"></div>
        <span>Application Root</span>
      </div>
      <div class="legend-item">
        <div class="legend-circle circle-prod"></div>
        <span>Production Library</span>
      </div>
      <div class="legend-item">
        <div class="legend-circle circle-dev"></div>
        <span>Development Tool</span>
      </div>
      <div style="border-left: 1px solid #334155; height: 14px; margin: 0 4px;"></div>
      <div id="status-counter">Showing 37 circles</div>
    </div>
  </div>

  <script>
    // Embedded Network Data
    const RAW_NODES = {nodes_json};
    const RAW_EDGES = {edges_json};

    let network = null;
    let physicsEnabled = true;
    let currentPreset = 'direct';
    let currentLimit = 50;

    const nodeLookup = {{}};
    RAW_NODES.forEach(n => nodeLookup[n.id] = n);

    function createCircularNode(node) {{
      const isRoot = node.id === 'root';
      const isProd = node.environment === 'production';
      const isDirect = node.type === 'direct';

      let bgColor = isRoot ? '#2563EB' : (isProd ? '#059669' : '#D97706');
      let borderColor = isRoot ? '#60A5FA' : (isProd ? '#34D399' : '#FBBF24');
      let nodeSize = isRoot ? 32 : (isDirect ? 20 : 14);

      return {{
        id: node.id,
        label: node.label,
        shape: 'circle',
        size: nodeSize,
        color: {{
          background: bgColor,
          border: borderColor,
          highlight: {{ background: '#38BDF8', border: '#FFFFFF' }},
          hover: {{ background: '#38BDF8', border: '#FFFFFF' }}
        }},
        borderWidth: isRoot ? 3 : 2,
        font: {{
          color: '#F8FAFC',
          size: isRoot ? 14 : 11,
          face: 'sans-serif',
          vadjust: 0
        }},
        shadow: {{
          enabled: true,
          color: 'rgba(0,0,0,0.6)',
          size: 10,
          x: 2,
          y: 2
        }},
        raw: node
      }};
    }}

    function filterNetworkData() {{
      const search = document.getElementById('search-input').value.trim().toLowerCase();
      let selectedNodeIds = new Set(['root']);

      if (search.length > 0) {{
        // Filter by search
        RAW_NODES.forEach(n => {{
          if (n.label && n.label.toLowerCase().includes(search)) {{
            selectedNodeIds.add(n.id);
          }}
        }});
        // Include edges between matches and root
        RAW_EDGES.forEach(e => {{
          if (selectedNodeIds.has(e.target)) selectedNodeIds.add(e.source);
        }});
      }} else {{
        if (currentPreset === 'direct') {{
          RAW_EDGES.forEach(e => {{
            if (e.source === 'root') selectedNodeIds.add(e.target);
          }});
        }} else if (currentPreset === 'prod') {{
          RAW_NODES.forEach(n => {{
            if (n.environment === 'production' && selectedNodeIds.size < currentLimit) {{
              selectedNodeIds.add(n.id);
            }}
          }});
        }} else if (currentPreset === 'shared') {{
          RAW_NODES.forEach(n => {{
            if (n.in_degree > 1 && selectedNodeIds.size < currentLimit) {{
              selectedNodeIds.add(n.id);
            }}
          }});
        }} else {{
          // 'all' up to limit
          RAW_NODES.forEach(n => {{
            if (selectedNodeIds.size < currentLimit) {{
              selectedNodeIds.add(n.id);
            }}
          }});
        }}
      }}

      // Slice up to currentLimit if not searching
      if (!search && selectedNodeIds.size > currentLimit) {{
        const arr = Array.from(selectedNodeIds).slice(0, currentLimit);
        selectedNodeIds = new Set(arr);
        selectedNodeIds.add('root');
      }}

      const displayNodes = [];
      selectedNodeIds.forEach(id => {{
        if (nodeLookup[id]) {{
          displayNodes.push(createCircularNode(nodeLookup[id]));
        }}
      }});

      const displayEdges = RAW_EDGES
        .filter(e => selectedNodeIds.has(e.source) && selectedNodeIds.has(e.target))
        .map((e, idx) => ({{
          id: 'edge_' + idx,
          from: e.source,
          to: e.target,
          arrows: 'to',
          color: {{
            color: e.source === 'root' ? '#3B82F6' : '#475569',
            highlight: '#38BDF8',
            hover: '#94A3B8'
          }},
          width: e.source === 'root' ? 2 : 1.2,
          smooth: {{ type: 'continuous', roundness: 0.3 }}
        }}));

      document.getElementById('status-counter').innerText =
        'Showing ' + displayNodes.length + ' circles (' + displayEdges.length + ' connections)';

      return {{ nodes: new vis.DataSet(displayNodes), edges: new vis.DataSet(displayEdges) }};
    }}

    function initNetwork() {{
      const container = document.getElementById('network-canvas');
      const data = filterNetworkData();

      const options = {{
        physics: {{
          enabled: true,
          solver: 'forceAtlas2Based',
          forceAtlas2Based: {{
            gravitationalConstant: -70,
            centralGravity: 0.015,
            springLength: 90,
            springConstant: 0.08,
            damping: 0.4
          }},
          stabilization: {{ iterations: 120 }}
        }},
        interaction: {{
          hover: true,
          tooltipDelay: 100,
          zoomView: true,
          dragView: true
        }}
      }};

      network = new vis.Network(container, data, options);

      // Node selection click handler
      network.on('click', function(params) {{
        if (params.nodes.length > 0) {{
          const nodeId = params.nodes[0];
          const nodeData = nodeLookup[nodeId];
          if (nodeData) openPanel(nodeData);
        }}
      }});
    }}

    function updateNetwork() {{
      if (!network) return;
      const data = filterNetworkData();
      network.setData(data);
      if (physicsEnabled) {{
        network.stabilize();
      }}
    }}

    function setPreset(preset) {{
      currentPreset = preset;
      ['direct', 'prod', 'shared', 'all'].forEach(p => {{
        const btn = document.getElementById('btn-' + p);
        if (btn) btn.classList.remove('active');
      }});
      const activeBtn = document.getElementById('btn-' + preset);
      if (activeBtn) activeBtn.classList.add('active');
      document.getElementById('search-input').value = '';
      updateNetwork();
    }}

    function onLimitChange(val) {{
      currentLimit = parseInt(val, 10);
      document.getElementById('limit-val').innerText = val;
      updateNetwork();
    }}

    document.getElementById('search-input').addEventListener('input', function() {{
      updateNetwork();
    }});

    function togglePhysics() {{
      physicsEnabled = !physicsEnabled;
      network.setOptions({{ physics: {{ enabled: physicsEnabled }} }});
      const btn = document.getElementById('btn-physics');
      btn.innerText = physicsEnabled ? 'Pause Physics' : 'Resume Physics';
      btn.classList.toggle('active', !physicsEnabled);
    }}

    function openPanel(data) {{
      const panel = document.getElementById('info-panel');
      document.getElementById('panel-name').innerText = data.label;
      document.getElementById('panel-ver').innerText = 'v' + (data.version || '1.3.0');
      document.getElementById('panel-env').innerText = (data.environment || 'production').toUpperCase();
      document.getElementById('panel-type').innerText = (data.type || 'transitive').toUpperCase() + ' DEPENDENCY';
      document.getElementById('panel-in').innerText = data.in_degree || 0;
      document.getElementById('panel-out').innerText = data.out_degree || 0;
      document.getElementById('panel-depth').innerText = (data.depth || 1) + ' levels';
      document.getElementById('panel-license').innerText = data.license || 'Apache-2.0';
      document.getElementById('panel-purl').innerText = data.purl || 'pkg:npm/' + data.label;
      panel.style.display = 'flex';
    }}

    function closePanel() {{
      document.getElementById('info-panel').style.display = 'none';
    }}

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
