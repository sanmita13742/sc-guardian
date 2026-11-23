"""Interactive graphs (vis-network from cdnjs, dark theme): the dependency explorer and the agent-workflow graph.

Data is JSON-embedded with script-closing sequences escaped. Offline, a clear message replaces the canvas.
"""
from __future__ import annotations

import json

import streamlit as st

VIS_URL = "https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/standalone/umd/vis-network.min.js"

_CSS = """
<style>
*{box-sizing:border-box} body{margin:0;background:#0b1020;color:#cbd5e1;font:12px system-ui,Segoe UI,sans-serif}
#bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:8px 10px;border-bottom:1px solid #1e293b;background:#0f172a}
#bar input[type=text],#bar select{background:#0b1020;color:#e2e8f0;border:1px solid #334155;border-radius:5px;padding:4px 7px;font-size:12px}
button{background:#0b1020;color:#e2e8f0;border:1px solid #334155;border-radius:5px;padding:4px 9px;font-size:12px;cursor:pointer}
button.on{background:#2563eb;border-color:#2563eb;color:#fff} button:hover{border-color:#64748b}
#wrap{position:relative} #net{height:__H__px;background:#0b1020} #side{position:absolute;top:8px;right:8px;width:270px;max-height:__H__px;overflow:auto;
background:#111a2ecc;border:1px solid #334155;border-radius:8px;padding:9px;font-size:12px;line-height:1.45;display:none}
#foot{display:flex;gap:14px;align-items:center;flex-wrap:wrap;padding:7px 10px;border-top:1px solid #1e293b;background:#0f172a;font-size:11px}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:4px;vertical-align:-1px}
.tag{font-size:11px;padding:1px 6px;border-radius:9px;border:1px solid #334155} code{color:#93c5fd}
</style>"""

_FALLBACK = "if(typeof vis==='undefined'){document.getElementById('net').innerHTML='<p style=\"padding:1rem\">vis-network could not be loaded (offline?). Use the other tabs.</p>';throw new Error('no vis');}"

DEP_HTML = _CSS + """
<div id="bar">
 <input id="q" type="text" placeholder="Search package e.g. express" size="22">
 <span>Filter:</span><span id="filters"></span>
 <span>Limit:</span><input id="lim" type="range" min="1" max="1" value="1" style="width:110px"><b id="limv" style="color:#60a5fa">1</b><span id="limt"></span>
 <span>Layout:</span><select id="lay"><option value="phys">Organic Network (Physics)</option><option value="tree">Hierarchical (by depth)</option><option value="radial">Radial (rings by depth)</option></select>
 <span style="flex:1"></span><span id="phys-status" class="tag" style="color:#34d399;border-color:#059669;font-size:11px">⚡ Settled</span><button id="pause">Pause Physics</button><button id="reset">Reset Selection</button>
</div>
<div id="wrap"><div id="net"></div><div id="side"></div></div>
<div id="foot"><span><i class="dot" style="background:#2563eb"></i>Application Root</span><span><i class="dot" style="background:#059669"></i>Production Runtime</span>
 <span><i class="dot" style="background:#d97706"></i>Development Tool</span><span><i class="dot" style="background:#ef4444"></i>Impact Path Selected</span>
 <span>Ring colour = worst vulnerability</span><b id="count"></b><span style="color:#64748b">Click: impact analysis · Drag: explore · Double-click: focus</span></div>
<script src="__URL__"></script>
<script>
__FALLBACK__
const D = __DATA__;
const SEV = {CRITICAL:'#dc2626',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#38bdf8',UNKNOWN:'#a78bfa'};
const COL = {root:'#2563eb',prod:'#059669',dev:'#d97706'};
const byId = {}; D.nodes.forEach(n => byId[n.id] = n);
const out = {}, inn = {}; D.nodes.forEach(n => {out[n.id] = []; inn[n.id] = [];});
D.edges.forEach(([u,v]) => {if (out[u]) out[u].push(v); if (inn[v]) inn[v].push(u);});
const roots = D.nodes.filter(n => n.kind === 'root').map(n => n.id);
const pkgs = D.nodes.filter(n => n.kind !== 'root');
const rank = n => (n.vuln ? 1000 + ({CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1}[n.vuln]||0)*100 : 0) + (n.desc||0) + (n.parents||0) * 2 + (n.direct ? 5 : 0);
const ranked = pkgs.slice().sort((a,b) => rank(b) - rank(a));
const nDirect = pkgs.filter(n => n.direct).length;
let filter = 'direct', limit = Math.min(Math.max(nDirect, 1), pkgs.length), focus = null, selected = null, layout = 'phys', physicsOn = true, query = '';
const FILTERS = [['direct','Direct Only ('+nDirect+')'],['prod','Production Only'],['hubs','Verified Shared Hubs'],['all','All Nodes']];
const fb = document.getElementById('filters');
FILTERS.forEach(([k,t]) => {const b = document.createElement('button'); b.textContent = (FILTERS.findIndex(f => f[0]===k)+1)+'. '+t; b.dataset.k = k; b.onclick = () => {filter = k; focus = null; physicsOn = (layout === 'phys'); draw(false);}; fb.appendChild(b);});
const lim = document.getElementById('lim'); lim.max = Math.max(pkgs.length, 1); lim.value = limit;

function chain(id, set) {  // shortest path to a root, so no shown node is orphaned
  let cur = id, guard = 0;
  while (cur && !set.has(cur) && guard++ < 60) {
    set.add(cur);
    const parents = inn[cur];
    if (!parents || !parents.length) break;
    const p = parents.slice().sort((a,b)=>(byId[a] ? byId[a].depth : 999) - (byId[b] ? byId[b].depth : 999))[0];
    cur = p;
  }
  if (cur) set.add(cur);
}
function visibleSet() {
  const set = new Set(roots);
  if (focus) {chain(focus, set); (out[focus]||[]).forEach(x => set.add(x)); (inn[focus]||[]).forEach(x => set.add(x)); return set;}
  let pool = ranked.filter(n => filter==='direct' ? n.direct : filter==='prod' ? n.kind==='prod' : filter==='hubs' ? (n.parents||0)>=2 : true);
  if (query) pool = pool.filter(n => n.label.toLowerCase().includes(query));
  pool.slice(0, limit).forEach(n => chain(n.id, set));
  return set;
}
function toVis(n, set) {
  const imp = Math.log2(2 + (n.desc||0)) + (n.vuln ? 2 : 0), fs = n.kind==='root' ? 18 : Math.min(8 + imp * 0.9, 14);
  const sel = selected && selSet.has(n.id);
  const lab = n.label.length > 16 ? n.label.slice(0,15) + '…' : n.label;
  return {id:n.id, label:lab, shape:'circle', margin:n.kind==='root'?16:5, borderWidth:n.vuln?4:2,
    color:{background: sel ? '#ef4444' : (n.id===selected ? '#ef4444' : COL[n.kind]), border: n.vuln ? SEV[n.vuln] : (n.kind==='root'?'#fff':'#0b1020'), highlight:{background:'#ef4444',border:'#fff'}},
    font:{color:'#fff', size:fs, bold:true}, title:n.label+(n.version?'@'+n.version:'')+(n.vuln?' — '+n.vuln:'')};
}
let selSet = new Set(), selEdges = new Set();
const nodes = new vis.DataSet(), edges = new vis.DataSet();
const net = new vis.Network(document.getElementById('net'), {nodes, edges}, {
  interaction:{hover:true, tooltipDelay:150, zoomView:true, dragView:true, hideEdgesOnDrag:true, hideEdgesOnZoom:true},
  physics:{
    solver:'forceAtlas2Based',
    forceAtlas2Based:{gravitationalConstant:-80, centralGravity:0.015, springLength:130, springConstant:0.08, damping:0.4, avoidOverlap:0.15},
    barnesHut:{gravitationalConstant:-2000, centralGravity:0.25, springLength:90, springConstant:0.04, damping:0.35, avoidOverlap:0},
    maxVelocity:35, minVelocity:0.75, timestep:0.5, adaptiveTimestep:true,
    stabilization:{enabled:true, iterations:80, updateInterval:25}
  },
  edges:{arrows:{to:{enabled:true, scaleFactor:0.6}}, smooth:false, width:1, color:{color:'#475569', highlight:'#ef4444'}}});

function updatePhysicsUI() {
  const pBtn = document.getElementById('pause');
  const pStat = document.getElementById('phys-status');
  if (layout !== 'phys') {
    pBtn.style.display = 'none';
    if (pStat) pStat.textContent = 'Static Layout';
    return;
  }
  pBtn.style.display = 'inline-block';
  pBtn.textContent = physicsOn ? 'Pause Physics' : 'Resume Physics';
  if (pStat) {
    pStat.textContent = physicsOn ? '● Physics Active' : '⚡ Settled (0% CPU)';
    pStat.style.color = physicsOn ? '#60a5fa' : '#34d399';
    pStat.style.borderColor = physicsOn ? '#2563eb' : '#059669';
  }
}

function highlightOnly() {
  const set = visibleSet();
  const nodeUpdates = [];
  [...set].forEach(id => {
    if (byId[id]) {
      const sel = selected && selSet.has(id);
      nodeUpdates.push({
        id: id,
        color: {
          background: sel ? '#ef4444' : (id === selected ? '#ef4444' : COL[byId[id].kind]),
          border: byId[id].vuln ? SEV[byId[id].vuln] : (byId[id].kind === 'root' ? '#fff' : '#0b1020')
        }
      });
    }
  });
  if (nodeUpdates.length) nodes.update(nodeUpdates);

  const edgeUpdates = [];
  edges.forEach(e => {
    const hot = selEdges.has(e.id);
    const u = e.from;
    const fromRoot = byId[u] && byId[u].kind === 'root';
    edgeUpdates.push({
      id: e.id,
      color: { color: hot ? '#ef4444' : fromRoot ? '#b91c1c' : '#475569' },
      width: hot ? 3 : fromRoot ? 1.5 : 1
    });
  });
  if (edgeUpdates.length) edges.update(edgeUpdates);
}

function draw(isInitial = false) {
  const set = visibleSet();
  const list = [...set].filter(id => byId[id]);
  const currentPos = (nodes.length > 0) ? net.getPositions() : {};
  const useBarnes = list.length > 120;
  const currentSolver = useBarnes ? 'barnesHut' : 'forceAtlas2Based';

  const vn = list.map(id => {
    const v = toVis(byId[id], set);
    if (currentPos[id]) {
      v.x = currentPos[id].x;
      v.y = currentPos[id].y;
    }
    return v;
  });

  if (layout === 'phys') {
    vn.forEach(v => {
      if (currentPos[v.id] === undefined) {
        const p = (inn[v.id] || []).find(pid => currentPos[pid]);
        if (p && currentPos[p]) {
          v.x = currentPos[p].x + (Math.random() - 0.5) * 50;
          v.y = currentPos[p].y + (Math.random() - 0.5) * 50;
        }
      }
    });
    if (roots.length === 1) {
      vn.forEach(v => { if (v.id === roots[0]) { v.x = 0; v.y = 0; v.fixed = true; } });
    }
  }

  if (layout === 'radial') {
    vn.forEach(v => {
      const d = byId[v.id].depth;
      const k = list.filter(x => byId[x].depth === d);
      const i = k.indexOf(v.id);
      const a = 2 * Math.PI * i / Math.max(k.length, 1);
      v.x = Math.cos(a) * d * 170;
      v.y = Math.sin(a) * d * 170;
      v.physics = false;
    });
  }

  const curIds = new Set(nodes.getIds());
  const nextIds = new Set(vn.map(n => n.id));
  const nodesToRemove = [...curIds].filter(id => !nextIds.has(id));
  const nodesToAdd = vn.filter(n => !curIds.has(n.id));
  const nodesToUpdate = vn.filter(n => curIds.has(n.id));

  if (nodesToRemove.length) nodes.remove(nodesToRemove);
  if (nodesToUpdate.length) nodes.update(nodesToUpdate);
  if (nodesToAdd.length) nodes.add(nodesToAdd);

  const ed = D.edges.filter(([u, v]) => set.has(u) && set.has(v)).map(([u, v]) => {
    const hot = selEdges.has(u + '>' + v), fromRoot = byId[u] && byId[u].kind === 'root';
    return {
      id: u + '>' + v,
      from: u,
      to: v,
      color: { color: hot ? '#ef4444' : fromRoot ? '#b91c1c' : '#475569' },
      width: hot ? 3 : fromRoot ? 1.5 : 1
    };
  });

  const curEdgeIds = new Set(edges.getIds());
  const nextEdgeIds = new Set(ed.map(e => e.id));
  const edgesToRemove = [...curEdgeIds].filter(id => !nextEdgeIds.has(id));
  const edgesToAdd = ed.filter(e => !curEdgeIds.has(e.id));
  const edgesToUpdate = ed.filter(e => curEdgeIds.has(e.id));

  if (edgesToRemove.length) edges.remove(edgesToRemove);
  if (edgesToUpdate.length) edges.update(edgesToUpdate);
  if (edgesToAdd.length) edges.add(edgesToAdd);

  const shouldStabilize = isInitial && layout === 'phys';
  net.setOptions({
    layout: layout === 'tree' ? { hierarchical: { enabled: true, direction: 'UD', sortMethod: 'directed', levelSeparation: 110, nodeSpacing: 90 } } : { hierarchical: { enabled: false } },
    physics: {
      enabled: layout === 'phys' && physicsOn,
      solver: currentSolver,
      stabilization: shouldStabilize ? { enabled: true, iterations: 80, updateInterval: 25 } : false
    }
  });

  if (layout !== 'phys') {
    net.fit({ animation: false });
  } else if (isInitial) {
    net.once('stabilized', () => net.fit({ animation: { duration: 300 } }));
    setTimeout(() => net.fit({ animation: false }), 1500);
  }

  const shown = list.filter(id => byId[id].kind !== 'root');
  const dir = shown.filter(id => byId[id].direct).length;
  document.getElementById('count').textContent = 'Showing ' + shown.length + ' of ' + D.total + ' packages (' + dir + ' direct, ' + (shown.length - dir) + ' transitive)' + (useBarnes ? ' • Fast Barnes-Hut solver' : '') + (D.truncated ? ' • list capped for performance' : '');
  document.getElementById('limv').textContent = limit;
  document.getElementById('limt').textContent = '/ ' + pkgs.length;
  [...fb.children].forEach(b => b.className = b.dataset.k === filter && !focus ? 'on' : '');
  updatePhysicsUI();
}

function ancestors(id) {const seen = new Set([id]), es = new Set(), st = [id]; while (st.length) {const c = st.pop(); (inn[c]||[]).forEach(p => {es.add(p+'>'+c); if (!seen.has(p)) {seen.add(p); st.push(p);}});} return [seen, es];}
function descCount(id) {const seen = new Set(), st = [id]; while (st.length) {(out[st.pop()]||[]).forEach(c => {if (!seen.has(c)) {seen.add(c); st.push(c);}});} return seen.size;}
function shortest(id) {let best = null; roots.forEach(r => {const prev = {[r]:null}, q = [r]; while (q.length) {const c = q.shift(); if (c===id) break; (out[c]||[]).forEach(x => {if (!(x in prev)) {prev[x] = c; q.push(x);}});}
  if (id in prev) {const p = []; for (let c = id; c; c = prev[c]) p.unshift(byId[c].label); if (!best || p.length < best.length) best = p;}}); return best || [];}

function select(id) {
  selected = id; const [s, e] = ancestors(id); selSet = s; selEdges = e;
  highlightOnly();
  const n = byId[id], side = document.getElementById('side'); side.style.display = 'block';
  const intro = [...s].filter(x => byId[x] && byId[x].direct && x !== id).map(x => byId[x].label).slice(0,6);
  side.innerHTML = '<b style="font-size:13px">Impact Analysis</b><br><b>' + n.label + '</b>' + (n.version ? '@' + n.version : '') + ' <span class="tag">' + (n.kind==='root' ? 'application root' : n.direct ? 'direct' : 'transitive') + '</span> <span class="tag">' + (n.kind==='dev' ? 'dev tool' : n.kind==='prod' ? 'production' : 'root') + '</span><br>' +
    (n.vuln ? '<span class="tag" style="color:' + SEV[n.vuln] + ';border-color:' + SEV[n.vuln] + '">' + n.vuln + '</span> ' + n.ids.map(i => '<code>' + i + '</code>').join(' ') + (n.fix ? '<br>Fixed in: <b>' + n.fix + '</b>' : '') + '<br>' : '') +
    'Reached from <b>' + Math.max(s.size - 1, 0) + '</b> package(s)/root(s)' + (intro.length && !n.direct ? '<br>Introduced via: ' + intro.join(', ') : '') + '<br>Blast radius: <b>' + descCount(id) + '</b> package(s) below it<br>Shortest path:<br><code>' + shortest(id).join(' → ') + '</code>';
}

function reset() {
  selected = null; selSet = new Set(); selEdges = new Set();
  if (focus) {
    focus = null;
    physicsOn = (layout === 'phys');
    draw(false);
  } else {
    highlightOnly();
  }
  document.getElementById('side').style.display = 'none';
}

net.on('click', p => {if (p.nodes.length) select(p.nodes[0]);});
net.on('doubleClick', p => {if (p.nodes.length) {focus = p.nodes[0]; selected = focus; const [s, e] = ancestors(focus); selSet = s; selEdges = e; physicsOn = (layout === 'phys'); draw(false); select(focus);}});
net.on('dragStart', () => {if (layout === 'phys' && !physicsOn) {physicsOn = true; net.setOptions({physics:{enabled:true, stabilization:false}}); updatePhysicsUI();}});
net.on('stabilized', () => {if (layout === 'phys' && physicsOn) {net.setOptions({physics:{enabled:false}}); physicsOn = false; updatePhysicsUI();}});

document.getElementById('reset').onclick = reset;
document.getElementById('pause').onclick = () => {physicsOn = !physicsOn; net.setOptions({physics:{enabled: layout==='phys' && physicsOn, stabilization:false}}); updatePhysicsUI();};
document.getElementById('lay').onchange = e => {layout = e.target.value; physicsOn = (layout === 'phys'); draw(layout === 'phys');};

let drawTimer = null;
function scheduleDraw(delay = 80) {
  clearTimeout(drawTimer);
  drawTimer = setTimeout(() => {
    physicsOn = (layout === 'phys');
    draw(false);
  }, delay);
}

lim.oninput = e => {
  limit = +e.target.value;
  document.getElementById('limv').textContent = limit;
  scheduleDraw(75);
};
lim.onchange = e => {
  limit = +e.target.value;
  document.getElementById('limv').textContent = limit;
  clearTimeout(drawTimer);
  physicsOn = (layout === 'phys');
  draw(false);
};

document.getElementById('q').oninput = e => {
  query = e.target.value.trim().toLowerCase();
  if (query) filter = 'all';
  scheduleDraw(150);
  const m = ranked.find(n => n.label.toLowerCase().includes(query));
  if (m && query.length > 1) setTimeout(() => net.focus(m.id, {scale:1.1, animation:true}), 300);
};

draw(true);
</script>"""

FLOW_HTML = _CSS + """
<div id="wrap"><div id="net"></div><div id="side" style="display:block"><b>Click an agent</b><br>to see its role, tools and outputs.</div></div>
<div id="foot">__LEGEND__<span style="color:#64748b">Arrows show data flow between agents · Detect branches run in parallel and join at Risk · SBOM may run a second pass when quality is low</span></div>
<script src="__URL__"></script>
<script>
__FALLBACK__
const D = __DATA__;
const nodes = new vis.DataSet(D.nodes.map(n => ({id:n.id, label:n.label, shape:'box', margin:9, color:{background:D.colors[n.phase], border:'#0b1020'}, font:{color:'#fff', size:13, bold:true}, widthConstraint:{minimum:100}})));
const edges = new vis.DataSet(D.edges.map(e => ({from:e[0], to:e[1], dashes:!!e[2], arrows:'to', color:{color:'#64748b'}})));
const net = new vis.Network(document.getElementById('net'), {nodes, edges}, {layout:{hierarchical:{enabled:true, direction:'LR', sortMethod:'directed', levelSeparation:130, nodeSpacing:40}}, physics:false, interaction:{dragNodes:false, hover:true}});
net.on('click', p => {if (!p.nodes.length) return; const n = D.nodes.find(x => x.id === p.nodes[0]);
  document.getElementById('side').innerHTML = '<b style="font-size:13px">' + n.label + '</b> <span class="tag" style="border-color:' + D.colors[n.phase] + '">' + n.phase + '</span><br>' + n.role +
    (n.steps.length ? '<br><br><b>Steps</b><br>' + n.steps.map(s => '• ' + s).join('<br>') : '') + (n.ai ? '<br><br><span class="tag">can use optional LLM (grounded)</span>' : '') + (n.approval ? '<br><span class="tag">human approval point</span>' : '');});
net.once('afterDrawing', () => net.fit());
</script>"""


def _embed(html: str, height: int, alt: str) -> None:
    html = html.replace("__H__", str(height)).replace("__URL__", VIS_URL).replace("__FALLBACK__", _FALLBACK)
    if hasattr(st, "iframe"):
        st.iframe(html, height=height + 90, alt=alt)
    else:
        import streamlit.components.v1 as components
        components.html(html, height=height + 90, scrolling=False)


def _json(obj: dict) -> str:
    return json.dumps(obj).replace("</", "<\\/")


def render_dependency_graph(payload: dict, height: int = 620) -> None:
    _embed(DEP_HTML.replace("__DATA__", _json(payload)), height, "Interactive dependency graph")


def render_workflow_graph(payload: dict, height: int = 460) -> None:
    legend = "".join(f"<span><i class='dot' style='background:{c}'></i>{p}</span>" for p, c in payload["colors"].items())
    _embed(FLOW_HTML.replace("__LEGEND__", legend).replace("__DATA__", _json(payload)), height, "Agent workflow graph")
