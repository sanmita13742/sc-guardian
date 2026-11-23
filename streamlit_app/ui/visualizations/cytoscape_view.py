"""Cytoscape.js embed (loaded from cdnjs). Graph data is JSON-embedded with script-closing sequences escaped."""
from __future__ import annotations

import json

import streamlit as st

CYTOSCAPE_URL = "https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.2/cytoscape.min.js"

TEMPLATE = """
<div style="font-family:system-ui,Segoe UI,sans-serif;font-size:13px">
<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:6px;color:#444">
 <span><b style="color:#2f6f4f">■</b> service root</span><span><b style="color:#7a8794">●</b> package</span>
 <span><b style="color:#b42318">●</b> critical</span><span><b style="color:#e5601c">●</b> high</span><span><b style="color:#d4a72c">●</b> medium</span>
 <span><b style="color:#4c8bf5">●</b> low</span><span><b style="color:#8250df">●</b> vulnerable (severity n/a)</span>
 <span>solid edge = recorded relationship, dashed = inferred</span></div>
<div id="cy" style="height:__H__px;border:1px solid #d0d7de;border-radius:6px;background:#fff"></div>
<div id="info" style="margin-top:6px;padding:8px;border:1px solid #d0d7de;border-radius:6px;min-height:44px;background:#f6f8fa">Click a node for details.</div>
</div>
<script src="__URL__"></script>
<script>
const elements = __ELEMENTS__;
if (typeof cytoscape === 'undefined') {
  document.getElementById('cy').innerHTML = '<p style="padding:1rem">Cytoscape.js could not be loaded (offline?). Use the tables below.</p>';
} else {
  const sev = {CRITICAL:'#b42318',HIGH:'#e5601c',MEDIUM:'#d4a72c',LOW:'#4c8bf5',UNKNOWN:'#8250df'};
  const cy = cytoscape({container: document.getElementById('cy'), elements: elements, wheelSensitivity: 0.25,
    style: [
      {selector:'node', style:{'label':'data(label)','font-size':8,'width':14,'height':14,'background-color':'#7a8794','text-valign':'bottom','text-margin-y':3,'text-wrap':'ellipsis','text-max-width':90}},
      {selector:'node[kind="root"]', style:{'shape':'round-rectangle','background-color':'#2f6f4f','width':26,'height':26,'font-size':10,'font-weight':'bold'}},
      {selector:'node[vuln]', style:{'width':20,'height':20,'border-width':2,'border-color':'#222'}},
      {selector:'node[vuln="CRITICAL"]', style:{'background-color':sev.CRITICAL}},
      {selector:'node[vuln="HIGH"]', style:{'background-color':sev.HIGH}},
      {selector:'node[vuln="MEDIUM"]', style:{'background-color':sev.MEDIUM}},
      {selector:'node[vuln="LOW"]', style:{'background-color':sev.LOW}},
      {selector:'node[vuln="UNKNOWN"]', style:{'background-color':sev.UNKNOWN}},
      {selector:'edge', style:{'width':1,'line-color':'#aab4be','target-arrow-color':'#aab4be','target-arrow-shape':'triangle','curve-style':'bezier','arrow-scale':0.8}},
      {selector:'edge[prov^="inferred"]', style:{'line-style':'dashed','line-color':'#c9a227','target-arrow-color':'#c9a227'}},
      {selector:'.hl', style:{'line-color':'#0969da','target-arrow-color':'#0969da','width':3,'background-color':'#0969da'}},
      {selector:'node.hl[vuln]', style:{'border-color':'#0969da'}}
    ],
    layout: elements.length > 400 ? {name:'cose', animate:false, nodeRepulsion:8000, idealEdgeLength:60} :
            {name:'breadthfirst', directed:true, roots:'node[kind="root"]', spacingFactor:1.15, animate:false}
  });
  cy.on('tap','node', function(evt){
    const n = evt.target, d = n.data();
    cy.elements().removeClass('hl');
    n.predecessors().addClass('hl'); n.addClass('hl');
    const preds = n.incomers('node').map(x=>x.data('label')).slice(0,8).join(', ') || '-';
    const succ = n.outgoers('node').map(x=>x.data('label')).slice(0,8).join(', ') || '-';
    document.getElementById('info').innerHTML =
      '<b>'+d.label+'</b>' + (d.ecosystem? ' ('+d.ecosystem+')':'') + (d.vuln? ' &mdash; <b style="color:'+(sev[d.vuln]||'#333')+'">vulnerable: '+d.vuln+'</b>':'') +
      '<br>PURL: '+(d.purl||'-')+'<br>Relationship to root(s): '+(d.rel||'-')+'<br>Parents: '+preds+'<br>Depends on: '+succ+
      '<br><i>Highlighted: all ancestors back to the service root(s).</i>';
  });
}
</script>
"""


def render_cytoscape(elements: list[dict], height: int = 560) -> None:
    payload = json.dumps(elements).replace("</", "<\\/")
    html = TEMPLATE.replace("__ELEMENTS__", payload).replace("__URL__", CYTOSCAPE_URL).replace("__H__", str(height))
    if hasattr(st, "iframe"):
        st.iframe(html, height=height + 150, alt="Dependency Graph Canvas")
    else:
        import streamlit.components.v1 as components
        components.html(html, height=height + 150, scrolling=False)
