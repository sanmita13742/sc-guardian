import { useEffect, useRef } from 'react'
import cytoscape from 'cytoscape'
import { nodeAppearance } from '../lib/graph.js'

export default function GraphNetwork({ graph, visible, layout, selectedId, path, onSelect, networkRef }) {
  const container = useRef(null)
  const pathSet = new Set(path)
  useEffect(() => {
    if (!container.current || !graph) return undefined
    const elements = [
      ...visible.nodes.map((node) => {
        const appearance = nodeAppearance(node, graph.root)
        return { data: { ...node, color: appearance.color, border: appearance.border } }
      }),
      ...visible.edges.map((edge, index) => ({ data: { id: `e${index}:${edge.source}:${edge.target}`, ...edge } })),
    ]
    const cy = cytoscape({
      container: container.current,
      elements,
      minZoom: 0.08,
      maxZoom: 4,
      wheelSensitivity: 0.2,
      style: [
        { selector: 'node', style: { 'background-color': 'data(color)', 'border-color': 'data(border)', 'border-width': 2, width: 18, height: 18, label: 'data(label)', color: '#cbd5e1', 'font-size': 8, 'text-valign': 'bottom', 'text-margin-y': 5, 'text-max-width': 110, 'text-wrap': 'ellipsis', 'overlay-opacity': 0 } },
        { selector: `node[id = "${CSS.escape(graph.root || '')}"]`, style: { width: 34, height: 34, 'font-size': 11, 'font-weight': 700 } },
        { selector: 'edge', style: { width: 1, 'line-color': '#475569', 'target-arrow-color': '#475569', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', opacity: 0.52 } },
        { selector: '.path', style: { width: 4, opacity: 1, 'line-color': '#e2e8f0', 'target-arrow-color': '#e2e8f0', 'border-width': 5, 'border-color': '#e2e8f0' } },
        { selector: ':selected', style: { 'border-width': 6, 'border-color': '#f8fafc' } },
      ],
    })
    networkRef.current = cy
    const layoutOptions = layout === 'breadthfirst' ? { name: layout, directed: true, padding: 35, spacingFactor: 1.15, animate: false }
      : layout === 'concentric' ? { name: layout, concentric: (node) => -(node.data('depth') ?? 999), levelWidth: () => 1, padding: 35, animate: false }
        : { name: layout, padding: 35, animate: false, fit: true, nodeRepulsion: 9000, idealEdgeLength: 65 }
    const runner = cy.layout(layoutOptions)
    runner.run()
    cy.on('tap', 'node', (event) => onSelect(event.target.id()))
    return () => { runner.stop(); cy.destroy(); networkRef.current = null }
  }, [graph, visible, layout, onSelect, networkRef])

  useEffect(() => {
    const cy = networkRef.current
    if (!cy) return
    cy.elements().removeClass('path')
    path.forEach((id) => cy.getElementById(id).addClass('path'))
    for (let index = 0; index < path.length - 1; index += 1) {
      cy.edges(`[source = "${CSS.escape(path[index])}"][target = "${CSS.escape(path[index + 1])}"]`).addClass('path')
    }
    if (selectedId) cy.getElementById(selectedId).select()
  }, [selectedId, path, networkRef, pathSet.size])

  return <div className="network-wrap">
    <div className="network" ref={container} />
    <div className="zoom-controls">
      <button title="Zoom in" onClick={() => networkRef.current?.zoom(networkRef.current.zoom() * 1.25)}>+</button>
      <button title="Zoom out" onClick={() => networkRef.current?.zoom(networkRef.current.zoom() / 1.25)}>−</button>
      <button title="Fit graph" onClick={() => networkRef.current?.fit(undefined, 30)}>Fit</button>
      <button title="Fit selected" onClick={() => { const node = networkRef.current?.$(':selected'); if (node?.length) networkRef.current.fit(node, 100) }}>◎</button>
    </div>
  </div>
}

