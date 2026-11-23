export default function Inspector({ node, path, graph, onSelect }) {
  if (!node) return <aside className="inspector empty"><div><span className="eyebrow">Package inspector</span><h2>Select a node</h2><p>Click any package to inspect its exact identity and a shortest dependency path from the application root.</p></div></aside>
  const nodeMap = new Map(graph.nodes.map((item) => [item.id, item]))
  const links = (ids) => ids.slice(0, 30).map((id) => <button className="package-link" key={id} title={id} onClick={() => onSelect(id)}>{nodeMap.get(id)?.label || id}</button>)
  return <aside className="inspector">
    <span className="eyebrow">Package inspector</span>
    <h2>{node.name}</h2><p className="version">{node.version || 'Version unavailable'}</p>
    {!node.hasComponent && <div className="warning">Reference-only node. Display name/version inferred from its ID are unverified.</div>}
    <dl>
      <dt>Exact bom-ref</dt><dd className="mono">{node.id}</dd>
      <dt>PURL</dt><dd className="mono">{node.purl || 'Unavailable'}</dd>
      <dt>Metadata</dt><dd>{node.metadata_status}</dd>
      <dt>Depth from root</dt><dd>{node.depth ?? 'Unreachable'}</dd>
      <dt>Classification</dt><dd>{node.id === graph.root ? 'Root application' : node.direct ? 'Direct dependency' : node.transitive ? 'Transitive dependency' : 'Disconnected / other'}</dd>
      <dt>Environment</dt><dd>{node.production === true ? 'Production / not excluded' : node.development ? 'Development (excluded scope)' : 'Unknown'}</dd>
      <dt>Global leaf</dt><dd>{node.leaf ? 'Yes — zero outgoing edges' : 'No'}</dd>
      <dt>Degrees</dt><dd>{node.inDegree} incoming · {node.outDegree} outgoing</dd>
    </dl>
    <h3>Path from root</h3>
    {path.length ? <ol className="path-list">{path.map((id) => <li key={id}>{nodeMap.get(id)?.label || id}</li>)}</ol> : <p className="muted">No root path exists.</p>}
    <p className="disclaimer">This is a package dependency path. It is not proof of vulnerable function reachability.</p>
    <h3>Parents ({node.parents.length})</h3><div className="package-links">{links(node.parents)}</div>
    <h3>Children ({node.children.length})</h3><div className="package-links">{links(node.children)}</div>
  </aside>
}

