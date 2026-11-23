const items = [
  ['total_nodes', 'Graph nodes'], ['total_edges', 'Unique edges'], ['direct_connections', 'Direct links'],
  ['transitive_connections', 'Transitive links'], ['other_connections', 'Disconnected links'],
  ['direct_node_count', 'Direct nodes'], ['transitive_node_count', 'Transitive nodes'],
  ['unresolved_node_count', 'Unresolved'], ['leaf_node_count', 'Leaves'],
  ['component_record_count', 'SBOM components'], ['dependency_record_count', 'Dependency records'],
]

export default function Stats({ stats }) {
  if (!stats) return null
  return <section className="stats" aria-label="Graph summary">
    {items.map(([key, label]) => <div className="stat" key={key}><strong>{Number(stats[key] ?? 0).toLocaleString()}</strong><span>{label}</span></div>)}
  </section>
}

