export const NODE_COLORS = {
  root: '#7c3aed',
  direct: '#0d9488',
  other: '#3b82f6',
  leaf: '#dc2626',
  unresolved: '#94a3b8',
}

export function nodeAppearance(node, root) {
  if (node.id === root) return { color: NODE_COLORS.root, border: NODE_COLORS.root }
  if (!node.hasComponent) return {
    color: NODE_COLORS.unresolved,
    border: node.leaf ? NODE_COLORS.leaf : NODE_COLORS.unresolved,
  }
  if (node.leaf) return { color: NODE_COLORS.leaf, border: NODE_COLORS.leaf }
  if (node.direct) return { color: NODE_COLORS.direct, border: NODE_COLORS.direct }
  return { color: NODE_COLORS.other, border: NODE_COLORS.other }
}

export function shortestPath(graph, targetId) {
  if (!graph?.root || !targetId) return []
  if (targetId === graph.root) return [graph.root]
  const children = new Map(graph.nodes.map((node) => [node.id, []]))
  graph.edges.forEach(({ source, target }) => children.get(source)?.push(target))
  const queue = [graph.root]
  const previous = new Map([[graph.root, null]])
  for (let index = 0; index < queue.length; index += 1) {
    const current = queue[index]
    for (const child of children.get(current) || []) {
      if (previous.has(child)) continue
      previous.set(child, current)
      if (child === targetId) {
        const path = [child]
        let cursor = current
        while (cursor !== null) { path.push(cursor); cursor = previous.get(cursor) }
        return path.reverse()
      }
      queue.push(child)
    }
  }
  return []
}

export function selectVisibleGraph(graph, { filter, search, limit, selectedId }) {
  if (!graph) return { nodes: [], edges: [] }
  const needle = search.trim().toLocaleLowerCase()
  const matches = (node) => !needle || [node.name, node.version, node.id, node.purl]
    .filter(Boolean).some((value) => String(value).toLocaleLowerCase().includes(needle))
  const passes = (node) => {
    if (node.id === graph.root) return true
    if (filter === 'direct') return node.direct
    if (filter === 'production') return node.production === true
    if (filter === 'hubs') return node.sharedHub
    return true
  }
  const pathIds = new Set(shortestPath(graph, selectedId))
  const ordered = [...graph.nodes].sort((a, b) => {
    const aPriority = pathIds.has(a.id) || matches(a) ? 0 : 1
    const bPriority = pathIds.has(b.id) || matches(b) ? 0 : 1
    return aPriority - bPriority || (a.depth ?? 1e9) - (b.depth ?? 1e9) || a.label.localeCompare(b.label)
  })
  let candidates = ordered.filter((node) => passes(node) && matches(node))
  if (!needle) candidates = ordered.filter(passes)
  const visible = new Set(candidates.slice(0, limit).map((node) => node.id))
  pathIds.forEach((id) => visible.add(id))
  if (graph.root) visible.add(graph.root)
  const nodes = graph.nodes.filter((node) => visible.has(node.id))
  const edges = graph.edges.filter((edge) => visible.has(edge.source) && visible.has(edge.target))
  return { nodes, edges }
}

