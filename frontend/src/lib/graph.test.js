import { describe, expect, it } from 'vitest'
import { selectVisibleGraph, shortestPath } from './graph.js'

const graph = {
  root: 'root',
  nodes: [
    { id: 'root', label: 'root', depth: 0, production: true },
    { id: 'a', label: 'a', depth: 1, direct: true, production: true, sharedHub: false },
    { id: 'b', label: 'b', depth: 2, transitive: true, production: false, sharedHub: true },
  ],
  edges: [{ source: 'root', target: 'a' }, { source: 'a', target: 'b' }],
}

describe('presentation graph helpers', () => {
  it('finds a dependency path', () => expect(shortestPath(graph, 'b')).toEqual(['root', 'a', 'b']))
  it('filters direct nodes', () => expect(selectVisibleGraph(graph, { filter: 'direct', search: '', limit: 50 }).nodes.map((n) => n.id)).toEqual(['root', 'a']))
  it('filters production nodes', () => expect(selectVisibleGraph(graph, { filter: 'production', search: '', limit: 50 }).nodes.map((n) => n.id)).toEqual(['root', 'a']))
  it('filters shared hubs', () => expect(selectVisibleGraph(graph, { filter: 'hubs', search: '', limit: 50 }).nodes.map((n) => n.id)).toEqual(['root', 'b']))
})

