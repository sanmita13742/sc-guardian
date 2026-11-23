export default function Toolbar({ state, setState, graph, visibleCount, paused, onPause, onReset }) {
  const total = graph?.nodes.length || 0
  return <section className="toolbar">
    <label className="search"><span>Search package or bom-ref</span><input value={state.search} onChange={(event) => setState({ ...state, search: event.target.value })} placeholder="lodash, pkg:npm/..." /></label>
    <div className="filter-group" aria-label="Graph filters">
      {[['direct', 'Direct Only'], ['production', 'Production Only'], ['hubs', 'Shared Hubs'], ['all', 'All Nodes']].map(([id, label]) =>
        <button key={id} className={state.filter === id ? 'active' : ''} onClick={() => setState({ ...state, filter: id })}>{label}</button>)}
    </div>
    <label><span>Layout</span><select value={state.layout} onChange={(event) => setState({ ...state, layout: event.target.value })}>
      <option value="cose">Organic / Physics</option><option value="breadthfirst">Hierarchical</option><option value="concentric">Radial</option><option value="grid">Grid</option>
    </select></label>
    <label className="limit"><span>Render {visibleCount.toLocaleString()} of {total.toLocaleString()}</span><input type="range" min="50" max={Math.max(50, total)} step="50" value={Math.min(state.limit, Math.max(50, total))} onChange={(event) => setState({ ...state, limit: Number(event.target.value) })} /></label>
    {state.layout === 'cose' && <button onClick={onPause}>{paused ? 'Resume Physics' : 'Pause Physics'}</button>}
    <button onClick={onReset}>Reset Selection</button>
  </section>
}

