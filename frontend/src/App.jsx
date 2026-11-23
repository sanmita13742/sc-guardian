import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from './lib/api.js'
import { selectVisibleGraph, shortestPath } from './lib/graph.js'
import Artifacts from './components/Artifacts.jsx'
import Changes from './components/Changes.jsx'
import GraphNetwork from './components/GraphNetwork.jsx'
import Inspector from './components/Inspector.jsx'
import Overview from './components/Overview.jsx'
import ProgressPanel from './components/ProgressPanel.jsx'
import ReportView from './components/ReportView.jsx'
import Risks from './components/Risks.jsx'
import Stats from './components/Stats.jsx'
import Toolbar from './components/Toolbar.jsx'

const DEFAULT_REPO = 'https://github.com/OWASP/NodeGoat'
const terminal = new Set(['completed', 'completed_with_warnings', 'failed', 'cancelled'])

export default function App() {
  const [repositoryUrl, setRepositoryUrl] = useState(DEFAULT_REPO)
  const [job, setJob] = useState(null)
  const [graph, setGraph] = useState(null)
  const [risks, setRisks] = useState(null)
  const [changes, setChanges] = useState(null)
  const [report, setReport] = useState(null)
  const [tab, setTab] = useState('overview')
  const [error, setError] = useState('')
  const [selectedId, setSelectedId] = useState(null)
  const [view, setView] = useState({ filter: 'all', search: '', limit: 300, layout: 'cose' })
  const [paused, setPaused] = useState(false)
  const networkRef = useRef(null)
  const pollingRef = useRef(null)

  const loadAnalysis = useCallback(async (finishedJob) => {
    const [graphResult, risksResult, changesResult, reportResult] = await Promise.allSettled([
      api.graph(finishedJob.job_id), api.risks(finishedJob.job_id), api.changes(finishedJob.job_id), api.report(finishedJob.job_id),
    ])
    if (graphResult.status === 'rejected') throw graphResult.reason
    const data = graphResult.value
    setGraph(data)
    setRisks(risksResult.status === 'fulfilled' ? risksResult.value : null)
    setChanges(changesResult.status === 'fulfilled' ? changesResult.value : null)
    setReport(reportResult.status === 'fulfilled' ? reportResult.value : null)
    setJob(finishedJob); setSelectedId(data.root); setTab('overview'); setError('')
  }, [])

  useEffect(() => {
    let active = true
    api.latest().then((latest) => active && loadAnalysis(latest)).catch((err) => {
      if (active && !String(err.message).includes('No completed')) setError(err.message)
    })
    return () => { active = false }
  }, [loadAnalysis])

  const poll = useCallback((jobId) => {
    window.clearInterval(pollingRef.current)
    const tick = async () => {
      try {
        const current = await api.status(jobId)
        setJob(current)
        if (terminal.has(current.status)) {
          window.clearInterval(pollingRef.current); pollingRef.current = null
          if (current.status === 'completed' || current.status === 'completed_with_warnings') await loadAnalysis(current)
          else setError(current.error?.message || `Analysis ${current.status}`)
        }
      } catch (err) { window.clearInterval(pollingRef.current); setError(err.message) }
    }
    tick(); pollingRef.current = window.setInterval(tick, 1500)
  }, [loadAnalysis])

  useEffect(() => () => window.clearInterval(pollingRef.current), [])

  async function analyze(event) {
    event.preventDefault()
    setError(''); setGraph(null); setRisks(null); setChanges(null); setReport(null); setSelectedId(null)
    try { const created = await api.create(repositoryUrl); setJob(created); poll(created.job_id) }
    catch (err) { setError(err.message) }
  }

  async function cancel() {
    if (job) { await api.cancel(job.job_id); setError('Cancellation requested. The current external command may finish before cancellation takes effect.') }
  }

  const visible = useMemo(() => selectVisibleGraph(graph, { ...view, selectedId }), [graph, view, selectedId])
  const path = useMemo(() => shortestPath(graph, selectedId), [graph, selectedId])
  const selected = graph?.nodes.find((node) => node.id === selectedId) || null
  const running = job && !terminal.has(job.status)
  const repo = graph?.info?.repository
  const generator = Array.isArray(graph?.info?.generator) ? graph.info.generator.find((tool) => tool.name === 'cyclonedx-npm') || graph.info.generator[0] : null

  return <main>
    <header><div><span className="brand-mark">G</span><div><h1>Software Supply Chain Guardian</h1><p>Dependency Risk &amp; Evidence Map</p></div></div><div className="repo-meta"><strong>{repo ? `${repo.owner}/${repo.name}` : 'No scan yet'}</strong><span>{job?.commit_sha ? `${job.commit_sha.slice(0, 12)} · ${new Date(job.completed_at || job.created_at).toLocaleString()}` : 'Awaiting an analysis'}</span></div></header>
    <section className="scan-panel"><form onSubmit={analyze}><label><span>Repository URL</span><input type="url" required pattern="https://github\.com/[^/]+/[^/?#]+/?" value={repositoryUrl} onChange={(event) => setRepositoryUrl(event.target.value)} /></label><button className="primary" disabled={running}>{running ? 'Analyzing…' : 'Analyze Repository'}</button>{running && <button type="button" onClick={cancel}>Cancel</button>}</form><p>HTTPS GitHub npm repositories only. Target code and lifecycle scripts are never executed.</p></section>
    {error && <div className="error-banner"><div><strong>Action needed</strong><span>{error}</span></div>{job?.status === 'failed' && <button onClick={analyze}>Retry</button>}</div>}
    {running && <ProgressPanel job={job} />}
    {graph ? <>
      <section className="scan-facts" aria-label="Scan provenance"><span><small>Status</small><strong>{job.status.replaceAll('_', ' ')}</strong></span><span><small>Official validation</small><strong>{graph.info.validation_status === 'passed' ? 'Passed' : 'Unavailable'}</strong></span><span><small>SBOM specification</small><strong>CycloneDX {graph.info.specVersion || 'Unknown'}</strong></span><span><small>Generator</small><strong>{generator ? `${generator.name} ${generator.version || ''}` : 'Not reported'}</strong></span><span><small>Commit</small><strong className="mono">{graph.info.commit_sha?.slice(0, 12)}</strong></span><span><small>Scanned</small><strong>{graph.info.generated_at ? new Date(graph.info.generated_at).toLocaleString() : 'Unknown'}</strong></span></section>
      <nav className="tabs" aria-label="Analysis views">{[['overview', 'Overview'], ['graph', 'Dependency Graph'], ['risks', `Known Vulnerabilities${risks ? ` (${risks.unique_advisory_count})` : ''}`], ['changes', 'Suspicious Changes'], ['report', 'Evidence Report']].map(([id, label]) => <button key={id} className={tab === id ? 'active' : ''} onClick={() => setTab(id)}>{label}</button>)}</nav>
      {tab === 'overview' && <><Stats stats={graph.stats} /><Overview job={job} graph={graph} risks={risks} changes={changes} report={report} /></>}
      {tab === 'graph' && <><Toolbar state={view} setState={setView} graph={graph} visibleCount={visible.nodes.length} paused={paused} onPause={() => { if (!paused) networkRef.current?.layout({ name: 'preset' }).stop(); else networkRef.current?.layout({ name: 'cose', animate: false }).run(); setPaused(!paused) }} onReset={() => { setSelectedId(null); networkRef.current?.elements().unselect(); networkRef.current?.fit(undefined, 30) }} /><section className="workspace"><GraphNetwork graph={graph} visible={visible} layout={view.layout} selectedId={selectedId} path={path} onSelect={setSelectedId} networkRef={networkRef} /><Inspector node={selected} path={path} graph={graph} onSelect={setSelectedId} /></section><section className="legend"><span><i className="purple" />Root</span><span><i className="teal" />Direct</span><span><i className="blue" />Transitive / other</span><span><i className="red" />Global leaf</span><span><i className="grey" />Missing metadata</span><em>Leaf red indicates graph structure, never vulnerability severity.</em></section>{graph.info.warnings?.length > 0 && <section className="warnings"><strong>Reconciliation warnings</strong>{graph.info.warnings.map((warning) => <span key={warning}>{warning}</span>)}</section>}</>}
      {tab === 'risks' && <Risks risks={risks} onInspect={(finding) => { const ref = finding.graph_match.bom_refs[0]; if (ref) { setSelectedId(ref); setTab('graph') } }} />}
      {tab === 'changes' && <Changes changes={changes} />}
      {tab === 'report' && <ReportView report={report} artifacts={job?.artifacts} />}
      <Artifacts artifacts={job?.artifacts} />
    </> : !running && <section className="empty-state"><div className="orb">G</div><h2>No analysis loaded</h2><p>Analyze the prefilled NodeGoat repository. SBOM, graph, OSV findings, historical changes, CI evidence, and reports will appear automatically.</p></section>}
  </main>
}
