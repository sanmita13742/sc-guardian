import { useMemo, useState } from 'react'

export default function Risks({ risks, onInspect }) {
  const [search, setSearch] = useState('')
  const findings = useMemo(() => (risks?.findings || []).filter((item) =>
    [item.package_name, item.package_version, item.advisory_id, ...(item.aliases || [])].join(' ').toLowerCase().includes(search.toLowerCase())), [risks, search])
  if (!risks) return <section className="tab-page"><div className="warning">This earlier analysis has no Phase 2 OSV artifact. Run a new analysis.</div></section>
  return <section className="tab-page">
    <div className="section-heading"><div><span className="eyebrow">OSV lockfile evidence</span><h2>Known vulnerabilities</h2></div><input placeholder="Filter package, GHSA, CVE…" value={search} onChange={(event) => setSearch(event.target.value)} /></div>
    <div className="risk-summary"><span><strong>{risks.unique_advisory_count}</strong> unique advisories</span><span><strong>{risks.unique_cve_count}</strong> CVE aliases</span><span><strong>{risks.affected_package_version_count}</strong> package/version pairs</span><span><strong>{risks.finding_count}</strong> finding instances</span></div>
    <div className="table-wrap"><table><thead><tr><th>Package</th><th>Advisory</th><th>Aliases</th><th>Severity evidence</th><th>Fix versions</th><th>Graph mapping</th><th>Reachability</th></tr></thead><tbody>
      {findings.slice(0, 500).map((item) => <tr key={item.finding_id}><td><button className="table-link" onClick={() => onInspect(item)}>{item.package_name}@{item.package_version}</button></td><td>{item.advisory_id}</td><td>{item.aliases.join(', ') || '—'}</td><td><span className="severity-badge">{item.severity.value || 'Not provided'}</span><small>{item.severity.source}</small></td><td>{item.fixed_versions.join(', ') || 'Not provided'}</td><td>{item.graph_match.status}<small>{item.graph_match.bom_refs.length} exact ref(s)</small></td><td>{item.function_reachability}</td></tr>)}
    </tbody></table></div>
    {findings.length > 500 && <p className="muted">Showing the first 500 of {findings.length.toLocaleString()} filtered findings. The artifact contains all findings.</p>}
  </section>
}

