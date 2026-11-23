const metric = (value) => Number(value || 0).toLocaleString()

export default function Overview({ job, graph, risks, changes, report }) {
  const stats = graph.stats
  const items = [
    ['SBOM components', stats.component_record_count], ['OSV package entries', risks?.scanner_package_entry_count],
    ['Graph nodes', stats.total_nodes], ['Unique edges', stats.total_edges], ['Reference-only nodes', stats.unresolved_node_count],
    ['Unique advisories', risks?.unique_advisory_count], ['Affected package/versions', risks?.affected_package_version_count],
    ['Suspicious changes', changes?.suspicious_change_count],
  ]
  return <section className="tab-page overview-page">
    <div className="status-hero"><div><span className="eyebrow">Overall pipeline state</span><h2>{job.status.replaceAll('_', ' ')}</h2><p>Static inventory, vulnerability, history, and supply-chain evidence tied to one pinned checkout.</p></div><span className={`status-pill ${job.status}`}>{job.status}</span></div>
    <div className="overview-metrics">{items.map(([label, value]) => <div key={label}><strong>{metric(value)}</strong><span>{label}</span></div>)}</div>
    <div className="overview-grid">
      <article><h3>Provenance</h3><dl><dt>Full commit SHA</dt><dd className="mono">{job.commit_sha}</dd><dt>Scan time</dt><dd>{new Date(job.completed_at).toLocaleString()}</dd><dt>CycloneDX</dt><dd>{graph.info.specVersion}</dd><dt>Validation</dt><dd>{graph.info.validation_status}</dd></dl></article>
      <article><h3>Evidence quality</h3><p>{report?.warnings?.length ? `${report.warnings.length} qualification(s) require attention.` : 'No pipeline warnings were recorded.'}</p>{report?.warnings?.map((warning) => <span className="warning-line" key={warning}>{warning}</span>)}</article>
      <article><h3>Method boundary</h3><p>The repository application and lifecycle scripts were not executed. Known vulnerable versions and dependency paths do not establish runtime exploitability.</p></article>
    </div>
  </section>
}

