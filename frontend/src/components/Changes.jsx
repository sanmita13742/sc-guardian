export default function Changes({ changes }) {
  if (!changes) return <section className="tab-page"><div className="warning">This earlier analysis has no Phase 2 change artifact. Run a new analysis.</div></section>
  const study = changes.case_study
  return <section className="tab-page">
    <div className="section-heading"><div><span className="eyebrow">Bounded Git history</span><h2>Suspicious dependency changes</h2></div><span className="status-pill">{changes.commits_examined} commits examined</span></div>
    {study ? <article className="case-study"><span className="eyebrow">Prioritized historical case</span><h3>{study.package_name}: {study.before} → {study.after}</h3><p>{study.assessment}. This historical signal is not evidence of malicious compromise.</p><dl><dt>Parent SHA</dt><dd className="mono">{study.parent_sha}</dd><dt>Child SHA</dt><dd className="mono">{study.child_sha}</dd><dt>Newly applicable advisories</dt><dd>{study.newly_applicable_advisory_ids.join(', ') || 'Unavailable or none'}</dd><dt>OSV comparison</dt><dd>{study.osv_comparison_status}</dd><dt>Source/integrity changed</dt><dd>{study.source_or_integrity_changed ? 'Yes' : 'No evidence'}</dd></dl></article> : <div className="warning">No explainable downgrade was found inside the fetched history window. This is unresolved, not a clean finding.</div>}
    <h3>Dependency change evidence ({changes.dependency_change_count})</h3>
    <div className="table-wrap"><table><thead><tr><th>Package</th><th>Type</th><th>Before</th><th>After</th><th>Historical child SHA</th></tr></thead><tbody>{changes.changes.slice(0, 250).map((item, index) => <tr key={`${item.child_sha}-${item.package_name}-${index}`}><td>{item.package_name}</td><td>{item.change_type}</td><td>{item.before || '—'}</td><td>{item.after || '—'}</td><td className="mono">{item.child_sha.slice(0, 12)}</td></tr>)}</tbody></table></div>
  </section>
}

