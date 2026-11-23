export default function ReportView({ report, artifacts }) {
  if (!report) return <section className="tab-page"><div className="warning">This earlier analysis has no generated Phase 2 evidence report. Run a new analysis.</div></section>
  return <section className="tab-page report-page">
    <div className="section-heading"><div><span className="eyebrow">Generated from saved evidence</span><h2>Evidence report</h2></div><div className="report-actions">{['report.html', 'report.md', 'report.json'].map((name) => artifacts?.[name] && <a key={name} href={artifacts[name]} target={name.endsWith('.html') ? '_blank' : undefined} download={!name.endsWith('.html')}>{name.endsWith('.html') ? 'Open printable report' : `Download ${name}`}</a>)}</div></div>
    <div className="status-hero"><div><h3>{report.overall_status.replaceAll('_', ' ')}</h3><p>Commit <span className="mono">{report.commit_sha}</span></p></div></div>
    <div className="overview-grid"><article><h3>Vulnerability evidence</h3>{Object.entries(report.vulnerability_summary).filter(([, value]) => typeof value !== 'object').map(([key, value]) => <span className="report-line" key={key}><em>{key.replaceAll('_', ' ')}</em><strong>{value}</strong></span>)}</article><article><h3>Change evidence</h3><p>{report.suspicious_change_summary.count} suspicious downgrade/source-change signal(s).</p><p>{report.suspicious_change_summary.case_study?.assessment || 'No bounded-history case study available.'}</p></article><article><h3>CI/CD inspection</h3><p>{report.ci_inspection.files_inspected.length} file(s) inspected; {report.ci_inspection.risk_signal_count} grounded signal(s).</p></article></div>
    <h3>Limitations</h3><ul>{report.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
  </section>
}
