const stages = [
  ['clone', 'Clone'], ['inventory', 'Inventory'], ['validate', 'Validate'], ['graph', 'Graph'],
  ['vulnerabilities', 'OSV'], ['changes', 'Changes'], ['supply_chain_context', 'CI/CD'],
  ['correlate', 'Correlate'], ['report', 'Report'], ['ready', 'Ready'],
]

export default function ProgressPanel({ job }) {
  if (!job) return null
  const activeIndex = stages.findIndex(([id]) => id === job.stage)
  return <section className="progress-panel" aria-live="polite">
    <div className="progress-title"><span>{job.stage_label}</span><strong>{job.progress}%</strong></div>
    <div className="progress-track"><i style={{ width: `${job.progress}%` }} /></div>
    <div className="stage-row">
      {stages.map(([id, label], index) => <span key={id} className={index <= activeIndex ? 'done' : ''}>{label}</span>)}
    </div>
  </section>
}

