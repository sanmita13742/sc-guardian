export default function Artifacts({ artifacts }) {
  const entries = Object.entries(artifacts || {})
  if (!entries.length) return null
  return <section className="artifacts"><span>Analysis artifacts</span>{entries.map(([name, url]) => <a href={url} download key={name}>{name}</a>)}</section>
}

