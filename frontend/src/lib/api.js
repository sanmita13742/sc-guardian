async function request(path, options) {
  let response
  try {
    response = await fetch(path, options)
  } catch (error) {
    throw new Error('Guardian API is offline. Start Uvicorn on 127.0.0.1:8000 and retry.')
  }
  if (!response.ok) {
    let body
    try { body = await response.json() } catch { body = {} }
    const detail = body.detail
    const message = typeof detail === 'string' ? detail : detail?.message
    throw new Error(message || `Request failed (${response.status})`)
  }
  return response.json()
}

export const api = {
  latest: () => request('/api/analyses/latest'),
  create: (repositoryUrl) => request('/api/analyses', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repository_url: repositoryUrl }),
  }),
  status: (jobId) => request(`/api/analyses/${jobId}`),
  graph: (jobId) => request(`/api/analyses/${jobId}/graph`),
  risks: (jobId) => request(`/api/analyses/${jobId}/risks`),
  changes: (jobId) => request(`/api/analyses/${jobId}/changes`),
  report: (jobId) => request(`/api/analyses/${jobId}/report`),
  cancel: (jobId) => request(`/api/analyses/${jobId}`, { method: 'DELETE' }),
}

