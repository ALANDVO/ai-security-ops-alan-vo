import React, { useState } from 'react'
import { api } from '../api/client'

export default function Query() {
  const [query, setQuery] = useState('')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const run = async () => {
    if (!query.trim()) return
    setLoading(true); setError(''); setResult(null)
    try { setResult(await api.query(query)) } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
  }

  return (
    <div className="query-page">
      <h2>AI Security Query</h2>
      <p className="query-hint">Ask natural language questions about your security posture</p>
      <div className="query-input-row">
        <input value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && run()}
          placeholder='e.g. "Show critical threats on web servers in the last hour"' />
        <button className="btn-primary" onClick={run} disabled={loading}>{loading ? 'Analyzing…' : 'Ask AI'}</button>
      </div>
      {error && <div className="alert alert-error">{error}</div>}
      {result && (
        <div className="query-result">
          <h3>AI Response</h3>
          {result.explanation && <p>{result.explanation}</p>}
          {result.filters && <pre className="json-block">{JSON.stringify(result.filters, null, 2)}</pre>}
          {result.suggested_followup && <p className="followup"><strong>Suggested:</strong> {result.suggested_followup}</p>}
        </div>
      )}
      <div className="query-examples">
        <h4>Examples</h4>
        {['What critical threats affected production servers yesterday?', 'Show me the top 5 assets by risk score', 'Any lateral movement patterns in the last 24h?'].map((ex, i) => (
          <button key={i} className="btn-link" onClick={() => setQuery(ex)}>{ex}</button>
        ))}
      </div>
    </div>
  )
}
