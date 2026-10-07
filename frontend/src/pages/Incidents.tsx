import React, { useState, useEffect, useCallback } from 'react'
import { api } from '../api/client'

export default function Incidents() {
  const [incidents, setIncidents] = useState<any[]>([])
  const [selected, setSelected] = useState<any>(null)
  const [timeline, setTimeline] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true); setError('')
    try { setIncidents(await api.incidents('')) } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const select = async (inc: any) => {
    setSelected(inc)
    try { setTimeline(await api.timeline(inc.id)) } catch { setTimeline([]) }
  }

  return (
    <div className="incidents-page">
      <h2>Incidents</h2>
      {error && <div className="alert alert-error">{error}</div>}
      {loading ? <div className="loading">Loading…</div> : (
        <div className="incidents-layout">
          <div className="incident-list">
            {incidents.map((inc: any) => (
              <div key={inc.id} className={`incident-item ${selected?.id === inc.id ? 'active' : ''}`} onClick={() => select(inc)}>
                <span className={`badge badge-${inc.severity}`}>{inc.severity}</span>
                <span className="incident-title">{inc.title}</span>
                <span className="incident-meta">{inc.threat_count} threats</span>
              </div>
            ))}
            {incidents.length === 0 && <p className="empty">No incidents</p>}
          </div>
          <div className="incident-detail">
            {selected ? (
              <>
                <h3>{selected.title}</h3>
                <div className="detail-meta">
                  <span>Severity: <span className={`badge badge-${selected.severity}`}>{selected.severity}</span></span>
                  <span>Status: {selected.status}</span>
                  <span>Threats: {selected.threat_count}</span>
                </div>
                {selected.llm_analysis && (
                  <div className="llm-box">
                    <h4>AI Analysis</h4>
                    <p>{selected.llm_analysis}</p>
                    {selected.llm_recommendation && <p><strong>Recommendation:</strong> {selected.llm_recommendation}</p>}
                  </div>
                )}
                <h4>Timeline</h4>
                <div className="timeline">
                  {timeline.map((t: any, i: number) => (
                    <div key={i} className="timeline-entry">
                      <span className="timeline-dot" />
                      <div>
                        <strong>{t.event_type}</strong> on {t.asset}
                        <p>{t.description}</p>
                        <small>{new Date(t.timestamp).toLocaleString()}</small>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            ) : <p className="empty">Select an incident to view details</p>}
          </div>
        </div>
      )}
    </div>
  )
}
