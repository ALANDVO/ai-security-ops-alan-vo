import React, { useState, useEffect } from 'react'
import { api } from '../api/client'

export default function Scores() {
  const [scores, setScores] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.scores().then(setScores).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const riskColor = (r: string) => ({ critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' })[r] || '#6b7280'

  return (
    <div className="scores-page">
      <h2>Asset Risk Scores</h2>
      {loading ? <div className="loading">Loading…</div> : (
        <div className="scores-grid">
          {scores.map((s: any) => (
            <div key={s.asset} className="score-card">
              <div className="score-header">
                <span className="score-asset">{s.asset}</span>
                <span className={`badge badge-${s.risk_level}`}>{s.risk_level}</span>
              </div>
              <div className="score-bar">
                <div className="score-fill" style={{ width: `${s.score}%`, background: riskColor(s.risk_level) }} />
              </div>
              <span className="score-value">{s.score}</span>
              {s.factors?.length > 0 && (
                <div className="score-factors">
                  {s.factors.map((f: string) => <span key={f} className="factor-tag">{f}</span>)}
                </div>
              )}
            </div>
          ))}
          {scores.length === 0 && <p className="empty">No asset scores yet</p>}
        </div>
      )}
    </div>
  )
}
