import React, { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'

const SEV_COLORS: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null)
  const [threats, setThreats] = useState<any[]>([])
  const [sev, setSev] = useState('')
  const [asset, setAsset] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const params = new URLSearchParams()
      if (sev) params.set('severity', sev)
      if (asset) params.set('asset', asset)
      const [s, t] = await Promise.all([api.stats(), api.threats(params.toString())])
      setStats(s); setThreats(t)
    } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
  }, [sev, asset])

  useEffect(() => { load() }, [load])

  const sevData = stats ? Object.entries(stats.by_severity || {}).map(([k, v]) => ({ name: k, value: v })) : []
  const typeData = stats ? Object.entries(stats.by_type || {}).map(([k, v]) => ({ name: k, value: v })) : []

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h2>Security Dashboard</h2>
        <div className="filter-bar">
          <select value={sev} onChange={e => setSev(e.target.value)}>
            <option value="">All Severities</option>
            <option value="critical">Critical</option><option value="high">High</option>
            <option value="medium">Medium</option><option value="low">Low</option>
          </select>
          <input placeholder="Filter by asset…" value={asset} onChange={e => setAsset(e.target.value)} />
          <button className="btn-secondary" onClick={load}>Apply</button>
        </div>
      </div>
      {error && <div className="alert alert-error">{error}</div>}
      {loading ? <div className="loading">Loading…</div> : stats && (
        <>
          <div className="stats-grid">
            <div className="stat-card"><span className="stat-label">Total Threats</span><span className="stat-value">{stats.total_threats}</span></div>
            <div className="stat-card"><span className="stat-label">Active Incidents</span><span className="stat-value">{stats.active_incidents}</span></div>
            <div className="stat-card"><span className="stat-label">Top Asset</span><span className="stat-value">{stats.top_assets?.[0] || '—'}</span></div>
            <div className="stat-card"><span className="stat-label">24h Trend</span><span className="stat-value">{stats.threat_trend_24h?.filter((t: any) => t.count > 0).length || 0}h</span></div>
          </div>
          <div className="charts-row">
            <div className="chart-box">
              <h3>Threats by Type</h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={typeData}><XAxis dataKey="name" /><YAxis /><Tooltip /><Bar dataKey="value" fill="#3b82f6" /></BarChart>
              </ResponsiveContainer>
            </div>
            <div className="chart-box">
              <h3>By Severity</h3>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart><Pie data={sevData} dataKey="value" label>{sevData.map((d: any) => <Cell key={d.name} fill={SEV_COLORS[d.name] || '#6b7280'} />)}</Pie><Tooltip /></PieChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="table-section">
            <h3>Recent Threat Events</h3>
            <table className="data-table">
              <thead><tr><th>ID</th><th>Type</th><th>Asset</th><th>Severity</th><th>Score</th><th>Time</th></tr></thead>
              <tbody>
                {threats.map((t: any) => (
                  <tr key={t.id} className={t.severity === 'critical' ? 'row-critical' : ''}>
                    <td className="mono">{t.id}</td><td>{t.event_type}</td><td>{t.asset}</td>
                    <td><span className={`badge badge-${t.severity}`}>{t.severity}</span></td>
                    <td>{t.score}</td><td>{new Date(t.detected_at).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}
