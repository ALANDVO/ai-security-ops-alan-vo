import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import React from 'react'
import { BrowserRouter } from 'react-router-dom'

// ── Mock API client ───────────────────────────────────────────────────────────

vi.mock('../api/client', () => ({
  api: {
    stats: vi.fn(),
    threats: vi.fn(),
    incidents: vi.fn(),
    timeline: vi.fn(),
    query: vi.fn(),
    scores: vi.fn(),
    me: vi.fn(),
  },
}))

// ── Mock AuthContext ──────────────────────────────────────────────────────────

vi.mock('../auth/AuthContext', () => ({
  useAuth: () => ({
    user: { email: 'test@example.com', name: 'Test User', role: 'analyst' },
    loading: false,
    login: vi.fn(),
    logout: vi.fn(),
  }),
  AuthProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))

import { api } from '../api/client'
import Dashboard from '../pages/Dashboard'
import Incidents from '../pages/Incidents'
import Scores from '../pages/Scores'

const mockStats = {
  total_threats: 42,
  by_severity: { critical: 5, high: 12, medium: 18, low: 7 },
  by_type: { intrusion: 15, malware: 10, phishing: 8, exfiltration: 9 },
  active_incidents: 3,
  avg_response_time_ms: 42.5,
  top_assets: ['web-01', 'db-01'],
  threat_trend_24h: [{ hour: 1, count: 3 }],
}

const mockThreats = [
  {
    id: 'threat-abc123',
    source: 'siem',
    event_type: 'intrusion',
    asset: 'web-01',
    severity: 'critical',
    confidence: 0.9,
    score: 95,
    raw_data: {},
    detected_at: '2026-01-01T12:00:00Z',
    correlated_incident: 'inc-001',
  },
]

const mockIncidents = [
  {
    id: 'inc-001',
    title: 'Intrusion on web-01',
    severity: 'critical',
    status: 'open',
    description: 'Detected intrusion',
    threat_count: 1,
    created_at: '2026-01-01T12:00:00Z',
    updated_at: '2026-01-01T12:05:00Z',
    llm_analysis: null,
    llm_recommendation: null,
  },
]

const mockScores = [
  { asset: 'web-01', score: 85, risk_level: 'critical', factors: ['intrusion'], last_assessed: '2026-01-01T12:00:00Z' },
]

function wrap(element: React.ReactElement) {
  return render(<BrowserRouter>{element}</BrowserRouter>)
}

// ── Dashboard Tests ───────────────────────────────────────────────────────────

describe('Dashboard', () => {
  beforeEach(() => {
    vi.mocked(api.stats).mockResolvedValue(mockStats)
    vi.mocked(api.threats).mockResolvedValue(mockThreats)
  })

  it('renders total threats count from API', async () => {
    wrap(<Dashboard />)
    await waitFor(() => expect(screen.getByText('42')).toBeInTheDocument())
  })

  it('renders threat rows in the table', async () => {
    wrap(<Dashboard />)
    await waitFor(() => expect(screen.getByText('threat-abc123')).toBeInTheDocument())
  })

  it('renders severity badge for critical threat', async () => {
    wrap(<Dashboard />)
    await waitFor(() => expect(screen.getByText('critical')).toBeInTheDocument())
  })

  it('shows loading state initially', () => {
    vi.mocked(api.stats).mockReturnValue(new Promise(() => {}))
    vi.mocked(api.threats).mockReturnValue(new Promise(() => {}))
    wrap(<Dashboard />)
    expect(screen.getByText(/loading/i)).toBeInTheDocument()
  })

  it('shows error state on API failure', async () => {
    vi.mocked(api.stats).mockRejectedValue(new Error('Network error'))
    vi.mocked(api.threats).mockRejectedValue(new Error('Network error'))
    wrap(<Dashboard />)
    await waitFor(() => expect(screen.getByText(/network error/i)).toBeInTheDocument())
  })

  it('renders active incidents count', async () => {
    wrap(<Dashboard />)
    await waitFor(() => expect(screen.getByText('3')).toBeInTheDocument())
  })
})

// ── Incidents Tests ───────────────────────────────────────────────────────────

describe('Incidents', () => {
  beforeEach(() => {
    vi.mocked(api.incidents).mockResolvedValue(mockIncidents)
    vi.mocked(api.timeline).mockResolvedValue([])
  })

  it('renders incident list', async () => {
    wrap(<Incidents />)
    await waitFor(() => expect(screen.getByText('Intrusion on web-01')).toBeInTheDocument())
  })

  it('shows empty state when no incidents', async () => {
    vi.mocked(api.incidents).mockResolvedValue([])
    wrap(<Incidents />)
    await waitFor(() => expect(screen.getByText(/no incidents/i)).toBeInTheDocument())
  })

  it('shows detail pane prompt when nothing selected', async () => {
    wrap(<Incidents />)
    await waitFor(() => expect(screen.getByText(/select an incident/i)).toBeInTheDocument())
  })
})

// ── Scores Tests ──────────────────────────────────────────────────────────────

describe('Scores', () => {
  beforeEach(() => {
    vi.mocked(api.scores).mockResolvedValue(mockScores)
  })

  it('renders asset name', async () => {
    wrap(<Scores />)
    await waitFor(() => expect(screen.getByText('web-01')).toBeInTheDocument())
  })

  it('renders risk level badge', async () => {
    wrap(<Scores />)
    await waitFor(() => expect(screen.getByText('critical')).toBeInTheDocument())
  })

  it('shows empty state when no scores', async () => {
    vi.mocked(api.scores).mockResolvedValue([])
    wrap(<Scores />)
    await waitFor(() => expect(screen.getByText(/no asset scores/i)).toBeInTheDocument())
  })
})
