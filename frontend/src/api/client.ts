const BASE = ''

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = localStorage.getItem('token')
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...(options?.headers as Record<string, string> || {}) }
  if (token) headers['Authorization'] = `Bearer ${token}`
  const resp = await fetch(`${BASE}${path}`, { ...options, headers })
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}))
    throw new Error(body.detail || `HTTP ${resp.status}`)
  }
  return resp.json()
}

export const api = {
  me: () => request<any>('/api/auth/me'),
  health: () => request<any>('/api/health'),
  threats: (params: string) => request<any[]>(`/api/threats?${params}`),
  incidents: (params: string) => request<any[]>(`/api/incidents?${params}`),
  timeline: (id: string) => request<any[]>(`/api/incidents/${id}/timeline`),
  query: (q: string) => request<any>('/api/query', { method: 'POST', body: JSON.stringify({ query: q }) }),
  stats: () => request<any>('/api/stats'),
  scores: () => request<any[]>('/api/scores'),
}
