import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './auth/AuthContext'
import Header from './components/Header'
import Sidebar from './components/Sidebar'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Incidents from './pages/Incidents'
import QueryPage from './pages/Query'
import Scores from './pages/Scores'

function ProtectedLayout({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) return <div className="loading">Loading…</div>
  if (!user) return <Navigate to="/login" replace />
  return (
    <div className="app-shell">
      <Header />
      <div className="app-body">
        <Sidebar />
        <main className="main-content">{children}</main>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<ProtectedLayout><Dashboard /></ProtectedLayout>} />
      <Route path="/incidents" element={<ProtectedLayout><Incidents /></ProtectedLayout>} />
      <Route path="/query" element={<ProtectedLayout><QueryPage /></ProtectedLayout>} />
      <Route path="/scores" element={<ProtectedLayout><Scores /></ProtectedLayout>} />
    </Routes>
  )
}
