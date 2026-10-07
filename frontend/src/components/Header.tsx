import React from 'react'
import { useAuth } from '../auth/AuthContext'

export default function Header() {
  const { user, logout } = useAuth()
  return (
    <header className="app-header">
      <div className="header-brand">
        <span className="header-logo">🛡️</span>
        <h1>Security Ops Center</h1>
      </div>
      <div className="header-user">
        {user && (
          <>
            <span className="user-name">{user.name || user.email}</span>
            <span className="user-role">{user.role}</span>
          </>
        )}
        <button className="btn-ghost" onClick={logout}>Sign Out</button>
      </div>
    </header>
  )
}
