import React from 'react'
import { useAuth } from '../auth/AuthContext'

export default function Login() {
  const { login } = useAuth()
  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo">🛡️</div>
        <h1>AI Security Ops Center</h1>
        <p className="login-sub">Enterprise Threat Intelligence &amp; Incident Management</p>
        <button className="btn-primary" onClick={login}>Sign in with SSO</button>
        <p className="login-footer">Powered by AI · Enterprise Edition</p>
      </div>
    </div>
  )
}
