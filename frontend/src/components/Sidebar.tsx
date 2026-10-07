import React from 'react'
import { NavLink } from 'react-router-dom'

const links = [
  { to: '/', label: 'Dashboard', icon: '📊' },
  { to: '/incidents', label: 'Incidents', icon: '🔥' },
  { to: '/query', label: 'AI Query', icon: '🤖' },
  { to: '/scores', label: 'Risk Scores', icon: '📈' },
]

export default function Sidebar() {
  return (
    <nav className="sidebar">
      {links.map(l => (
        <NavLink key={l.to} to={l.to} end={l.to === '/'}
          className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}>
          <span className="sidebar-icon">{l.icon}</span>
          <span>{l.label}</span>
        </NavLink>
      ))}
    </nav>
  )
}
