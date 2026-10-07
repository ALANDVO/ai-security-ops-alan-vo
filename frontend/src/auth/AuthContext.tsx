import React, { createContext, useContext, useState, useCallback } from 'react'
import { api } from '../api/client'

interface User { email: string; name: string; role: string }
interface AuthState {
  user: User | null
  loading: boolean
  login: () => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthState>({ user: null, loading: true, login: async () => {}, logout: () => {} })

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  const checkAuth = useCallback(async () => {
    const token = localStorage.getItem('token')
    if (!token) { setLoading(false); return }
    try {
      const me = await api.me()
      setUser(me)
    } catch {
      localStorage.removeItem('token')
    } finally {
      setLoading(false)
    }
  }, [])

  const login = useCallback(async () => {
    await window.location.assign('/api/auth/saml/login')
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem('token')
    setUser(null)
  }, [])

  React.useEffect(() => { checkAuth() }, [checkAuth])

  return <AuthContext.Provider value={{ user, loading, login, logout }}>{children}</AuthContext.Provider>
}

export const useAuth = () => useContext(AuthContext)
