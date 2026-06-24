import React, { createContext, useContext, useEffect, useState } from 'react'
import { useMsal } from '@azure/msal-react'
import { DEV_MODE, loginRequest } from './msalConfig'

interface AuthUser {
  name: string
  email: string
  roles: string[]
  token: string | null
}

interface AuthContextValue {
  user: AuthUser | null
  loading: boolean
  login: () => Promise<void>
  logout: () => void
  hasRole: (...roles: string[]) => boolean
}

const AuthContext = createContext<AuthContextValue | null>(null)

const DEV_USER: AuthUser = {
  name: 'Dev Admin',
  email: 'dev@sentinel.local',
  roles: ['Sentinel.Admin', 'Sentinel.Analyst', 'Sentinel.ReadOnly'],
  token: null,
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const { instance, accounts } = useMsal()
  const [user, setUser] = useState<AuthUser | null>(DEV_MODE ? DEV_USER : null)
  const [loading, setLoading] = useState(!DEV_MODE)

  useEffect(() => {
    if (DEV_MODE) return
    if (accounts.length === 0) {
      setLoading(false)
      return
    }
    const account = accounts[0]
    instance
      .acquireTokenSilent({ ...loginRequest, account })
      .then((res) => {
        const claims = res.idTokenClaims as Record<string, unknown>
        setUser({
          name: account.name || account.username,
          email: account.username,
          roles: (claims?.roles as string[]) ?? [],
          token: res.accessToken,
        })
      })
      .catch(() => setUser(null))
      .finally(() => setLoading(false))
  }, [accounts, instance])

  const login = async () => {
    if (DEV_MODE) return
    const res = await instance.loginPopup(loginRequest)
    const claims = res.idTokenClaims as Record<string, unknown>
    setUser({
      name: res.account?.name || res.account?.username || '',
      email: res.account?.username || '',
      roles: (claims?.roles as string[]) ?? [],
      token: res.accessToken,
    })
  }

  const logout = () => {
    if (DEV_MODE) return
    instance.logoutPopup()
    setUser(null)
  }

  const hasRole = (...roles: string[]) =>
    DEV_MODE || roles.some((r) => user?.roles.includes(r))

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, hasRole }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be inside AuthProvider')
  return ctx
}
