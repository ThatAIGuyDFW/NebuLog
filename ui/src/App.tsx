import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MsalProvider } from '@azure/msal-react'
import { PublicClientApplication } from '@azure/msal-browser'
import { useEffect } from 'react'

import { msalConfig, DEV_MODE } from './auth/msalConfig'
import { AuthProvider, useAuth } from './auth/AuthContext'
import { setAuthToken } from './api/client'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Events } from './pages/Events'
import { EventDetail } from './pages/EventDetail'
import { Alerts } from './pages/Alerts'
import { AlertDetail } from './pages/AlertDetail'
import { Rules } from './pages/Rules'
import { Sources } from './pages/Sources'
import { Compliance } from './pages/Compliance'
import { Spinner } from './components/Spinner'

const msalInstance = new PublicClientApplication(msalConfig)
const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 30_000 },
  },
})

function TokenSync() {
  const { user } = useAuth()
  useEffect(() => {
    setAuthToken(user?.token ?? null)
  }, [user?.token])
  return null
}

function LoginGate({ children }: { children: React.ReactNode }) {
  const { user, loading, login } = useAuth()

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Spinner size="lg" />
      </div>
    )
  }

  if (!user && !DEV_MODE) {
    return (
      <div className="flex h-screen flex-col items-center justify-center gap-4">
        <h1 className="text-2xl font-bold text-gray-100">Sentinel SIEM</h1>
        <p className="text-gray-400 text-sm">Sign in with your organizational account</p>
        <button className="btn-primary px-6 py-2 text-base" onClick={login}>
          Sign in with Microsoft
        </button>
      </div>
    )
  }

  return <>{children}</>
}

export default function App() {
  return (
    <MsalProvider instance={msalInstance}>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <TokenSync />
          <LoginGate>
            <BrowserRouter>
              <Routes>
                <Route element={<Layout />}>
                  <Route index element={<Dashboard />} />
                  <Route path="events" element={<Events />} />
                  <Route path="events/:id" element={<EventDetail />} />
                  <Route path="alerts" element={<Alerts />} />
                  <Route path="alerts/:id" element={<AlertDetail />} />
                  <Route path="rules" element={<Rules />} />
                  <Route path="sources" element={<Sources />} />
                  <Route path="compliance" element={<Compliance />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Route>
              </Routes>
            </BrowserRouter>
          </LoginGate>
        </AuthProvider>
      </QueryClientProvider>
    </MsalProvider>
  )
}
