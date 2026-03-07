import { Suspense, lazy, useState, useEffect } from 'react'
import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { CSpinner } from '@coreui/react'
import { isLoggedIn, initializeAuth } from './api.js'

const DefaultLayout  = lazy(() => import('./layout/DefaultLayout.jsx'))
const Login          = lazy(() => import('./pages/Login.jsx'))
const Dashboard      = lazy(() => import('./pages/Dashboard.jsx'))
const Users          = lazy(() => import('./pages/Users.jsx'))
const Profile        = lazy(() => import('./pages/Profile.jsx'))
const Sites          = lazy(() => import('./pages/Sites.jsx'))
const WAFRules       = lazy(() => import('./pages/WAFRules.jsx'))
const IPLists        = lazy(() => import('./pages/IPLists.jsx'))
const Certificates   = lazy(() => import('./pages/Certificates.jsx'))
const Analytics      = lazy(() => import('./pages/Analytics.jsx'))
const Settings       = lazy(() => import('./pages/Settings.jsx'))

function RequireAuth({ children }) {
  const location = useLocation()
  if (!isLoggedIn()) return <Navigate to="/login" state={{ from: location }} replace />
  return children
}

const loading = (
  <div className="min-vh-100 d-flex align-items-center justify-content-center">
    <CSpinner color="primary" />
  </div>
)

export default function App() {
  const [authReady, setAuthReady] = useState(false)

  useEffect(() => {
    initializeAuth().finally(() => setAuthReady(true))
  }, [])

  if (!authReady) return loading

  return (
    <Suspense fallback={loading}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <DefaultLayout />
            </RequireAuth>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard"    element={<Dashboard />} />
          <Route path="users"        element={<Users />} />
          <Route path="users/:id"    element={<Profile />} />
          <Route path="sites"        element={<Sites />} />
          <Route path="rules"        element={<WAFRules />} />
          <Route path="ip-lists"     element={<IPLists />} />
          <Route path="certificates" element={<Certificates />} />
          <Route path="analytics"    element={<Analytics />} />
          <Route path="settings"     element={<Settings />} />
          <Route path="*"            element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </Suspense>
  )
}
