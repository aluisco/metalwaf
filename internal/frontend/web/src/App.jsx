import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { isLoggedIn } from './api.js'
import Layout from './components/Layout.jsx'
import Login from './pages/Login.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Sites from './pages/Sites.jsx'
import WAFRules from './pages/WAFRules.jsx'
import Certificates from './pages/Certificates.jsx'
import Analytics from './pages/Analytics.jsx'
import Settings from './pages/Settings.jsx'
import Users from './pages/Users.jsx'
import Profile from './pages/Profile.jsx'
import IPLists from './pages/IPLists.jsx'

function RequireAuth({ children }) {
  const location = useLocation()
  if (!isLoggedIn()) return <Navigate to="/login" state={{ from: location }} replace />
  return children
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<RequireAuth><Layout /></RequireAuth>}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard"    element={<Dashboard />} />
        <Route path="sites"        element={<Sites />} />
        <Route path="rules"        element={<WAFRules />} />
        <Route path="certificates" element={<Certificates />} />
        <Route path="analytics"    element={<Analytics />} />
        <Route path="ip-lists"     element={<IPLists />} />
        <Route path="users"        element={<Users />} />
        <Route path="profile"      element={<Profile />} />
        <Route path="settings"     element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
