import { Routes, Route, Navigate } from 'react-router-dom'
import { lazy } from 'react'
import { ProtectedRoute } from './components/ProtectedRoute'
import { Layout } from './components/layout/Layout'
import { ADMIN_ROLES } from './lib/roles'
const Orders = lazy(() => import('./pages/Orders').then(m => ({ default: m.Orders })))
const Reports = lazy(() => import('./pages/Reports'))

const STAFF = ['clerk', ...ADMIN_ROLES]

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<div>Login</div>} />
      <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route index element={<Navigate to="/orders" replace />} />
        <Route path="orders" element={<ProtectedRoute requiredRoles={STAFF}><Orders /></ProtectedRoute>} />
        <Route path="reports" element={<ProtectedRoute requiredRoles={['manager']} requiredFeature="reports"><Reports /></ProtectedRoute>} />
      </Route>
    </Routes>
  )
}
