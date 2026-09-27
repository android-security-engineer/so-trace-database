import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './auth/useAuth'
import { useUiCommandBus } from './hooks/useUiCommandBus'
import AiControlIndicator from './components/AiControlIndicator'
import MainLayout from './components/Layout'
import Login from './pages/Login'
import Setup from './pages/Setup'
import Dashboard from './pages/Dashboard'
import SOFiles from './pages/SOFiles'
import SOFileDetail from './pages/SOFileDetail'
import Traces from './pages/Traces'
import TraceViewer from './pages/TraceViewer'
import MemoryInspector from './pages/MemoryInspector'
import ThreadAnalysis from './pages/ThreadAnalysis'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isSetupRequired } = useAuth()

  if (isSetupRequired) {
    return <Navigate to="/setup" replace />
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

export default function App() {
  const { lastCommandId } = useUiCommandBus()
  return (
    <>
      <AiControlIndicator lastCommandId={lastCommandId} />
      <Routes>
        <Route path="/setup" element={<Setup />} />
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <MainLayout />
            </ProtectedRoute>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="so-files" element={<SOFiles />} />
          <Route path="so-files/:id" element={<SOFileDetail />} />
          <Route path="traces" element={<Traces />} />
          <Route path="traces/:id" element={<TraceViewer />} />
          <Route path="traces/:id/memory" element={<MemoryInspector />} />
          <Route path="traces/:id/threads" element={<ThreadAnalysis />} />
        </Route>
      </Routes>
    </>
  )
}

