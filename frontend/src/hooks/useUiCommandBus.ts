import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'

interface UiCommand {
  id: number
  command: string
  params: Record<string, unknown>
}

const API_BASE = '/api/v1'

export function reportUiState(
  page: string,
  traceId?: number,
  tab?: string,
  lastAckedCommandId?: number,
): void {
  fetch(`${API_BASE}/ui/state`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      page,
      trace_id: traceId ?? null,
      tab: tab ?? null,
      updated_at: Date.now(),
      last_acked_command_id: lastAckedCommandId ?? 0,
    }),
  }).catch(() => {})
}

export function useUiCommandBus(): { lastCommandId: number } {
  const navigate = useNavigate()
  const esRef = useRef<EventSource | null>(null)
  const [lastCommandId, setLastCommandId] = useState(0)

  useEffect(() => {
    const es = new EventSource(`${API_BASE}/ui/events`)
    esRef.current = es

    es.addEventListener('command', (e: MessageEvent) => {
      try {
        const cmd = JSON.parse(e.data as string) as UiCommand
        setLastCommandId(cmd.id)
        handleCommand(cmd, navigate)
        // ACK: report the executed command ID back to the server
        reportUiState(window.location.pathname.replace(/^\//, '') || 'dashboard', undefined, undefined, cmd.id)
      } catch {
        // ignore malformed events
      }
    })

    es.onerror = () => {
      // SSE reconnects automatically
    }

    return () => {
      es.close()
      esRef.current = null
    }
  }, [navigate])

  return { lastCommandId }
}

type NavigateFn = ReturnType<typeof useNavigate>

function handleCommand(cmd: UiCommand, navigate: NavigateFn): void {
  switch (cmd.command) {
    case 'navigate': {
      const page = String(cmd.params.page ?? 'dashboard')
      const traceId = cmd.params.trace_id as number | undefined
      const tab = cmd.params.tab as string | undefined

      let route: string
      if (page === 'thread-analysis' && traceId != null) {
        route = `/traces/${traceId}/threads`
      } else if (page === 'trace-viewer' && traceId != null) {
        route = `/traces/${traceId}`
      } else if (page === 'memory-inspector' && traceId != null) {
        route = `/traces/${traceId}/memory`
      } else {
        const PAGE_ROUTES: Record<string, string> = {
          dashboard: '/dashboard',
          traces: '/traces',
          'so-files': '/so-files',
        }
        route = PAGE_ROUTES[page] ?? '/dashboard'
      }

      const searchParams = new URLSearchParams()
      if (tab != null) searchParams.set('tab', tab)
      const search = searchParams.toString()
      navigate(route + (search ? `?${search}` : ''))
      break
    }

    case 'select_trace': {
      const traceId = cmd.params.trace_id as number | undefined
      if (traceId != null) {
        navigate(`/traces?selected=${traceId}`)
      }
      break
    }

    case 'switch_tab': {
      const tab = cmd.params.tab as string | undefined
      if (tab != null) {
        const url = new URL(window.location.href)
        url.searchParams.set('tab', tab)
        navigate(url.pathname + url.search)
      }
      break
    }

    case 'refresh':
      window.location.reload()
      break

    case 'close_modal':
      window.dispatchEvent(new CustomEvent('sotrace:close-modal'))
      break

    default:
      break
  }
}
