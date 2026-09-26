import { Typography } from 'antd'

const { Title, Paragraph } = Typography

const modes = [
  {
    icon: '📦',
    title: 'Embedded Library',
    subtitle: 'For Rust tools',
    color: '#f97316',
    code: `use sotrace_engine::TraceEngine;

let engine = TraceEngine::new(config)?;
engine.feed_events(events)?;
let races = engine.analyze_races(trace_id)?;`,
  },
  {
    icon: '🌐',
    title: 'HTTP API Server',
    subtitle: 'Language-agnostic REST',
    color: '#1677ff',
    code: `POST /api/v1/traces/import
GET  /api/v1/traces/:id/analyze/threads/races
GET  /api/v1/traces/:id/analyze/threads/deadlocks
GET  /api/v1/traces/:id/analyze/threads/scheduling`,
  },
  {
    icon: '🤖',
    title: 'MCP Server',
    subtitle: 'AI assistant integration',
    color: '#a855f7',
    code: `# Connect to Claude or any MCP client
sotrace-mcp --stdio

# Claude will see tools like:
# sotrace_analyze_races
# sotrace_detect_deadlocks`,
  },
]

export default function UsageModes() {
  return (
    <section style={{ background: '#0a0a0f', padding: '96px 24px' }}>
      <div style={{ maxWidth: 1100, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 64 }}>
          <Title level={2} style={{ color: '#ffffff', marginBottom: 12 }}>
            Three Ways to Use
          </Title>
          <Paragraph style={{ color: '#64748b', fontSize: 17 }}>
            Embed it, call it over HTTP, or let your AI assistant use it.
          </Paragraph>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          gap: 24,
        }}>
          {modes.map(({ icon, title, subtitle, color, code }) => (
            <div key={title} style={{
              background: '#0f0f1a',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: 16,
              overflow: 'hidden',
            }}>
              <div style={{ padding: '24px 24px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
                  <span style={{ fontSize: 28 }}>{icon}</span>
                  <div>
                    <div style={{ fontSize: 17, fontWeight: 600, color: '#e2e8f0' }}>{title}</div>
                    <div style={{ fontSize: 12, color: color }}>{subtitle}</div>
                  </div>
                </div>
              </div>
              <pre style={{
                margin: 0,
                padding: '20px 24px',
                background: '#0d1117',
                fontSize: 13,
                color: '#94a3b8',
                lineHeight: 1.8,
                overflowX: 'auto',
                fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
              }}>{code}</pre>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
