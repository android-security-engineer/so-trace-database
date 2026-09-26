import { Typography } from 'antd'

const { Title, Paragraph } = Typography

const steps = [
  {
    num: '01',
    title: 'Capture a Trace',
    desc: 'Run the sotrace plugin alongside your analysis tool. Events are streamed directly to sotrace-server — no intermediate files.',
    code: `# Frida (dynamic instrumentation)
python plugins/sotrace-frida/sotrace-frida.py \\
  --server http://localhost:3000 -U -f com.target.app

# Or GDB, LLDB, DynamoRIO, IDA Pro, Ghidra... (20+ tools)`,
  },
  {
    num: '02',
    title: 'Query or Analyze',
    desc: 'Ask structured questions about the trace. 12 thread analysis dimensions, memory/register/call queries — all via HTTP.',
    code: `# Race condition detection
curl localhost:3000/api/v1/traces/1/analyze/threads/races

# What touched address 0x7fff1234?
curl "localhost:3000/api/v1/traces/1/memory/0x7fff1234"

# Reconstruct call stack at step 50000
curl localhost:3000/api/v1/traces/1/call-stack/50000`,
  },
  {
    num: '03',
    title: 'Let Your AI Analyze',
    desc: 'Connect Claude (or any MCP client) to sotrace-mcp. Your AI gets 45 tools to import traces, query data, and run analysis — fully autonomously.',
    code: `# In Claude Code or any MCP host:
sotrace-mcp --stdio

# Claude can now:
# - import_trace, detect_races, analyze_deadlocks
# - query_instructions, query_call_stack
# - workflow_security_audit (multi-step analysis)`,
  },
]

export default function QuickStart() {
  return (
    <section style={{ background: '#0f0f1a', padding: '96px 24px' }}>
      <div style={{ maxWidth: 860, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 64 }}>
          <Title level={2} style={{ color: '#ffffff', marginBottom: 12 }}>
            Quick Start
          </Title>
          <Paragraph style={{ color: '#64748b', fontSize: 17 }}>
            Up and running in three commands.
          </Paragraph>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          {steps.map(({ num, title, desc, code }) => (
            <div key={num} style={{
              display: 'flex',
              gap: 24,
              alignItems: 'flex-start',
            }}>
              <div style={{
                flexShrink: 0,
                width: 48,
                height: 48,
                borderRadius: 12,
                background: 'rgba(22, 119, 255, 0.15)',
                border: '1px solid rgba(22, 119, 255, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 13,
                fontWeight: 700,
                color: '#4096ff',
                fontFamily: 'monospace',
              }}>
                {num}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 17, fontWeight: 600, color: '#e2e8f0', marginBottom: 6 }}>{title}</div>
                <div style={{ fontSize: 14, color: '#64748b', marginBottom: 12 }}>{desc}</div>
                <pre style={{
                  margin: 0,
                  padding: '14px 18px',
                  background: '#0d1117',
                  border: '1px solid rgba(255,255,255,0.08)',
                  borderRadius: 10,
                  fontSize: 13,
                  color: '#94a3b8',
                  fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                  overflowX: 'auto',
                }}>{code}</pre>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
