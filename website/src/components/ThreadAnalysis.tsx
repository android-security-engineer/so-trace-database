import { Tag, Typography } from 'antd'

const { Title, Paragraph } = Typography

const dimensions: { label: string; color: string }[] = [
  { label: 'Race Conditions', color: 'red' },
  { label: 'Deadlock Detection', color: 'volcano' },
  { label: 'Lock Contention', color: 'orange' },
  { label: 'Critical Sections', color: 'gold' },
  { label: 'JNI Boundary', color: 'lime' },
  { label: 'Thread Scheduling', color: 'green' },
  { label: 'Thread Lifecycle', color: 'cyan' },
  { label: 'Thread States', color: 'blue' },
  { label: 'Function Safety', color: 'geekblue' },
  { label: 'Function Association', color: 'purple' },
  { label: 'Data Flows', color: 'magenta' },
  { label: 'Producer-Consumer', color: 'processing' },
]

export default function ThreadAnalysis() {
  return (
    <section style={{ background: '#0f0f1a', padding: '96px 24px' }}>
      <div style={{ maxWidth: 900, margin: '0 auto', textAlign: 'center' }}>
        <Title level={2} style={{ color: '#ffffff', marginBottom: 12 }}>
          12-Dimension Thread Analysis
        </Title>
        <Paragraph style={{ color: '#64748b', fontSize: 17, marginBottom: 48 }}>
          Feed your trace once. Query any dimension instantly via HTTP or MCP.
          Every analysis is backed by indexed incremental storage — no full scan required.
        </Paragraph>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, justifyContent: 'center', marginBottom: 48 }}>
          {dimensions.map(({ label, color }) => (
            <Tag
              key={label}
              color={color}
              style={{
                fontSize: 14,
                padding: '6px 16px',
                borderRadius: 20,
                cursor: 'default',
              }}
            >
              {label}
            </Tag>
          ))}
        </div>

        <div style={{
          background: '#13131f',
          border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: 16,
          overflow: 'hidden',
          textAlign: 'left',
        }}>
          <div style={{
            padding: '12px 20px',
            background: '#0d1117',
            borderBottom: '1px solid rgba(255,255,255,0.06)',
            fontSize: 12,
            color: '#475569',
            fontFamily: 'monospace',
          }}>
            Example: Race Condition Detection
          </div>
          <pre style={{
            margin: 0,
            padding: '20px',
            fontSize: 13,
            color: '#94a3b8',
            lineHeight: 1.8,
            fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
            overflowX: 'auto',
          }}>{`GET /api/v1/traces/42/analyze/threads/races

{
  "races": [
    {
      "address": "0x1a3f0",
      "thread_a": 1, "thread_b": 3,
      "overlap_size": 4,
      "first_access_size": 4,
      "second_access_size": 4
    }
  ]
}`}</pre>
        </div>
      </div>
    </section>
  )
}
