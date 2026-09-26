import { Typography } from 'antd'
import { CheckOutlined, CloseOutlined } from '@ant-design/icons'

const { Title } = Typography

const rows = [
  { feature: 'Compression', raw: false, db: false, sotrace: true, detail: '10x+ via delta encoding' },
  { feature: 'Address → Symbol', raw: false, db: false, sotrace: true, detail: 'ELF parsing + symbol linkage' },
  { feature: 'Structured Query API', raw: false, db: 'partial' as const, sotrace: true, detail: 'REST + MCP + CLI' },
  { feature: 'Multi-tool import', raw: false, db: false, sotrace: true, detail: '20+ adapters' },
  { feature: 'Thread analysis', raw: false, db: false, sotrace: true, detail: '12 dimensions' },
  { feature: 'AI / MCP integration', raw: false, db: false, sotrace: true, detail: '45 MCP tools' },
  { feature: 'JNI boundary detection', raw: false, db: false, sotrace: true, detail: 'Native-aware' },
  { feature: 'Zero-copy storage', raw: false, db: false, sotrace: true, detail: 'mmap + WAL' },
]

type CellValue = boolean | 'partial'

function Cell({ val, detail }: { val: CellValue; detail?: string }) {
  if (val === true) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
        <CheckOutlined style={{ color: '#4ade80', fontSize: 18 }} />
        {detail && <span style={{ fontSize: 11, color: '#4ade80', textAlign: 'center' }}>{detail}</span>}
      </div>
    )
  }
  if (val === 'partial') {
    return <div style={{ color: '#fbbf24', fontSize: 13 }}>Partial</div>
  }
  return <CloseOutlined style={{ color: '#ef4444', fontSize: 16 }} />
}

export default function Comparison() {
  return (
    <section style={{ background: '#0f0f1a', padding: '96px 24px' }}>
      <div style={{ maxWidth: 900, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 48 }}>
          <Title level={2} style={{ color: '#ffffff', marginBottom: 12 }}>
            SOTrace vs Alternatives
          </Title>
        </div>

        <div style={{
          border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: 16,
          overflow: 'hidden',
        }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
            <thead>
              <tr style={{ background: '#13131f' }}>
                <th style={{ padding: '16px 20px', textAlign: 'left', color: '#94a3b8', fontWeight: 500 }}>Capability</th>
                <th style={{ padding: '16px 20px', textAlign: 'center', color: '#94a3b8', fontWeight: 500 }}>Raw Log Files</th>
                <th style={{ padding: '16px 20px', textAlign: 'center', color: '#94a3b8', fontWeight: 500 }}>General DB</th>
                <th style={{ padding: '16px 20px', textAlign: 'center', color: '#60a5fa', fontWeight: 600 }}>SO Trace DB</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ feature, raw, db, sotrace, detail }, i) => (
                <tr
                  key={feature}
                  style={{
                    background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)',
                    borderTop: '1px solid rgba(255,255,255,0.06)',
                  }}
                >
                  <td style={{ padding: '14px 20px', color: '#e2e8f0' }}>{feature}</td>
                  <td style={{ padding: '14px 20px', textAlign: 'center' }}>
                    <Cell val={raw as CellValue} />
                  </td>
                  <td style={{ padding: '14px 20px', textAlign: 'center' }}>
                    <Cell val={db as CellValue} />
                  </td>
                  <td style={{ padding: '14px 20px', textAlign: 'center' }}>
                    <Cell val={sotrace as CellValue} detail={detail} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}
