import { Typography } from 'antd'

const { Title, Paragraph } = Typography

const groups = [
  {
    label: 'Dynamic Instrumentation',
    color: '#1677ff',
    tools: [
      { name: 'Frida', emoji: '🪝' },
      { name: 'GDB', emoji: '🐛' },
      { name: 'LLDB', emoji: '🔬' },
      { name: 'unidbg', emoji: '⚙️' },
      { name: 'Qiling', emoji: '🐉' },
    ],
  },
  {
    label: 'Binary Analysis',
    color: '#a855f7',
    tools: [
      { name: 'IDA Pro', emoji: '🔭' },
      { name: 'Ghidra', emoji: '👻' },
      { name: 'Binary Ninja', emoji: '🥷' },
      { name: 'radare2', emoji: '🔴' },
    ],
  },
  {
    label: 'Emulation & Symbolic',
    color: '#f97316',
    tools: [
      { name: 'DynamoRIO', emoji: '⚡' },
      { name: 'Intel Pin', emoji: '📌' },
      { name: 'QEMU', emoji: '🖥️' },
      { name: 'angr', emoji: '🕸️' },
      { name: 'Triton', emoji: '🔱' },
    ],
  },
  {
    label: 'Sanitizers & Profiling',
    color: '#52c41a',
    tools: [
      { name: 'Valgrind', emoji: '🧪' },
      { name: 'ThreadSanitizer', emoji: '🧵' },
      { name: 'strace', emoji: '📡' },
    ],
  },
]

export default function Integrations() {
  return (
    <section style={{ background: '#0a0a0f', padding: '96px 24px' }}>
      <div style={{ maxWidth: 1100, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 64 }}>
          <Title level={2} style={{ color: '#ffffff', marginBottom: 12 }}>
            20+ Trace Tool Integrations
          </Title>
          <Paragraph style={{ color: '#64748b', fontSize: 17 }}>
            Push-side plugins for every major Android reverse engineering tool in the ecosystem.
          </Paragraph>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: 24,
        }}>
          {groups.map(({ label, color, tools }) => (
            <div key={label} style={{
              background: '#0f0f1a',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: 16,
              padding: 24,
            }}>
              <div style={{
                fontSize: 12,
                fontWeight: 600,
                color: color,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                marginBottom: 16,
              }}>
                {label}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {tools.map(({ name, emoji }) => (
                  <div key={name} style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    fontSize: 15,
                    color: '#cbd5e1',
                  }}>
                    <span style={{ fontSize: 20 }}>{emoji}</span>
                    {name}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
