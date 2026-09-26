import { Typography } from 'antd'

const { Title, Paragraph } = Typography

const features = [
  {
    icon: '🗜️',
    title: '10x+ Storage Compression',
    desc: 'Sequential instruction addresses differ by just 4 bytes — NumericDelta encoding stores them in 1–2 bytes. Bitmask encoding for register deltas, page-granularity for memory. 2GB Frida trace → under 200MB.',
  },
  {
    icon: '⚡',
    title: 'Sub-millisecond Queries',
    desc: 'SkipList + AddressIndex + ThreadIndex + FunctionIndex enable O(log N) lookups. "All instructions accessing 0x7fff1234" returns instantly on million-instruction traces.',
  },
  {
    icon: '🔗',
    title: 'Binary Context Linkage',
    desc: 'Import your SO once. Every trace address is automatically linked to function names from the symbol table, ELF section info, and JNI boundary detection — no manual address-to-symbol mapping.',
  },
  {
    icon: '🔄',
    title: 'Universal Trace Import',
    desc: '20+ push-side plugins normalize traces from Frida, GDB, LLDB, DynamoRIO, Intel Pin, IDA Pro, Ghidra, angr, Qiling, Valgrind into one schema. Combine data from multiple tools seamlessly.',
  },
  {
    icon: '🧵',
    title: '12-Dimension Thread Analysis',
    desc: 'Race conditions, deadlocks, lock contention, critical sections, JNI boundary, scheduling, lifecycle, states, function safety, function association, data flows, producer-consumer — all via a single API.',
  },
  {
    icon: '🤖',
    title: 'Native MCP Integration',
    desc: '45 MCP tools let Claude and other AI assistants directly import traces, query data, and run all 12 analysis dimensions. Your AI assistant becomes a trace analysis engine.',
  },
]

export default function Features() {
  return (
    <section style={{
      background: '#0f0f1a',
      padding: '96px 24px',
    }}>
      <div style={{ maxWidth: 1100, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 64 }}>
          <Title level={2} style={{ color: '#ffffff', marginBottom: 12 }}>
            Why SOTrace?
          </Title>
          <Paragraph style={{ color: '#64748b', fontSize: 17, maxWidth: 580, margin: '0 auto' }}>
            Built specifically for the data patterns in execution traces — not a general-purpose database.
          </Paragraph>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          gap: 24,
        }}>
          {features.map(({ icon, title, desc }) => (
            <div key={title} style={{
              background: '#13131f',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: 16,
              padding: 28,
              transition: 'border-color 0.2s',
            }}>
              <div style={{ fontSize: 40, marginBottom: 16 }}>{icon}</div>
              <div style={{ fontSize: 18, fontWeight: 600, color: '#e2e8f0', marginBottom: 10 }}>{title}</div>
              <div style={{ fontSize: 14, color: '#64748b', lineHeight: 1.7 }}>{desc}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
