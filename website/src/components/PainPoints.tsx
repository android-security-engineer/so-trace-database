import { useState, useEffect } from 'react'
import { Typography } from 'antd'

const { Title, Paragraph } = Typography

const pains = [
  {
    num: '01',
    title: 'Trace Files Are Massive',
    problem: 'One hour of Frida Stalker instruction-level trace produces 2GB+ of raw text. No tool compresses it; analysts run out of disk before they can analyze anything.',
    solve: 'NumericDelta encoding reduces sequential address diffs to 1–2 bytes. Bitmask encoding for register deltas. 10x+ compression on real traces.',
  },
  {
    num: '02',
    title: 'Querying Means Writing Scripts',
    problem: '"Which functions accessed address 0x7fff1234?" means grep-ing gigabytes of logs. Every question needs a new ad-hoc script. Analysis becomes a scripting project.',
    solve: 'SkipList + AddressIndex + FunctionIndex enable O(log N) lookups by address, function, call chain, or data flow — via a REST API, no scripting required.',
  },
  {
    num: '03',
    title: 'Addresses Disconnected from Symbols',
    problem: 'Raw trace contains virtual addresses. Symbol names, ELF sections, and IDA/Ghidra analysis live in separate tools. Manual cross-referencing wastes hours.',
    solve: 'Import your SO binary once. All trace addresses are automatically linked to function names, ELF segments, and JNI boundaries.',
  },
  {
    num: '04',
    title: 'Every Tool Has Its Own Format',
    problem: 'Frida outputs JS objects, DynamoRIO outputs custom binary, strace outputs text. Combining data from multiple tools is nearly impossible without custom parsers.',
    solve: '20+ push-side plugins normalize events to a single import schema. Cross-tool trace analysis becomes a single API call.',
  },
]

function useNarrow(breakpoint = 768) {
  const [narrow, setNarrow] = useState(
    typeof window !== 'undefined' ? window.innerWidth < breakpoint : false
  )
  useEffect(() => {
    const check = () => setNarrow(window.innerWidth < breakpoint)
    window.addEventListener('resize', check)
    return () => window.removeEventListener('resize', check)
  }, [breakpoint])
  return narrow
}

export default function PainPoints() {
  const narrow = useNarrow()

  return (
    <section style={{ background: '#0a0a0f', padding: '96px 24px' }}>
      <div style={{ maxWidth: 1100, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 64 }}>
          <Title level={2} style={{ color: '#ffffff', marginBottom: 12 }}>
            Why Another Tool?
          </Title>
          <Paragraph style={{ color: '#64748b', fontSize: 17, maxWidth: 580, margin: '0 auto' }}>
            Existing trace tools solve collection. Nobody solved storage and analysis.
          </Paragraph>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {pains.map(({ num, title, problem, solve }) => (
            <div
              key={num}
              style={{
                display: 'grid',
                gridTemplateColumns: narrow ? '1fr' : '48px 1fr 1fr',
                gap: 24,
                background: '#0f0f1a',
                border: '1px solid rgba(255,255,255,0.07)',
                borderRadius: 16,
                padding: narrow ? '24px 20px' : '28px 32px',
                alignItems: 'start',
              }}
            >
              <div style={{
                fontSize: 12,
                fontWeight: 700,
                color: 'rgba(239, 68, 68, 0.7)',
                fontFamily: 'monospace',
                paddingTop: narrow ? 0 : 4,
              }}>
                {num}
              </div>
              <div>
                <div style={{ fontSize: 16, fontWeight: 600, color: '#fca5a5', marginBottom: 8 }}>{title}</div>
                <div style={{ fontSize: 14, color: '#94a3b8', lineHeight: 1.7 }}>{problem}</div>
              </div>
              <div style={{
                background: 'rgba(22, 119, 255, 0.08)',
                border: '1px solid rgba(22, 119, 255, 0.2)',
                borderRadius: 10,
                padding: '16px 20px',
                marginTop: narrow ? 12 : 0,
              }}>
                <div style={{ fontSize: 12, color: '#60a5fa', fontWeight: 600, marginBottom: 6, letterSpacing: '0.05em' }}>
                  ✓ HOW WE SOLVE IT
                </div>
                <div style={{ fontSize: 14, color: '#93c5fd', lineHeight: 1.7 }}>{solve}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
