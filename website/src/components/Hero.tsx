import { Button, Space, Typography } from 'antd'
import { GithubOutlined, BookOutlined } from '@ant-design/icons'

const { Title, Paragraph } = Typography

const GITHUB = 'https://github.com/android-security-engineer/so-trace-database'

export default function Hero() {
  return (
    <section style={{
      background: 'linear-gradient(135deg, #0a0a0f 0%, #0d1117 50%, #0f172a 100%)',
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      textAlign: 'center',
      padding: '80px 24px',
      position: 'relative',
      overflow: 'hidden',
    }}>
      <div style={{
        position: 'absolute', inset: 0,
        backgroundImage: 'radial-gradient(circle at 25% 25%, rgba(22, 119, 255, 0.08) 0%, transparent 50%), radial-gradient(circle at 75% 75%, rgba(82, 196, 26, 0.05) 0%, transparent 50%)',
        pointerEvents: 'none',
      }} />

      <div style={{ maxWidth: 800, position: 'relative' }}>
        <div style={{
          display: 'inline-block',
          background: 'rgba(22, 119, 255, 0.15)',
          border: '1px solid rgba(22, 119, 255, 0.3)',
          borderRadius: 20,
          padding: '4px 16px',
          marginBottom: 24,
          fontSize: 13,
          color: '#4096ff',
          letterSpacing: '0.05em',
        }}>
          🛡️ Android SO Reverse Engineering
        </div>

        <Title level={1} style={{
          color: '#ffffff',
          fontSize: 'clamp(36px, 6vw, 64px)',
          fontWeight: 800,
          lineHeight: 1.1,
          marginBottom: 16,
          background: 'linear-gradient(135deg, #ffffff 30%, #60a5fa 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
        }}>
          SO Trace Database
        </Title>

        <Paragraph style={{
          fontSize: 'clamp(16px, 2.5vw, 20px)',
          color: '#94a3b8',
          maxWidth: 680,
          margin: '0 auto 24px',
          lineHeight: 1.7,
        }}>
          Android SO reverse engineers deal with gigabytes of raw trace logs, write
          ad-hoc scripts to find what they need, and manually cross-reference
          addresses with IDA symbols. SO Trace Database fixes this: a purpose-built
          database that stores, indexes, and analyzes execution traces from any tool
          in one place.
        </Paragraph>

        <Space size={16} wrap style={{ justifyContent: 'center' }}>
          <Button
            type="primary"
            size="large"
            icon={<GithubOutlined />}
            href={GITHUB}
            target="_blank"
            style={{ height: 48, paddingInline: 28, fontSize: 16 }}
          >
            Get Started
          </Button>
          <Button
            size="large"
            icon={<BookOutlined />}
            href={`${GITHUB}/tree/main/docs`}
            target="_blank"
            style={{
              height: 48, paddingInline: 28, fontSize: 16,
              background: 'rgba(255,255,255,0.05)',
              borderColor: 'rgba(255,255,255,0.15)',
              color: '#e2e8f0',
            }}
          >
            View Docs
          </Button>
        </Space>

        <div style={{
          display: 'flex',
          justifyContent: 'center',
          gap: 48,
          marginTop: 64,
          flexWrap: 'wrap',
        }}>
          {[
            { value: '10x+', label: 'Storage Compression' },
            { value: '20+',  label: 'Tool Integrations' },
            { value: '12',   label: 'Analysis Dimensions' },
            { value: '45',   label: 'MCP Tools' },
          ].map(({ value, label }) => (
            <div key={label} style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 32, fontWeight: 700, color: '#60a5fa' }}>{value}</div>
              <div style={{ fontSize: 13, color: '#64748b', marginTop: 4 }}>{label}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
