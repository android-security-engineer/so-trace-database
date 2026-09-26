import { GithubOutlined } from '@ant-design/icons'

const GITHUB = 'https://github.com/android-security-engineer/so-trace-database'

export default function Footer() {
  return (
    <footer style={{
      background: '#070710',
      borderTop: '1px solid rgba(255,255,255,0.06)',
      padding: '40px 24px',
      textAlign: 'center',
    }}>
      <div style={{ maxWidth: 1100, margin: '0 auto' }}>
        <a
          href={GITHUB}
          target="_blank"
          rel="noopener noreferrer"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            fontSize: 15,
            color: '#64748b',
            textDecoration: 'none',
            marginBottom: 16,
            transition: 'color 0.2s',
          }}
          onMouseEnter={e => (e.currentTarget.style.color = '#94a3b8')}
          onMouseLeave={e => (e.currentTarget.style.color = '#64748b')}
        >
          <GithubOutlined style={{ fontSize: 20 }} />
          android-security-engineer/so-trace-database
        </a>
        <div style={{ fontSize: 13, color: '#334155' }}>
          © {new Date().getFullYear()} SO Trace Database. MIT License.
        </div>
      </div>
    </footer>
  )
}
