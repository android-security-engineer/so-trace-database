import { useEffect, useState } from 'react'
import { Badge, Tooltip } from 'antd'
import { RobotOutlined } from '@ant-design/icons'

interface Props {
  lastCommandId: number
}

export default function AiControlIndicator({ lastCommandId }: Props) {
  const [visible, setVisible] = useState(false)
  const [fadeOut, setFadeOut] = useState(false)

  useEffect(() => {
    if (lastCommandId === 0) return

    setVisible(true)
    setFadeOut(false)

    const hide = setTimeout(() => {
      setFadeOut(true)
      setTimeout(() => setVisible(false), 600)
    }, 3000)

    return () => clearTimeout(hide)
  }, [lastCommandId])

  if (!visible) return null

  return (
    <Tooltip title="AI is navigating the UI" placement="left">
      <div
        style={{
          position: 'fixed',
          bottom: 24,
          right: 24,
          zIndex: 9999,
          background: 'rgba(22, 119, 255, 0.15)',
          border: '1px solid rgba(22, 119, 255, 0.4)',
          borderRadius: 12,
          padding: '8px 14px',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          backdropFilter: 'blur(8px)',
          boxShadow: '0 4px 20px rgba(22, 119, 255, 0.2)',
          opacity: fadeOut ? 0 : 1,
          transition: 'opacity 0.6s ease',
          pointerEvents: 'none',
        }}
      >
        <Badge status="processing" color="#1677ff" />
        <RobotOutlined style={{ color: '#4096ff', fontSize: 14 }} />
        <span style={{ fontSize: 12, color: '#60a5fa', fontWeight: 500 }}>
          AI Control
        </span>
      </div>
    </Tooltip>
  )
}
