import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { Input, Button, Space, Card, Typography, Descriptions } from 'antd'
import { SearchOutlined } from '@ant-design/icons'
import { traceApi } from '../api/client'
import type { MemoryValue } from '../types'

const { Title, Text } = Typography

export default function MemoryInspector() {
  const { id } = useParams<{ id: string }>()
  const traceId = Number(id)
  const [seq, setSeq] = useState('')
  const [address, setAddress] = useState('')
  const [memoryValue, setMemoryValue] = useState<MemoryValue | null>(null)
  const [loading, setLoading] = useState(false)

  const queryMemory = () => {
    if (!traceId || !seq || !address) return
    setLoading(true)
    traceApi.queryMemoryValue(traceId, Number(seq), address)
      .then((res) => setMemoryValue(res.data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  return (
    <div>
      <Title level={4}>内存检查器</Title>
      <Space style={{ marginBottom: 16 }}>
        <Input
          placeholder="时序号 (seq)"
          value={seq}
          onChange={(e) => setSeq(e.target.value)}
          style={{ width: 150 }}
        />
        <Input
          placeholder="地址 (hex, 如 0x7FF00010)"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          style={{ width: 250 }}
        />
        <Button icon={<SearchOutlined />} onClick={queryMemory} loading={loading}>查询</Button>
      </Space>

      {memoryValue && (
        <Card title="查询结果" style={{ marginTop: 16 }}>
          <Descriptions bordered size="small">
            <Descriptions.Item label="地址">0x{memoryValue.address.toString(16)}</Descriptions.Item>
            <Descriptions.Item label="大小">{memoryValue.size} bytes</Descriptions.Item>
          </Descriptions>
          <div style={{ marginTop: 16 }}>
            <Text strong>值 (Hex):</Text>
            <pre style={{ background: '#f5f5f5', padding: 12, marginTop: 8, borderRadius: 4 }}>
              {memoryValue.value.map((b: number) => b.toString(16).padStart(2, '0')).join(' ')}
            </pre>
          </div>
        </Card>
      )}
    </div>
  )
}
