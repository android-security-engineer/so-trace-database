import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Tabs, Table, Input, Button, Space, Typography, Card } from 'antd'
import { SearchOutlined, HddOutlined, ThunderboltOutlined } from '@ant-design/icons'
import { traceApi } from '../api/client'
import type { InstructionTrace, StackFrame } from '../types'

const { Title } = Typography

export default function TraceViewer() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const traceId = Number(id)
  const [instructions, setInstructions] = useState<InstructionTrace[]>([])
  const [callStack, setCallStack] = useState<StackFrame[]>([])
  const [loading, setLoading] = useState(false)
  const [addressQuery, setAddressQuery] = useState('')
  const [seqQuery, setSeqQuery] = useState('')

  const queryInstructions = () => {
    if (!traceId) return
    setLoading(true)
    const params: Record<string, string> = {}
    if (addressQuery) params.address = addressQuery
    traceApi.queryInstructions(traceId, params)
      .then((res) => setInstructions(res.data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  const queryCallStack = () => {
    if (!traceId || !seqQuery) return
    setLoading(true)
    traceApi.rebuildCallStack(traceId, Number(seqQuery))
      .then((res) => setCallStack(res.data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  const instrColumns = [
    { title: 'Seq', dataIndex: 'seq', key: 'seq', width: 80 },
    { title: 'Thread', dataIndex: 'thread_id', key: 'thread_id', width: 60 },
    {
      title: 'Address', dataIndex: 'address', key: 'address', width: 120,
      render: (v: number) => `0x${v.toString(16)}`,
    },
    { title: 'Branch', dataIndex: 'is_branch', key: 'is_branch', width: 60, render: (v: boolean) => v ? '✓' : '' },
    { title: 'Taken', dataIndex: 'branch_taken', key: 'branch_taken', width: 60, render: (v: boolean) => v ? '✓' : '' },
  ]

  const stackColumns = [
    { title: 'Depth', dataIndex: 'depth', key: 'depth', width: 60 },
    { title: 'Function', dataIndex: 'func_name', key: 'func_name' },
    { title: 'Entry', dataIndex: 'entry_address', key: 'entry_address', render: (v: number) => `0x${v.toString(16)}` },
    { title: 'Call Site', dataIndex: 'call_site', key: 'call_site', render: (v: number) => `0x${v.toString(16)}` },
  ]

  return (
    <div>
      <Title level={4}>Trace 分析 #{traceId}</Title>
      <Tabs items={[
        {
          key: 'instructions',
          label: '指令 Trace',
          children: (
            <div>
              <Space style={{ marginBottom: 16 }}>
                <Input
                  placeholder="地址 (hex)"
                  value={addressQuery}
                  onChange={(e) => setAddressQuery(e.target.value)}
                  style={{ width: 200 }}
                />
                <Button icon={<SearchOutlined />} onClick={queryInstructions} loading={loading}>查询</Button>
              </Space>
              <Table columns={instrColumns} dataSource={instructions} rowKey="seq" size="small" />
            </div>
          ),
        },
        {
          key: 'call-chain',
          label: '调用链',
          children: (
            <div>
              <Space style={{ marginBottom: 16 }}>
                <Input
                  placeholder="时序号 (seq)"
                  value={seqQuery}
                  onChange={(e) => setSeqQuery(e.target.value)}
                  style={{ width: 200 }}
                />
                <Button icon={<SearchOutlined />} onClick={queryCallStack} loading={loading}>重建调用栈</Button>
              </Space>
              <Table columns={stackColumns} dataSource={callStack} rowKey="depth" size="small" />
            </div>
          ),
        },
        {
          key: 'memory',
          label: '内存',
          children: (
            <Card>
              <Button icon={<HddOutlined />} onClick={() => window.location.href = `/traces/${traceId}/memory`}>
                打开内存检查器
              </Button>
            </Card>
          ),
        },
        {
          key: 'threads',
          label: '线程分析',
          children: (
            <Card>
              <Button
                icon={<ThunderboltOutlined />}
                onClick={() => navigate(`/traces/${traceId}/threads`)}
              >
                打开线程分析
              </Button>
            </Card>
          ),
        },
      ]} />
    </div>
  )
}
