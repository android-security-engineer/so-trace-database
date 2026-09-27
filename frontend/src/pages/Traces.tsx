import { useEffect, useState } from 'react'
import { Table, Button, Upload, message, Typography } from 'antd'
import { UploadOutlined } from '@ant-design/icons'
import { traceApi } from '../api/client'
import type { TraceSession } from '../types'

const { Title } = Typography

export default function Traces() {
  const [traces, setTraces] = useState<TraceSession[]>([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setLoading(true)
    traceApi.list()
      .then((res) => setTraces(res.data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const columns = [
    { title: 'ID', dataIndex: 'id', key: 'id' },
    { title: 'SO 文件', dataIndex: 'so_file_name', key: 'so_file_name' },
    {
      title: '指令数', dataIndex: 'instruction_count', key: 'instruction_count',
      render: (v: number) => v.toLocaleString(),
    },
    {
      title: '调用数', dataIndex: 'call_count', key: 'call_count',
      render: (v: number) => v.toLocaleString(),
    },
    {
      title: '内存 Delta', dataIndex: 'memory_delta_count', key: 'memory_delta_count',
      render: (v: number) => v.toLocaleString(),
    },
    {
      title: '创建时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: number) => new Date(v * 1000).toLocaleString(),
    },
  ]

  return (
    <div>
      <Title level={4}>Trace 会话</Title>
      <div style={{ marginBottom: 16 }}>
        <Upload
          beforeUpload={async (file) => {
            const formData = new FormData()
            formData.append('file', file)
            try {
              await traceApi.import(formData)
              message.success('导入成功')
            } catch {
              message.error('导入失败')
            }
            return false
          }}
          showUploadList={false}
        >
          <Button icon={<UploadOutlined />}>导入 Trace</Button>
        </Upload>
      </div>
      <Table
        columns={columns}
        dataSource={traces}
        rowKey="id"
        loading={loading}
        onRow={(record) => ({
          onClick: () => window.location.href = `/traces/${record.id}`,
          style: { cursor: 'pointer' },
        })}
      />
    </div>
  )
}
