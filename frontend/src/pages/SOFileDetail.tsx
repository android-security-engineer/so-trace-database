import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { Descriptions, Table, Tabs, Typography, Tag } from 'antd'
import { soFileApi } from '../api/client'
import type { SOFile, SOFunction } from '../types'

const { Title } = Typography

export default function SOFileDetail() {
  const { id } = useParams<{ id: string }>()
  const [soFile, setSoFile] = useState<SOFile | null>(null)
  const [functions, setFunctions] = useState<SOFunction[]>([])

  useEffect(() => {
    if (id) {
      soFileApi.get(Number(id)).then((res) => setSoFile(res.data)).catch(() => {})
      soFileApi.getFunctions(Number(id)).then((res) => setFunctions(res.data)).catch(() => {})
    }
  }, [id])

  const funcColumns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '偏移', dataIndex: 'offset', key: 'offset', render: (v: number) => `0x${v.toString(16)}` },
    { title: '大小', dataIndex: 'size', key: 'size' },
    {
      title: '类型', key: 'type',
      render: (_: unknown, r: SOFunction) => (
        <>
          {r.is_jni && <Tag color="green">JNI</Tag>}
          {r.is_exported && <Tag color="blue">导出</Tag>}
          {r.is_imported && <Tag color="orange">导入</Tag>}
        </>
      ),
    },
  ]

  if (!soFile) return <div>加载中...</div>

  return (
    <div>
      <Title level={4}>{soFile.path}</Title>
      <Descriptions bordered size="small" style={{ marginBottom: 24 }}>
        <Descriptions.Item label="架构">{soFile.arch}</Descriptions.Item>
        <Descriptions.Item label="文件大小">{soFile.file_size} bytes</Descriptions.Item>
        <Descriptions.Item label="基地址">0x{soFile.loaded_base_address.toString(16)}</Descriptions.Item>
        <Descriptions.Item label="SHA-256" span={3}>{soFile.sha256}</Descriptions.Item>
      </Descriptions>
      <Tabs items={[
        { key: 'functions', label: '函数列表', children: <Table columns={funcColumns} dataSource={functions} rowKey="id" size="small" /> },
      ]} />
    </div>
  )
}
