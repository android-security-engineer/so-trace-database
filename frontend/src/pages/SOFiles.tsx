import { useEffect, useState } from 'react'
import { Table, Button, Upload, message, Typography, Tag } from 'antd'
import { UploadOutlined, ReloadOutlined } from '@ant-design/icons'
import { soFileApi } from '../api/client'
import type { SOFile } from '../types'

const { Title } = Typography

export default function SOFiles() {
  const [files, setFiles] = useState<SOFile[]>([])
  const [loading, setLoading] = useState(false)

  const fetchFiles = () => {
    setLoading(true)
    soFileApi.list()
      .then((res) => setFiles(res.data))
      .catch(() => message.error('获取 SO 文件列表失败'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { fetchFiles() }, [])

  const columns = [
    { title: 'ID', dataIndex: 'id', key: 'id' },
    { title: '路径', dataIndex: 'path', key: 'path' },
    {
      title: '架构', dataIndex: 'arch', key: 'arch',
      render: (arch: string) => <Tag color="blue">{arch}</Tag>,
    },
    {
      title: '大小', dataIndex: 'file_size', key: 'file_size',
      render: (size: number) => `${(size / 1024).toFixed(1)} KB`,
    },
    { title: 'MD5', dataIndex: 'md5', key: 'md5', ellipsis: true },
    {
      title: '基地址', dataIndex: 'loaded_base_address', key: 'base_addr',
      render: (addr: number) => `0x${addr.toString(16)}`,
    },
  ]

  return (
    <div>
      <Title level={4}>SO 文件管理</Title>
      <div style={{ marginBottom: 16, display: 'flex', gap: 8 }}>
        <Upload
          beforeUpload={async (file) => {
            const formData = new FormData()
            formData.append('file', file)
            try {
              await soFileApi.create(formData)
              message.success('导入成功')
              fetchFiles()
            } catch {
              message.error('导入失败')
            }
            return false
          }}
          showUploadList={false}
        >
          <Button icon={<UploadOutlined />}>导入 SO 文件</Button>
        </Upload>
        <Button icon={<ReloadOutlined />} onClick={fetchFiles}>刷新</Button>
      </div>
      <Table
        columns={columns}
        dataSource={files}
        rowKey="id"
        loading={loading}
        onRow={(record) => ({
          onClick: () => window.location.href = `/so-files/${record.id}`,
          style: { cursor: 'pointer' },
        })}
      />
    </div>
  )
}
