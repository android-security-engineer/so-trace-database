import { useEffect, useState } from 'react'
import { Card, Row, Col, Statistic, Typography } from 'antd'
import {
  DatabaseOutlined,
  FileOutlined,
  CodeOutlined,
  SwapOutlined,
  HddOutlined,
} from '@ant-design/icons'
import { statsApi } from '../api/client'
import type { Stats } from '../types'

const { Title } = Typography

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    statsApi.get()
      .then((res) => setStats(res.data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return (
    <div>
      <Title level={4}>仪表盘</Title>
      <Row gutter={[16, 16]}>
        <Col span={8}>
          <Card loading={loading}>
            <Statistic
              title="SO 文件数"
              value={stats?.so_file_count ?? 0}
              prefix={<FileOutlined />}
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card loading={loading}>
            <Statistic
              title="Trace 会话数"
              value={stats?.trace_count ?? 0}
              prefix={<DatabaseOutlined />}
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card loading={loading}>
            <Statistic
              title="指令总数"
              value={stats?.total_instructions ?? 0}
              prefix={<CodeOutlined />}
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card loading={loading}>
            <Statistic
              title="调用记录数"
              value={stats?.total_calls ?? 0}
              prefix={<SwapOutlined />}
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card loading={loading}>
            <Statistic
              title="内存 Delta 数"
              value={stats?.total_memory_deltas ?? 0}
              prefix={<HddOutlined />}
            />
          </Card>
        </Col>
        <Col span={8}>
          <Card loading={loading}>
            <Statistic
              title="数据库大小"
              value={stats?.database_size ?? 0}
              suffix="bytes"
              prefix={<DatabaseOutlined />}
            />
          </Card>
        </Col>
      </Row>
    </div>
  )
}
