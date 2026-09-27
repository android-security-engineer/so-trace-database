import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Card,
  Table,
  Tag,
  Tabs,
  Space,
  Statistic,
  Row,
  Col,
  Alert,
  Progress,
  Tooltip,
  Typography,
  Spin,
} from 'antd'
import {
  WarningOutlined,
  BugOutlined,
  LockOutlined,
  SwapOutlined,
  FunctionOutlined,
  SafetyOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import type {
  RaceCondition,
  DeadlockRisk,
  LockContentionInfo,
  ThreadFunctionAssoc,
  FunctionThreadSafety,
  ThreadDataFlow,
  ProducerConsumerPattern,
  ThreadInfo,
} from '../types'

const { Title, Text } = Typography

/** Mock data for development — will be replaced by API calls */
const MOCK_THREADS: ThreadInfo[] = [
  { thread_id: 1, parent_thread_id: 0, create_step: 0, name: 'main', stack_base: 0x7f000000, stack_size: 8388608, tls_addr: 0x7f008000, is_jni_attached: false },
  { thread_id: 2, parent_thread_id: 1, create_step: 5000, name: 'worker-1', stack_base: 0x7e000000, stack_size: 4194304, tls_addr: 0x7e040000, is_jni_attached: false },
  { thread_id: 3, parent_thread_id: 1, create_step: 8000, name: 'Java-AsyncTask', stack_base: 0x7d000000, stack_size: 4194304, tls_addr: 0x7d040000, is_jni_attached: true },
]

const MOCK_RACES: RaceCondition[] = [
  { address: 0x1000, first_step: 100, first_thread: 2, second_step: 150, second_thread: 3, first_is_write: true, second_is_write: false, confidence: 0.85, description: 'Thread 2 wrote to 0x1000 at step 100, then thread 3 read at step 150 without synchronization' },
  { address: 0x2000, first_step: 300, first_thread: 1, second_step: 350, second_thread: 2, first_is_write: true, second_is_write: true, confidence: 0.72, description: 'Thread 1 wrote to 0x2000 at step 300, then thread 2 wrote at step 350 without synchronization' },
]

const MOCK_DEADLOCKS: DeadlockRisk[] = [
  { lock_cycle: [0xabcd0000, 0xef010000], threads: [1, 2], violation_steps: [200, 250], description: 'Lock ordering cycle: 0xABCD0000 → 0xEF010000 (thread 1) vs 0xEF010000 → 0xABCD0000 (thread 2)' },
]

const MOCK_CONTENTIONS: LockContentionInfo[] = [
  { lock_address: 0xabcd0000, acquire_count: 120, contention_count: 45, contention_ratio: 0.375, total_wait_ns: 50000000, avg_wait_ns: 1111111, max_wait_ns: 8000000, contending_threads: [1, 2, 3] },
  { lock_address: 0xef010000, acquire_count: 80, contention_count: 10, contention_ratio: 0.125, total_wait_ns: 5000000, avg_wait_ns: 500000, max_wait_ns: 2000000, contending_threads: [1, 2] },
]

const MOCK_FUNC_ASSOCS: ThreadFunctionAssoc[] = [
  { thread_id: 1, function_address: 0x4000, call_count: 15, first_call_step: 100, last_call_step: 5000 },
  { thread_id: 2, function_address: 0x4000, call_count: 30, first_call_step: 5500, last_call_step: 9000 },
  { thread_id: 3, function_address: 0x4000, call_count: 8, first_call_step: 8000, last_call_step: 12000 },
  { thread_id: 2, function_address: 0x5000, call_count: 5, first_call_step: 6000, last_call_step: 8500 },
]

const MOCK_FUNC_SAFETY: FunctionThreadSafety[] = [
  { function_address: 0x4000, calling_thread_count: 3, calling_threads: [1, 2, 3], safety: 'Unsafe', race_count: 2, sync_event_count: 0 },
  { function_address: 0x5000, calling_thread_count: 1, calling_threads: [2], safety: 'Unknown', race_count: 0, sync_event_count: 0 },
  { function_address: 0x6000, calling_thread_count: 2, calling_threads: [1, 2], safety: 'ThreadSafe', race_count: 0, sync_event_count: 15 },
]

const MOCK_DATA_FLOWS: ThreadDataFlow[] = [
  { from_thread: 1, to_thread: 2, address: 0x3000, write_step: 50, read_step: 100, is_synchronized: false },
  { from_thread: 2, to_thread: 3, address: 0x5000, write_step: 200, read_step: 250, is_synchronized: true },
]

const MOCK_PROD_CONS: ProducerConsumerPattern[] = [
  { producer_thread: 1, consumer_thread: 2, shared_addresses: [0x5000, 0x5010], cycle_count: 25, avg_latency_steps: 100, sync_mechanism: 0xabcd0000 },
]

// ============================================================================
// Confidence color helper
// ============================================================================
function confidenceColor(confidence: number): string {
  if (confidence >= 0.8) return '#ff4d4f'
  if (confidence >= 0.5) return '#faad14'
  return '#52c41a'
}

function safetyColor(safety: string): string {
  switch (safety) {
    case 'Unsafe': return 'red'
    case 'PotentiallyUnsafe': return 'orange'
    case 'Unknown': return 'default'
    case 'ThreadSafe': return 'green'
    default: return 'default'
  }
}

// ============================================================================
// Column definitions
// ============================================================================
const raceColumns: ColumnsType<RaceCondition> = [
  {
    title: '地址',
    dataIndex: 'address',
    key: 'address',
    render: (addr: number) => <Text code>0x{addr.toString(16).toUpperCase()}</Text>,
    sorter: (a, b) => a.address - b.address,
  },
  {
    title: '步骤',
    key: 'steps',
    render: (_, r) => (
      <Space direction="vertical" size={0}>
        <Text type="secondary">T{r.first_thread}: step {r.first_step}</Text>
        <Text type="secondary">T{r.second_thread}: step {r.second_step}</Text>
      </Space>
    ),
  },
  {
    title: '操作',
    key: 'ops',
    render: (_, r) => (
      <Space>
        <Tag color={r.first_is_write ? 'red' : 'blue'}>{r.first_is_write ? '写' : '读'}</Tag>
        <Tag color={r.second_is_write ? 'red' : 'blue'}>{r.second_is_write ? '写' : '读'}</Tag>
      </Space>
    ),
  },
  {
    title: '置信度',
    dataIndex: 'confidence',
    key: 'confidence',
    render: (c: number) => (
      <Tooltip title={`${(c * 100).toFixed(0)}%`}>
        <Progress
          percent={Math.round(c * 100)}
          size="small"
          strokeColor={confidenceColor(c)}
          format={(p) => `${p}%`}
        />
      </Tooltip>
    ),
    sorter: (a, b) => a.confidence - b.confidence,
    defaultSortOrder: 'descend',
  },
  {
    title: '描述',
    dataIndex: 'description',
    key: 'description',
    ellipsis: true,
  },
]

const deadlockColumns: ColumnsType<DeadlockRisk> = [
  {
    title: '锁环',
    key: 'lock_cycle',
    render: (_, r) => (
      <Space>
        {r.lock_cycle.map((l, i) => (
          <span key={i}>
            <Text code>0x{l.toString(16).toUpperCase()}</Text>
            {i < r.lock_cycle.length - 1 && <Text type="secondary">→</Text>}
          </span>
        ))}
      </Space>
    ),
  },
  {
    title: '涉及线程',
    dataIndex: 'threads',
    key: 'threads',
    render: (tids: number[]) => (
      <Space>
        {tids.map((t) => (
          <Tag key={t}>T{t}</Tag>
        ))}
      </Space>
    ),
  },
  {
    title: '描述',
    dataIndex: 'description',
    key: 'description',
    ellipsis: true,
  },
]

const contentionColumns: ColumnsType<LockContentionInfo> = [
  {
    title: '锁地址',
    dataIndex: 'lock_address',
    key: 'lock_address',
    render: (addr: number) => <Text code>0x{addr.toString(16).toUpperCase()}</Text>,
    sorter: (a, b) => a.contention_ratio - b.contention_ratio,
    defaultSortOrder: 'descend',
  },
  {
    title: '获取次数',
    dataIndex: 'acquire_count',
    key: 'acquire_count',
    sorter: (a, b) => a.acquire_count - b.acquire_count,
  },
  {
    title: '争用次数',
    dataIndex: 'contention_count',
    key: 'contention_count',
    sorter: (a, b) => a.contention_count - b.contention_count,
  },
  {
    title: '争用率',
    dataIndex: 'contention_ratio',
    key: 'contention_ratio',
    render: (r: number) => (
      <Progress
        percent={Math.round(r * 100)}
        size="small"
        strokeColor={r > 0.3 ? '#ff4d4f' : r > 0.1 ? '#faad14' : '#52c41a'}
        format={(p) => `${p}%`}
      />
    ),
    sorter: (a, b) => a.contention_ratio - b.contention_ratio,
  },
  {
    title: '平均等待',
    dataIndex: 'avg_wait_ns',
    key: 'avg_wait_ns',
    render: (ns: number) => {
      if (ns >= 1_000_000) return `${(ns / 1_000_000).toFixed(2)} ms`
      if (ns >= 1_000) return `${(ns / 1_000).toFixed(2)} µs`
      return `${ns} ns`
    },
  },
  {
    title: '争用线程',
    dataIndex: 'contending_threads',
    key: 'contending_threads',
    render: (tids: number[]) => (
      <Space>
        {tids.map((t) => (
          <Tag key={t}>T{t}</Tag>
        ))}
      </Space>
    ),
  },
]

const funcAssocColumns: ColumnsType<ThreadFunctionAssoc> = [
  {
    title: '线程',
    dataIndex: 'thread_id',
    key: 'thread_id',
    render: (tid: number) => <Tag>T{tid}</Tag>,
  },
  {
    title: '函数地址',
    dataIndex: 'function_address',
    key: 'function_address',
    render: (addr: number) => <Text code>0x{addr.toString(16).toUpperCase()}</Text>,
  },
  {
    title: '调用次数',
    dataIndex: 'call_count',
    key: 'call_count',
    sorter: (a, b) => a.call_count - b.call_count,
    defaultSortOrder: 'descend',
  },
  {
    title: '步骤范围',
    key: 'step_range',
    render: (_, r) => <Text type="secondary">{r.first_call_step} — {r.last_call_step}</Text>,
  },
]

const funcSafetyColumns: ColumnsType<FunctionThreadSafety> = [
  {
    title: '函数地址',
    dataIndex: 'function_address',
    key: 'function_address',
    render: (addr: number) => <Text code>0x{addr.toString(16).toUpperCase()}</Text>,
  },
  {
    title: '安全性',
    dataIndex: 'safety',
    key: 'safety',
    render: (s: string) => <Tag color={safetyColor(s)}>{s}</Tag>,
  },
  {
    title: '调用线程数',
    dataIndex: 'calling_thread_count',
    key: 'calling_thread_count',
    sorter: (a, b) => a.calling_thread_count - b.calling_thread_count,
  },
  {
    title: '竞态数',
    dataIndex: 'race_count',
    key: 'race_count',
    render: (n: number) => n > 0 ? <Tag color="red">{n}</Tag> : <Tag>{n}</Tag>,
  },
  {
    title: '同步事件数',
    dataIndex: 'sync_event_count',
    key: 'sync_event_count',
  },
  {
    title: '调用线程',
    dataIndex: 'calling_threads',
    key: 'calling_threads',
    render: (tids: number[]) => (
      <Space>
        {tids.map((t) => <Tag key={t}>T{t}</Tag>)}
      </Space>
    ),
  },
]

const dataFlowColumns: ColumnsType<ThreadDataFlow> = [
  {
    title: '方向',
    key: 'direction',
    render: (_, r) => (
      <Space>
        <Tag>T{r.from_thread}</Tag>
        <SwapOutlined />
        <Tag>T{r.to_thread}</Tag>
      </Space>
    ),
  },
  {
    title: '地址',
    dataIndex: 'address',
    key: 'address',
    render: (addr: number) => <Text code>0x{addr.toString(16).toUpperCase()}</Text>,
  },
  {
    title: '步骤',
    key: 'steps',
    render: (_, r) => (
      <Text type="secondary">W:{r.write_step} → R:{r.read_step}</Text>
    ),
  },
  {
    title: '同步',
    dataIndex: 'is_synchronized',
    key: 'is_synchronized',
    render: (sync: boolean) => (
      <Tag color={sync ? 'green' : 'red'} icon={sync ? <SafetyOutlined /> : <WarningOutlined />}>
        {sync ? '已同步' : '未同步'}
      </Tag>
    ),
  },
]

const prodConsColumns: ColumnsType<ProducerConsumerPattern> = [
  {
    title: '生产者',
    dataIndex: 'producer_thread',
    key: 'producer_thread',
    render: (tid: number) => <Tag color="blue">T{tid}</Tag>,
  },
  {
    title: '消费者',
    dataIndex: 'consumer_thread',
    key: 'consumer_thread',
    render: (tid: number) => <Tag color="orange">T{tid}</Tag>,
  },
  {
    title: '共享地址',
    dataIndex: 'shared_addresses',
    key: 'shared_addresses',
    render: (addrs: number[]) => (
      <Space>
        {addrs.map((a) => <Tag key={a}><Text code>0x{a.toString(16).toUpperCase()}</Text></Tag>)}
      </Space>
    ),
  },
  {
    title: '周期数',
    dataIndex: 'cycle_count',
    key: 'cycle_count',
    sorter: (a, b) => a.cycle_count - b.cycle_count,
    defaultSortOrder: 'descend',
  },
  {
    title: '平均延迟',
    dataIndex: 'avg_latency_steps',
    key: 'avg_latency_steps',
    render: (steps: number) => `${steps} steps`,
  },
  {
    title: '同步机制',
    dataIndex: 'sync_mechanism',
    key: 'sync_mechanism',
    render: (addr: number | undefined) =>
      addr !== undefined ? <Text code>mutex@0x{addr.toString(16).toUpperCase()}</Text> : <Text type="secondary">无</Text>,
  },
]

// ============================================================================
// ThreadAnalysis Page
// ============================================================================
export default function ThreadAnalysis() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [activeTab, setActiveTab] = useState(searchParams.get('tab') ?? 'races')
  const [loading] = useState(false)

  const totalRaces = MOCK_RACES.length
  const totalDeadlocks = MOCK_DEADLOCKS.length
  const unsafeFuncs = MOCK_FUNC_SAFETY.filter(f => f.safety === 'Unsafe').length
  const hotLocks = MOCK_CONTENTIONS.filter(c => c.contention_ratio > 0.3).length

  return (
    <div>
      <Title level={4}>
        <ThunderboltOutlined /> 线程分析
      </Title>
      <Text type="secondary">
        针对 Android SO 多线程场景的深度分析：竞态检测、死锁风险、锁争用、线程数据流
      </Text>

      <Spin spinning={loading}>
        {/* Summary alerts */}
        <Row gutter={16} style={{ marginTop: 16, marginBottom: 24 }}>
          {totalRaces > 0 && (
            <Col span={24}>
              <Alert
                type="error"
                showIcon
                icon={<BugOutlined />}
                message={`检测到 ${totalRaces} 个潜在竞态条件`}
                description="多线程同时访问共享内存且未使用同步机制保护，可能导致数据损坏或安全漏洞"
                banner
              />
            </Col>
          )}
          {totalDeadlocks > 0 && (
            <Col span={24} style={{ marginTop: 8 }}>
              <Alert
                type="warning"
                showIcon
                icon={<WarningOutlined />}
                message={`检测到 ${totalDeadlocks} 个潜在死锁风险`}
                description="存在锁获取顺序不一致的模式，可能导致线程永久阻塞"
                banner
              />
            </Col>
          )}
        </Row>

        {/* Summary stats */}
        <Row gutter={16} style={{ marginBottom: 24 }}>
          <Col span={6}>
            <Card>
              <Statistic
                title="竞态条件"
                value={totalRaces}
                prefix={<BugOutlined />}
                valueStyle={{ color: totalRaces > 0 ? '#cf1322' : '#3f8600' }}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic
                title="死锁风险"
                value={totalDeadlocks}
                prefix={<WarningOutlined />}
                valueStyle={{ color: totalDeadlocks > 0 ? '#d48806' : '#3f8600' }}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic
                title="不安全函数"
                value={unsafeFuncs}
                prefix={<SafetyOutlined />}
                valueStyle={{ color: unsafeFuncs > 0 ? '#cf1322' : '#3f8600' }}
              />
            </Card>
          </Col>
          <Col span={6}>
            <Card>
              <Statistic
                title="热锁（>30%争用）"
                value={hotLocks}
                prefix={<LockOutlined />}
                valueStyle={{ color: hotLocks > 0 ? '#d48806' : '#3f8600' }}
              />
            </Card>
          </Col>
        </Row>

        {/* Thread list */}
        <Card title="线程概览" style={{ marginBottom: 24 }}>
          <Table
            dataSource={MOCK_THREADS}
            rowKey="thread_id"
            pagination={false}
            size="small"
            columns={[
              { title: '线程 ID', dataIndex: 'thread_id', key: 'tid' },
              { title: '名称', dataIndex: 'name', key: 'name', render: (n: string | undefined) => n || <Text type="secondary">未命名</Text> },
              { title: '父线程', dataIndex: 'parent_thread_id', key: 'parent' },
              { title: '创建步骤', dataIndex: 'create_step', key: 'create' },
              { title: '栈基址', dataIndex: 'stack_base', key: 'stack_base', render: (a: number) => <Text code>0x{a.toString(16).toUpperCase()}</Text> },
              { title: '栈大小', dataIndex: 'stack_size', key: 'stack_size', render: (s: number) => `${(s / 1024).toFixed(0)} KB` },
              {
                title: 'JNI',
                dataIndex: 'is_jni_attached',
                key: 'jni',
                render: (v: boolean) => v ? <Tag color="blue">JNI</Tag> : <Tag>Native</Tag>,
              },
            ]}
          />
        </Card>

        {/* Analysis tabs */}
        <Card>
          <Tabs
            activeKey={activeTab}
            onChange={(key) => {
              setActiveTab(key)
              setSearchParams((prev) => { prev.set('tab', key); return prev }, { replace: true })
            }}
            items={[
              {
                key: 'races',
                label: (
                  <span>
                    <BugOutlined /> 竞态条件
                    {totalRaces > 0 && <Tag color="red" style={{ marginLeft: 8 }}>{totalRaces}</Tag>}
                  </span>
                ),
                children: (
                  <Table
                    dataSource={MOCK_RACES}
                    columns={raceColumns}
                    rowKey={(_, i) => `race-${i}`}
                    size="small"
                    pagination={{ pageSize: 10 }}
                  />
                ),
              },
              {
                key: 'deadlocks',
                label: (
                  <span>
                    <WarningOutlined /> 死锁风险
                    {totalDeadlocks > 0 && <Tag color="orange" style={{ marginLeft: 8 }}>{totalDeadlocks}</Tag>}
                  </span>
                ),
                children: (
                  <Table
                    dataSource={MOCK_DEADLOCKS}
                    columns={deadlockColumns}
                    rowKey={(_, i) => `deadlock-${i}`}
                    size="small"
                    pagination={{ pageSize: 10 }}
                  />
                ),
              },
              {
                key: 'contentions',
                label: (
                  <span>
                    <LockOutlined /> 锁争用
                  </span>
                ),
                children: (
                  <Table
                    dataSource={MOCK_CONTENTIONS}
                    columns={contentionColumns}
                    rowKey="lock_address"
                    size="small"
                    pagination={{ pageSize: 10 }}
                  />
                ),
              },
              {
                key: 'func_assoc',
                label: (
                  <span>
                    <FunctionOutlined /> 线程-函数关联
                  </span>
                ),
                children: (
                  <Table
                    dataSource={MOCK_FUNC_ASSOCS}
                    columns={funcAssocColumns}
                    rowKey={(_, i) => `assoc-${i}`}
                    size="small"
                    pagination={{ pageSize: 10 }}
                  />
                ),
              },
              {
                key: 'func_safety',
                label: (
                  <span>
                    <SafetyOutlined /> 函数线程安全
                  </span>
                ),
                children: (
                  <>
                    <Alert
                      type="info"
                      message="线程安全分类说明"
                      description={
                        <ul style={{ margin: 0, paddingLeft: 20 }}>
                          <li><Tag color="red">Unsafe</Tag> — 多线程调用且存在竞态条件</li>
                          <li><Tag color="orange">PotentiallyUnsafe</Tag> — 多线程调用但未观察到同步</li>
                          <li><Tag>Unknown</Tag> — 仅被单一线程调用，无法判断</li>
                          <li><Tag color="green">ThreadSafe</Tag> — 多线程调用且存在同步保护</li>
                        </ul>
                      }
                      style={{ marginBottom: 16 }}
                    />
                    <Table
                      dataSource={MOCK_FUNC_SAFETY}
                      columns={funcSafetyColumns}
                      rowKey="function_address"
                      size="small"
                      pagination={{ pageSize: 10 }}
                    />
                  </>
                ),
              },
              {
                key: 'data_flow',
                label: (
                  <span>
                    <SwapOutlined /> 线程数据流
                  </span>
                ),
                children: (
                  <Table
                    dataSource={MOCK_DATA_FLOWS}
                    columns={dataFlowColumns}
                    rowKey={(_, i) => `flow-${i}`}
                    size="small"
                    pagination={{ pageSize: 10 }}
                  />
                ),
              },
              {
                key: 'prod_cons',
                label: (
                  <span>
                    <ThunderboltOutlined /> 生产者-消费者
                  </span>
                ),
                children: (
                  <>
                    <Alert
                      type="info"
                      message="生产者-消费者模式"
                      description="检测线程间通过共享内存实现的典型生产者-消费者通信模式，并识别其同步机制"
                      style={{ marginBottom: 16 }}
                    />
                    <Table
                      dataSource={MOCK_PROD_CONS}
                      columns={prodConsColumns}
                      rowKey={(_, i) => `pc-${i}`}
                      size="small"
                      pagination={{ pageSize: 10 }}
                    />
                  </>
                ),
              },
            ]}
          />
        </Card>
      </Spin>
    </div>
  )
}
